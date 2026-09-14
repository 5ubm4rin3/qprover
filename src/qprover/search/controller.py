"""Budget-equal search orchestration and structured event ledger."""

from __future__ import annotations

import time
import uuid
from collections import Counter
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from types import MappingProxyType

from qprover.models import Candidate, ConfirmationStatus, Outcome, SearchLimits
from qprover.search.base import (
    CandidateEvaluator,
    Evaluation,
    SearchStrategy,
    StrategyStats,
    candidate_to_dict,
    freeze_json_mapping,
    thaw_json,
)
from qprover.search.bqm import SearchProblem


@dataclass(frozen=True, slots=True)
class SearchEvent:
    run_id: str
    sequence: int
    timestamp_offset: float
    phase: str
    severity: str
    category: str
    payload: Mapping[str, object]

    def __post_init__(self) -> None:
        object.__setattr__(self, "payload", freeze_json_mapping(self.payload))

    def to_dict(self) -> dict[str, object]:
        return {
            "run_id": self.run_id,
            "sequence": self.sequence,
            "timestamp_offset": self.timestamp_offset,
            "phase": self.phase,
            "severity": self.severity,
            "category": self.category,
            "payload": thaw_json(self.payload),
        }


@dataclass(frozen=True, slots=True)
class EvaluatedCandidate:
    candidate: Candidate
    evaluation: Evaluation


@dataclass(frozen=True, slots=True)
class SearchRun:
    run_id: str
    stop_reason: str
    confirmation_status: ConfirmationStatus
    candidates_evaluated: int
    evm_transactions: int
    duplicate_proposals: int
    wall_seconds: float
    outcome_counts: Mapping[Outcome, int]
    evaluations: tuple[EvaluatedCandidate, ...]
    events: tuple[SearchEvent, ...]
    strategy_stats: StrategyStats
    violation: Candidate | None = None
    failed: bool = False
    failure_reason: str | None = None

    def __post_init__(self) -> None:
        counts = dict(self.outcome_counts)
        if any(
            not isinstance(outcome, Outcome) or type(count) is not int or count < 0
            for outcome, count in counts.items()
        ):
            raise ValueError("outcome counts must be nonnegative exact integers")
        evaluations = tuple(self.evaluations)
        events = tuple(self.events)
        if any(not isinstance(item, EvaluatedCandidate) for item in evaluations):
            raise TypeError("evaluations must contain EvaluatedCandidate records")
        if any(not isinstance(item, SearchEvent) for item in events):
            raise TypeError("events must contain SearchEvent records")
        object.__setattr__(self, "outcome_counts", MappingProxyType(counts))
        object.__setattr__(self, "evaluations", evaluations)
        object.__setattr__(self, "events", events)

    def to_dict(self) -> dict[str, object]:
        return {
            "run_id": self.run_id,
            "stop_reason": self.stop_reason,
            "confirmation_status": self.confirmation_status.value,
            "candidates_evaluated": self.candidates_evaluated,
            "evm_transactions": self.evm_transactions,
            "duplicate_proposals": self.duplicate_proposals,
            "wall_seconds": self.wall_seconds,
            "outcome_counts": {
                outcome.value: self.outcome_counts.get(outcome, 0)
                for outcome in Outcome
            },
            "evaluations": [
                {
                    "candidate": candidate_to_dict(item.candidate),
                    "evaluation": item.evaluation.to_dict(),
                }
                for item in self.evaluations
            ],
            "events": [event.to_dict() for event in self.events],
            "strategy_stats": self.strategy_stats.to_dict(),
            "violation": (
                candidate_to_dict(self.violation)
                if self.violation is not None
                else None
            ),
            "failed": self.failed,
            "failure_reason": self.failure_reason,
        }


class _EventLedger:
    def __init__(self, run_id: str, started: float) -> None:
        self.run_id = run_id
        self.started = started
        self.events: list[SearchEvent] = []

    def record(
        self,
        now: float,
        phase: str,
        *,
        severity: str = "info",
        category: str = "search",
        payload: Mapping[str, object] | None = None,
    ) -> None:
        self.events.append(
            SearchEvent(
                run_id=self.run_id,
                sequence=len(self.events),
                timestamp_offset=max(0.0, now - self.started),
                phase=phase,
                severity=severity,
                category=category,
                payload=freeze_json_mapping(payload),
            )
        )


def _evaluation_contract_error(
    candidate: Candidate,
    result: Evaluation,
) -> str | None:
    length = len(candidate.steps)
    count = result.transaction_count
    if result.outcome is Outcome.PASS and count != length:
        return "PASS transaction_count must equal candidate length"
    if result.outcome is Outcome.VIOLATION:
        prefix = result.metadata.get("violation_prefix_length")
        if count == length and prefix in (None, count):
            return None
        if not 1 <= count < length or prefix != count:
            if prefix is None:
                return "VIOLATION transaction_count must equal candidate length"
            return (
                "VIOLATION transaction_count must equal candidate length or its "
                "recorded positive candidate prefix"
            )
    if result.outcome is Outcome.REVERT and not 1 <= count <= length:
        return "REVERT transaction_count must be a positive prefix"
    if result.outcome in {Outcome.INCONCLUSIVE, Outcome.INFRA_ERROR} and count > length:
        return f"{result.outcome.value} transaction_count exceeds candidate length"
    return None


class SearchController:
    """Run a strategy under hard proposal, transaction, and wall-clock gates.

    ``candidate_validator`` permits callers that own a ``SearchProblem`` to
    inject exact allowed-variant validation without changing the specified
    ``run(strategy, evaluator, limits)`` interface. Structural validation is
    always enforced, even when no validator is provided.
    """

    def __init__(
        self,
        *,
        clock: Callable[[], float] = time.monotonic,
        run_id_factory: Callable[[], str] = lambda: uuid.uuid4().hex,
        duplicate_retry_limit: int = 32,
        candidate_validator: Callable[[Candidate], bool] | None = None,
    ) -> None:
        if type(duplicate_retry_limit) is not int or duplicate_retry_limit <= 0:
            raise ValueError("duplicate_retry_limit must be an exact positive integer")
        self._clock = clock
        self._run_id_factory = run_id_factory
        self._duplicate_retry_limit = duplicate_retry_limit
        self._candidate_validator = candidate_validator

    def run(
        self,
        strategy: SearchStrategy,
        evaluator: CandidateEvaluator,
        limits: SearchLimits,
        *,
        problem: SearchProblem | None = None,
        seed: int | None = None,
    ) -> SearchRun:
        started = self._clock()
        run_id = self._run_id_factory()
        if not isinstance(run_id, str) or not run_id:
            raise ValueError("run_id_factory must return a nonempty string")
        ledger = _EventLedger(run_id, started)
        seen: set[str] = set()
        evaluations: list[EvaluatedCandidate] = []
        outcomes: Counter[Outcome] = Counter()
        transactions = 0
        duplicate_proposals = 0
        consecutive_duplicates = 0
        violation: Candidate | None = None
        failed = False
        failure_reason: str | None = None
        stop_reason = "solver_exhausted_unproven"
        finished = started

        initialization_stopped = False
        if (problem is None) != (seed is None):
            raise ValueError("problem and seed must be supplied together")
        if problem is not None and seed is not None:
            try:
                strategy.initialize(problem, seed)
            except Exception as error:  # strategy initialization boundary
                finished = self._clock()
                failed = True
                failure_reason = (
                    f"strategy initialization raised {type(error).__name__}"
                )
                stop_reason = "strategy_initialization_error"
                initialization_stopped = True
                ledger.record(
                    finished,
                    "initialization",
                    severity="error",
                    category="strategy",
                    payload={"error_type": type(error).__name__, "seed": seed},
                )
            else:
                finished = self._clock()
                ledger.record(
                    finished,
                    "initialization",
                    payload={"seed": seed, "problem_sha256": problem.sha256},
                )
                if finished - started >= limits.wall_seconds:
                    stop_reason = "wall_budget"
                    initialization_stopped = True

        while not initialization_stopped:
            now = self._clock()
            finished = now
            if now - started >= limits.wall_seconds:
                stop_reason = "wall_budget"
                break
            if len(evaluations) >= limits.candidate_budget:
                stop_reason = "candidate_budget"
                break
            remaining = limits.transaction_budget - transactions
            if remaining <= 0:
                stop_reason = "transaction_budget"
                break

            proposed = strategy.propose(remaining)
            proposal_finished = self._clock()
            finished = proposal_finished
            if proposed is None:
                if proposal_finished - started >= limits.wall_seconds:
                    stop_reason = "wall_budget"
                else:
                    proposal_stats = getattr(strategy, "stats", None)
                    proven = (
                        isinstance(proposal_stats, StrategyStats)
                        and proposal_stats.metadata.get("exhaustion_proven") is True
                    )
                    stop_reason = (
                        "search_space_exhausted"
                        if proven
                        else "solver_exhausted_unproven"
                    )
                break
            if not isinstance(proposed, Candidate):
                failed = True
                failure_reason = "strategy proposal must be a Candidate or None"
                stop_reason = "invalid_candidate"
                ledger.record(
                    proposal_finished,
                    "proposal",
                    severity="error",
                    category="strategy-contract",
                    payload={"candidate_id": None, "valid": False},
                )
                break
            if proposal_finished - started >= limits.wall_seconds:
                ledger.record(
                    proposal_finished,
                    "proposal",
                    payload={
                        "candidate_id": proposed.canonical_id,
                        "transactions": len(proposed.steps),
                    },
                )
                stop_reason = "wall_budget"
                break
            if not proposed.steps:
                failed = True
                failure_reason = "candidate must contain at least one transaction"
                stop_reason = "invalid_candidate"
                ledger.record(
                    proposal_finished,
                    "proposal",
                    severity="error",
                    category="strategy-contract",
                    payload={
                        "candidate_id": proposed.canonical_id,
                        "transactions": 0,
                        "valid": False,
                    },
                )
                break
            if len(proposed.steps) > limits.max_sequence_length:
                failed = True
                failure_reason = "candidate exceeds maximum sequence length"
                stop_reason = "invalid_candidate"
                ledger.record(
                    proposal_finished,
                    "proposal",
                    severity="error",
                    category="strategy-contract",
                    payload={
                        "candidate_id": proposed.canonical_id,
                        "transactions": len(proposed.steps),
                        "valid": False,
                    },
                )
                break
            if self._candidate_validator is not None:
                try:
                    valid = self._candidate_validator(proposed)
                except Exception as error:  # validator boundary normalization
                    failed = True
                    failure_reason = (
                        f"candidate validator raised {type(error).__name__}"
                    )
                    stop_reason = "candidate_validation_error"
                    ledger.record(
                        proposal_finished,
                        "proposal",
                        severity="error",
                        category="candidate-validator",
                        payload={
                            "candidate_id": proposed.canonical_id,
                            "error_type": type(error).__name__,
                            "valid": False,
                        },
                    )
                    break
                if type(valid) is not bool:
                    failed = True
                    returned_type = type(valid).__name__
                    failure_reason = (
                        f"candidate validator returned {returned_type}, expected bool"
                    )
                    stop_reason = "candidate_validation_error"
                    ledger.record(
                        proposal_finished,
                        "proposal",
                        severity="error",
                        category="candidate-validator",
                        payload={
                            "candidate_id": proposed.canonical_id,
                            "returned_type": returned_type,
                            "valid": False,
                        },
                    )
                    break
                if not valid:
                    failed = True
                    failure_reason = "candidate rejected by validator"
                    stop_reason = "invalid_candidate"
                    ledger.record(
                        proposal_finished,
                        "proposal",
                        severity="error",
                        category="strategy-contract",
                        payload={
                            "candidate_id": proposed.canonical_id,
                            "transactions": len(proposed.steps),
                            "valid": False,
                        },
                    )
                    break
            is_duplicate = proposed.canonical_id in seen
            ledger.record(
                proposal_finished,
                "proposal",
                payload={
                    "candidate_id": proposed.canonical_id,
                    "duplicate": is_duplicate,
                    "transactions": len(proposed.steps),
                    "valid": True,
                },
            )
            if is_duplicate:
                duplicate_proposals += 1
                consecutive_duplicates += 1
                if consecutive_duplicates >= self._duplicate_retry_limit:
                    proposal_stats = getattr(strategy, "stats", None)
                    stop_reason = (
                        "search_space_exhausted"
                        if isinstance(proposal_stats, StrategyStats)
                        and proposal_stats.metadata.get("exhaustion_proven") is True
                        else "solver_exhausted_unproven"
                    )
                    break
                continue
            consecutive_duplicates = 0
            seen.add(proposed.canonical_id)
            if len(proposed.steps) > remaining:
                stop_reason = "transaction_budget"
                break

            try:
                result = evaluator.evaluate(proposed)
            except Exception as error:  # evaluator boundary normalization
                finished = self._clock()
                failed = True
                failure_reason = f"evaluator raised {type(error).__name__}"
                stop_reason = "evaluator_error"
                ledger.record(
                    finished,
                    "execution",
                    severity="error",
                    category="evaluator",
                    payload={
                        "candidate_id": proposed.canonical_id,
                        "error_type": type(error).__name__,
                        "valid": False,
                    },
                )
                break
            finished = self._clock()
            if not isinstance(result, Evaluation):
                failed = True
                failure_reason = "evaluator must return an Evaluation record"
                stop_reason = "invalid_evaluation"
                ledger.record(
                    finished,
                    "execution",
                    severity="error",
                    category="evaluator-contract",
                    payload={
                        "candidate_id": proposed.canonical_id,
                        "valid": False,
                    },
                )
                break
            accounting_error = _evaluation_contract_error(proposed, result)
            if accounting_error is not None:
                failed = True
                failure_reason = accounting_error
                stop_reason = "invalid_evaluation"
                ledger.record(
                    finished,
                    "execution",
                    severity="error",
                    category="evaluator-contract",
                    payload={
                        "candidate_id": proposed.canonical_id,
                        "outcome": result.outcome.value,
                        "transaction_count": result.transaction_count,
                        "valid": False,
                    },
                )
                break
            timed_out = finished - started >= limits.wall_seconds
            transactions += result.transaction_count
            outcomes[result.outcome] += 1
            evaluations.append(EvaluatedCandidate(proposed, result))
            is_infrastructure_error = result.outcome is Outcome.INFRA_ERROR
            if is_infrastructure_error:
                failed = True
                failure_reason = "evaluator returned INFRA_ERROR"
            ledger.record(
                finished,
                "execution",
                severity="error" if is_infrastructure_error else "info",
                category="infrastructure" if is_infrastructure_error else "candidate",
                payload={
                    "candidate_id": proposed.canonical_id,
                    "outcome": result.outcome.value,
                    "transaction_count": result.transaction_count,
                    "timed_out": timed_out,
                    "feedback_applied": not timed_out,
                },
            )
            if timed_out:
                stop_reason = "wall_budget"
                break
            strategy.observe(proposed, result)
            ledger.record(
                finished,
                "feedback",
                payload={
                    "candidate_id": proposed.canonical_id,
                    "outcome": result.outcome.value,
                },
            )
            if result.outcome is Outcome.VIOLATION:
                violation = proposed
                stop_reason = "violation"
                break
            if is_infrastructure_error:
                stop_reason = "infrastructure_error"
                break

        severity = "error" if failed else "info"
        if failed:
            stop_category = "infrastructure"
        elif stop_reason.endswith("_budget"):
            stop_category = "budget"
        else:
            stop_category = "search"
        ledger.record(
            finished,
            "stop",
            severity=severity,
            category=stop_category,
            payload={"reason": stop_reason, "failure_reason": failure_reason},
        )
        strategy_stats = getattr(
            strategy,
            "stats",
            StrategyStats(name=type(strategy).__name__),
        )
        if not isinstance(strategy_stats, StrategyStats):
            raise ValueError("optional strategy stats must be a StrategyStats record")
        return SearchRun(
            run_id=run_id,
            stop_reason=stop_reason,
            confirmation_status=(
                ConfirmationStatus.CANDIDATE_VIOLATION
                if violation is not None
                else ConfirmationStatus.NOT_CONFIRMED
            ),
            candidates_evaluated=len(evaluations),
            evm_transactions=transactions,
            duplicate_proposals=duplicate_proposals,
            wall_seconds=max(0.0, finished - started),
            outcome_counts={outcome: outcomes[outcome] for outcome in Outcome},
            evaluations=tuple(evaluations),
            events=tuple(ledger.events),
            strategy_stats=strategy_stats,
            violation=violation,
            failed=failed,
            failure_reason=failure_reason,
        )
