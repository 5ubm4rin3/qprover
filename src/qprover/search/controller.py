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
)


def _mapping(value: Mapping | None = None) -> MappingProxyType:
    return MappingProxyType(dict(value or {}))


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
        object.__setattr__(self, "payload", _mapping(self.payload))

    def to_dict(self) -> dict[str, object]:
        return {
            "run_id": self.run_id,
            "sequence": self.sequence,
            "timestamp_offset": self.timestamp_offset,
            "phase": self.phase,
            "severity": self.severity,
            "category": self.category,
            "payload": dict(self.payload),
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

    def __post_init__(self) -> None:
        object.__setattr__(self, "outcome_counts", _mapping(self.outcome_counts))


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
                payload=_mapping(payload),
            )
        )


class SearchController:
    def __init__(
        self,
        *,
        clock: Callable[[], float] = time.monotonic,
        run_id_factory: Callable[[], str] = lambda: uuid.uuid4().hex,
        duplicate_retry_limit: int = 32,
    ) -> None:
        if type(duplicate_retry_limit) is not int or duplicate_retry_limit <= 0:
            raise ValueError("duplicate_retry_limit must be an exact positive integer")
        self._clock = clock
        self._run_id_factory = run_id_factory
        self._duplicate_retry_limit = duplicate_retry_limit

    def run(
        self,
        strategy: SearchStrategy,
        evaluator: CandidateEvaluator,
        limits: SearchLimits,
    ) -> SearchRun:
        started = self._clock()
        run_id = self._run_id_factory()
        ledger = _EventLedger(run_id, started)
        seen: set[str] = set()
        evaluations: list[EvaluatedCandidate] = []
        outcomes: Counter[Outcome] = Counter()
        transactions = 0
        duplicate_proposals = 0
        consecutive_duplicates = 0
        violation: Candidate | None = None
        failed = False
        stop_reason = "search_space_exhausted"
        finished = started

        while True:
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
            if proposed is None:
                stop_reason = "search_space_exhausted"
                break
            is_duplicate = proposed.canonical_id in seen
            ledger.record(
                now,
                "proposal",
                payload={
                    "candidate_id": proposed.canonical_id,
                    "duplicate": is_duplicate,
                    "transactions": len(proposed.steps),
                },
            )
            if is_duplicate:
                duplicate_proposals += 1
                consecutive_duplicates += 1
                if consecutive_duplicates >= self._duplicate_retry_limit:
                    stop_reason = "search_space_exhausted"
                    break
                continue
            consecutive_duplicates = 0
            seen.add(proposed.canonical_id)
            if len(proposed.steps) > remaining:
                stop_reason = "transaction_budget"
                break

            result = evaluator.evaluate(proposed)
            if result.transaction_count > len(proposed.steps):
                raise ValueError(
                    "evaluation transaction_count exceeds candidate length"
                )
            transactions += result.transaction_count
            finished = self._clock()
            outcomes[result.outcome] += 1
            evaluations.append(EvaluatedCandidate(proposed, result))
            ledger.record(
                finished,
                "execution",
                severity="error" if result.outcome is Outcome.INFRA_ERROR else "info",
                category=(
                    "infrastructure"
                    if result.outcome is Outcome.INFRA_ERROR
                    else "candidate"
                ),
                payload={
                    "candidate_id": proposed.canonical_id,
                    "outcome": result.outcome.value,
                    "transaction_count": result.transaction_count,
                },
            )
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
            if result.outcome is Outcome.INFRA_ERROR:
                failed = True
                stop_reason = "infrastructure_error"
                break

        severity = "error" if failed else "info"
        ledger.record(
            finished,
            "stop",
            severity=severity,
            category="infrastructure" if failed else "budget",
            payload={"reason": stop_reason},
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
        )
