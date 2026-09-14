from __future__ import annotations

import json
from collections.abc import Iterable

import pytest

from qprover.models import (
    ActionStep,
    Candidate,
    ConfirmationStatus,
    Outcome,
    SearchLimits,
)
from qprover.search.base import Evaluation, StrategyStats
from qprover.search.controller import SearchController, SearchEvent


def candidate(*actions: str) -> Candidate:
    return Candidate(
        tuple(ActionStep(action, "vault", f"{action}()", 0, ()) for action in actions)
    )


class ScriptedStrategy:
    name = "scripted"

    def __init__(self, candidates: Iterable[Candidate | None]) -> None:
        self._candidates = iter(candidates)
        self.observed: list[tuple[Candidate, Evaluation]] = []

    def initialize(self, problem, seed: int) -> None:
        del problem, seed

    def propose(self, remaining_transactions: int) -> Candidate | None:
        del remaining_transactions
        return next(self._candidates, None)

    def observe(self, candidate: Candidate, result: Evaluation) -> None:
        self.observed.append((candidate, result))

    @property
    def stats(self) -> StrategyStats:
        return StrategyStats(name=self.name, counters={"observed": len(self.observed)})


class FakeEvaluator:
    def __init__(self, outcomes: Iterable[Outcome], transaction_counts=None) -> None:
        self._outcomes = iter(outcomes)
        self._transaction_counts = iter(transaction_counts or ())
        self.calls: list[Candidate] = []

    def evaluate(self, proposed: Candidate) -> Evaluation:
        self.calls.append(proposed)
        outcome = next(self._outcomes)
        transactions = next(self._transaction_counts, len(proposed.steps))
        return Evaluation(
            outcome=outcome,
            transaction_count=transactions,
            trace_features=frozenset({proposed.canonical_id[:8]}),
            state_fingerprint=proposed.canonical_id,
        )


def limits(
    *, transaction_budget: int = 10, candidate_budget: int = 10, wall_seconds: int = 30
) -> SearchLimits:
    return SearchLimits(
        max_sequence_length=3,
        transaction_budget=transaction_budget,
        candidate_budget=candidate_budget,
        wall_seconds=wall_seconds,
    )


def controller(*, clock=None, duplicate_retry_limit: int = 3) -> SearchController:
    options = {
        "run_id_factory": lambda: "run-fixed",
        "duplicate_retry_limit": duplicate_retry_limit,
    }
    if clock is not None:
        options["clock"] = clock
    return SearchController(**options)


def test_controller_counts_actual_transactions_and_refuses_oversized_proposal() -> None:
    short = candidate("prepare", "trigger")
    too_long_for_remainder = candidate("prepare", "observe")
    strategy = ScriptedStrategy((short, too_long_for_remainder))
    evaluator = FakeEvaluator((Outcome.PASS,), transaction_counts=(2,))

    run = controller().run(
        strategy=strategy,
        evaluator=evaluator,
        limits=limits(transaction_budget=3),
    )

    assert run.evm_transactions == 2
    assert run.candidates_evaluated == 1
    assert evaluator.calls == [short]
    assert run.stop_reason == "transaction_budget"
    assert run.confirmation_status is ConfirmationStatus.NOT_CONFIRMED


def test_controller_uses_returned_transaction_count_not_candidate_length() -> None:
    reverted = candidate("prepare", "trigger", "observe")
    final = candidate("trigger")
    strategy = ScriptedStrategy((reverted, final, None))
    evaluator = FakeEvaluator((Outcome.REVERT, Outcome.PASS), transaction_counts=(1, 1))

    run = controller().run(
        strategy=strategy,
        evaluator=evaluator,
        limits=limits(transaction_budget=4),
    )

    assert run.evm_transactions == 2
    assert run.candidates_evaluated == 2
    assert run.outcome_counts[Outcome.REVERT] == 1
    assert run.outcome_counts[Outcome.PASS] == 1


def test_controller_stops_on_executed_violation_without_confirming() -> None:
    violation = candidate("prepare", "trigger")
    skipped = candidate("observe")
    strategy = ScriptedStrategy((violation, skipped))
    evaluator = FakeEvaluator((Outcome.VIOLATION, Outcome.PASS))

    run = controller().run(strategy=strategy, evaluator=evaluator, limits=limits())

    assert evaluator.calls == [violation]
    assert run.stop_reason == "violation"
    assert run.violation == violation
    assert run.confirmation_status is ConfirmationStatus.CANDIDATE_VIOLATION
    assert run.confirmation_status is not ConfirmationStatus.CONFIRMED


def test_controller_rejects_empty_candidate_before_evaluation() -> None:
    empty = Candidate(())
    strategy = ScriptedStrategy((empty,))
    evaluator = FakeEvaluator((Outcome.VIOLATION,), transaction_counts=(0,))

    run = controller().run(strategy=strategy, evaluator=evaluator, limits=limits())

    assert run.failed
    assert run.stop_reason == "invalid_candidate"
    assert run.failure_reason == "candidate must contain at least one transaction"
    assert run.candidates_evaluated == 0
    assert run.evm_transactions == 0
    assert run.outcome_counts[Outcome.VIOLATION] == 0
    assert evaluator.calls == []
    assert strategy.observed == []
    assert run.events[0].severity == "error"
    assert run.events[0].category == "strategy-contract"
    assert "duplicate" not in run.events[0].payload


def test_controller_applies_injected_candidate_validator_before_evaluation() -> None:
    proposed = candidate("prepare")
    strategy = ScriptedStrategy((proposed,))
    evaluator = FakeEvaluator((Outcome.PASS,))
    guarded = SearchController(
        candidate_validator=lambda item: item.steps[0].action_id != "prepare",
        run_id_factory=lambda: "run-fixed",
    )

    run = guarded.run(strategy=strategy, evaluator=evaluator, limits=limits())

    assert run.failed
    assert run.stop_reason == "invalid_candidate"
    assert run.failure_reason == "candidate rejected by validator"
    assert evaluator.calls == []


@pytest.mark.parametrize("outcome", [Outcome.PASS, Outcome.VIOLATION])
@pytest.mark.parametrize("transaction_count", [0, 1])
def test_controller_rejects_unexecuted_or_partial_success_records(
    outcome: Outcome,
    transaction_count: int,
) -> None:
    proposed = candidate("prepare", "trigger")
    strategy = ScriptedStrategy((proposed,))
    evaluator = FakeEvaluator((outcome,), transaction_counts=(transaction_count,))

    run = controller().run(strategy=strategy, evaluator=evaluator, limits=limits())

    assert run.failed
    assert run.stop_reason == "invalid_evaluation"
    assert run.failure_reason == (
        f"{outcome.value} transaction_count must equal candidate length"
    )
    assert run.candidates_evaluated == 0
    assert run.evm_transactions == 0
    assert run.outcome_counts[outcome] == 0
    assert strategy.observed == []


def test_controller_rejects_zero_transaction_revert_record() -> None:
    proposed = candidate("prepare")
    strategy = ScriptedStrategy((proposed,))
    evaluator = FakeEvaluator((Outcome.REVERT,), transaction_counts=(0,))

    run = controller().run(strategy=strategy, evaluator=evaluator, limits=limits())

    assert run.failed
    assert run.stop_reason == "invalid_evaluation"
    assert run.failure_reason == "REVERT transaction_count must be a positive prefix"
    assert run.candidates_evaluated == 0
    assert run.outcome_counts[Outcome.REVERT] == 0


def test_controller_documents_zero_execution_error_outcomes() -> None:
    inconclusive = controller().run(
        strategy=ScriptedStrategy((candidate("prepare"), None)),
        evaluator=FakeEvaluator((Outcome.INCONCLUSIVE,), transaction_counts=(0,)),
        limits=limits(),
    )
    infrastructure = controller().run(
        strategy=ScriptedStrategy((candidate("prepare"),)),
        evaluator=FakeEvaluator((Outcome.INFRA_ERROR,), transaction_counts=(0,)),
        limits=limits(),
    )

    assert not inconclusive.failed
    assert inconclusive.candidates_evaluated == 1
    assert inconclusive.evm_transactions == 0
    assert inconclusive.outcome_counts[Outcome.INCONCLUSIVE] == 1
    assert infrastructure.failed
    assert infrastructure.stop_reason == "infrastructure_error"
    assert infrastructure.outcome_counts[Outcome.INFRA_ERROR] == 1


def test_controller_propagates_infrastructure_error_as_failed_run() -> None:
    strategy = ScriptedStrategy((candidate("prepare"), candidate("trigger")))
    evaluator = FakeEvaluator((Outcome.INFRA_ERROR, Outcome.PASS))

    run = controller().run(strategy=strategy, evaluator=evaluator, limits=limits())

    assert run.failed
    assert run.stop_reason == "infrastructure_error"
    assert run.outcome_counts[Outcome.INFRA_ERROR] == 1
    assert len(evaluator.calls) == 1
    assert run.confirmation_status is ConfirmationStatus.NOT_CONFIRMED


def test_controller_retains_revert_and_inconclusive_as_measured_outcomes() -> None:
    strategy = ScriptedStrategy((candidate("prepare"), candidate("trigger"), None))
    evaluator = FakeEvaluator((Outcome.REVERT, Outcome.INCONCLUSIVE))

    run = controller().run(strategy=strategy, evaluator=evaluator, limits=limits())

    assert not run.failed
    assert run.candidates_evaluated == 2
    assert run.outcome_counts[Outcome.REVERT] == 1
    assert run.outcome_counts[Outcome.INCONCLUSIVE] == 1
    assert len(strategy.observed) == 2
    assert run.confirmation_status is ConfirmationStatus.NOT_CONFIRMED


def test_controller_enforces_candidate_budget_without_safe_verdict() -> None:
    strategy = ScriptedStrategy(
        (candidate("prepare"), candidate("trigger"), candidate("observe"))
    )
    evaluator = FakeEvaluator((Outcome.PASS, Outcome.PASS, Outcome.PASS))

    run = controller().run(
        strategy=strategy,
        evaluator=evaluator,
        limits=limits(candidate_budget=2),
    )

    assert run.candidates_evaluated == 2
    assert run.stop_reason == "candidate_budget"
    assert run.confirmation_status is ConfirmationStatus.NOT_CONFIRMED


class TickClock:
    def __init__(self, values: Iterable[float]) -> None:
        self._values = iter(values)

    def __call__(self) -> float:
        return next(self._values)


def test_controller_enforces_wall_budget_with_injected_monotonic_clock() -> None:
    clock = TickClock((100.0, 100.0, 100.5, 101.0, 105.0))
    strategy = ScriptedStrategy((candidate("prepare"), candidate("trigger")))
    evaluator = FakeEvaluator((Outcome.PASS, Outcome.PASS))

    run = controller(clock=clock).run(
        strategy=strategy,
        evaluator=evaluator,
        limits=limits(wall_seconds=3),
    )

    assert run.candidates_evaluated == 1
    assert run.stop_reason == "wall_budget"
    assert run.wall_seconds == pytest.approx(5.0)


def test_controller_rechecks_wall_budget_after_slow_proposal_at_equality() -> None:
    clock = TickClock((20.0, 20.0, 23.0))
    strategy = ScriptedStrategy((candidate("prepare"),))
    evaluator = FakeEvaluator((Outcome.PASS,))

    run = controller(clock=clock).run(
        strategy=strategy,
        evaluator=evaluator,
        limits=limits(wall_seconds=3),
    )

    assert run.stop_reason == "wall_budget"
    assert run.wall_seconds == pytest.approx(3.0)
    assert evaluator.calls == []
    assert tuple(event.phase for event in run.events) == ("proposal", "stop")
    assert run.events[0].timestamp_offset == pytest.approx(3.0)


def test_controller_charges_strategy_initialization_to_wall_budget() -> None:
    from qprover.search.bqm import SearchProblem

    clock = TickClock((20.0, 23.0))
    strategy = ScriptedStrategy((candidate("prepare"),))
    evaluator = FakeEvaluator((Outcome.PASS,))

    run = controller(clock=clock).run(
        strategy=strategy,
        evaluator=evaluator,
        limits=limits(wall_seconds=3),
        problem=SearchProblem(actions=("prepare",), max_sequence_length=1),
        seed=7,
    )

    assert run.stop_reason == "wall_budget"
    assert run.candidates_evaluated == 0
    assert evaluator.calls == []
    assert run.events[0].phase == "initialization"


def test_none_proposal_is_unproven_without_explicit_exhaustion_proof() -> None:
    run = controller().run(
        strategy=ScriptedStrategy((None,)),
        evaluator=FakeEvaluator(()),
        limits=limits(),
    )

    assert run.stop_reason == "solver_exhausted_unproven"


def test_controller_accepts_first_violation_prefix_accounting() -> None:
    proposed = candidate("prepare", "trigger", "repair")
    strategy = ScriptedStrategy((proposed,))

    class PrefixEvaluator:
        def evaluate(self, candidate: Candidate) -> Evaluation:
            return Evaluation(
                outcome=Outcome.VIOLATION,
                transaction_count=2,
                metadata={"violation_prefix_length": 2},
            )

    run = controller().run(strategy, PrefixEvaluator(), limits())

    assert not run.failed
    assert run.stop_reason == "violation"
    assert run.evm_transactions == 2


@pytest.mark.parametrize(
    "outcome",
    [Outcome.PASS, Outcome.VIOLATION, Outcome.REVERT],
)
def test_controller_records_but_does_not_credit_evaluation_finishing_at_deadline(
    outcome: Outcome,
) -> None:
    clock = TickClock((10.0, 10.0, 10.0, 13.0, 13.0))
    strategy = ScriptedStrategy((candidate("prepare"),))
    evaluator = FakeEvaluator((outcome,), transaction_counts=(1,))

    run = controller(clock=clock).run(
        strategy=strategy,
        evaluator=evaluator,
        limits=limits(wall_seconds=3),
    )

    assert run.stop_reason == "wall_budget"
    assert not run.failed
    assert run.failure_reason is None
    assert run.confirmation_status is ConfirmationStatus.NOT_CONFIRMED
    assert run.violation is None
    assert run.evm_transactions == 1
    assert run.candidates_evaluated == 1
    assert run.outcome_counts[outcome] == 1
    assert strategy.observed == []
    assert tuple(event.phase for event in run.events) == (
        "proposal",
        "execution",
        "stop",
    )
    assert run.events[1].timestamp_offset == pytest.approx(3.0)
    assert run.events[1].payload["timed_out"] is True
    assert run.events[1].payload["feedback_applied"] is False


@pytest.mark.parametrize("finished_at", [13.0, 14.0])
@pytest.mark.parametrize("transaction_count", [0, 1])
def test_controller_marks_late_infrastructure_evaluation_as_failed(
    finished_at: float,
    transaction_count: int,
) -> None:
    clock = TickClock((10.0, 10.0, 10.0, finished_at))
    proposed = candidate("prepare")
    strategy = ScriptedStrategy((proposed,))
    evaluator = FakeEvaluator(
        (Outcome.INFRA_ERROR,), transaction_counts=(transaction_count,)
    )

    run = controller(clock=clock).run(
        strategy=strategy,
        evaluator=evaluator,
        limits=limits(wall_seconds=3),
    )

    assert run.failed
    assert run.failure_reason == "evaluator returned INFRA_ERROR"
    assert run.stop_reason == "wall_budget"
    assert run.wall_seconds == pytest.approx(finished_at - 10.0)
    assert run.confirmation_status is ConfirmationStatus.NOT_CONFIRMED
    assert run.violation is None
    assert run.evm_transactions == transaction_count
    assert run.candidates_evaluated == 1
    assert run.outcome_counts[Outcome.INFRA_ERROR] == 1
    assert run.evaluations[0].candidate == proposed
    assert run.evaluations[0].evaluation.transaction_count == transaction_count
    assert strategy.observed == []
    assert tuple(event.phase for event in run.events) == (
        "proposal",
        "execution",
        "stop",
    )
    assert run.events[1].severity == "error"
    assert run.events[1].category == "infrastructure"
    assert run.events[1].payload["timed_out"] is True
    assert run.events[1].payload["feedback_applied"] is False
    assert run.events[2].severity == "error"
    assert run.events[2].category == "infrastructure"


def test_controller_normalizes_candidate_validator_exception() -> None:
    def broken_validator(proposed: Candidate) -> bool:
        del proposed
        raise RuntimeError("secret validator detail")

    strategy = ScriptedStrategy((candidate("prepare"),))
    evaluator = FakeEvaluator((Outcome.PASS,))
    guarded = SearchController(
        candidate_validator=broken_validator,
        run_id_factory=lambda: "run-fixed",
    )

    run = guarded.run(strategy=strategy, evaluator=evaluator, limits=limits())

    assert run.failed
    assert run.stop_reason == "candidate_validation_error"
    assert run.failure_reason == "candidate validator raised RuntimeError"
    assert evaluator.calls == []
    assert strategy.observed == []
    assert run.evm_transactions == 0
    assert run.candidates_evaluated == 0
    assert run.events[0].severity == "error"
    assert run.events[0].category == "candidate-validator"
    assert "secret" not in json.dumps(run.to_dict())


@pytest.mark.parametrize("invalid", [None, 0, 1, object()])
def test_controller_rejects_non_exact_bool_candidate_validator_result(invalid) -> None:
    strategy = ScriptedStrategy((candidate("prepare"),))
    evaluator = FakeEvaluator((Outcome.PASS,))
    guarded = SearchController(
        candidate_validator=lambda proposed: invalid,
        run_id_factory=lambda: "run-fixed",
    )

    run = guarded.run(strategy=strategy, evaluator=evaluator, limits=limits())

    assert run.failed
    assert run.stop_reason == "candidate_validation_error"
    assert run.failure_reason == (
        f"candidate validator returned {type(invalid).__name__}, expected bool"
    )
    assert evaluator.calls == []
    assert strategy.observed == []
    assert run.evm_transactions == 0
    assert run.events[0].payload["returned_type"] == type(invalid).__name__


def test_controller_bounds_duplicate_retries() -> None:
    repeated = candidate("prepare")
    strategy = ScriptedStrategy((repeated, repeated, repeated, repeated, repeated))
    evaluator = FakeEvaluator((Outcome.PASS,))

    run = controller(duplicate_retry_limit=3).run(
        strategy=strategy,
        evaluator=evaluator,
        limits=limits(),
    )

    assert run.candidates_evaluated == 1
    assert len(evaluator.calls) == 1
    assert run.duplicate_proposals == 3
    assert run.stop_reason == "solver_exhausted_unproven"


def test_controller_records_stable_event_ledger() -> None:
    strategy = ScriptedStrategy((candidate("prepare"), None))
    evaluator = FakeEvaluator((Outcome.INCONCLUSIVE,))

    run = controller().run(strategy=strategy, evaluator=evaluator, limits=limits())

    assert run.run_id == "run-fixed"
    assert tuple(event.sequence for event in run.events) == tuple(
        range(len(run.events))
    )
    assert all(event.run_id == run.run_id for event in run.events)
    assert tuple(event.phase for event in run.events) == (
        "proposal",
        "execution",
        "feedback",
        "stop",
    )
    assert all(event.timestamp_offset >= 0 for event in run.events)
    assert run.events[-1].payload["reason"] == "solver_exhausted_unproven"
    assert json.loads(json.dumps(run.events[-1].to_dict()))["run_id"] == "run-fixed"


def test_event_and_run_records_snapshot_nested_payloads() -> None:
    source = {"nested": {"items": [1, {"value": "before"}]}}
    event = SearchEvent(
        run_id="run",
        sequence=0,
        timestamp_offset=0.0,
        phase="proposal",
        severity="info",
        category="search",
        payload=source,
    )
    source["nested"]["items"][1]["value"] = "after"
    source["nested"]["items"].append(2)

    assert event.to_dict()["payload"] == {"nested": {"items": [1, {"value": "before"}]}}
    assert json.loads(json.dumps(event.to_dict()))["payload"]["nested"]["items"] == [
        1,
        {"value": "before"},
    ]

    run = controller().run(
        strategy=ScriptedStrategy((candidate("prepare"), None)),
        evaluator=FakeEvaluator((Outcome.PASS,)),
        limits=limits(),
    )
    assert json.loads(json.dumps(run.to_dict()))["events"][-1]["phase"] == "stop"


def test_event_rejects_non_json_payload_values() -> None:
    with pytest.raises(TypeError, match="JSON-like"):
        SearchEvent(
            run_id="run",
            sequence=0,
            timestamp_offset=0.0,
            phase="proposal",
            severity="info",
            category="search",
            payload={"mutable": {1, 2}},
        )


def test_controller_accepts_exact_lifecycle_without_optional_stats() -> None:
    class LifecycleOnlyStrategy:
        def initialize(self, problem, seed: int) -> None:
            del problem, seed

        def propose(self, remaining_transactions: int) -> Candidate | None:
            del remaining_transactions
            return None

        def observe(self, candidate: Candidate, result: Evaluation) -> None:
            del candidate, result

    run = controller().run(
        strategy=LifecycleOnlyStrategy(),
        evaluator=FakeEvaluator(()),
        limits=limits(),
    )

    assert run.stop_reason == "solver_exhausted_unproven"
    assert run.strategy_stats.name == "LifecycleOnlyStrategy"
    assert run.strategy_stats.counters == {}


@pytest.mark.parametrize("bad_count", [-1, 2])
def test_controller_rejects_impossible_evaluator_transaction_counts(
    bad_count: int,
) -> None:
    one_step = candidate("prepare")
    strategy = ScriptedStrategy((one_step,))
    evaluator = FakeEvaluator((Outcome.PASS,), transaction_counts=(bad_count,))

    if bad_count < 0:
        run = controller().run(strategy=strategy, evaluator=evaluator, limits=limits())
        assert run.failed
        assert run.stop_reason == "evaluator_error"
        assert run.failure_reason == "evaluator raised ValueError"
        assert run.candidates_evaluated == 0
    else:
        run = controller().run(strategy=strategy, evaluator=evaluator, limits=limits())
        assert run.failed
        assert run.stop_reason == "invalid_evaluation"
