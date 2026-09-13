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
from qprover.search.controller import SearchController


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
    clock = TickClock((100.0, 100.0, 101.0, 105.0))
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
    assert run.stop_reason == "search_space_exhausted"


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
    assert run.events[-1].payload["reason"] == "search_space_exhausted"
    assert json.loads(json.dumps(run.events[-1].to_dict()))["run_id"] == "run-fixed"


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

    assert run.stop_reason == "search_space_exhausted"
    assert run.strategy_stats.name == "LifecycleOnlyStrategy"
    assert run.strategy_stats.counters == {}


@pytest.mark.parametrize("bad_count", [-1, 2])
def test_controller_rejects_impossible_evaluator_transaction_counts(
    bad_count: int,
) -> None:
    one_step = candidate("prepare")
    strategy = ScriptedStrategy((one_step,))
    evaluator = FakeEvaluator((Outcome.PASS,), transaction_counts=(bad_count,))

    with pytest.raises(ValueError, match="transaction_count"):
        controller().run(strategy=strategy, evaluator=evaluator, limits=limits())
