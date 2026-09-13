from __future__ import annotations

import json
from collections import Counter

import pytest

from qprover.models import (
    ActionStep,
    Candidate,
    ConfirmationStatus,
    Outcome,
    SearchLimits,
)
from qprover.parameters import ActionVariant
from qprover.search.base import Evaluation, StrategyStats, candidate_is_valid
from qprover.search.bqm import SampleSet, SearchProblem, sample_from_bits
from qprover.search.controller import SearchController
from qprover.search.coverage import CoverageGuidedStrategy
from qprover.search.exact import ExactBackend
from qprover.search.qubo import QuboStrategy
from qprover.search.random import RandomStrategy
from qprover.search.risk import RiskGuidedStrategy


def variant(
    action_id: str,
    *,
    sender_slot: int = 0,
    argument: int = 0,
    max_repetitions: int = 1,
) -> ActionVariant:
    return ActionVariant(
        action_id=action_id,
        target_id="vault",
        signature=f"{action_id}(uint256)",
        sender_slot=sender_slot,
        args=(argument,),
        value_wei=0,
        max_repetitions=max_repetitions,
        argument_provenance=(("explicit",),),
        value_provenance=("explicit",),
    )


@pytest.fixture
def variants() -> tuple[ActionVariant, ...]:
    return (
        variant("prepare", argument=0),
        variant("prepare", argument=1),
        variant("trigger", sender_slot=0, argument=7),
        variant("observe", sender_slot=1, argument=9, max_repetitions=2),
    )


@pytest.fixture
def problem(variants: tuple[ActionVariant, ...]) -> SearchProblem:
    return SearchProblem(
        actions=("prepare", "trigger", "observe"),
        variants=variants,
        max_sequence_length=2,
        utilities={"prepare": 0.2, "trigger": 0.9, "observe": 0.1},
        transitions={("prepare", "trigger"): 1.0},
        repetition_limits={"prepare": 1, "trigger": 1, "observe": 2},
        length_weight=0.25,
    )


def evaluation(candidate: Candidate, *, outcome: Outcome = Outcome.PASS) -> Evaluation:
    actions = tuple(step.action_id for step in candidate.steps)
    return Evaluation(
        outcome=outcome,
        transaction_count=len(candidate.steps),
        trace_features=frozenset({f"prefix:{'/'.join(actions)}"}),
        state_fingerprint=f"state:{'/'.join(actions)}",
    )


def collect(
    strategy, problem: SearchProblem, seed: int, count: int
) -> tuple[Candidate, ...]:
    strategy.initialize(problem, seed)
    proposed: list[Candidate] = []
    for _ in range(count):
        candidate = strategy.propose(problem.max_sequence_length)
        if candidate is None:
            break
        proposed.append(candidate)
        strategy.observe(candidate, evaluation(candidate))
    return tuple(proposed)


@pytest.mark.parametrize(
    "factory",
    [
        RandomStrategy,
        CoverageGuidedStrategy,
        RiskGuidedStrategy,
        lambda: QuboStrategy(backend=ExactBackend(max_bits=20), reads=256),
    ],
)
def test_strategies_emit_only_valid_unique_candidates(
    factory, problem: SearchProblem
) -> None:
    candidates = collect(factory(), problem, seed=73, count=18)

    assert candidates
    assert len({candidate.canonical_id for candidate in candidates}) == len(candidates)
    assert all(candidate_is_valid(problem, candidate) for candidate in candidates)
    for candidate in candidates:
        counts = Counter(step.action_id for step in candidate.steps)
        assert len(candidate.steps) <= problem.max_sequence_length
        assert all(
            counts[action] <= problem.repetition_limits[action]
            for action in problem.actions
        )


@pytest.mark.parametrize(
    "factory",
    [
        RandomStrategy,
        CoverageGuidedStrategy,
        RiskGuidedStrategy,
        lambda: QuboStrategy(backend=ExactBackend(max_bits=20), reads=256),
    ],
)
def test_strategy_proposal_order_is_seed_deterministic(
    factory, problem: SearchProblem
) -> None:
    first = collect(factory(), problem, seed=914, count=12)
    second = collect(factory(), problem, seed=914, count=12)

    assert tuple(item.canonical_id for item in first) == tuple(
        item.canonical_id for item in second
    )


def test_search_problem_contains_no_hidden_witness_or_label(
    problem: SearchProblem,
) -> None:
    assert not hasattr(problem, "known_witness")
    assert not hasattr(problem, "expected_label")
    assert set(problem.__dataclass_fields__).isdisjoint(
        {"known_witness", "expected_label", "is_vulnerable"}
    )


def test_search_problem_derives_repetition_limits_from_concrete_variants() -> None:
    concrete = variant("repeat", max_repetitions=2)

    derived = SearchProblem(
        actions=("repeat",),
        variants=(concrete,),
        max_sequence_length=3,
    )

    assert derived.repetition_limits == {"repeat": 2}


def test_random_strategy_honors_remaining_transaction_budget(
    problem: SearchProblem,
) -> None:
    strategy = RandomStrategy()
    strategy.initialize(problem, seed=4)

    for _ in range(20):
        candidate = strategy.propose(1)
        if candidate is None:
            break
        assert len(candidate.steps) == 1
        strategy.observe(candidate, evaluation(candidate))


@pytest.mark.parametrize("factory", [RandomStrategy, CoverageGuidedStrategy])
def test_randomized_strategies_cap_length_at_total_legal_repetitions(factory) -> None:
    only = variant("once", max_repetitions=1)
    constrained = SearchProblem(
        actions=("once",),
        variants=(only,),
        max_sequence_length=3,
        repetition_limits={"once": 1},
    )
    strategy = factory()
    strategy.initialize(constrained, seed=0)

    proposals = collect(strategy, constrained, seed=0, count=4)

    assert len(proposals) == 1
    assert len(proposals[0].steps) == 1


def test_task_four_public_api_is_exported() -> None:
    from qprover.search import (  # noqa: PLC0415
        CoverageGuidedStrategy,
        Evaluation,
        QuboStrategy,
        RandomStrategy,
        RiskGuidedStrategy,
        SearchController,
        SearchStrategy,
        StrategyStats,
    )

    assert all(
        item is not None
        for item in (
            CoverageGuidedStrategy,
            Evaluation,
            QuboStrategy,
            RandomStrategy,
            RiskGuidedStrategy,
            SearchController,
            SearchStrategy,
            StrategyStats,
        )
    )


def test_coverage_strategy_keeps_only_novel_feedback_in_corpus(
    problem: SearchProblem,
) -> None:
    strategy = CoverageGuidedStrategy()
    strategy.initialize(problem, seed=6)
    first = strategy.propose(3)
    assert first is not None

    novel = evaluation(first)
    strategy.observe(first, novel)
    corpus_size = strategy.stats.counters["corpus_size"]
    duplicate_feedback = Evaluation(
        outcome=Outcome.PASS,
        transaction_count=len(first.steps),
        trace_features=novel.trace_features,
        state_fingerprint=novel.state_fingerprint,
    )
    strategy.observe(first, duplicate_feedback)

    assert strategy.stats.counters["corpus_size"] == corpus_size
    assert strategy.stats.counters["novel_observations"] == 1


def test_coverage_strategy_exercises_all_required_mutation_families(
    problem: SearchProblem,
) -> None:
    strategy = CoverageGuidedStrategy()
    strategy.initialize(problem, seed=19)
    for _ in range(80):
        candidate = strategy.propose(3)
        if candidate is None:
            break
        strategy.observe(candidate, evaluation(candidate))

    attempted = strategy.stats.metadata["mutation_attempts"]
    assert set(attempted) == {"append", "argument", "delete", "replace", "splice"}
    assert all(attempted[name] > 0 for name in attempted)
    assert json.loads(json.dumps(strategy.stats.to_dict()))["name"] == "coverage"


def test_evaluation_and_strategy_stats_snapshot_nested_metadata() -> None:
    evaluation_source = {"solver": {"reads": [1, 2]}}
    stats_source = {"mutation": {"names": ["append", "splice"]}}
    result = Evaluation(
        outcome=Outcome.INCONCLUSIVE,
        transaction_count=0,
        metadata=evaluation_source,
    )
    stats = StrategyStats(name="test", metadata=stats_source)
    evaluation_source["solver"]["reads"].append(3)
    stats_source["mutation"]["names"].append("delete")

    assert result.to_dict()["metadata"] == {"solver": {"reads": [1, 2]}}
    assert stats.to_dict()["metadata"] == {"mutation": {"names": ["append", "splice"]}}
    json.dumps(result.to_dict())
    json.dumps(stats.to_dict())


@pytest.mark.parametrize("factory", [Evaluation, StrategyStats])
def test_metadata_records_reject_non_json_values(factory) -> None:
    kwargs = (
        {"outcome": Outcome.PASS, "transaction_count": 1}
        if factory is Evaluation
        else {"name": "test"}
    )
    with pytest.raises(TypeError, match="JSON-like"):
        factory(**kwargs, metadata={"unsupported": object()})


def test_risk_strategy_prioritizes_public_dependency(problem: SearchProblem) -> None:
    strategy = RiskGuidedStrategy(beam_width=8)
    strategy.initialize(problem, seed=11)

    candidate = strategy.propose(3)

    assert candidate is not None
    assert tuple(step.action_id for step in candidate.steps) == ("prepare", "trigger")
    assert strategy.stats.metadata["ranking_inputs"] == (
        "dynamic_novelty",
        "hypothesis_relevance",
        "length_cost",
        "revert_penalty",
        "static_utility",
        "transition_benefit",
    )


def test_qubo_strategy_records_solver_and_decoding_metadata(
    problem: SearchProblem,
) -> None:
    strategy = QuboStrategy(backend=ExactBackend(max_bits=20), reads=256)
    strategy.initialize(problem, seed=5)

    first = strategy.propose(3)
    assert first is not None
    strategy.observe(first, evaluation(first))
    second = strategy.propose(3)

    assert second is not None
    assert second.canonical_id != first.canonical_id
    metadata = strategy.stats.metadata
    assert metadata["solver"]["backend"] == "exact-bit-enumeration"
    assert metadata["decoded_feasible"] > 0
    assert metadata["decoded_infeasible"] >= 0
    assert metadata["transition_enabled"] is True
    assert metadata["repair_count"] == 0


def test_qubo_transition_ablation_changes_publicly_guided_proposal(
    problem: SearchProblem,
) -> None:
    guided = QuboStrategy(
        backend=ExactBackend(max_bits=20), reads=256, transition_enabled=True
    )
    ablated = QuboStrategy(
        backend=ExactBackend(max_bits=20), reads=256, transition_enabled=False
    )
    guided.initialize(problem, seed=1)
    ablated.initialize(problem, seed=1)

    guided_candidate = guided.propose(3)
    ablated_candidate = ablated.propose(3)

    assert guided_candidate is not None
    assert ablated_candidate is not None
    assert tuple(step.action_id for step in guided_candidate.steps) == (
        "prepare",
        "trigger",
    )
    assert guided_candidate.canonical_id != ablated_candidate.canonical_id
    assert guided.stats.metadata["transition_enabled"] is True
    assert ablated.stats.metadata["transition_enabled"] is False


class SparseBackend:
    """Returns one identical feasible sample regardless of repeated calls."""

    def sample(self, bqm, **options) -> SampleSet:
        del options
        bits = bqm.encode((bqm.problem.actions[0],))
        return SampleSet(
            (sample_from_bits(bqm, bits),),
            {"backend": "sparse", "details": {"reads": [1]}},
        )


class PassingEvaluator:
    def evaluate(self, proposed: Candidate) -> Evaluation:
        return evaluation(proposed)


def test_qubo_falls_back_when_sparse_batches_repeat_evaluated_candidate() -> None:
    concrete = (variant("first"), variant("second"))
    small = SearchProblem(
        actions=("first", "second"),
        variants=concrete,
        max_sequence_length=1,
        repetition_limits={"first": 1, "second": 1},
    )
    strategy = QuboStrategy(
        backend=SparseBackend(),
        reads=1,
        resample_attempts=2,
        max_exact_fallback_sequences=8,
    )
    strategy.initialize(small, seed=9)

    first = strategy.propose(1)
    assert first is not None
    strategy.observe(first, evaluation(first))
    second = strategy.propose(1)

    assert second is not None
    assert second.canonical_id != first.canonical_id
    assert {first.steps[0].action_id, second.steps[0].action_id} == {
        "first",
        "second",
    }
    assert strategy.stats.metadata["resample_attempts"] == 2
    assert strategy.stats.metadata["exact_fallbacks"] == 1


def test_qubo_reports_proven_exhaustion_after_exact_small_space_fallback() -> None:
    concrete = (variant("only"),)
    small = SearchProblem(
        actions=("only",),
        variants=concrete,
        max_sequence_length=1,
        repetition_limits={"only": 1},
    )
    strategy = QuboStrategy(
        backend=SparseBackend(),
        reads=1,
        resample_attempts=1,
        max_exact_fallback_sequences=4,
    )
    strategy.initialize(small, seed=1)

    first = strategy.propose(1)
    assert first is not None
    strategy.observe(first, evaluation(first))

    assert strategy.propose(1) is None
    assert strategy.stats.metadata["exhaustion_proven"] is True
    assert strategy.stats.metadata["solver_calls"] == 2


def test_qubo_exact_fallback_counts_only_aggregate_repetition_feasible_sequences() -> (
    None
):
    concrete = (variant("first"), variant("second"))
    repeated = SearchProblem(
        actions=("first", "second"),
        variants=concrete,
        max_sequence_length=3,
        repetition_limits={"first": 1, "second": 1},
    )
    strategy = QuboStrategy(
        backend=SparseBackend(),
        reads=1,
        resample_attempts=0,
        max_exact_fallback_sequences=4,
    )
    strategy.initialize(repeated, seed=3)

    candidates = []
    for _ in range(4):
        proposed = strategy.propose(3)
        assert proposed is not None
        candidates.append(proposed)
        strategy.observe(proposed, evaluation(proposed))

    assert strategy.propose(3) is None
    assert {
        tuple(step.action_id for step in proposed.steps) for proposed in candidates
    } == {
        ("first",),
        ("second",),
        ("first", "second"),
        ("second", "first"),
    }
    assert len({proposed.canonical_id for proposed in candidates}) == 4
    assert strategy.stats.metadata["feasible_space_count"] == 4
    assert strategy.stats.metadata["feasible_count_exact"] is True
    assert strategy.stats.metadata["exhaustion_proven"] is True


def test_controller_marks_above_cap_qubo_exhaustion_unproven() -> None:
    concrete = (
        variant("first", max_repetitions=3),
        variant("second", max_repetitions=3),
    )
    large = SearchProblem(
        actions=("first", "second"),
        variants=concrete,
        max_sequence_length=3,
        repetition_limits={"first": 3, "second": 3},
    )
    strategy = QuboStrategy(
        backend=SparseBackend(),
        reads=1,
        resample_attempts=0,
        max_exact_fallback_sequences=4,
    )
    strategy.initialize(large, seed=3)

    run = SearchController(run_id_factory=lambda: "run-fixed").run(
        strategy=strategy,
        evaluator=PassingEvaluator(),
        limits=SearchLimits(
            max_sequence_length=3,
            transaction_budget=10,
            candidate_budget=10,
            wall_seconds=30,
        ),
    )

    assert run.stop_reason == "solver_exhausted_unproven"
    assert run.confirmation_status is ConfirmationStatus.NOT_CONFIRMED
    assert run.strategy_stats.metadata["exhaustion_proven"] is False
    assert run.strategy_stats.metadata["feasible_count_exact"] is False
    assert run.strategy_stats.metadata["feasible_space_count"] == 5


def test_fake_violation_sequence_is_known_only_to_evaluator(
    problem: SearchProblem,
) -> None:
    class FakeEvaluator:
        _witness = ("prepare", "trigger")

        def evaluate(self, candidate: Candidate) -> Evaluation:
            actions = tuple(step.action_id for step in candidate.steps)
            outcome = Outcome.VIOLATION if actions == self._witness else Outcome.PASS
            return evaluation(candidate, outcome=outcome)

    strategy = RiskGuidedStrategy()
    strategy.initialize(problem, seed=2)
    candidate = strategy.propose(3)

    assert candidate is not None
    assert FakeEvaluator().evaluate(candidate).outcome is Outcome.VIOLATION
    assert all("witness" not in name and "label" not in name for name in vars(strategy))


def test_candidate_validation_rejects_non_variant_and_excess_repetition(
    problem: SearchProblem,
) -> None:
    unknown = Candidate((ActionStep("unknown", "vault", "unknown()", 0, ()),))
    prepare = next(item for item in problem.variants if item.action_id == "prepare")
    step = ActionStep(
        prepare.action_id,
        prepare.target_id,
        prepare.signature,
        prepare.sender_slot,
        prepare.args,
        prepare.value_wei,
    )

    assert not candidate_is_valid(problem, unknown)
    assert not candidate_is_valid(problem, Candidate((step, step)))
