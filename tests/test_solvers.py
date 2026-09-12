from __future__ import annotations

import pytest

from qprover.search.annealing import AnnealingConfig, SimulatedAnnealingBackend
from qprover.search.bqm import SearchFeedback, SearchProblem, SequenceBQMBuilder
from qprover.search.exact import (
    ExactBackend,
    ExactConfig,
    SolverError,
    exact_feasible_sequences,
)


@pytest.fixture
def problem() -> SearchProblem:
    return SearchProblem(
        actions=("prepare", "trigger"),
        max_sequence_length=2,
        utilities={"prepare": 0.4, "trigger": 1.0},
        transitions={("prepare", "trigger"): 0.8},
        repetition_limits={"prepare": 1, "trigger": 1},
        discounts=(1.0, 0.5),
        length_weight=0.1,
    )


def test_exact_backend_finds_known_minimum_and_reports_metadata(
    problem: SearchProblem,
) -> None:
    bqm = SequenceBQMBuilder().build(problem, SearchFeedback.empty())

    samples = ExactBackend(max_bits=20).sample(bqm, reads=8)

    assert samples.first.decoded.sequence == ("prepare", "trigger")
    assert samples.first.decoded.feasibility.feasible
    assert samples.metadata["backend"] == "exact-bit-enumeration"
    assert samples.metadata["states_evaluated"] == 2 ** len(bqm.variables)
    assert samples.metadata["optimality_proven"] is True
    assert samples.metadata["wall_seconds"] >= 0
    assert any(not sample.decoded.feasibility.feasible for sample in samples.samples)


def test_exact_backend_enforces_max_bits(problem: SearchProblem) -> None:
    bqm = SequenceBQMBuilder().build(problem, SearchFeedback.empty())

    with pytest.raises(SolverError, match="max_bits"):
        ExactBackend(max_bits=5).sample(bqm)


def test_exact_backend_accepts_explicit_config(problem: SearchProblem) -> None:
    bqm = SequenceBQMBuilder().build(problem, SearchFeedback.empty())

    samples = ExactBackend(max_bits=20).sample(bqm, ExactConfig(reads=3))

    assert len(samples.samples) == 3
    assert samples.metadata["reads_requested"] == 3


def test_exact_and_independent_feasible_oracles_agree(
    problem: SearchProblem,
) -> None:
    bqm = SequenceBQMBuilder().build(problem, SearchFeedback.empty())

    binary = ExactBackend(max_bits=20).sample(bqm, reads=8)
    feasible = exact_feasible_sequences(problem, bqm)

    assert binary.first.energy == pytest.approx(feasible.first.energy)
    assert binary.first.bits == feasible.first.bits
    assert feasible.metadata["backend"] == "exact-feasible-sequences"
    assert all(sample.decoded.feasibility.feasible for sample in feasible.samples)


def test_exact_feasible_oracle_includes_empty_and_bounded_repetitions() -> None:
    problem = SearchProblem(
        actions=("repeat",),
        max_sequence_length=3,
        repetition_limits={"repeat": 2},
    )
    bqm = SequenceBQMBuilder().build(problem, SearchFeedback.empty())

    samples = exact_feasible_sequences(problem, bqm)
    sequences = {sample.decoded.sequence for sample in samples.samples}

    assert sequences == {(), ("repeat",), ("repeat", "repeat")}


def test_quadratic_repetition_constraint_enforces_limit_above_one() -> None:
    problem = SearchProblem(
        actions=("repeat",),
        max_sequence_length=3,
        utilities={"repeat": 100.0},
        repetition_limits={"repeat": 2},
        length_weight=0.0,
    )
    bqm = SequenceBQMBuilder().build(problem, SearchFeedback.empty())

    binary = ExactBackend(max_bits=20).sample(bqm)
    feasible = exact_feasible_sequences(problem, bqm)

    assert binary.first.decoded.sequence == ("repeat", "repeat")
    assert binary.first.decoded.feasibility.feasible
    assert binary.first.energy == pytest.approx(feasible.first.energy)


def test_simulated_annealing_is_repeatable_for_fixed_seed(
    problem: SearchProblem,
) -> None:
    bqm = SequenceBQMBuilder().build(problem, SearchFeedback.empty())
    config = AnnealingConfig(
        seed=914,
        reads=12,
        sweeps=80,
        temperature_start=8.0,
        temperature_end=0.01,
    )
    backend = SimulatedAnnealingBackend()

    first = backend.sample(bqm, config)
    second = backend.sample(bqm, config)

    assert tuple((item.bits, item.energy) for item in first.samples) == tuple(
        (item.bits, item.energy) for item in second.samples
    )
    assert first.first.decoded.sequence == ("prepare", "trigger")
    assert first.metadata["backend"] == "simulated-annealing"
    assert first.metadata["seed"] == 914
    assert first.metadata["reads"] == 12
    assert first.metadata["sweeps"] == 80
    assert first.metadata["start_policy"] == "random-binary"
    assert first.metadata["update_order"] == "random-permutation"
    assert first.metadata["temperature_schedule"] == "geometric"
    assert first.metadata["wall_seconds"] >= 0


def test_simulated_annealing_rejects_invalid_configuration(
    problem: SearchProblem,
) -> None:
    bqm = SequenceBQMBuilder().build(problem, SearchFeedback.empty())

    with pytest.raises(ValueError, match="temperature"):
        SimulatedAnnealingBackend().sample(
            bqm,
            AnnealingConfig(temperature_start=0.0),
        )
