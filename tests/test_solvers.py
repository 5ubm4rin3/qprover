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


def test_exact_feasible_oracle_aggregates_concrete_variant_repetitions() -> None:
    problem = SearchProblem(
        actions=("prime:v1", "prime:v2", "attack:v1"),
        max_sequence_length=3,
        repetition_groups={
            "prime:v1": "prime",
            "prime:v2": "prime",
            "attack:v1": "attack",
        },
        group_repetition_limits={"prime": 1, "attack": 1},
    )
    bqm = SequenceBQMBuilder().build(problem, SearchFeedback.empty())

    sequences = {
        sample.decoded.sequence
        for sample in exact_feasible_sequences(problem, bqm).samples
    }

    assert ("prime:v1", "prime:v2") not in sequences
    assert ("prime:v2", "attack:v1") in sequences


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
    assert first.metadata["temperature_schedule"] == "geometric-log-space"
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


@pytest.mark.parametrize("bad_integer", [True, 1.0])
def test_exact_solver_rejects_coerced_integer_configuration(
    problem: SearchProblem, bad_integer
) -> None:
    bqm = SequenceBQMBuilder().build(problem, SearchFeedback.empty())
    with pytest.raises(ValueError, match="max_bits"):
        ExactBackend(max_bits=bad_integer)
    with pytest.raises(ValueError, match="reads"):
        ExactConfig(reads=bad_integer)
    with pytest.raises(ValueError, match="reads"):
        ExactBackend(max_bits=20).sample(bqm, reads=bad_integer)


@pytest.mark.parametrize("field", ["reads", "sweeps", "seed"])
@pytest.mark.parametrize("bad_integer", [True, 1.0])
def test_annealing_rejects_coerced_integer_configuration(
    field: str, bad_integer
) -> None:
    with pytest.raises(ValueError, match=field):
        AnnealingConfig(**{field: bad_integer})


@pytest.mark.parametrize(
    ("field", "bad_temperature"),
    [
        ("temperature_start", True),
        ("temperature_end", "0.1"),
        ("temperature_start", float("inf")),
        ("temperature_end", float("nan")),
        ("temperature_start", 10**1000),
    ],
)
def test_annealing_rejects_invalid_temperature_types_and_values(
    field: str, bad_temperature
) -> None:
    with pytest.raises(ValueError, match="temperature"):
        AnnealingConfig(**{field: bad_temperature})


def test_annealing_extreme_finite_temperatures_do_not_underflow_schedule(
    problem: SearchProblem,
) -> None:
    bqm = SequenceBQMBuilder().build(problem, SearchFeedback.empty())
    config = AnnealingConfig(
        seed=1,
        reads=2,
        sweeps=4,
        temperature_start=1e308,
        temperature_end=5e-324,
    )

    samples = SimulatedAnnealingBackend().sample(bqm, config)

    assert len(samples.samples) == 2
    assert samples.metadata["temperature_schedule"] == "geometric-log-space"
