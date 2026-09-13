from __future__ import annotations

import itertools

import pytest
from hypothesis import given
from hypothesis import strategies as st

from qprover.search.bqm import (
    STOP,
    SearchFeedback,
    SearchProblem,
    SequenceBQMBuilder,
)


class _TransitionTuple(tuple):
    pass


class _ActionText(str):
    pass


@pytest.fixture
def tiny_problem() -> SearchProblem:
    return SearchProblem(
        actions=("prepare", "trigger"),
        max_sequence_length=2,
        utilities={"prepare": 0.4, "trigger": 1.0},
        transitions={("prepare", "trigger"): 0.8},
        repetition_limits={"prepare": 1, "trigger": 1},
        discounts=(1.0, 0.5),
        utility_weight=1.0,
        transition_weight=1.0,
        revert_weight=1.0,
        length_weight=0.1,
    )


def _manual_components(problem, feedback, bqm, bits):
    chosen = {
        (position, action): bits[bqm.index(position, action)]
        for position in range(problem.max_sequence_length)
        for action in (*problem.actions, STOP)
    }
    penalty = bqm.constraint_penalty
    one_hot = penalty * sum(
        (1 - sum(chosen[position, action] for action in (*problem.actions, STOP))) ** 2
        for position in range(problem.max_sequence_length)
    )
    stop_suffix = penalty * sum(
        chosen[position, STOP] * chosen[position + 1, action]
        for position in range(problem.max_sequence_length - 1)
        for action in problem.actions
    )
    repetition = penalty * sum(
        chosen[first, action] * chosen[second, action]
        for action in problem.actions
        if problem.repetition_limits[action] == 1
        for first in range(problem.max_sequence_length)
        for second in range(first + 1, problem.max_sequence_length)
    )
    utility = -problem.utility_weight * sum(
        problem.discounts[position]
        * problem.utilities[action]
        * chosen[position, action]
        for position in range(problem.max_sequence_length)
        for action in problem.actions
    )
    transition = -problem.transition_weight * sum(
        problem.transitions.get((first, second), 0.0)
        * chosen[position, first]
        * chosen[position + 1, second]
        for position in range(problem.max_sequence_length - 1)
        for first in problem.actions
        for second in problem.actions
    )
    learned_revert = problem.revert_weight * sum(
        feedback.revert_penalties.get(action, 0.0) * chosen[position, action]
        for position in range(problem.max_sequence_length)
        for action in problem.actions
    )
    length = problem.length_weight * sum(
        chosen[position, action]
        for position in range(problem.max_sequence_length)
        for action in problem.actions
    )
    return {
        "one_hot": one_hot,
        "stop_suffix": stop_suffix,
        "repetition": repetition,
        "utility": utility,
        "transition": transition,
        "learned_revert": learned_revert,
        "length": length,
    }


def test_bqm_uses_single_count_upper_triangle(tiny_problem: SearchProblem) -> None:
    feedback = SearchFeedback(revert_penalties={"prepare": 0.2})
    bqm = SequenceBQMBuilder().build(tiny_problem, feedback)

    assert all(first <= second for first, second in bqm.quadratic)
    for bits in itertools.product((0, 1), repeat=len(bqm.variables)):
        expected = _manual_components(tiny_problem, feedback, bqm, bits)
        components = bqm.objective_components(bits)
        assert components.as_dict() == pytest.approx(expected)
        assert bqm.energy(bits) == pytest.approx(sum(expected.values()))
        assert bqm.energy(bits) == pytest.approx(components.total)


@given(st.lists(st.integers(min_value=0, max_value=1), min_size=6, max_size=6))
def test_bqm_energy_property_matches_independent_declaration(bits) -> None:
    problem = SearchProblem(
        actions=("a", "b"),
        max_sequence_length=2,
        utilities={"a": 0.25, "b": 0.75},
        transitions={("a", "b"): 0.5, ("b", "a"): -0.25},
        repetition_limits={"a": 1, "b": 1},
        discounts=(1.0, 0.4),
    )
    feedback = SearchFeedback(revert_penalties={"b": 0.3})
    bqm = SequenceBQMBuilder().build(problem, feedback)

    expected = sum(_manual_components(problem, feedback, bqm, bits).values())

    assert bqm.energy(bits) == pytest.approx(expected)


def test_constraint_penalty_is_derived_only_from_non_constraint_coefficients(
    tiny_problem: SearchProblem,
) -> None:
    bqm = SequenceBQMBuilder().build(tiny_problem, SearchFeedback.empty())

    expected = 1 + sum(abs(value) for value in bqm.non_constraint_linear.values())
    expected += sum(abs(value) for value in bqm.non_constraint_quadratic.values())
    assert bqm.constraint_penalty == pytest.approx(expected)


def test_decoding_audits_one_hot_stop_suffix_and_repetition(
    tiny_problem: SearchProblem,
) -> None:
    bqm = SequenceBQMBuilder().build(tiny_problem, SearchFeedback.empty())
    valid = bqm.encode(("prepare", "trigger"))
    invalid = list(valid)
    invalid[bqm.index(0, STOP)] = 1

    assert bqm.decode(valid).sequence == ("prepare", "trigger")
    assert bqm.decode(valid).feasibility.feasible
    audit = bqm.decode(tuple(invalid)).feasibility
    assert not audit.feasible
    assert audit.one_hot_violations == (0,)
    assert audit.stop_suffix_violations == (0,)


def test_stop_encoding_forms_a_complete_suffix(tiny_problem: SearchProblem) -> None:
    bqm = SequenceBQMBuilder().build(tiny_problem, SearchFeedback.empty())

    bits = bqm.encode(("prepare",))

    assert bits[bqm.index(0, "prepare")] == 1
    assert bits[bqm.index(1, STOP)] == 1
    assert bqm.decode(bits).feasibility.feasible


def test_search_problem_rejects_hidden_or_ambiguous_inputs() -> None:
    with pytest.raises(ValueError, match="duplicate"):
        SearchProblem(actions=("a", "a"), max_sequence_length=2)
    with pytest.raises(ValueError, match="STOP"):
        SearchProblem(actions=(STOP,), max_sequence_length=2)
    with pytest.raises(ValueError, match="unknown"):
        SearchProblem(
            actions=("a",),
            max_sequence_length=2,
            utilities={"known_witness": 1.0},
        )


@pytest.mark.parametrize("bad_length", [True, 2.0])
def test_search_problem_rejects_coerced_sequence_length(bad_length) -> None:
    with pytest.raises(ValueError, match="max_sequence_length"):
        SearchProblem(actions=("a",), max_sequence_length=bad_length)


@pytest.mark.parametrize("bad_limit", [True, 1.0])
def test_search_problem_rejects_coerced_repetition_limits(bad_limit) -> None:
    with pytest.raises(ValueError, match="repetition"):
        SearchProblem(
            actions=("a",),
            max_sequence_length=2,
            repetition_limits={"a": bad_limit},
        )


@pytest.mark.parametrize(
    "bad_key",
    [
        ("a",),
        ("a", "a", "a"),
        "a",
        (True, "a"),
        ("a", 1),
        _TransitionTuple(("a", "a")),
        (_ActionText("a"), "a"),
        ("a", _ActionText("a")),
    ],
)
def test_search_problem_rejects_malformed_transition_keys(bad_key) -> None:
    with pytest.raises(ValueError, match="transition keys"):
        SearchProblem(
            actions=("a",),
            max_sequence_length=2,
            transitions={bad_key: 1.0},
        )


def test_search_problem_rejects_unknown_transition_actions() -> None:
    with pytest.raises(ValueError, match="unknown action"):
        SearchProblem(
            actions=("a",),
            max_sequence_length=2,
            transitions={("a", "other"): 1.0},
        )


@pytest.mark.parametrize("bad_score", [True, "1", float("inf"), float("nan")])
def test_search_problem_rejects_non_real_or_nonfinite_scores(bad_score) -> None:
    with pytest.raises(ValueError, match="utilities"):
        SearchProblem(
            actions=("a",),
            max_sequence_length=2,
            utilities={"a": bad_score},
        )
    with pytest.raises(ValueError, match="transitions"):
        SearchProblem(
            actions=("a",),
            max_sequence_length=2,
            transitions={("a", "a"): bad_score},
        )
    with pytest.raises(ValueError, match="weights"):
        SearchProblem(
            actions=("a",),
            max_sequence_length=2,
            utility_weight=bad_score,
        )
    with pytest.raises(ValueError, match="discounts"):
        SearchProblem(
            actions=("a",),
            max_sequence_length=2,
            discounts=(1.0, bad_score),
        )


@pytest.mark.parametrize("bad_score", [True, "1", float("inf"), float("nan")])
def test_feedback_rejects_non_real_or_nonfinite_scores(bad_score) -> None:
    with pytest.raises(ValueError, match="revert penalties"):
        SearchFeedback(revert_penalties={"a": bad_score})


def test_large_finite_penalty_remains_strictly_dominant() -> None:
    problem = SearchProblem(
        actions=("a",),
        max_sequence_length=2,
        utilities={"a": 1e20},
        repetition_limits={"a": 1},
        length_weight=0.0,
    )
    bqm = SequenceBQMBuilder().build(problem, SearchFeedback.empty())
    bound = sum(abs(value) for value in bqm.non_constraint_linear.values()) + sum(
        abs(value) for value in bqm.non_constraint_quadratic.values()
    )

    assert bqm.constraint_penalty > bound
    feasible = bqm.encode(("a",))
    infeasible = list(bqm.encode(("a",)))
    infeasible[bqm.index(1, "a")] = 1
    infeasible[bqm.index(1, STOP)] = 0
    assert bqm.energy(feasible) < bqm.energy(infeasible)
    assert not bqm.decode(infeasible).feasibility.feasible


def test_builder_rejects_nonfinite_derived_coefficients() -> None:
    problem = SearchProblem(
        actions=("a",),
        max_sequence_length=2,
        utilities={"a": 1e308},
    )

    with pytest.raises(ValueError, match="non-finite"):
        SequenceBQMBuilder().build(problem, SearchFeedback.empty())


@pytest.mark.parametrize("bad_bit", [0.0, 1.0, True, False])
def test_bqm_samples_reject_coerced_bits(tiny_problem: SearchProblem, bad_bit) -> None:
    bqm = SequenceBQMBuilder().build(tiny_problem, SearchFeedback.empty())
    bits = list(bqm.encode(("prepare", "trigger")))
    bits[0] = bad_bit

    with pytest.raises(ValueError, match="exact integers"):
        bqm.energy(bits)


@pytest.mark.parametrize("bad_position", [True, False, 0.0, 1.0])
def test_bqm_index_rejects_coerced_positions(
    tiny_problem: SearchProblem, bad_position
) -> None:
    bqm = SequenceBQMBuilder().build(tiny_problem, SearchFeedback.empty())

    with pytest.raises(ValueError, match="exact integer"):
        bqm.index(bad_position, "prepare")
