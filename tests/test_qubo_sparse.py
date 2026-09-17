from __future__ import annotations

from types import SimpleNamespace

import pytest

from qprover.search.annealing import _flip_delta
from qprover.search.bqm import SearchFeedback, SequenceBQMBuilder


class _ForbiddenDenseQuadratic(dict[tuple[int, int], float]):
    def items(self):
        raise AssertionError("flip delta must not scan the full quadratic mapping")


class _CountingTransitions(dict[tuple[str, str], float]):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.get_calls = 0
        self.items_calls = 0

    def get(self, key, default=None):
        self.get_calls += 1
        return super().get(key, default)

    def items(self):
        self.items_calls += 1
        return super().items()


def test_flip_delta_uses_precomputed_sparse_adjacency() -> None:
    bqm = SimpleNamespace(
        linear={0: 0.5, 1: -0.25},
        quadratic=_ForbiddenDenseQuadratic({(0, 0): 0.75, (0, 1): 1.25}),
        quadratic_adjacency=(
            ((0, 0.75), (1, 1.25)),
            ((0, 1.25),),
        ),
    )
    bits = [1, 1]

    assert _flip_delta(bqm, bits, 0) == pytest.approx(-2.5)


def test_bqm_builder_iterates_only_explicit_transition_edges() -> None:
    transitions = _CountingTransitions({("a", "b"): 0.5})
    problem = SimpleNamespace(
        actions=("a", "b", "c"),
        max_sequence_length=2,
        utilities={"a": 0.1, "b": 0.2, "c": 0.3},
        transitions=transitions,
        repetition_groups={"a": "a", "b": "b", "c": "c"},
        group_repetition_limits={"a": 2, "b": 2, "c": 2},
        groups=("a", "b", "c"),
        discounts=(1.0, 0.5),
        utility_weight=1.0,
        transition_weight=1.0,
        revert_weight=1.0,
        length_weight=0.1,
    )

    SequenceBQMBuilder().build(problem, SearchFeedback.empty())

    assert transitions.get_calls == 0
    assert transitions.items_calls >= 1
