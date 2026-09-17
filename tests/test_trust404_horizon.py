from __future__ import annotations

from types import SimpleNamespace

import pytest

import qprover.trust404_runner as runner
from qprover.trust404 import Track04Action, Track04SearchModel, Track04Variant


def _model(max_sequence_length: int = 6) -> Track04SearchModel:
    actions = (
        Track04Action(
            id="call:alpha()",
            kind="call",
            signature="alpha()",
            function_id="function:Demo:alpha()",
            param_types=(),
            payable=False,
            utility=0.9,
            storage_reads=(),
            storage_writes=("storage:x",),
            provenance=("Demo.sol", "0:1:0"),
        ),
        Track04Action(
            id="call:beta()",
            kind="call",
            signature="beta()",
            function_id="function:Demo:beta()",
            param_types=(),
            payable=False,
            utility=0.8,
            storage_reads=("storage:x",),
            storage_writes=(),
            provenance=("Demo.sol", "1:1:0"),
        ),
    )
    variants = tuple(
        Track04Variant(
            action_id=action.id,
            signature=action.signature,
            args=(),
            value_wei=0,
        )
        for action in actions
    )
    return Track04SearchModel(
        actions=actions,
        variants=variants,
        utilities={action.id: action.utility for action in actions},
        transitions={(actions[0].id, actions[1].id): 0.8},
        max_sequence_length=max_sequence_length,
        analysis=SimpleNamespace(),
    )


def test_skeleton_problem_uses_explicit_active_horizon() -> None:
    problem = runner._skeleton_problem(_model(), horizon=2)

    assert problem.max_sequence_length == 2
    assert problem.discounts == (1.0, 0.5)
    assert tuple(item.action_id for item in problem.variants) == (
        "call:alpha()",
        "call:beta()",
    )


def test_search_horizons_deepen_shortest_first_with_full_fallback() -> None:
    assert runner._search_horizons(_model(6)) == (1, 2, 3, 4, 5, 6)
    assert runner._search_horizons(_model(3)) == (1, 2, 3)


def test_skeleton_problem_rejects_invalid_horizon() -> None:
    model = _model(6)

    with pytest.raises(ValueError, match="horizon"):
        runner._skeleton_problem(model, horizon=0)
    with pytest.raises(ValueError, match="horizon"):
        runner._skeleton_problem(model, horizon=7)
