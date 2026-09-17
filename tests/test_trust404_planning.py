from __future__ import annotations

from types import SimpleNamespace

from qprover.models import ActionStep, Candidate
from qprover.trust404 import Track04Action, Track04SearchModel, Track04Variant
from qprover.trust404_runner import _concrete_candidates, _skeleton_problem


def _model() -> Track04SearchModel:
    actions = (
        Track04Action(
            id="call:deposit()",
            kind="call",
            signature="deposit()",
            function_id="deposit",
            param_types=(),
            payable=True,
            utility=0.5,
            storage_reads=(),
            storage_writes=("credit",),
            provenance=("Demo.sol", "0:1:0"),
        ),
        Track04Action(
            id="call:withdraw(uint256)@callback",
            kind="call",
            signature="withdraw(uint256)",
            function_id="withdraw",
            param_types=("uint256",),
            payable=False,
            utility=0.8,
            storage_reads=("credit",),
            storage_writes=("credit",),
            provenance=("Demo.sol", "1:1:0"),
            callback_enabled=True,
        ),
    )
    variants = (
        Track04Variant("call:deposit()", "deposit()", (), 0),
        Track04Variant("call:deposit()", "deposit()", (), 10**18),
        Track04Variant(
            "call:withdraw(uint256)@callback",
            "withdraw(uint256)",
            (0,),
            0,
        ),
        Track04Variant(
            "call:withdraw(uint256)@callback",
            "withdraw(uint256)",
            ("__QPROVER_UINT_REF__:credit",),
            0,
        ),
    )
    return Track04SearchModel(
        actions=actions,
        variants=variants,
        utilities={action.id: action.utility for action in actions},
        transitions={(actions[0].id, actions[1].id): 0.8},
        max_sequence_length=4,
        analysis=SimpleNamespace(),
    )


def test_track04_qubo_problem_has_one_variant_per_action() -> None:
    model = _model()
    problem = _skeleton_problem(model)

    assert len(model.variants) > len(model.actions)
    assert len(problem.variants) == len(model.actions)
    assert {variant.action_id for variant in problem.variants} == {
        action.id for action in model.actions
    }


def test_track04_parameter_completion_prefers_dynamic_and_funded_values() -> None:
    model = _model()
    skeleton = Candidate(
        (
            ActionStep("call:deposit()", "target", "deposit()", 0, (), 0),
            ActionStep(
                "call:withdraw(uint256)@callback",
                "target",
                "withdraw(uint256)",
                0,
                (0,),
                0,
            ),
        )
    )

    concrete = _concrete_candidates(model, skeleton, 2)

    assert concrete
    first = concrete[0]
    assert first.steps[0].value_wei == 10**18
    assert first.steps[1].args == ("__QPROVER_UINT_REF__:credit",)
