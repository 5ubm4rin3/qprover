from __future__ import annotations

from types import SimpleNamespace

from qprover.models import ActionStep, Candidate
from qprover.trust404 import Track04Action, Track04SearchModel, Track04Variant
from qprover.trust404_runner import (
    _concrete_candidates,
    _semantic_hypotheses,
    _skeleton_problem,
)


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


def test_semantic_hypothesis_chains_token_prerequisites_and_state_dependency() -> None:
    def call(member: str, receiver: str) -> SimpleNamespace:
        return SimpleNamespace(member_name=member, receiver_name=receiver)

    def function(
        canonical_id: str,
        *,
        reads: tuple[str, ...] = (),
        writes: tuple[str, ...] = (),
        calls: tuple[object, ...] = (),
    ) -> SimpleNamespace:
        return SimpleNamespace(
            canonical_id=canonical_id,
            storage_reads=reads,
            storage_writes=writes,
            calls=calls,
        )

    def action(
        action_id: str,
        function_id: str,
        signature: str,
        path: tuple[str, ...],
        *,
        reads: tuple[str, ...] = (),
        writes: tuple[str, ...] = (),
    ) -> Track04Action:
        return Track04Action(
            id=action_id,
            kind="call",
            signature=signature,
            function_id=function_id,
            param_types=(),
            payable=False,
            utility=0.5,
            storage_reads=reads,
            storage_writes=writes,
            provenance=("Neutral.sol", "0:1:0"),
            target_path=path,
        )

    acquire = action("call:acquire()", "fn:acquire", "acquire()", ())
    approve_credit = action(
        "call:creditAsset():approve(address,uint256)",
        "fn:approve",
        "approve(address,uint256)",
        ("creditAsset()",),
    )
    trade = action(
        "call:market():trade(uint256)",
        "fn:trade",
        "trade(uint256)",
        ("market()",),
    )
    approve_collateral = action(
        "call:collateralAsset():approve(address,uint256)",
        "fn:approve",
        "approve(address,uint256)",
        ("collateralAsset()",),
    )
    lock = action(
        "call:lock(uint256)",
        "fn:lock",
        "lock(uint256)",
        (),
        writes=("position",),
    )
    settle = action(
        "call:settle(uint256)",
        "fn:settle",
        "settle(uint256)",
        (),
        reads=("position",),
    )
    actions = (
        acquire,
        approve_credit,
        trade,
        approve_collateral,
        lock,
        settle,
    )
    functions = (
        function("fn:acquire", calls=(call("mint", "creditAsset"),)),
        function("fn:approve"),
        function(
            "fn:trade",
            calls=(
                call("transferFrom", "inputAsset"),
                call("transfer", "outputAsset"),
            ),
        ),
        function(
            "fn:lock",
            writes=("position",),
            calls=(call("transferFrom", "collateralAsset"),),
        ),
        function("fn:settle", reads=("position",)),
    )
    model = Track04SearchModel(
        actions=actions,
        variants=tuple(
            Track04Variant(item.id, item.signature, (), 0) for item in actions
        ),
        utilities={item.id: item.utility for item in actions},
        transitions={},
        max_sequence_length=6,
        analysis=SimpleNamespace(
            report=SimpleNamespace(contracts=(SimpleNamespace(functions=functions),))
        ),
    )
    addresses = {
        "instance:root": "0x" + "01" * 20,
        "instance:path:creditAsset()": "0x" + "02" * 20,
        "instance:path:market()|inputAsset()": "0x" + "02" * 20,
        "instance:path:collateralAsset()": "0x" + "03" * 20,
        "instance:path:market()|outputAsset()": "0x" + "03" * 20,
        "instance:path:market()": "0x" + "04" * 20,
    }
    runtime = SimpleNamespace(instance_address=addresses.__getitem__)

    hypotheses = _semantic_hypotheses(model, runtime)

    assert (
        acquire.id,
        approve_credit.id,
        trade.id,
        approve_collateral.id,
        lock.id,
        settle.id,
    ) in hypotheses
