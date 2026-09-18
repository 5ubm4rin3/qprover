from __future__ import annotations

from types import SimpleNamespace

from qprover.trust404_values import (
    ContractAddress,
    ReadUint,
    Scale,
    SelfAddress,
    complete_parameters,
)


def _action(
    action_id: str,
    param_types: tuple[str, ...],
    *,
    reads: tuple[str, ...] = (),
    writes: tuple[str, ...] = (),
):
    return SimpleNamespace(
        id=action_id,
        function_id=f"function:{action_id}",
        param_types=param_types,
        storage_reads=reads,
        storage_writes=writes,
    )


def _step(action_id: str, target_instance_id: str):
    return SimpleNamespace(
        action_id=action_id,
        target_instance_id=target_instance_id,
        signature=action_id.removeprefix("call:"),
        value_wei=0,
    )


def test_contextual_address_prefers_next_action_target_without_name_checks() -> None:
    first = _action("call:alpha(address)", ("address",))
    second = _action("call:omega()", ())
    analysis = SimpleNamespace(
        actions=(first, second),
        parameter_constraints=(),
    )
    state = SimpleNamespace(
        runtime_uint_sources=(),
        previous_returns=(),
    )
    skeleton = SimpleNamespace(
        steps=(
            _step(first.id, "instance:root"),
            _step(second.id, "instance:consumer"),
        )
    )

    completed = complete_parameters(
        skeleton,
        state,
        analysis,
        limit=4,
    )

    assert completed
    assert completed[0].steps[0].args == (ContractAddress("instance:consumer"),)


def test_uint_parameter_admits_self_indexed_runtime_read_and_scaled_forms() -> None:
    action = _action(
        "call:theta(uint256)",
        ("uint256",),
        reads=("storage:credit",),
    )
    source = SimpleNamespace(
        instance_id="instance:root",
        signature="ledger(address)",
        argument_mode="self",
        reads=("storage:credit",),
    )
    analysis = SimpleNamespace(
        actions=(action,),
        parameter_constraints=(),
    )
    state = SimpleNamespace(
        runtime_uint_sources=(source,),
        previous_returns=(),
    )
    skeleton = SimpleNamespace(
        steps=(_step(action.id, "instance:root"),),
    )

    completed = complete_parameters(
        skeleton,
        state,
        analysis,
        limit=8,
    )

    expressions = tuple(candidate.steps[0].args[0] for candidate in completed)
    read = ReadUint(
        "instance:root",
        "ledger(address)",
        (SelfAddress(),),
    )

    assert expressions[0] == read
    assert Scale(read, 1, 2) in expressions[:4]
    assert Scale(read, 2, 1) in expressions[:4]


def test_bounded_parameter_constraint_produces_z3_model() -> None:
    action = _action("call:kappa(uint256)", ("uint256",))
    constraint = SimpleNamespace(
        function_id=action.function_id,
        parameter_index=0,
        operator=">=",
        constant=7,
    )
    analysis = SimpleNamespace(
        actions=(action,),
        parameter_constraints=(constraint,),
        source_constants=(),
    )
    state = SimpleNamespace(runtime_uint_sources=(), previous_returns=())
    skeleton = SimpleNamespace(
        steps=(_step(action.id, "instance:root"),),
    )

    completed = complete_parameters(skeleton, state, analysis, limit=4)

    assert completed
    values = tuple(candidate.steps[0].args[0] for candidate in completed)
    assert any(getattr(value, "value", None) == 7 for value in values)
