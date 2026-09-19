from __future__ import annotations

from types import SimpleNamespace

from qprover.trust404_values import (
    CallbackProgram,
    Const,
    ContractAddress,
    Max,
    Min,
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
    callback_enabled: bool = False,
):
    return SimpleNamespace(
        id=action_id,
        function_id=f"function:{action_id}",
        param_types=param_types,
        storage_reads=reads,
        storage_writes=writes,
        callback_enabled=callback_enabled,
    )


def _step(action_id: str, target_instance_id: str):
    return SimpleNamespace(
        action_id=action_id,
        target_instance_id=target_instance_id,
        signature=action_id.removeprefix("call:").removesuffix("@callback"),
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


def test_exact_parameter_constraint_precedes_unrelated_runtime_read() -> None:
    action = _action("call:advance(uint256)", ("uint256",))
    constraint = SimpleNamespace(
        function_id=action.function_id,
        parameter_index=0,
        operator="==",
        constant=37,
    )
    unrelated = SimpleNamespace(
        instance_id="instance:root",
        signature="counter()",
        argument_mode="none",
        reads=("storage:counter",),
    )
    analysis = SimpleNamespace(
        actions=(action,),
        parameter_constraints=(constraint,),
        source_constants=(37,),
    )
    state = SimpleNamespace(
        runtime_uint_sources=(unrelated,),
        previous_returns=(),
    )
    skeleton = SimpleNamespace(
        steps=(_step(action.id, "instance:root"),),
    )

    completed = complete_parameters(skeleton, state, analysis, limit=1)

    assert completed[0].steps[0].args == (Const(37),)


def test_token_input_amount_prefers_recent_asset_balance_over_reserve_read() -> None:
    approve = _action("call:approve(address,uint256)", ("address", "uint256"))
    consume = _action(
        "call:consume(uint256)",
        ("uint256",),
        reads=("storage:balance", "storage:reserve0", "storage:reserve1"),
    )
    consume_fact = SimpleNamespace(
        canonical_id=consume.function_id,
        calls=(SimpleNamespace(member_name="transferFrom"),),
        parameter_constraints=(),
    )
    analysis = SimpleNamespace(
        actions=(approve, consume),
        parameter_constraints=(),
        report=SimpleNamespace(contracts=(SimpleNamespace(functions=(consume_fact,)),)),
    )
    state = SimpleNamespace(
        runtime_uint_sources=(
            SimpleNamespace(
                instance_id="instance:pool",
                signature="spotPrice()",
                argument_mode="none",
                reads=("storage:reserve0", "storage:reserve1"),
            ),
            SimpleNamespace(
                instance_id="instance:asset",
                signature="balanceOf(address)",
                argument_mode="self",
                reads=("storage:balance",),
            ),
        ),
        previous_returns=(),
    )
    skeleton = SimpleNamespace(
        steps=(
            _step(approve.id, "instance:asset"),
            _step(consume.id, "instance:pool"),
        )
    )

    completed = complete_parameters(skeleton, state, analysis, limit=2)

    assert completed[0].steps[1].args == (
        ReadUint(
            "instance:asset",
            "balanceOf(address)",
            (SelfAddress(),),
        ),
    )


def test_callback_capable_action_has_generic_self_callback() -> None:
    deposit = _action("call:deposit()", ())
    callback = _action(
        "call:collect()@callback",
        (),
        callback_enabled=True,
    )
    settle = _action("call:settle()", ())
    analysis = SimpleNamespace(
        actions=(deposit, callback, settle),
        parameter_constraints=(),
    )
    state = SimpleNamespace(runtime_uint_sources=(), previous_returns=())
    skeleton = SimpleNamespace(
        steps=(
            _step(deposit.id, "instance:root"),
            _step(callback.id, "instance:root"),
            _step(settle.id, "instance:root"),
        )
    )

    completed = complete_parameters(skeleton, state, analysis, limit=1)

    program = completed[0].steps[1].callback_program
    assert isinstance(program, CallbackProgram)
    assert tuple(item.signature for item in program.instructions) == ("collect()",)


def test_multistep_runtime_read_is_positive_and_capped_by_source_constant() -> None:
    mutate = _action(
        "call:mutate(uint256)",
        ("uint256",),
        reads=("storage:credit",),
        writes=("storage:credit",),
    )
    consume = _action(
        "call:consume(uint256)",
        ("uint256",),
        reads=("storage:credit",),
    )
    source = SimpleNamespace(
        instance_id="instance:root",
        signature="credit(address)",
        argument_mode="self",
        reads=("storage:credit",),
    )
    analysis = SimpleNamespace(
        actions=(mutate, consume),
        parameter_constraints=(),
        source_constants=(10,),
    )
    state = SimpleNamespace(
        runtime_uint_sources=(source,),
        previous_returns=(),
    )
    skeleton = SimpleNamespace(
        steps=(
            _step(mutate.id, "instance:root"),
            _step(consume.id, "instance:root"),
        )
    )

    completed = complete_parameters(skeleton, state, analysis, limit=1)

    read = ReadUint(
        "instance:root",
        "credit(address)",
        (SelfAddress(),),
    )
    bounded = Min(Max(read, Const(1)), Const(10))
    assert completed[0].steps[0].args == (bounded,)
    assert completed[0].steps[1].args == (bounded,)
