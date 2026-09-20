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


def test_semantic_hypothesis_chains_state_dependency_without_api_templates() -> None:
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

    assert (lock.id, settle.id) in hypotheses


def test_semantic_hypothesis_backchains_constant_state_guards() -> None:
    storage = "storage:Neutral.sol:Stage:1:phase"

    def function(
        canonical_id: str,
        guard: int | None,
        assignment: int | None,
    ) -> SimpleNamespace:
        return SimpleNamespace(
            canonical_id=canonical_id,
            contract="Stage",
            storage_reads=(storage,) if guard is not None else (),
            storage_writes=(storage,),
            calls=(),
            storage_guards=(
                SimpleNamespace(
                    storage_id=storage,
                    operator="==",
                    constant=guard,
                ),
            )
            if guard is not None
            else (),
            storage_assignments=(
                SimpleNamespace(storage_id=storage, constant=assignment),
            )
            if assignment is not None
            else (),
        )

    def action(name: str) -> Track04Action:
        return Track04Action(
            id=f"call:{name}()",
            kind="call",
            signature=f"{name}()",
            function_id=f"fn:{name}",
            param_types=(),
            payable=False,
            utility=0.5,
            storage_reads=(storage,),
            storage_writes=(storage,),
            provenance=("Neutral.sol", "0:1:0"),
        )

    actions = tuple(action(name) for name in ("alpha", "beta", "gamma", "omega"))
    functions = (
        function("fn:alpha", 0, 1),
        function("fn:beta", 1, 2),
        function("fn:gamma", 2, 3),
        function("fn:omega", 3, None),
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
            source_name="Neutral.sol",
            contract_name="Stage",
            report=SimpleNamespace(
                contracts=(
                    SimpleNamespace(
                        name="Stage",
                        storage=(),
                        functions=functions,
                    ),
                )
            ),
        ),
    )
    runtime = SimpleNamespace(instance_address=lambda instance_id: "0x" + "01" * 20)

    hypotheses = _semantic_hypotheses(model, runtime)

    assert tuple(item.id for item in actions) in hypotheses


def test_semantic_hypothesis_joins_runtime_aliases_across_contracts() -> None:
    unit = "storage:Neutral.sol:Resource:1:units"
    ready = "storage:Neutral.sol:Helper:2:ready"
    breached = "storage:Neutral.sol:Alpha:3:breached"

    def storage(
        declaration_id: int,
        name: str,
        type_name: str,
        canonical_id: str,
    ) -> SimpleNamespace:
        return SimpleNamespace(
            declaration_id=declaration_id,
            name=name,
            type_name=type_name,
            canonical_id=canonical_id,
        )

    root_resource = storage(10, "resource", "contract Resource", "root:resource")
    root_helper = storage(11, "helper", "contract Helper", "root:helper")
    helper_resource = storage(12, "resource", "contract Resource", "helper:resource")
    unit_storage = storage(13, "units", "uint256", unit)
    ready_storage = storage(14, "ready", "uint256", ready)

    def getter(member, receiver, declaration, receiver_type):
        return SimpleNamespace(
            kind="unknown",
            member_name=member,
            receiver_name=receiver,
            receiver_declaration=declaration,
            receiver_type=receiver_type,
            callee_id=None,
        )

    functions = (
        SimpleNamespace(
            canonical_id="fn:produce",
            contract="Resource",
            storage_reads=(),
            storage_writes=(unit,),
            calls=(),
            storage_guards=(),
            storage_assignments=(),
            role_guards=(),
        ),
        SimpleNamespace(
            canonical_id="fn:consume",
            contract="Helper",
            storage_reads=(),
            storage_writes=(ready,),
            calls=(getter("units", "resource", 12, "contract Resource"),),
            storage_guards=(),
            storage_assignments=(),
            role_guards=(),
        ),
        SimpleNamespace(
            canonical_id="fn:finish",
            contract="Alpha",
            storage_reads=(),
            storage_writes=(breached,),
            calls=(getter("ready", "helper", 11, "contract Helper"),),
            storage_guards=(),
            storage_assignments=(),
            role_guards=(),
        ),
    )

    def action(
        action_id: str,
        function_id: str,
        path: tuple[str, ...],
        reads: tuple[str, ...],
        writes: tuple[str, ...],
    ) -> Track04Action:
        return Track04Action(
            id=action_id,
            kind="call",
            signature=action_id.rsplit(":", 1)[-1],
            function_id=function_id,
            param_types=(),
            payable=False,
            utility=0.5,
            storage_reads=reads,
            storage_writes=writes,
            provenance=("Neutral.sol", "0:1:0"),
            target_path=path,
        )

    actions = (
        action("call:resource():produce()", "fn:produce", ("resource()",), (), (unit,)),
        action(
            "call:helper():consume()", "fn:consume", ("helper()",), (unit,), (ready,)
        ),
        action("call:finish()", "fn:finish", (), (ready,), (breached,)),
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
            source_name="Neutral.sol",
            contract_name="Alpha",
            report=SimpleNamespace(
                contracts=(
                    SimpleNamespace(
                        name="Alpha",
                        storage=(root_resource, root_helper),
                        functions=(functions[2],),
                    ),
                    SimpleNamespace(
                        name="Helper",
                        storage=(helper_resource, ready_storage),
                        functions=(functions[1],),
                    ),
                    SimpleNamespace(
                        name="Resource",
                        storage=(unit_storage,),
                        functions=(functions[0],),
                    ),
                )
            ),
        ),
    )
    addresses = {
        "instance:root": "0x" + "01" * 20,
        "instance:path:resource()": "0x" + "02" * 20,
        "instance:path:helper()": "0x" + "03" * 20,
        "instance:path:helper()|resource()": "0x" + "02" * 20,
    }
    runtime = SimpleNamespace(instance_address=addresses.__getitem__)

    hypotheses = _semantic_hypotheses(model, runtime)

    assert tuple(item.id for item in actions) in hypotheses


def test_semantic_hypothesis_keeps_bounded_state_novel_repetition() -> None:
    resource = "storage:Neutral.sol:Alpha:1:resource"
    total = "storage:Neutral.sol:Alpha:2:total"
    prepare = Track04Action(
        id="call:alpha()",
        kind="call",
        signature="alpha()",
        function_id="fn:alpha",
        param_types=(),
        payable=False,
        utility=0.5,
        storage_reads=(),
        storage_writes=(resource,),
        provenance=("Neutral.sol", "0:1:0"),
    )
    consume = Track04Action(
        id="call:omega()",
        kind="call",
        signature="omega()",
        function_id="fn:omega",
        param_types=(),
        payable=False,
        utility=0.8,
        storage_reads=(resource, total),
        storage_writes=(total,),
        provenance=("Neutral.sol", "1:1:0"),
    )
    functions = (
        SimpleNamespace(
            canonical_id="fn:alpha",
            storage_reads=(),
            storage_writes=(resource,),
            calls=(),
            storage_guards=(),
            storage_assignments=(),
            role_guards=(),
        ),
        SimpleNamespace(
            canonical_id="fn:omega",
            storage_reads=(resource, total),
            storage_writes=(total,),
            calls=(SimpleNamespace(kind="builtin", member_name="require"),),
            storage_guards=(),
            storage_assignments=(),
            role_guards=(),
        ),
    )
    model = Track04SearchModel(
        actions=(prepare, consume),
        variants=(
            Track04Variant(prepare.id, prepare.signature, (), 0),
            Track04Variant(consume.id, consume.signature, (), 0),
        ),
        utilities={prepare.id: prepare.utility, consume.id: consume.utility},
        transitions={},
        max_sequence_length=6,
        analysis=SimpleNamespace(
            contract_name="Alpha",
            report=SimpleNamespace(
                contracts=(
                    SimpleNamespace(name="Alpha", storage=(), functions=functions),
                )
            ),
        ),
    )
    runtime = SimpleNamespace(instance_address=lambda instance_id: "0x" + "01" * 20)

    hypotheses = _semantic_hypotheses(model, runtime)

    assert (prepare.id, consume.id, consume.id, consume.id) in hypotheses


def test_semantic_hypothesis_does_not_repeat_exact_state_transition() -> None:
    phase = "storage:Neutral.sol:Stage:1:phase"
    advance = Track04Action(
        id="call:advance()",
        kind="call",
        signature="advance()",
        function_id="fn:advance",
        param_types=(),
        payable=False,
        utility=0.8,
        storage_reads=(phase,),
        storage_writes=(phase,),
        provenance=("Neutral.sol", "0:1:0"),
    )
    function = SimpleNamespace(
        canonical_id="fn:advance",
        storage_reads=(phase,),
        storage_writes=(phase,),
        calls=(),
        storage_guards=(SimpleNamespace(storage_id=phase, constant=0),),
        storage_assignments=(SimpleNamespace(storage_id=phase, constant=1),),
        role_guards=(),
    )
    model = Track04SearchModel(
        actions=(advance,),
        variants=(Track04Variant(advance.id, advance.signature, (), 0),),
        utilities={advance.id: advance.utility},
        transitions={},
        max_sequence_length=6,
        analysis=SimpleNamespace(
            contract_name="Stage",
            report=SimpleNamespace(
                contracts=(
                    SimpleNamespace(name="Stage", storage=(), functions=(function,)),
                )
            ),
        ),
    )
    runtime = SimpleNamespace(instance_address=lambda instance_id: "0x" + "01" * 20)

    hypotheses = _semantic_hypotheses(model, runtime)

    assert all(sequence.count(advance.id) <= 1 for sequence in hypotheses)


def test_semantic_hypothesis_seeds_direct_property_storage_writer() -> None:
    protected = "storage:Neutral.sol:Alpha:1:protected"
    action = Track04Action(
        id="call:change(address)",
        kind="call",
        signature="change(address)",
        function_id="fn:change",
        param_types=("address",),
        payable=False,
        utility=0.5,
        storage_reads=(),
        storage_writes=(protected,),
        provenance=("Neutral.sol", "0:1:0"),
    )
    function = SimpleNamespace(
        canonical_id="fn:change",
        signature="change(address)",
        storage_reads=(),
        storage_writes=(protected,),
        calls=(),
        storage_guards=(),
        storage_assignments=(),
        role_guards=(),
    )
    storage = SimpleNamespace(
        declaration_id=1,
        name="protected",
        type_name="address",
        canonical_id=protected,
    )
    model = Track04SearchModel(
        actions=(action,),
        variants=(Track04Variant(action.id, action.signature, ("0x00",), 0),),
        utilities={action.id: action.utility},
        transitions={},
        max_sequence_length=6,
        analysis=SimpleNamespace(
            source_name="Neutral.sol",
            contract_name="Alpha",
            property_analysis=SimpleNamespace(
                facts=(SimpleNamespace(target_calls=("protected",)),)
            ),
            report=SimpleNamespace(
                contracts=(
                    SimpleNamespace(
                        name="Alpha",
                        storage=(storage,),
                        functions=(function,),
                    ),
                )
            ),
        ),
    )
    runtime = SimpleNamespace(instance_address=lambda _: "0x" + "01" * 20)

    hypotheses = _semantic_hypotheses(model, runtime)

    assert (action.id,) in hypotheses


def test_semantic_hypothesis_keeps_bounded_alternative_resource_producers() -> None:
    resource = "storage:Neutral.sol:Alpha:1:resource"

    def action(action_id: str, function_id: str, reads=(), writes=()):
        return Track04Action(
            id=action_id,
            kind="call",
            signature=action_id.removeprefix("call:"),
            function_id=function_id,
            param_types=(),
            payable=False,
            utility=0.5,
            storage_reads=reads,
            storage_writes=writes,
            provenance=("Neutral.sol", "0:1:0"),
        )

    alpha = action("call:alpha()", "fn:alpha", writes=(resource,))
    beta = action("call:beta()", "fn:beta", writes=(resource,))
    omega = action("call:omega()", "fn:omega", reads=(resource,))
    actions = (alpha, beta, omega)
    functions = tuple(
        SimpleNamespace(
            canonical_id=item.function_id,
            signature=item.signature,
            storage_reads=item.storage_reads,
            storage_writes=item.storage_writes,
            calls=(),
            storage_guards=(),
            storage_assignments=(),
            role_guards=(),
        )
        for item in actions
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
            contract_name="Alpha",
            report=SimpleNamespace(
                contracts=(
                    SimpleNamespace(name="Alpha", storage=(), functions=functions),
                )
            ),
        ),
    )
    runtime = SimpleNamespace(instance_address=lambda _: "0x" + "01" * 20)

    hypotheses = _semantic_hypotheses(model, runtime)

    assert (alpha.id, omega.id) in hypotheses
    assert (beta.id, omega.id) in hypotheses


def test_semantic_hypothesis_preserves_callback_resource_prerequisite() -> None:
    credit = "storage:Neutral.sol:Alpha:1:credit"
    prepare = Track04Action(
        id="call:prepare()",
        kind="call",
        signature="prepare()",
        function_id="fn:prepare",
        param_types=(),
        payable=True,
        utility=0.5,
        storage_reads=(),
        storage_writes=(credit,),
        provenance=("Neutral.sol", "0:1:0"),
    )
    release = Track04Action(
        id="call:release()@callback",
        kind="call",
        signature="release()",
        function_id="fn:release",
        param_types=(),
        payable=False,
        utility=0.8,
        storage_reads=(credit,),
        storage_writes=(credit,),
        provenance=("Neutral.sol", "1:1:0"),
        callback_enabled=True,
    )
    functions = (
        SimpleNamespace(
            canonical_id="fn:prepare",
            storage_reads=(),
            storage_writes=(credit,),
            calls=(),
            storage_guards=(),
            storage_assignments=(),
            role_guards=(),
        ),
        SimpleNamespace(
            canonical_id="fn:release",
            storage_reads=(credit,),
            storage_writes=(credit,),
            calls=(SimpleNamespace(kind="low_level"),),
            storage_guards=(),
            storage_assignments=(),
            role_guards=(),
        ),
    )
    model = Track04SearchModel(
        actions=(prepare, release),
        variants=(
            Track04Variant(prepare.id, prepare.signature, (), 10**18),
            Track04Variant(release.id, release.signature, (), 0),
        ),
        utilities={prepare.id: prepare.utility, release.id: release.utility},
        transitions={},
        max_sequence_length=4,
        analysis=SimpleNamespace(
            contract_name="Alpha",
            report=SimpleNamespace(
                contracts=(
                    SimpleNamespace(
                        name="Alpha",
                        storage=(
                            SimpleNamespace(
                                declaration_id=1,
                                name="credit",
                                type_name="mapping(address => uint256)",
                                canonical_id=credit,
                            ),
                        ),
                        functions=functions,
                    ),
                )
            ),
        ),
    )
    runtime = SimpleNamespace(instance_address=lambda _: "0x" + "01" * 20)

    hypotheses = _semantic_hypotheses(model, runtime)

    assert (prepare.id, release.id) in hypotheses
    assert all(sequence.count(prepare.id) <= 1 for sequence in hypotheses)
