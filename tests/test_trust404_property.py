from __future__ import annotations

from types import SimpleNamespace

from qprover.artifacts import SourceUnitArtifact
from qprover.trust404_property import (
    PropertyAnalysis,
    PropertyFact,
    extract_property_analysis,
)
from qprover.trust404_resources import build_property_slices, score_function_relevance


def _identifier(name: str, declaration: int, node_id: int) -> dict[str, object]:
    return {
        "nodeType": "Identifier",
        "id": node_id,
        "name": name,
        "referencedDeclaration": declaration,
        "src": f"{node_id}:1:0",
    }


def _parameter(
    name: str, node_id: int, type_string: str = "address"
) -> dict[str, object]:
    return {
        "nodeType": "VariableDeclaration",
        "id": node_id,
        "name": name,
        "stateVariable": False,
        "typeDescriptions": {"typeString": type_string},
        "src": f"{node_id}:1:0",
    }


def _function(
    name: str,
    node_id: int,
    *,
    body: dict[str, object],
    parameters: tuple[dict[str, object], ...] = (),
) -> dict[str, object]:
    return {
        "nodeType": "FunctionDefinition",
        "kind": "function",
        "id": node_id,
        "name": name,
        "visibility": "public",
        "stateMutability": "view",
        "parameters": {"parameters": list(parameters)},
        "returnParameters": {
            "parameters": [
                _parameter("", node_id + 10_000, "bool"),
            ]
        },
        "body": body,
        "src": f"{node_id}:20:0",
    }


def _source_unit(functions: tuple[dict[str, object], ...]) -> SourceUnitArtifact:
    seed = {
        "nodeType": "VariableDeclaration",
        "id": 11,
        "name": "SEED",
        "stateVariable": True,
        "constant": True,
        "value": {
            "nodeType": "Literal",
            "id": 12,
            "kind": "number",
            "value": "10000000000000000000",
            "src": "12:1:0",
        },
        "src": "11:1:0",
    }
    return SourceUnitArtifact(
        source_name="Invariants.sol",
        source_sha256="1" * 64,
        ast={
            "nodeType": "SourceUnit",
            "id": 0,
            "nodes": [
                {
                    "nodeType": "ContractDefinition",
                    "id": 1,
                    "name": "Invariants",
                    "nodes": [seed, *functions],
                    "src": "0:500:0",
                }
            ],
            "src": "0:500:0",
        },
    )


def test_extracts_target_balance_property_fact() -> None:
    target = _parameter("target", 10)
    balance = {
        "nodeType": "MemberAccess",
        "id": 30,
        "memberName": "balance",
        "expression": _identifier("target", 10, 31),
        "src": "30:1:0",
    }
    comparison = {
        "nodeType": "BinaryOperation",
        "id": 32,
        "operator": ">=",
        "leftExpression": balance,
        "rightExpression": _identifier("SEED", 11, 33),
        "src": "32:1:0",
    }
    vault = _function(
        "vaultSolvent",
        20,
        parameters=(target,),
        body={
            "nodeType": "Block",
            "id": 34,
            "statements": [
                {
                    "nodeType": "Return",
                    "id": 35,
                    "expression": comparison,
                    "src": "35:1:0",
                }
            ],
            "src": "34:1:0",
        },
    )
    check_all = _function(
        "checkAll",
        40,
        parameters=(_parameter("target", 41),),
        body={
            "nodeType": "Block",
            "id": 42,
            "statements": [
                {
                    "nodeType": "ExpressionStatement",
                    "id": 43,
                    "expression": {
                        "nodeType": "FunctionCall",
                        "id": 44,
                        "expression": {
                            "nodeType": "Identifier",
                            "id": 45,
                            "name": "vaultSolvent",
                            "referencedDeclaration": 20,
                        },
                        "arguments": [_identifier("target", 41, 46)],
                    },
                }
            ],
            "src": "42:1:0",
        },
    )

    analysis = extract_property_analysis(
        (_source_unit((vault, check_all)),),
        invariants_source_name="Invariants.sol",
        predicates=("vaultSolvent",),
    )
    fact = analysis.fact("vaultSolvent")

    assert fact.known is True
    assert fact.target_parameter_index == 0
    assert fact.target_balance_read is True
    assert fact.constants == (10_000_000_000_000_000_000,)
    assert fact.comparison_hints == ((">=", "target.balance", "constant"),)
    assert fact.bound_from_check_all is True


def test_extracts_target_call_through_interface_type_conversion() -> None:
    target = _parameter("target", 110)
    converted_target = {
        "nodeType": "FunctionCall",
        "id": 111,
        "kind": "typeConversion",
        "expression": {
            "nodeType": "ElementaryTypeNameExpression",
            "id": 112,
        },
        "arguments": [_identifier("target", 110, 113)],
    }
    getter_call = {
        "nodeType": "FunctionCall",
        "id": 114,
        "expression": {
            "nodeType": "MemberAccess",
            "id": 115,
            "memberName": "protected",
            "expression": converted_target,
        },
        "arguments": [],
    }
    predicate = _function(
        "protectedUnchanged",
        120,
        parameters=(target,),
        body={
            "nodeType": "Block",
            "id": 121,
            "statements": [
                {
                    "nodeType": "Return",
                    "id": 122,
                    "expression": getter_call,
                }
            ],
        },
    )
    check_all = _function(
        "checkAll",
        130,
        parameters=(_parameter("target", 131),),
        body={
            "nodeType": "Block",
            "id": 132,
            "statements": [
                {
                    "nodeType": "ExpressionStatement",
                    "expression": {
                        "nodeType": "FunctionCall",
                        "id": 133,
                        "expression": {
                            "nodeType": "Identifier",
                            "referencedDeclaration": 120,
                        },
                        "arguments": [_identifier("target", 131, 134)],
                    },
                }
            ],
        },
    )

    analysis = extract_property_analysis(
        (_source_unit((predicate, check_all)),),
        invariants_source_name="Invariants.sol",
        predicates=("protectedUnchanged",),
    )

    assert analysis.fact("protectedUnchanged").target_calls == ("protected",)


def test_predicate_not_called_from_check_all_is_unknown() -> None:
    target = _parameter("target", 50)
    predicate = _function(
        "ownerUnchanged",
        60,
        parameters=(target,),
        body={
            "nodeType": "Block",
            "id": 61,
            "statements": [
                {
                    "nodeType": "Return",
                    "id": 62,
                    "expression": {
                        "nodeType": "Literal",
                        "id": 63,
                        "kind": "bool",
                        "value": "true",
                    },
                }
            ],
        },
    )
    check_all = _function(
        "checkAll",
        70,
        parameters=(_parameter("target", 71),),
        body={"nodeType": "Block", "id": 72, "statements": []},
    )

    analysis = extract_property_analysis(
        (_source_unit((predicate, check_all)),),
        invariants_source_name="Invariants.sol",
        predicates=("ownerUnchanged",),
    )
    fact = analysis.fact("ownerUnchanged")

    assert fact.bound_from_check_all is False
    assert fact.known is False


def test_check_all_order_ignores_non_predicate_helper_calls() -> None:
    target = _parameter("target", 80)
    helper = _function(
        "normalize",
        81,
        body={"nodeType": "Block", "id": 82, "statements": []},
    )
    predicate = _function(
        "positionSafe",
        83,
        parameters=(target,),
        body={"nodeType": "Block", "id": 84, "statements": []},
    )
    check_all = _function(
        "checkAll",
        85,
        parameters=(_parameter("target", 86),),
        body={
            "nodeType": "Block",
            "id": 87,
            "statements": [
                {
                    "nodeType": "ExpressionStatement",
                    "expression": {
                        "nodeType": "FunctionCall",
                        "id": 88,
                        "src": "10:1:0",
                        "expression": {
                            "nodeType": "Identifier",
                            "referencedDeclaration": 81,
                        },
                    },
                },
                {
                    "nodeType": "ExpressionStatement",
                    "expression": {
                        "nodeType": "FunctionCall",
                        "id": 89,
                        "src": "20:1:0",
                        "expression": {
                            "nodeType": "Identifier",
                            "referencedDeclaration": 83,
                        },
                    },
                },
            ],
        },
    )

    analysis = extract_property_analysis(
        (_source_unit((helper, predicate, check_all)),),
        invariants_source_name="Invariants.sol",
        predicates=("positionSafe",),
    )

    assert analysis.check_all_predicates == ("positionSafe",)


def test_balance_property_slice_prioritizes_native_value_out() -> None:
    properties = PropertyAnalysis(
        invariants_source_name="Invariants.sol",
        contract_name="Invariants",
        facts=(
            PropertyFact(
                predicate_name="vaultSolvent",
                function_id="function:Invariants.sol:Invariants:20:vaultSolvent(address)",
                target_parameter_index=0,
                target_balance_read=True,
                target_calls=(),
                constants=(10 * 10**18,),
                comparison_hints=((">=", "target.balance", "constant"),),
                source_span="20:20:0",
                bound_from_check_all=True,
                known=True,
            ),
        ),
    )

    slices = build_property_slices(properties, root_target_identity="root")
    property_slice = slices[0]

    assert property_slice.property_id == "vaultSolvent"
    assert property_slice.direction_hint == "decrease"
    assert tuple((item.kind, item.identity) for item in property_slice.resources) == (
        ("native_balance", "root"),
    )

    native_out = SimpleNamespace(
        canonical_id="function:Target.sol:Target:1:withdraw()",
        transitive_storage_reads=(),
        transitive_storage_writes=(),
        value_flows=(SimpleNamespace(asset="native", direction="out"),),
        calls=(),
    )
    unrelated = SimpleNamespace(
        canonical_id="function:Target.sol:Target:2:setFlag()",
        transitive_storage_reads=(),
        transitive_storage_writes=("storage:Target.sol:Target:3:flag",),
        value_flows=(),
        calls=(),
    )

    assert score_function_relevance(native_out, slices) > score_function_relevance(
        unrelated, slices
    )
