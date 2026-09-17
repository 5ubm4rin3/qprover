from __future__ import annotations

from qprover.artifacts import SourceUnitArtifact
from qprover.trust404_property import extract_property_analysis


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
