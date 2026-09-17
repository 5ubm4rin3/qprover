"""Compiler-backed property facts for TRUST404 Track 04 invariants."""

from __future__ import annotations

from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

_COMPARISON_OPERATORS = frozenset({"==", "!=", "<", "<=", ">", ">="})
_UNIT_MULTIPLIERS = {
    "wei": 1,
    "gwei": 10**9,
    "ether": 10**18,
    "seconds": 1,
    "minutes": 60,
    "hours": 60 * 60,
    "days": 24 * 60 * 60,
    "weeks": 7 * 24 * 60 * 60,
}


@dataclass(frozen=True, slots=True)
class PropertyFact:
    predicate_name: str
    function_id: str | None
    target_parameter_index: int | None
    target_balance_read: bool
    target_calls: tuple[str, ...]
    constants: tuple[int, ...]
    comparison_hints: tuple[tuple[str, str, str], ...]
    source_span: str | None
    bound_from_check_all: bool
    known: bool


@dataclass(frozen=True, slots=True)
class PropertyAnalysis:
    invariants_source_name: str
    contract_name: str | None
    facts: tuple[PropertyFact, ...]

    def fact(self, predicate_name: str) -> PropertyFact:
        matches = [item for item in self.facts if item.predicate_name == predicate_name]
        if len(matches) != 1:
            raise KeyError(f"property fact not found or ambiguous: {predicate_name}")
        return matches[0]


def _walk(value: object) -> Iterator[Mapping[str, Any]]:
    if isinstance(value, Mapping):
        yield value
        for child in value.values():
            yield from _walk(child)
    elif isinstance(value, (tuple, list)):
        for child in value:
            yield from _walk(child)


def _parameter_type(parameter: Mapping[str, Any]) -> str:
    description = parameter.get("typeDescriptions")
    if not isinstance(description, Mapping):
        return "unknown"
    type_string = description.get("typeString")
    if not isinstance(type_string, str):
        return "unknown"
    if type_string.startswith(("contract ", "interface ")):
        return "address"
    if type_string == "address payable":
        return "address"
    return (
        type_string.replace(" memory", "")
        .replace(" calldata", "")
        .replace(" storage", "")
    )


def _signature(function: Mapping[str, Any]) -> str:
    name = function.get("name") or "<anonymous>"
    parameters = function.get("parameters")
    parameter_nodes = (
        parameters.get("parameters", ()) if isinstance(parameters, Mapping) else ()
    )
    return f"{name}({','.join(_parameter_type(item) for item in parameter_nodes)})"


def _source_unit(
    source_units: Sequence[object], source_name: str
) -> Mapping[str, Any] | None:
    matches = [
        getattr(item, "ast", None)
        for item in source_units
        if getattr(item, "source_name", None) == source_name
    ]
    matches = [item for item in matches if isinstance(item, Mapping)]
    return matches[0] if len(matches) == 1 else None


def _contract_node(
    source_unit: Mapping[str, Any], predicates: tuple[str, ...]
) -> Mapping[str, Any] | None:
    contracts = [
        node
        for node in source_unit.get("nodes", ())
        if isinstance(node, Mapping) and node.get("nodeType") == "ContractDefinition"
    ]
    named = [item for item in contracts if item.get("name") == "Invariants"]
    if len(named) == 1:
        return named[0]

    required = set(predicates) | {"checkAll"}
    candidates: list[Mapping[str, Any]] = []
    for contract in contracts:
        names = {
            str(node.get("name"))
            for node in contract.get("nodes", ())
            if isinstance(node, Mapping)
            and node.get("nodeType") == "FunctionDefinition"
            and node.get("kind") == "function"
        }
        if required.issubset(names):
            candidates.append(contract)
    return candidates[0] if len(candidates) == 1 else None


def _literal_integer(node: object) -> int | None:
    if not isinstance(node, Mapping) or node.get("nodeType") != "Literal":
        return None
    value = node.get("value")
    if not isinstance(value, str):
        return None
    try:
        integer = int(value, 0)
    except ValueError:
        return None
    unit = node.get("subdenomination")
    if unit is None:
        return integer
    multiplier = _UNIT_MULTIPLIERS.get(str(unit))
    return integer * multiplier if multiplier is not None else None


def _constant_values(contract: Mapping[str, Any]) -> dict[int, int]:
    result: dict[int, int] = {}
    for node in contract.get("nodes", ()):
        if (
            not isinstance(node, Mapping)
            or node.get("nodeType") != "VariableDeclaration"
            or node.get("constant") is not True
            or not isinstance(node.get("id"), int)
        ):
            continue
        value = _literal_integer(node.get("value"))
        if value is not None:
            result[int(node["id"])] = value
    return result


def _functions(contract: Mapping[str, Any]) -> tuple[Mapping[str, Any], ...]:
    return tuple(
        node
        for node in contract.get("nodes", ())
        if isinstance(node, Mapping)
        and node.get("nodeType") == "FunctionDefinition"
        and node.get("kind") == "function"
    )


def _target_parameter(function: Mapping[str, Any]) -> tuple[int | None, int | None]:
    parameters = function.get("parameters")
    parameter_nodes = (
        tuple(parameters.get("parameters", ()))
        if isinstance(parameters, Mapping)
        else ()
    )
    named = [
        (index, item)
        for index, item in enumerate(parameter_nodes)
        if isinstance(item, Mapping)
        and item.get("name") == "target"
        and isinstance(item.get("id"), int)
    ]
    if len(named) == 1:
        index, node = named[0]
        return index, int(node["id"])

    address_parameters = [
        (index, item)
        for index, item in enumerate(parameter_nodes)
        if isinstance(item, Mapping)
        and _parameter_type(item) == "address"
        and isinstance(item.get("id"), int)
    ]
    if len(address_parameters) == 1:
        index, node = address_parameters[0]
        return index, int(node["id"])
    return None, None


def _is_target_identifier(node: object, target_declaration: int | None) -> bool:
    return (
        target_declaration is not None
        and isinstance(node, Mapping)
        and node.get("nodeType") == "Identifier"
        and node.get("referencedDeclaration") == target_declaration
    )


def _is_target_balance(node: object, target_declaration: int | None) -> bool:
    return (
        isinstance(node, Mapping)
        and node.get("nodeType") == "MemberAccess"
        and node.get("memberName") == "balance"
        and _is_target_identifier(node.get("expression"), target_declaration)
    )


def _referenced_constants(
    body: object, constant_values: Mapping[int, int]
) -> tuple[int, ...]:
    values = {
        constant_values[declaration]
        for node in _walk(body)
        if node.get("nodeType") == "Identifier"
        and isinstance((declaration := node.get("referencedDeclaration")), int)
        and declaration in constant_values
    }
    return tuple(sorted(values))


def _target_calls(body: object, target_declaration: int | None) -> tuple[str, ...]:
    members: set[str] = set()
    for node in _walk(body):
        if node.get("nodeType") != "FunctionCall":
            continue
        expression = node.get("expression")
        if (
            isinstance(expression, Mapping)
            and expression.get("nodeType") == "MemberAccess"
            and _is_target_identifier(expression.get("expression"), target_declaration)
            and isinstance(expression.get("memberName"), str)
        ):
            members.add(str(expression["memberName"]))
    return tuple(sorted(members))


def _operand_kind(
    node: object,
    *,
    target_declaration: int | None,
    constant_values: Mapping[int, int],
) -> str | None:
    if _is_target_balance(node, target_declaration):
        return "target.balance"
    if isinstance(node, Mapping):
        if node.get("nodeType") == "Identifier":
            declaration = node.get("referencedDeclaration")
            if isinstance(declaration, int) and declaration in constant_values:
                return "constant"
        if _literal_integer(node) is not None:
            return "constant"
    return None


def _comparison_hints(
    body: object,
    *,
    target_declaration: int | None,
    constant_values: Mapping[int, int],
) -> tuple[tuple[str, str, str], ...]:
    hints: set[tuple[str, str, str]] = set()
    for node in _walk(body):
        if node.get("nodeType") != "BinaryOperation":
            continue
        operator = node.get("operator")
        if operator not in _COMPARISON_OPERATORS:
            continue
        left = _operand_kind(
            node.get("leftExpression"),
            target_declaration=target_declaration,
            constant_values=constant_values,
        )
        right = _operand_kind(
            node.get("rightExpression"),
            target_declaration=target_declaration,
            constant_values=constant_values,
        )
        if left is not None and right is not None:
            hints.add((str(operator), left, right))
    return tuple(sorted(hints))


def _bound_predicate_ids(functions: Sequence[Mapping[str, Any]]) -> frozenset[int]:
    check_all = [item for item in functions if item.get("name") == "checkAll"]
    if len(check_all) != 1:
        return frozenset()
    identifiers: set[int] = set()
    for node in _walk(check_all[0].get("body")):
        if node.get("nodeType") != "FunctionCall":
            continue
        expression = node.get("expression")
        declaration: object | None = None
        if isinstance(expression, Mapping) and expression.get("nodeType") in {
            "Identifier",
            "MemberAccess",
        }:
            declaration = expression.get("referencedDeclaration")
        if isinstance(declaration, int):
            identifiers.add(declaration)
    return frozenset(identifiers)


def extract_property_analysis(
    source_units: Sequence[object],
    *,
    invariants_source_name: str,
    predicates: Sequence[str],
) -> PropertyAnalysis:
    """Extract conservative search-only property facts from compiler ASTs."""

    predicate_names = tuple(str(item) for item in predicates)
    source_unit = _source_unit(source_units, invariants_source_name)
    if source_unit is None:
        return PropertyAnalysis(invariants_source_name, None, tuple())
    contract = _contract_node(source_unit, predicate_names)
    if contract is None:
        return PropertyAnalysis(invariants_source_name, None, tuple())

    functions = _functions(contract)
    by_name: dict[str, list[Mapping[str, Any]]] = {}
    for function in functions:
        by_name.setdefault(str(function.get("name")), []).append(function)
    constants = _constant_values(contract)
    bound_ids = _bound_predicate_ids(functions)
    contract_name = str(contract.get("name"))

    facts: list[PropertyFact] = []
    for predicate_name in predicate_names:
        matches = by_name.get(predicate_name, [])
        if len(matches) != 1:
            facts.append(
                PropertyFact(
                    predicate_name=predicate_name,
                    function_id=None,
                    target_parameter_index=None,
                    target_balance_read=False,
                    target_calls=(),
                    constants=(),
                    comparison_hints=(),
                    source_span=None,
                    bound_from_check_all=False,
                    known=False,
                )
            )
            continue

        function = matches[0]
        function_declaration = function.get("id")
        target_index, target_declaration = _target_parameter(function)
        body = function.get("body")
        balance_read = any(
            _is_target_balance(node, target_declaration) for node in _walk(body)
        )
        target_calls = _target_calls(body, target_declaration)
        referenced_constants = _referenced_constants(body, constants)
        comparison_hints = _comparison_hints(
            body,
            target_declaration=target_declaration,
            constant_values=constants,
        )
        bound = (
            isinstance(function_declaration, int) and function_declaration in bound_ids
        )
        semantics_known = balance_read or bool(target_calls)
        function_id = (
            f"function:{invariants_source_name}:{contract_name}:"
            f"{function_declaration}:{_signature(function)}"
            if isinstance(function_declaration, int)
            else None
        )
        facts.append(
            PropertyFact(
                predicate_name=predicate_name,
                function_id=function_id,
                target_parameter_index=target_index,
                target_balance_read=balance_read,
                target_calls=target_calls,
                constants=referenced_constants,
                comparison_hints=comparison_hints,
                source_span=(
                    str(function.get("src"))
                    if isinstance(function.get("src"), str)
                    else None
                ),
                bound_from_check_all=bound,
                known=bound and target_index is not None and semantics_known,
            )
        )

    return PropertyAnalysis(
        invariants_source_name=invariants_source_name,
        contract_name=contract_name,
        facts=tuple(facts),
    )
