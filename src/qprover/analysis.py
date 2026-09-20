"""Conservative semantic fact extraction from Solidity compact ASTs."""

from __future__ import annotations

import dataclasses
import json
from collections.abc import Iterable, Iterator, Mapping
from dataclasses import dataclass, replace
from typing import Any

from qprover.artifacts import ArtifactBundle

_SUBDENOMINATION_MULTIPLIERS = {
    "wei": 1,
    "gwei": 10**9,
    "ether": 10**18,
    "seconds": 1,
    "minutes": 60,
    "hours": 60 * 60,
    "days": 24 * 60 * 60,
    "weeks": 7 * 24 * 60 * 60,
}

_ORACLE_MEMBERS = {
    "getprice",
    "latestanswer",
    "latestrounddata",
    "getreserves",
    "price",
}
_TOKEN_MEMBERS = {
    "approve",
    "burn",
    "mint",
    "safetransferfrom",
    "transfer",
    "transferfrom",
}


def _src_start(source_span: str) -> int:
    try:
        return int(source_span.split(":", maxsplit=1)[0])
    except (TypeError, ValueError):
        return -1


def _known_before(first_span: str, second_span: str) -> bool:
    first = _src_start(first_span)
    second = _src_start(second_span)
    return first >= 0 and second >= 0 and first < second


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
    type_string = description.get("typeString", "unknown") if description else "unknown"
    if type_string.startswith(("contract ", "interface ")):
        return "address"
    if type_string == "address payable":
        return "address"
    return (
        type_string.replace(" memory", "")
        .replace(" calldata", "")
        .replace(" storage", "")
    )


def _signature(node: Mapping[str, Any]) -> str:
    name = node.get("name") or "<anonymous>"
    parameters = node.get("parameters", {}).get("parameters", ())
    return f"{name}({','.join(_parameter_type(item) for item in parameters)})"


def _parameter_records(node: Mapping[str, Any], field: str) -> tuple[str, ...]:
    parameters = node.get(field, {}).get("parameters", ())
    return tuple(_parameter_type(item) for item in parameters)


def _contract_id(source_name: str, name: str, declaration_id: int) -> str:
    return f"contract:{source_name}:{name}:{declaration_id}"


def _storage_id(
    source_name: str, contract_name: str, declaration_id: int, name: str
) -> str:
    return f"storage:{source_name}:{contract_name}:{declaration_id}:{name}"


def _function_id(
    source_name: str,
    contract_name: str,
    declaration_id: int,
    signature: str,
) -> str:
    return f"function:{source_name}:{contract_name}:{declaration_id}:{signature}"


@dataclass(frozen=True, slots=True)
class StorageFacts:
    source_name: str
    contract: str
    canonical_id: str
    name: str
    declaration_id: int
    type_name: str
    slot: str | None
    offset: int | None
    source_span: str


@dataclass(frozen=True, slots=True)
class CallFact:
    kind: str
    member_name: str
    callee_contract: str | None
    callee_signature: str | None
    callee_id: str | None
    receiver_type: str | None
    ast_id: int
    source_span: str
    receiver_name: str | None = None
    receiver_declaration: int | None = None


@dataclass(frozen=True, slots=True)
class ValueFlowFact:
    asset: str
    operation: str
    direction: str
    ast_id: int
    source_span: str


@dataclass(frozen=True, slots=True)
class OrderedCallWriteFact:
    call_ast_id: int
    call_member_name: str
    call_source_span: str
    storage_id: str
    write_source_span: str


@dataclass(frozen=True, slots=True)
class ParameterConstraintFact:
    parameter_index: int
    operator: str
    constant: int
    source_span: str


@dataclass(frozen=True, slots=True)
class StorageGuardFact:
    storage_id: str
    operator: str
    constant: int
    source_span: str


@dataclass(frozen=True, slots=True)
class StorageAssignmentFact:
    storage_id: str
    constant: int
    source_span: str


@dataclass(frozen=True, slots=True)
class ParameterExpressionFact:
    parameter_index: int
    operator: str
    source_kind: str
    source_id: str
    offset: int
    source_span: str


@dataclass(frozen=True, slots=True)
class FunctionFacts:
    source_name: str
    contract: str
    canonical_name: str
    canonical_id: str
    signature: str
    declaration_id: int
    function_selector: str | None
    visibility: str
    state_mutability: str
    modifiers: tuple[str, ...]
    parameters: tuple[str, ...]
    returns: tuple[str, ...]
    source_span: str
    storage_reads: tuple[str, ...]
    storage_writes: tuple[str, ...]
    calls: tuple[CallFact, ...]
    value_flows: tuple[ValueFlowFact, ...]
    role_guards: tuple[str, ...]
    oracle_calls: tuple[str, ...]
    ordered_call_writes: tuple[OrderedCallWriteFact, ...]
    external_call_before_write: bool
    transitive_storage_reads: tuple[str, ...]
    transitive_storage_writes: tuple[str, ...]
    transitive_calls: tuple[str, ...]
    parameter_constraints: tuple[ParameterConstraintFact, ...] = ()
    storage_guards: tuple[StorageGuardFact, ...] = ()
    storage_assignments: tuple[StorageAssignmentFact, ...] = ()
    parameter_expressions: tuple[ParameterExpressionFact, ...] = ()
    parameter_declarations: tuple[int, ...] = ()
    comparison_constants: tuple[int, ...] = ()


@dataclass(frozen=True, slots=True)
class ContractFacts:
    source_name: str
    name: str
    canonical_name: str
    canonical_id: str
    declaration_id: int
    kind: str
    source_span: str
    linearized_base_contracts: tuple[str, ...]
    abi_signatures: tuple[str, ...]
    abi_function_selectors: tuple[tuple[str, str | None], ...]
    storage: tuple[StorageFacts, ...]
    functions: tuple[FunctionFacts, ...]


@dataclass(frozen=True, slots=True)
class AnalysisReport:
    source_sha256: str
    artifact_sha256: tuple[str, ...]
    contracts: tuple[ContractFacts, ...]

    def contract(self, *identity: str) -> ContractFacts:
        if len(identity) == 1:
            source_name = None
            name = identity[0]
        elif len(identity) == 2:
            source_name, name = identity
        else:
            raise TypeError("contract expects name or source_name, name")
        matches = [
            item
            for item in self.contracts
            if item.name == name
            and (source_name is None or item.source_name == source_name)
        ]
        if len(matches) != 1:
            raise KeyError(f"contract not found or ambiguous: {identity}")
        return matches[0]

    def function(self, *identity: str) -> FunctionFacts:
        if len(identity) == 2:
            contract_name, signature = identity
            contract = self.contract(contract_name)
        elif len(identity) == 3:
            source_name, contract_name, signature = identity
            contract = self.contract(source_name, contract_name)
        else:
            raise TypeError(
                "function expects contract, signature or source, contract, signature"
            )
        matches = [item for item in contract.functions if item.signature == signature]
        if len(matches) != 1:
            raise KeyError(f"function not found or ambiguous: {identity}")
        return matches[0]

    def storage(self, source: str, contract: str, name: str) -> StorageFacts:
        matches = [
            item
            for item in self.contract(source, contract).storage
            if item.name == name
        ]
        if len(matches) != 1:
            raise KeyError(
                f"storage not found or ambiguous: {source}:{contract}:{name}"
            )
        return matches[0]

    def to_json(self) -> str:
        return json.dumps(
            dataclasses.asdict(self), sort_keys=True, separators=(",", ":")
        )


@dataclass(frozen=True, slots=True)
class _ContractIdentity:
    source_name: str
    name: str
    declaration_id: int

    @property
    def canonical_id(self) -> str:
        return _contract_id(self.source_name, self.name, self.declaration_id)


def _state_identifiers(
    value: object, state_facts: Mapping[int, StorageFacts]
) -> Iterator[Mapping[str, Any]]:
    for node in _walk(value):
        declaration = node.get("referencedDeclaration")
        if node.get("nodeType") == "Identifier" and declaration in state_facts:
            yield node


def _call_expression(node: Mapping[str, Any]) -> Mapping[str, Any] | None:
    expression = node.get("expression")
    if not isinstance(expression, Mapping):
        return None
    if expression.get("nodeType") == "FunctionCallOptions":
        nested = expression.get("expression")
        return nested if isinstance(nested, Mapping) else None
    return expression


def _receiver_type(expression: Mapping[str, Any]) -> str | None:
    receiver = expression.get("expression")
    if not isinstance(receiver, Mapping):
        return None
    descriptions = receiver.get("typeDescriptions")
    value = (
        descriptions.get("typeString") if isinstance(descriptions, Mapping) else None
    )
    return value if isinstance(value, str) else None


def _call_fact(
    node: Mapping[str, Any],
    declarations: Mapping[int, Mapping[str, Any]],
    function_identities: Mapping[int, tuple[_ContractIdentity, str, str]],
    contract_identities: Mapping[int, _ContractIdentity],
) -> CallFact | None:
    if node.get("kind") == "typeConversion":
        return None
    expression = _call_expression(node)
    if expression is None:
        return CallFact(
            "unknown",
            "<unknown>",
            None,
            None,
            None,
            None,
            int(node.get("id", -1)),
            str(node.get("src", "unknown")),
        )

    if expression.get("nodeType") == "NewExpression":
        type_name = expression.get("typeName")
        reference = (
            type_name.get("referencedDeclaration")
            if isinstance(type_name, Mapping)
            else None
        )
        target = (
            contract_identities.get(reference) if isinstance(reference, int) else None
        )
        return CallFact(
            kind="creation",
            member_name="new",
            callee_contract=target.name if target else None,
            callee_signature=None,
            callee_id=target.canonical_id if target else None,
            receiver_type=None,
            ast_id=int(node.get("id", -1)),
            source_span=str(node.get("src", "unknown")),
        )

    if expression.get("nodeType") == "MemberAccess":
        member_name = str(expression.get("memberName", "<unknown>"))
        receiver_type = _receiver_type(expression)
        receiver = expression.get("expression")
        receiver_name = (
            str(receiver.get("name"))
            if isinstance(receiver, Mapping) and isinstance(receiver.get("name"), str)
            else None
        )
        receiver_reference = (
            receiver.get("referencedDeclaration")
            if isinstance(receiver, Mapping)
            else None
        )
        receiver_declaration = (
            receiver_reference if isinstance(receiver_reference, int) else None
        )
    else:
        member_name = str(expression.get("name", "<unknown>"))
        receiver_type = None
        receiver_name = None
        receiver_declaration = None
    reference = expression.get("referencedDeclaration")
    target = function_identities.get(reference) if isinstance(reference, int) else None
    if target:
        target_contract, callee_signature, callee_id = target
        callee_contract = target_contract.name
    else:
        callee_signature = None
        callee_id = None
        callee_contract = None

    native_receiver = receiver_type in {"address", "address payable"}
    if member_name in {"require", "assert"}:
        kind = "builtin"
    elif (
        member_name in {"call", "delegatecall", "send", "transfer"} and native_receiver
    ) or member_name == "selfdestruct":
        kind = "low_level"
    elif expression.get("nodeType") == "MemberAccess":
        kind = "external" if callee_signature is not None else "unknown"
    elif callee_signature is not None:
        kind = "internal"
    else:
        kind = "unknown"
    return CallFact(
        kind=kind,
        member_name=member_name,
        callee_contract=callee_contract,
        callee_signature=callee_signature,
        callee_id=callee_id,
        receiver_type=receiver_type,
        ast_id=int(node.get("id", -1)),
        source_span=str(node.get("src", "unknown")),
        receiver_name=receiver_name,
        receiver_declaration=receiver_declaration,
    )


def _has_msg_sender(value: object) -> bool:
    return any(
        node.get("nodeType") == "MemberAccess"
        and node.get("memberName") == "sender"
        and isinstance(node.get("expression"), Mapping)
        and node["expression"].get("name") == "msg"
        for node in _walk(value)
    )


def _value_flow(
    call: CallFact, declarations: Mapping[int, Mapping[str, Any]]
) -> ValueFlowFact | None:
    if call.kind == "low_level":
        if call.member_name in {"send", "transfer", "selfdestruct"}:
            return ValueFlowFact(
                "native", call.member_name, "out", call.ast_id, call.source_span
            )
        if call.member_name == "call":
            call_node = declarations.get(call.ast_id)
            expression = call_node.get("expression") if call_node else None
            names = (
                expression.get("names", ()) if isinstance(expression, Mapping) else ()
            )
            if "value" in names:
                return ValueFlowFact(
                    "native", "call", "out", call.ast_id, call.source_span
                )
    if call.kind == "external" and call.member_name.lower() in _TOKEN_MEMBERS:
        operation = call.member_name
        if operation.lower() == "approve":
            direction = "approval"
        elif operation.lower() in {"mint", "burn", "transferfrom"}:
            direction = "unknown"
        else:
            direction = "out"
        return ValueFlowFact(
            "token", operation, direction, call.ast_id, call.source_span
        )
    return None


def _literal_integer(
    node: object,
    declarations: Mapping[int, Mapping[str, Any]],
) -> int | None:
    if not isinstance(node, Mapping):
        return None
    if node.get("nodeType") == "Literal":
        value = node.get("value")
        if isinstance(value, str):
            cleaned = value.replace("_", "")
            try:
                parsed = int(cleaned, 0)
            except ValueError:
                try:
                    parsed = int(cleaned, 10)
                except ValueError:
                    return None
            denomination = node.get("subdenomination")
            if denomination is None:
                return parsed
            multiplier = _SUBDENOMINATION_MULTIPLIERS.get(str(denomination))
            return parsed * multiplier if multiplier is not None else None
    if node.get("nodeType") == "FunctionCall" and node.get("kind") == "typeConversion":
        arguments = tuple(node.get("arguments", ()))
        if len(arguments) == 1:
            return _literal_integer(arguments[0], declarations)
    if node.get("nodeType") == "UnaryOperation" and node.get("operator") == "-":
        nested = _literal_integer(node.get("subExpression"), declarations)
        return -nested if nested is not None else None
    if node.get("nodeType") == "BinaryOperation":
        left = _literal_integer(node.get("leftExpression"), declarations)
        right = _literal_integer(node.get("rightExpression"), declarations)
        if left is None or right is None:
            return None
        operator = node.get("operator")
        if operator == "+":
            return left + right
        if operator == "-":
            return left - right
        if operator == "*":
            return left * right
        if operator == "/" and right != 0:
            return left // right
    if node.get("nodeType") == "Identifier":
        reference = node.get("referencedDeclaration")
        declaration = (
            declarations.get(reference) if isinstance(reference, int) else None
        )
        if (
            isinstance(declaration, Mapping)
            and declaration.get("nodeType") == "VariableDeclaration"
            and declaration.get("constant") is True
        ):
            return _literal_integer(declaration.get("value"), declarations)
    return None


def _parameter_constraint_facts(
    node: Mapping[str, Any],
    declarations: Mapping[int, Mapping[str, Any]],
) -> tuple[ParameterConstraintFact, ...]:
    parameters = tuple(node.get("parameters", {}).get("parameters", ()))
    parameter_ids = {
        item.get("id"): index
        for index, item in enumerate(parameters)
        if isinstance(item, Mapping) and isinstance(item.get("id"), int)
    }
    reverse_operator = {
        "<": ">",
        "<=": ">=",
        ">": "<",
        ">=": "<=",
        "==": "==",
        "!=": "!=",
    }
    facts: list[ParameterConstraintFact] = []
    for candidate in _walk(node.get("body")):
        if candidate.get("nodeType") != "FunctionCall":
            continue
        expression = _call_expression(candidate)
        if not expression or expression.get("name") not in {"require", "assert"}:
            continue
        arguments = candidate.get("arguments", ())
        if not isinstance(arguments, (tuple, list)) or not arguments:
            continue
        for condition in _walk(arguments[0]):
            if (
                condition.get("nodeType") != "BinaryOperation"
                or condition.get("operator") not in reverse_operator
            ):
                continue
            operator = str(condition["operator"])
            left = condition.get("leftExpression")
            right = condition.get("rightExpression")

            left_ref = (
                left.get("referencedDeclaration")
                if isinstance(left, Mapping) and left.get("nodeType") == "Identifier"
                else None
            )
            right_ref = (
                right.get("referencedDeclaration")
                if isinstance(right, Mapping) and right.get("nodeType") == "Identifier"
                else None
            )
            if left_ref in parameter_ids:
                constant = _literal_integer(right, declarations)
                parameter_index = parameter_ids[left_ref]
                normalized = operator
            elif right_ref in parameter_ids:
                constant = _literal_integer(left, declarations)
                parameter_index = parameter_ids[right_ref]
                normalized = reverse_operator[operator]
            else:
                continue
            if constant is None:
                continue
            facts.append(
                ParameterConstraintFact(
                    parameter_index=parameter_index,
                    operator=normalized,
                    constant=constant,
                    source_span=str(condition.get("src", "unknown")),
                )
            )
    return tuple(
        sorted(
            set(facts),
            key=lambda item: (
                item.parameter_index,
                item.operator,
                item.constant,
                item.source_span,
            ),
        )
    )


def _storage_reference(
    node: object,
    state_facts: Mapping[int, StorageFacts],
) -> str | None:
    if not isinstance(node, Mapping) or node.get("nodeType") != "Identifier":
        return None
    reference = node.get("referencedDeclaration")
    storage = state_facts.get(reference) if isinstance(reference, int) else None
    return storage.canonical_id if storage is not None else None


def _storage_guard_facts(
    node: Mapping[str, Any],
    declarations: Mapping[int, Mapping[str, Any]],
    state_facts: Mapping[int, StorageFacts],
) -> tuple[StorageGuardFact, ...]:
    reverse_operator = {
        "<": ">",
        "<=": ">=",
        ">": "<",
        ">=": "<=",
        "==": "==",
        "!=": "!=",
    }
    facts: set[StorageGuardFact] = set()
    for candidate in _walk(node.get("body")):
        if candidate.get("nodeType") != "FunctionCall":
            continue
        expression = _call_expression(candidate)
        if not expression or expression.get("name") not in {"require", "assert"}:
            continue
        arguments = candidate.get("arguments", ())
        if not isinstance(arguments, (tuple, list)) or not arguments:
            continue
        for condition in _walk(arguments[0]):
            if (
                condition.get("nodeType") != "BinaryOperation"
                or condition.get("operator") not in reverse_operator
            ):
                continue
            operator = str(condition["operator"])
            left = condition.get("leftExpression")
            right = condition.get("rightExpression")
            left_storage = _storage_reference(left, state_facts)
            right_storage = _storage_reference(right, state_facts)
            if left_storage is not None:
                storage_id = left_storage
                constant = _literal_integer(right, declarations)
                normalized = operator
            elif right_storage is not None:
                storage_id = right_storage
                constant = _literal_integer(left, declarations)
                normalized = reverse_operator[operator]
            else:
                continue
            if constant is None:
                continue
            facts.add(
                StorageGuardFact(
                    storage_id=storage_id,
                    operator=normalized,
                    constant=constant,
                    source_span=str(condition.get("src", "unknown")),
                )
            )
    return tuple(
        sorted(
            facts,
            key=lambda item: (
                item.storage_id,
                item.operator,
                item.constant,
                item.source_span,
            ),
        )
    )


def _storage_assignment_facts(
    node: Mapping[str, Any],
    declarations: Mapping[int, Mapping[str, Any]],
    state_facts: Mapping[int, StorageFacts],
) -> tuple[StorageAssignmentFact, ...]:
    facts: set[StorageAssignmentFact] = set()
    for candidate in _walk(node.get("body")):
        if (
            candidate.get("nodeType") != "Assignment"
            or candidate.get("operator") != "="
        ):
            continue
        storage_id = _storage_reference(candidate.get("leftHandSide"), state_facts)
        constant = _literal_integer(candidate.get("rightHandSide"), declarations)
        if storage_id is None or constant is None:
            continue
        facts.add(
            StorageAssignmentFact(
                storage_id=storage_id,
                constant=constant,
                source_span=str(candidate.get("src", "unknown")),
            )
        )
    return tuple(
        sorted(
            facts,
            key=lambda item: (item.storage_id, item.constant, item.source_span),
        )
    )


def _parameter_affine(
    node: object,
    parameter_ids: Mapping[int, int],
    declarations: Mapping[int, Mapping[str, Any]],
) -> tuple[int, int] | None:
    if not isinstance(node, Mapping):
        return None
    if node.get("nodeType") == "Identifier":
        reference = node.get("referencedDeclaration")
        if reference in parameter_ids:
            return parameter_ids[reference], 0
        return None
    if node.get("nodeType") != "BinaryOperation" or node.get("operator") not in {
        "+",
        "-",
    }:
        return None
    left = _parameter_affine(node.get("leftExpression"), parameter_ids, declarations)
    right_constant = _literal_integer(node.get("rightExpression"), declarations)
    if left is not None and right_constant is not None:
        index, offset = left
        return index, offset + (
            right_constant if node.get("operator") == "+" else -right_constant
        )
    if node.get("operator") == "+":
        right = _parameter_affine(
            node.get("rightExpression"), parameter_ids, declarations
        )
        left_constant = _literal_integer(node.get("leftExpression"), declarations)
        if right is not None and left_constant is not None:
            return right[0], right[1] + left_constant
    return None


def _context_source_affine(
    node: object,
    declarations: Mapping[int, Mapping[str, Any]],
    function_identities: Mapping[int, tuple[_ContractIdentity, str, str]],
    state_facts: Mapping[int, StorageFacts],
) -> tuple[str, str, int] | None:
    storage_id = _storage_reference(node, state_facts)
    if storage_id is not None:
        return "storage", storage_id, 0
    nested_storage = {
        state_facts[item["referencedDeclaration"]].canonical_id
        for item in _state_identifiers(node, state_facts)
    }
    if len(nested_storage) == 1:
        return "storage", next(iter(nested_storage)), 0
    if isinstance(node, Mapping) and node.get("nodeType") == "FunctionCall":
        arguments = node.get("arguments", ())
        expression = _call_expression(node)
        reference = expression.get("referencedDeclaration") if expression else None
        function = (
            function_identities.get(reference) if isinstance(reference, int) else None
        )
        if function is not None and not arguments:
            return "function", function[2], 0
    if (
        not isinstance(node, Mapping)
        or node.get("nodeType") != "BinaryOperation"
        or node.get("operator") not in {"+", "-"}
    ):
        return None
    left = _context_source_affine(
        node.get("leftExpression"), declarations, function_identities, state_facts
    )
    right_constant = _literal_integer(node.get("rightExpression"), declarations)
    if left is not None and right_constant is not None:
        kind, source_id, offset = left
        return (
            kind,
            source_id,
            offset
            + (right_constant if node.get("operator") == "+" else -right_constant),
        )
    if node.get("operator") == "+":
        right = _context_source_affine(
            node.get("rightExpression"), declarations, function_identities, state_facts
        )
        left_constant = _literal_integer(node.get("leftExpression"), declarations)
        if right is not None and left_constant is not None:
            return right[0], right[1], right[2] + left_constant
    return None


def _parameter_expression_facts(
    node: Mapping[str, Any],
    declarations: Mapping[int, Mapping[str, Any]],
    function_identities: Mapping[int, tuple[_ContractIdentity, str, str]],
    state_facts: Mapping[int, StorageFacts],
) -> tuple[ParameterExpressionFact, ...]:
    parameters = tuple(node.get("parameters", {}).get("parameters", ()))
    parameter_ids = {
        int(item["id"]): index
        for index, item in enumerate(parameters)
        if isinstance(item, Mapping) and isinstance(item.get("id"), int)
    }
    reverse_operator = {
        "<": ">",
        "<=": ">=",
        ">": "<",
        ">=": "<=",
        "==": "==",
        "!=": "!=",
    }
    facts: set[ParameterExpressionFact] = set()
    for candidate in _walk(node.get("body")):
        if candidate.get("nodeType") != "FunctionCall":
            continue
        expression = _call_expression(candidate)
        if not expression or expression.get("name") not in {"require", "assert"}:
            continue
        arguments = candidate.get("arguments", ())
        if not isinstance(arguments, (tuple, list)) or not arguments:
            continue
        for condition in _walk(arguments[0]):
            if (
                condition.get("nodeType") != "BinaryOperation"
                or condition.get("operator") not in reverse_operator
            ):
                continue
            operator = str(condition["operator"])
            left_node = condition.get("leftExpression")
            right_node = condition.get("rightExpression")
            left_parameter = _parameter_affine(left_node, parameter_ids, declarations)
            right_parameter = _parameter_affine(right_node, parameter_ids, declarations)
            if left_parameter is not None:
                source = _context_source_affine(
                    right_node, declarations, function_identities, state_facts
                )
                normalized = operator
                parameter = left_parameter
            elif right_parameter is not None:
                source = _context_source_affine(
                    left_node, declarations, function_identities, state_facts
                )
                normalized = reverse_operator[operator]
                parameter = right_parameter
            else:
                continue
            if source is None:
                continue
            parameter_index, parameter_offset = parameter
            source_kind, source_id, source_offset = source
            facts.add(
                ParameterExpressionFact(
                    parameter_index=parameter_index,
                    operator=normalized,
                    source_kind=source_kind,
                    source_id=source_id,
                    offset=source_offset - parameter_offset,
                    source_span=str(condition.get("src", "unknown")),
                )
            )
    return tuple(
        sorted(
            facts,
            key=lambda item: (
                item.parameter_index,
                item.operator,
                item.source_kind,
                item.source_id,
                item.offset,
                item.source_span,
            ),
        )
    )


def _comparison_constants(
    node: Mapping[str, Any],
    declarations: Mapping[int, Mapping[str, Any]],
) -> tuple[int, ...]:
    values: set[int] = set()
    comparison_operators = {"<", "<=", ">", ">=", "==", "!="}
    for candidate in _walk(node.get("body")):
        if (
            candidate.get("nodeType") != "BinaryOperation"
            or candidate.get("operator") not in comparison_operators
        ):
            continue
        for expression in _walk(candidate):
            value = _literal_integer(expression, declarations)
            if value is not None:
                values.add(value)
    return tuple(sorted(values))


def _extract_function(
    source_name: str,
    contract: _ContractIdentity,
    node: Mapping[str, Any],
    declarations: Mapping[int, Mapping[str, Any]],
    function_identities: Mapping[int, tuple[_ContractIdentity, str, str]],
    contract_identities: Mapping[int, _ContractIdentity],
    state_facts: Mapping[int, StorageFacts],
) -> FunctionFacts:
    body = node.get("body")
    write_occurrences: set[int] = set()
    write_ids: set[str] = set()
    compound_reads: set[str] = set()
    write_events: list[tuple[str, str]] = []
    for candidate in _walk(body):
        target: object | None = None
        compound = False
        if candidate.get("nodeType") == "Assignment":
            target = candidate.get("leftHandSide")
            compound = candidate.get("operator") != "="
        elif candidate.get("nodeType") == "UnaryOperation" and candidate.get(
            "operator"
        ) in {"++", "--", "delete"}:
            target = candidate.get("subExpression")
            compound = candidate.get("operator") != "delete"
        if target is None:
            continue
        identifiers = tuple(_state_identifiers(target, state_facts))
        for identifier in identifiers:
            write_occurrences.add(int(identifier.get("id", -1)))
            storage = state_facts[identifier["referencedDeclaration"]]
            write_ids.add(storage.canonical_id)
            write_events.append(
                (storage.canonical_id, str(candidate.get("src", "unknown")))
            )
            if compound:
                compound_reads.add(storage.canonical_id)

    read_ids = set(compound_reads)
    for identifier in _state_identifiers(body, state_facts):
        if int(identifier.get("id", -1)) not in write_occurrences:
            read_ids.add(state_facts[identifier["referencedDeclaration"]].canonical_id)

    calls = tuple(
        sorted(
            filter(
                None,
                (
                    _call_fact(
                        item,
                        declarations,
                        function_identities,
                        contract_identities,
                    )
                    for item in _walk(body)
                    if item.get("nodeType") == "FunctionCall"
                ),
            ),
            key=lambda item: (_src_start(item.source_span), item.ast_id),
        )
    )
    value_flows = tuple(
        flow
        for flow in (_value_flow(call, declarations) for call in calls)
        if flow is not None
    )
    role_guards: set[str] = set()
    for candidate in _walk(body):
        if candidate.get("nodeType") != "FunctionCall":
            continue
        expression = _call_expression(candidate)
        if not expression or expression.get("name") not in {"require", "assert"}:
            continue
        arguments = candidate.get("arguments", ())
        if _has_msg_sender(arguments):
            role_guards.update(
                state_facts[item["referencedDeclaration"]].canonical_id
                for item in _state_identifiers(arguments, state_facts)
            )

    external_calls = [call for call in calls if call.kind in {"external", "low_level"}]
    ordered_call_writes = tuple(
        sorted(
            (
                OrderedCallWriteFact(
                    call.ast_id,
                    call.member_name,
                    call.source_span,
                    storage_id,
                    write_span,
                )
                for call in external_calls
                for storage_id, write_span in write_events
                if _known_before(call.source_span, write_span)
            ),
            key=lambda item: (
                _src_start(item.call_source_span),
                _src_start(item.write_source_span),
                item.storage_id,
            ),
        )
    )
    modifiers = tuple(
        sorted(
            str(modifier.get("modifierName", {}).get("name", "<unknown>"))
            for modifier in node.get("modifiers", ())
        )
    )
    oracle_calls = tuple(
        sorted(
            {
                call.member_name
                for call in calls
                if call.member_name.lower() in _ORACLE_MEMBERS
                or "price" in call.member_name.lower()
                or "reserve" in call.member_name.lower()
            }
        )
    )
    signature = _signature(node)
    canonical_id = _function_id(source_name, contract.name, int(node["id"]), signature)
    return FunctionFacts(
        source_name=source_name,
        contract=contract.name,
        canonical_name=f"{source_name}:{contract.name}.{signature}",
        canonical_id=canonical_id,
        signature=signature,
        declaration_id=int(node["id"]),
        function_selector=(
            str(node["functionSelector"]).lower()
            if node.get("visibility") in {"public", "external"}
            and isinstance(node.get("functionSelector"), str)
            else None
        ),
        visibility=str(node.get("visibility", "unknown")),
        state_mutability=str(node.get("stateMutability", "unknown")),
        modifiers=modifiers,
        parameters=_parameter_records(node, "parameters"),
        returns=_parameter_records(node, "returnParameters"),
        source_span=str(node.get("src", "unknown")),
        storage_reads=tuple(sorted(read_ids)),
        storage_writes=tuple(sorted(write_ids)),
        calls=calls,
        value_flows=value_flows,
        role_guards=tuple(sorted(role_guards)),
        oracle_calls=oracle_calls,
        ordered_call_writes=ordered_call_writes,
        external_call_before_write=bool(ordered_call_writes),
        transitive_storage_reads=tuple(sorted(read_ids)),
        transitive_storage_writes=tuple(sorted(write_ids)),
        transitive_calls=(),
        parameter_constraints=_parameter_constraint_facts(node, declarations),
        storage_guards=_storage_guard_facts(node, declarations, state_facts),
        storage_assignments=_storage_assignment_facts(node, declarations, state_facts),
        parameter_expressions=_parameter_expression_facts(
            node,
            declarations,
            function_identities,
            state_facts,
        ),
        parameter_declarations=tuple(
            int(item["id"])
            for item in node.get("parameters", {}).get("parameters", ())
            if isinstance(item, Mapping) and isinstance(item.get("id"), int)
        ),
        comparison_constants=_comparison_constants(node, declarations),
    )


def _with_transitive(functions: Iterable[FunctionFacts]) -> dict[str, FunctionFacts]:
    by_id = {function.canonical_id: function for function in functions}
    reads = {key: set(value.storage_reads) for key, value in by_id.items()}
    writes = {key: set(value.storage_writes) for key, value in by_id.items()}
    reached = {key: set() for key in by_id}
    direct = {
        key: {
            call.callee_id
            for call in function.calls
            if call.kind == "internal" and call.callee_id in by_id
        }
        for key, function in by_id.items()
    }
    changed = True
    while changed:
        changed = False
        for function_id in sorted(by_id):
            previous = (
                set(reads[function_id]),
                set(writes[function_id]),
                set(reached[function_id]),
            )
            for target in direct[function_id] | reached[function_id]:
                reads[function_id].update(reads[target])
                writes[function_id].update(writes[target])
                reached[function_id].add(target)
                reached[function_id].update(reached[target])
            reached[function_id].discard(function_id)
            if previous != (
                reads[function_id],
                writes[function_id],
                reached[function_id],
            ):
                changed = True
    return {
        function_id: replace(
            function,
            transitive_storage_reads=tuple(sorted(reads[function_id])),
            transitive_storage_writes=tuple(sorted(writes[function_id])),
            transitive_calls=tuple(sorted(reached[function_id] | direct[function_id])),
        )
        for function_id, function in by_id.items()
    }


def _abi_type(parameter: Mapping[str, Any]) -> str:
    type_name = parameter.get("type")
    if not isinstance(type_name, str):
        return "unknown"
    if not type_name.startswith("tuple"):
        return type_name
    components = parameter.get("components")
    if not isinstance(components, (tuple, list)):
        return type_name
    suffix = type_name[len("tuple") :]
    return f"({','.join(_abi_type(item) for item in components)}){suffix}"


def _abi_signatures(abi: Iterable[Mapping[str, Any]]) -> tuple[str, ...]:
    signatures = set()
    for item in abi:
        if item.get("type") != "function" or not isinstance(item.get("name"), str):
            continue
        inputs = item.get("inputs", ())
        if not isinstance(inputs, (tuple, list)):
            continue
        signatures.add(
            f"{item['name']}({','.join(_abi_type(parameter) for parameter in inputs)})"
        )
    return tuple(sorted(signatures))


def analyze(bundle: ArtifactBundle) -> AnalysisReport:
    """Extract deterministic, source-qualified facts from the full compiler closure."""

    declarations: dict[int, Mapping[str, Any]] = {}
    declaration_sources: dict[int, str] = {}
    contract_nodes: list[tuple[str, Mapping[str, Any]]] = []
    for source_unit in bundle.source_units:
        for node in _walk(source_unit.ast):
            declaration_id = node.get("id")
            if isinstance(declaration_id, int):
                declarations[declaration_id] = node
                declaration_sources[declaration_id] = source_unit.source_name
        contract_nodes.extend(
            (source_unit.source_name, node)
            for node in source_unit.ast.get("nodes", ())
            if node.get("nodeType") == "ContractDefinition"
        )

    contract_identities = {
        int(node["id"]): _ContractIdentity(
            source_name, str(node["name"]), int(node["id"])
        )
        for source_name, node in contract_nodes
    }
    abi_by_artifact: dict[
        str, tuple[tuple[str, ...], tuple[tuple[str, str | None], ...]]
    ] = {}
    for artifact in bundle.artifacts:
        signatures = _abi_signatures(artifact.abi)
        method_identifiers = dict(artifact.method_identifiers)
        abi_by_artifact[artifact.compilation_target] = (
            signatures,
            tuple(
                (signature, method_identifiers.get(signature))
                for signature in signatures
            ),
        )
    function_identities: dict[int, tuple[_ContractIdentity, str, str]] = {}
    function_contract: dict[int, _ContractIdentity] = {}
    for _, contract_node in contract_nodes:
        contract = contract_identities[int(contract_node["id"])]
        for child in contract_node.get("nodes", ()):
            if (
                child.get("nodeType") != "FunctionDefinition"
                or child.get("kind") != "function"
            ):
                continue
            signature = _signature(child)
            canonical_id = _function_id(
                contract.source_name, contract.name, int(child["id"]), signature
            )
            function_identities[int(child["id"])] = (
                contract,
                signature,
                canonical_id,
            )
            function_contract[int(child["id"])] = contract

    layout_by_id: dict[int, Mapping[str, Any]] = {}
    for artifact in bundle.artifacts:
        for item in artifact.storage_layout.get("storage", ()):
            if isinstance(item, Mapping) and isinstance(item.get("astId"), int):
                layout_by_id[int(item["astId"])] = item

    state_facts: dict[int, StorageFacts] = {}
    for declaration_id, node in declarations.items():
        if (
            node.get("nodeType") != "VariableDeclaration"
            or node.get("stateVariable") is not True
        ):
            continue
        scope = node.get("scope")
        contract = contract_identities.get(scope) if isinstance(scope, int) else None
        if contract is None:
            continue
        layout = layout_by_id.get(declaration_id, {})
        description = node.get("typeDescriptions", {})
        name = str(node["name"])
        state_facts[declaration_id] = StorageFacts(
            source_name=contract.source_name,
            contract=contract.name,
            canonical_id=_storage_id(
                contract.source_name, contract.name, declaration_id, name
            ),
            name=name,
            declaration_id=declaration_id,
            type_name=str(description.get("typeString", "unknown")),
            slot=str(layout["slot"]) if "slot" in layout else None,
            offset=int(layout["offset"]) if "offset" in layout else None,
            source_span=str(node.get("src", "unknown")),
        )

    extracted: list[FunctionFacts] = []
    for declaration_id, (_, _, _) in function_identities.items():
        contract = function_contract[declaration_id]
        extracted.append(
            _extract_function(
                declaration_sources[declaration_id],
                contract,
                declarations[declaration_id],
                declarations,
                function_identities,
                contract_identities,
                state_facts,
            )
        )
    transitive = _with_transitive(extracted)

    contracts: list[ContractFacts] = []
    for source_name, node in contract_nodes:
        identity = contract_identities[int(node["id"])]
        functions = tuple(
            sorted(
                (
                    transitive[function_identities[int(child["id"])][2]]
                    for child in node.get("nodes", ())
                    if int(child.get("id", -1)) in function_identities
                ),
                key=lambda item: item.signature,
            )
        )
        storage = tuple(
            sorted(
                (
                    state_facts[int(child["id"])]
                    for child in node.get("nodes", ())
                    if int(child.get("id", -1)) in state_facts
                ),
                key=lambda item: item.name,
            )
        )
        abi_signatures, abi_function_selectors = abi_by_artifact.get(
            f"{source_name}:{identity.name}", ((), ())
        )
        contracts.append(
            ContractFacts(
                source_name=source_name,
                name=identity.name,
                canonical_name=(
                    f"{source_name}:{node.get('canonicalName', identity.name)}"
                ),
                canonical_id=identity.canonical_id,
                declaration_id=identity.declaration_id,
                kind=str(node.get("contractKind", "unknown")),
                source_span=str(node.get("src", "unknown")),
                linearized_base_contracts=tuple(
                    contract_identities[declaration_id].canonical_id
                    for declaration_id in node.get("linearizedBaseContracts", ())
                    if declaration_id in contract_identities
                ),
                abi_signatures=abi_signatures,
                abi_function_selectors=abi_function_selectors,
                storage=storage,
                functions=functions,
            )
        )
    return AnalysisReport(
        source_sha256=bundle.source_sha256,
        artifact_sha256=tuple(
            sorted(artifact.artifact_sha256 for artifact in bundle.artifacts)
        ),
        contracts=tuple(sorted(contracts, key=lambda item: item.canonical_id)),
    )
