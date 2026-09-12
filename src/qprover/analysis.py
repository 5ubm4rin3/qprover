"""Conservative semantic fact extraction from Solidity compact ASTs."""

from __future__ import annotations

import dataclasses
import json
from collections.abc import Iterable, Iterator, Mapping
from dataclasses import dataclass, replace
from typing import Any

from qprover.artifacts import ArtifactBundle

_LOW_LEVEL_MEMBERS = {
    "call",
    "delegatecall",
    "send",
    "transfer",
    "selfdestruct",
}
_ORACLE_MEMBERS = {
    "getprice",
    "latestanswer",
    "latestrounddata",
    "getreserves",
    "price",
}


def _src_start(source_span: str) -> int:
    try:
        return int(source_span.split(":", maxsplit=1)[0])
    except (TypeError, ValueError):
        return -1


def _walk(value: object) -> Iterator[Mapping[str, Any]]:
    if isinstance(value, Mapping):
        yield value
        for child in value.values():
            yield from _walk(child)
    elif isinstance(value, (tuple, list)):
        for child in value:
            yield from _walk(child)


def _state_identifiers(
    value: object, state_declarations: Mapping[int, Mapping[str, Any]]
) -> Iterator[Mapping[str, Any]]:
    for node in _walk(value):
        declaration = node.get("referencedDeclaration")
        if node.get("nodeType") == "Identifier" and declaration in state_declarations:
            yield node


def _parameter_type(parameter: Mapping[str, Any]) -> str:
    description = parameter.get("typeDescriptions")
    type_string = description.get("typeString", "unknown") if description else "unknown"
    if type_string.startswith("contract ") or type_string.startswith("interface "):
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


@dataclass(frozen=True, slots=True)
class StorageFacts:
    contract: str
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
    ast_id: int
    source_span: str


@dataclass(frozen=True, slots=True)
class ValueFlowFact:
    asset: str
    operation: str
    direction: str
    ast_id: int
    source_span: str


@dataclass(frozen=True, slots=True)
class FunctionFacts:
    contract: str
    canonical_name: str
    signature: str
    declaration_id: int
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
    external_call_before_write: bool
    transitive_storage_reads: tuple[str, ...]
    transitive_storage_writes: tuple[str, ...]
    transitive_calls: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ContractFacts:
    name: str
    canonical_name: str
    declaration_id: int
    kind: str
    source_span: str
    storage: tuple[StorageFacts, ...]
    functions: tuple[FunctionFacts, ...]


@dataclass(frozen=True, slots=True)
class AnalysisReport:
    source_sha256: str
    artifact_sha256: tuple[str, ...]
    contracts: tuple[ContractFacts, ...]

    def contract(self, name: str) -> ContractFacts:
        matches = [item for item in self.contracts if item.name == name]
        if len(matches) != 1:
            raise KeyError(f"contract not found or ambiguous: {name}")
        return matches[0]

    def function(self, contract: str, signature: str) -> FunctionFacts:
        matches = [
            item
            for item in self.contract(contract).functions
            if item.signature == signature
        ]
        if len(matches) != 1:
            raise KeyError(f"function not found or ambiguous: {contract}:{signature}")
        return matches[0]

    def to_json(self) -> str:
        return json.dumps(
            dataclasses.asdict(self), sort_keys=True, separators=(",", ":")
        )


def _call_expression(node: Mapping[str, Any]) -> Mapping[str, Any] | None:
    expression = node.get("expression")
    if not isinstance(expression, Mapping):
        return None
    if expression.get("nodeType") == "FunctionCallOptions":
        nested = expression.get("expression")
        return nested if isinstance(nested, Mapping) else None
    return expression


def _call_fact(
    node: Mapping[str, Any],
    declarations: Mapping[int, Mapping[str, Any]],
    function_contract: Mapping[int, str],
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
            int(node.get("id", -1)),
            str(node.get("src", "unknown")),
        )

    member_name: str
    if expression.get("nodeType") == "MemberAccess":
        member_name = str(expression.get("memberName", "<unknown>"))
    else:
        member_name = str(expression.get("name", "<unknown>"))
    reference = expression.get("referencedDeclaration")
    target = declarations.get(reference) if isinstance(reference, int) else None
    callee_signature = (
        _signature(target)
        if target is not None and target.get("nodeType") == "FunctionDefinition"
        else None
    )
    callee_contract = (
        function_contract.get(reference) if isinstance(reference, int) else None
    )

    if member_name in {"require", "assert"}:
        kind = "builtin"
    elif member_name in _LOW_LEVEL_MEMBERS:
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
        ast_id=int(node.get("id", -1)),
        source_span=str(node.get("src", "unknown")),
    )


def _has_msg_sender(value: object) -> bool:
    return any(
        node.get("nodeType") == "MemberAccess"
        and node.get("memberName") == "sender"
        and isinstance(node.get("expression"), Mapping)
        and node["expression"].get("name") == "msg"
        for node in _walk(value)
    )


def _extract_function(
    contract_name: str,
    node: Mapping[str, Any],
    declarations: Mapping[int, Mapping[str, Any]],
    function_contract: Mapping[int, str],
    state_declarations: Mapping[int, Mapping[str, Any]],
) -> FunctionFacts:
    body = node.get("body")
    write_occurrences: set[int] = set()
    write_names: set[str] = set()
    compound_reads: set[str] = set()
    write_positions: list[int] = []
    for candidate in _walk(body):
        if candidate.get("nodeType") == "Assignment":
            identifiers = tuple(
                _state_identifiers(candidate.get("leftHandSide"), state_declarations)
            )
            for identifier in identifiers:
                write_occurrences.add(int(identifier.get("id", -1)))
                declaration = state_declarations[identifier["referencedDeclaration"]]
                write_names.add(str(declaration["name"]))
                if candidate.get("operator") != "=":
                    compound_reads.add(str(declaration["name"]))
            if identifiers:
                write_positions.append(_src_start(str(candidate.get("src", "-1"))))
        elif candidate.get("nodeType") == "UnaryOperation" and candidate.get(
            "operator"
        ) in {"++", "--", "delete"}:
            identifiers = tuple(
                _state_identifiers(candidate.get("subExpression"), state_declarations)
            )
            for identifier in identifiers:
                write_occurrences.add(int(identifier.get("id", -1)))
                declaration = state_declarations[identifier["referencedDeclaration"]]
                write_names.add(str(declaration["name"]))
                if candidate.get("operator") != "delete":
                    compound_reads.add(str(declaration["name"]))
            if identifiers:
                write_positions.append(_src_start(str(candidate.get("src", "-1"))))

    read_names = set(compound_reads)
    for identifier in _state_identifiers(body, state_declarations):
        if int(identifier.get("id", -1)) not in write_occurrences:
            read_names.add(
                str(state_declarations[identifier["referencedDeclaration"]]["name"])
            )

    calls = tuple(
        sorted(
            filter(
                None,
                (
                    _call_fact(item, declarations, function_contract)
                    for item in _walk(body)
                    if item.get("nodeType") == "FunctionCall"
                ),
            ),
            key=lambda item: (_src_start(item.source_span), item.ast_id),
        )
    )
    value_flows: list[ValueFlowFact] = []
    for call in calls:
        if call.member_name in {"send", "transfer"}:
            value_flows.append(
                ValueFlowFact(
                    "native", call.member_name, "out", call.ast_id, call.source_span
                )
            )
        elif call.member_name == "call":
            call_node = declarations.get(call.ast_id)
            expression = call_node.get("expression") if call_node else None
            names = (
                expression.get("names", ()) if isinstance(expression, Mapping) else ()
            )
            if "value" in names:
                value_flows.append(
                    ValueFlowFact(
                        "native", "call", "out", call.ast_id, call.source_span
                    )
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
                str(state_declarations[item["referencedDeclaration"]]["name"])
                for item in _state_identifiers(arguments, state_declarations)
            )

    external_positions = [
        _src_start(call.source_span)
        for call in calls
        if call.kind in {"external", "low_level"}
    ]
    before_write = any(
        call_position >= 0 and write_position >= 0 and call_position < write_position
        for call_position in external_positions
        for write_position in write_positions
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
    return FunctionFacts(
        contract=contract_name,
        canonical_name=f"{contract_name}.{signature}",
        signature=signature,
        declaration_id=int(node["id"]),
        visibility=str(node.get("visibility", "unknown")),
        state_mutability=str(node.get("stateMutability", "unknown")),
        modifiers=modifiers,
        parameters=_parameter_records(node, "parameters"),
        returns=_parameter_records(node, "returnParameters"),
        source_span=str(node.get("src", "unknown")),
        storage_reads=tuple(sorted(read_names)),
        storage_writes=tuple(sorted(write_names)),
        calls=calls,
        value_flows=tuple(
            sorted(
                value_flows,
                key=lambda item: (_src_start(item.source_span), item.ast_id),
            )
        ),
        role_guards=tuple(sorted(role_guards)),
        oracle_calls=oracle_calls,
        external_call_before_write=before_write,
        transitive_storage_reads=tuple(sorted(read_names)),
        transitive_storage_writes=tuple(sorted(write_names)),
        transitive_calls=(),
    )


def _with_transitive(functions: Iterable[FunctionFacts]) -> tuple[FunctionFacts, ...]:
    by_signature = {function.signature: function for function in functions}
    reads = {
        signature: set(function.storage_reads)
        for signature, function in by_signature.items()
    }
    writes = {
        signature: set(function.storage_writes)
        for signature, function in by_signature.items()
    }
    reached = {signature: set() for signature in by_signature}
    direct = {
        signature: {
            call.callee_signature
            for call in function.calls
            if call.kind == "internal" and call.callee_signature in by_signature
        }
        for signature, function in by_signature.items()
    }
    changed = True
    while changed:
        changed = False
        for signature in sorted(by_signature):
            previous = (
                set(reads[signature]),
                set(writes[signature]),
                set(reached[signature]),
            )
            for target in direct[signature] | reached[signature]:
                reads[signature].update(reads[target])
                writes[signature].update(writes[target])
                reached[signature].add(target)
                reached[signature].update(reached[target])
            reached[signature].discard(signature)
            if previous != (reads[signature], writes[signature], reached[signature]):
                changed = True
    return tuple(
        replace(
            function,
            transitive_storage_reads=tuple(sorted(reads[function.signature])),
            transitive_storage_writes=tuple(sorted(writes[function.signature])),
            transitive_calls=tuple(
                sorted(reached[function.signature] | direct[function.signature])
            ),
        )
        for function in sorted(by_signature.values(), key=lambda item: item.signature)
    )


def analyze(bundle: ArtifactBundle) -> AnalysisReport:
    """Extract deterministic, provenance-bearing facts from compiler ASTs."""

    contracts: list[ContractFacts] = []
    seen_contracts: set[tuple[str, int]] = set()
    for artifact in bundle.artifacts:
        declarations = {
            int(node["id"]): node
            for node in _walk(artifact.ast)
            if isinstance(node.get("id"), int)
        }
        contract_nodes = [
            node
            for node in _walk(artifact.ast)
            if node.get("nodeType") == "ContractDefinition"
        ]
        function_contract = {
            int(function["id"]): str(contract["name"])
            for contract in contract_nodes
            for function in contract.get("nodes", ())
            if function.get("nodeType") == "FunctionDefinition"
        }
        state_declarations = {
            declaration_id: node
            for declaration_id, node in declarations.items()
            if node.get("nodeType") == "VariableDeclaration"
            and node.get("stateVariable") is True
        }
        layout_by_id = {
            int(item["astId"]): item
            for item in artifact.storage_layout.get("storage", ())
            if isinstance(item, Mapping) and isinstance(item.get("astId"), int)
        }
        for contract in contract_nodes:
            contract_key = (str(contract["name"]), int(contract["id"]))
            if contract_key in seen_contracts:
                continue
            seen_contracts.add(contract_key)
            storage: list[StorageFacts] = []
            functions: list[FunctionFacts] = []
            for child in contract.get("nodes", ()):
                if (
                    child.get("nodeType") == "VariableDeclaration"
                    and child.get("stateVariable") is True
                ):
                    layout = layout_by_id.get(int(child["id"]), {})
                    description = child.get("typeDescriptions", {})
                    storage.append(
                        StorageFacts(
                            contract=str(contract["name"]),
                            name=str(child["name"]),
                            declaration_id=int(child["id"]),
                            type_name=str(description.get("typeString", "unknown")),
                            slot=str(layout["slot"]) if "slot" in layout else None,
                            offset=int(layout["offset"])
                            if "offset" in layout
                            else None,
                            source_span=str(child.get("src", "unknown")),
                        )
                    )
                elif (
                    child.get("nodeType") == "FunctionDefinition"
                    and child.get("kind") == "function"
                ):
                    functions.append(
                        _extract_function(
                            str(contract["name"]),
                            child,
                            declarations,
                            function_contract,
                            state_declarations,
                        )
                    )
            contracts.append(
                ContractFacts(
                    name=str(contract["name"]),
                    canonical_name=str(contract.get("canonicalName", contract["name"])),
                    declaration_id=int(contract["id"]),
                    kind=str(contract.get("contractKind", "unknown")),
                    source_span=str(contract.get("src", "unknown")),
                    storage=tuple(sorted(storage, key=lambda item: item.name)),
                    functions=_with_transitive(functions),
                )
            )
    return AnalysisReport(
        source_sha256=bundle.source_sha256,
        artifact_sha256=tuple(
            sorted(artifact.artifact_sha256 for artifact in bundle.artifacts)
        ),
        contracts=tuple(sorted(contracts, key=lambda item: item.canonical_name)),
    )
