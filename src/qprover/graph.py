"""Typed, deterministic dependency graph derived from compiler-backed facts."""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any

import networkx as nx

from qprover.analysis import AnalysisReport, FunctionFacts

NODE_KINDS = frozenset(
    {
        "contract",
        "function",
        "storage",
        "actor_guard",
        "external_call",
        "value_flow",
        "oracle",
        "lead",
    }
)
EDGE_KINDS = frozenset(
    {
        "contains",
        "calls",
        "reads",
        "writes",
        "guards",
        "transfers",
        "prices_from",
        "before",
        "depends_on",
    }
)


def _immutable(attributes: Mapping[str, Any] | None = None) -> Mapping[str, Any]:
    return MappingProxyType(dict(attributes or {}))


def _plain(value: object) -> object:
    if isinstance(value, Mapping):
        return {key: _plain(item) for key, item in sorted(value.items())}
    if isinstance(value, tuple):
        return [_plain(item) for item in value]
    return value


@dataclass(frozen=True, slots=True)
class GraphNode:
    id: str
    kind: str
    provenance: tuple[str, ...]
    attributes: Mapping[str, Any]


@dataclass(frozen=True, slots=True)
class GraphEdge:
    source: str
    target: str
    kind: str
    provenance: tuple[str, ...]
    attributes: Mapping[str, Any]


class ProgramGraph:
    """Read-only public facade over a NetworkX multidigraph."""

    def __init__(self, graph: nx.MultiDiGraph) -> None:
        self._graph = graph.copy()

    @property
    def nodes(self) -> tuple[GraphNode, ...]:
        records = [data["record"] for _, data in self._graph.nodes(data=True)]
        return tuple(sorted(records, key=lambda item: item.id))

    @property
    def edges(self) -> tuple[GraphEdge, ...]:
        records = [
            data["record"] for _, _, _, data in self._graph.edges(keys=True, data=True)
        ]
        return tuple(
            sorted(
                records,
                key=lambda item: (item.source, item.target, item.kind, item.provenance),
            )
        )

    def node(self, node_id: str) -> GraphNode:
        try:
            return self._graph.nodes[node_id]["record"]
        except KeyError as error:
            raise KeyError(f"graph node not found: {node_id}") from error

    def edge(self, source: str, target: str, kind: str | None = None) -> GraphEdge:
        data = self._graph.get_edge_data(source, target, default={})
        matches = [
            item["record"]
            for item in data.values()
            if kind is None or item["record"].kind == kind
        ]
        if len(matches) != 1:
            raise KeyError(
                f"graph edge not found or ambiguous: {source} -> {target} ({kind})"
            )
        return matches[0]

    def out_edges(self, source: str, kind: str | None = None) -> tuple[GraphEdge, ...]:
        matches = [
            data["record"]
            for _, _, _, data in self._graph.out_edges(source, keys=True, data=True)
            if kind is None or data["record"].kind == kind
        ]
        return tuple(sorted(matches, key=lambda item: (item.kind, item.target)))

    def in_edges(self, target: str, kind: str | None = None) -> tuple[GraphEdge, ...]:
        matches = [
            data["record"]
            for _, _, _, data in self._graph.in_edges(target, keys=True, data=True)
            if kind is None or data["record"].kind == kind
        ]
        return tuple(sorted(matches, key=lambda item: (item.kind, item.source)))

    def action_utility(self, node_id: str) -> float:
        node = self.node(node_id)
        if node.kind != "function":
            return 0.0
        attributes = node.attributes
        utility = 0.05
        if attributes.get("visibility") in {"public", "external"}:
            utility += 0.15
        if attributes.get("value_flow"):
            utility += 0.3
        if attributes.get("external_call_before_write"):
            utility += 0.35
        if attributes.get("role_guards"):
            utility += 0.05
        if attributes.get("oracle_calls"):
            utility += 0.1
        return round(min(1.0, max(0.0, utility)), 6)

    def transition_benefit(self, source: str, target: str) -> float:
        data = self._graph.get_edge_data(source, target, default={})
        dependency = any(item["record"].kind == "depends_on" for item in data.values())
        if not dependency:
            return 0.0
        benefit = 0.45 + 0.35 * self.action_utility(target)
        return round(min(1.0, max(-1.0, benefit)), 6)

    def to_json(self) -> str:
        payload = {
            "nodes": [
                {
                    "id": node.id,
                    "kind": node.kind,
                    "provenance": list(node.provenance),
                    "attributes": _plain(node.attributes),
                }
                for node in self.nodes
            ],
            "edges": [
                {
                    "source": edge.source,
                    "target": edge.target,
                    "kind": edge.kind,
                    "provenance": list(edge.provenance),
                    "attributes": _plain(edge.attributes),
                }
                for edge in self.edges
            ],
        }
        return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def _add_node(
    graph: nx.MultiDiGraph,
    node_id: str,
    kind: str,
    provenance: tuple[str, ...],
    attributes: Mapping[str, Any] | None = None,
) -> None:
    if kind not in NODE_KINDS:
        raise ValueError(f"unsupported graph node kind: {kind}")
    graph.add_node(
        node_id,
        record=GraphNode(node_id, kind, provenance, _immutable(attributes)),
    )


def _add_edge(
    graph: nx.MultiDiGraph,
    source: str,
    target: str,
    kind: str,
    provenance: tuple[str, ...],
    attributes: Mapping[str, Any] | None = None,
) -> None:
    if kind not in EDGE_KINDS:
        raise ValueError(f"unsupported graph edge kind: {kind}")
    record = GraphEdge(source, target, kind, provenance, _immutable(attributes))
    key = f"{kind}:{len(graph.get_edge_data(source, target, default={}))}"
    graph.add_edge(source, target, key=key, record=record)


def _function_id(function: FunctionFacts) -> str:
    return f"function:{function.contract}:{function.signature}"


def build_program_graph(report: AnalysisReport) -> ProgramGraph:
    """Build a graph whose transitions are backed by compiler AST provenance."""

    graph = nx.MultiDiGraph()
    functions: list[FunctionFacts] = []
    for contract in report.contracts:
        contract_id = f"contract:{contract.name}"
        _add_node(graph, contract_id, "contract", (contract.source_span,))
        for storage in contract.storage:
            storage_id = f"storage:{contract.name}:{storage.name}"
            _add_node(
                graph,
                storage_id,
                "storage",
                (storage.source_span,),
                {"slot": storage.slot, "type": storage.type_name},
            )
            _add_edge(
                graph, contract_id, storage_id, "contains", (storage.source_span,)
            )
        for function in contract.functions:
            functions.append(function)
            function_id = _function_id(function)
            _add_node(
                graph,
                function_id,
                "function",
                (function.source_span,),
                {
                    "signature": function.signature,
                    "contract": function.contract,
                    "visibility": function.visibility,
                    "storage_reads": function.storage_reads,
                    "storage_writes": function.storage_writes,
                    "transitive_storage_reads": function.transitive_storage_reads,
                    "transitive_storage_writes": function.transitive_storage_writes,
                    "role_guards": function.role_guards,
                    "oracle_calls": function.oracle_calls,
                    "value_flow": bool(function.value_flows),
                    "external_call_before_write": function.external_call_before_write,
                },
            )
            _add_edge(
                graph, contract_id, function_id, "contains", (function.source_span,)
            )
            for storage_name in function.storage_reads:
                _add_edge(
                    graph,
                    function_id,
                    f"storage:{function.contract}:{storage_name}",
                    "reads",
                    (function.source_span,),
                )
            for storage_name in function.storage_writes:
                _add_edge(
                    graph,
                    function_id,
                    f"storage:{function.contract}:{storage_name}",
                    "writes",
                    (function.source_span,),
                )
            call_nodes: list[tuple[str, int]] = []
            for call in function.calls:
                if call.kind == "internal" and call.callee_signature:
                    target_id = (
                        f"function:{call.callee_contract}:{call.callee_signature}"
                    )
                elif call.kind == "builtin":
                    continue
                else:
                    target_id = (
                        f"external_call:{function.contract}:{function.signature}:"
                        f"{call.member_name}:{call.ast_id}"
                    )
                    _add_node(
                        graph,
                        target_id,
                        "external_call",
                        (call.source_span,),
                        {"member_name": call.member_name, "call_kind": call.kind},
                    )
                    call_nodes.append((target_id, int(call.source_span.split(":")[0])))
                _add_edge(
                    graph,
                    function_id,
                    target_id,
                    "calls",
                    (call.source_span,),
                    {"call_kind": call.kind},
                )
            for guard_name in function.role_guards:
                guard_id = (
                    f"actor_guard:{function.contract}:{function.signature}:{guard_name}"
                )
                _add_node(
                    graph,
                    guard_id,
                    "actor_guard",
                    (function.source_span,),
                    {"storage": guard_name},
                )
                _add_edge(
                    graph, function_id, guard_id, "guards", (function.source_span,)
                )
            for index, flow in enumerate(function.value_flows):
                flow_id = (
                    f"value_flow:{function.contract}:{function.signature}:"
                    f"{flow.operation}:{flow.ast_id}:{index}"
                )
                _add_node(
                    graph,
                    flow_id,
                    "value_flow",
                    (flow.source_span,),
                    {"asset": flow.asset, "operation": flow.operation},
                )
                _add_edge(graph, function_id, flow_id, "transfers", (flow.source_span,))
            for oracle_name in function.oracle_calls:
                oracle_id = (
                    f"oracle:{function.contract}:{function.signature}:{oracle_name}"
                )
                _add_node(
                    graph,
                    oracle_id,
                    "oracle",
                    (function.source_span,),
                    {"selector": oracle_name},
                )
                _add_edge(
                    graph,
                    function_id,
                    oracle_id,
                    "prices_from",
                    (function.source_span,),
                )
            if function.external_call_before_write:
                for call_id, call_position in call_nodes:
                    for storage_name in function.storage_writes:
                        storage_id = f"storage:{function.contract}:{storage_name}"
                        _add_edge(
                            graph,
                            call_id,
                            storage_id,
                            "before",
                            (f"source-offset:{call_position}", function.source_span),
                        )

    public_functions = [
        function
        for function in functions
        if function.visibility in {"public", "external"}
    ]
    for writer in public_functions:
        written = set(writer.transitive_storage_writes)
        if not written:
            continue
        for reader in public_functions:
            if writer is reader:
                continue
            dependency = tuple(
                sorted(written.intersection(reader.transitive_storage_reads))
            )
            if not dependency:
                continue
            provenance = tuple(
                sorted(
                    {
                        writer.source_span,
                        reader.source_span,
                        *(f"storage:{writer.contract}:{name}" for name in dependency),
                    }
                )
            )
            _add_edge(
                graph,
                _function_id(writer),
                _function_id(reader),
                "depends_on",
                provenance,
                {"storage": dependency},
            )
    return ProgramGraph(graph)
