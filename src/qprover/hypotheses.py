"""Provenance-backed graph motifs for test prioritization, never verdicts."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass

from qprover.graph import GraphEdge, GraphNode, ProgramGraph
from qprover.models import ActionSpec, TargetManifest


@dataclass(frozen=True, slots=True)
class Hypothesis:
    id: str
    kind: str
    action_ids: tuple[str, ...]
    action_signatures: tuple[str, ...]
    function_ids: tuple[str, ...]
    evidence: tuple[str, ...]
    provenance: tuple[str, ...]
    evidence_hash: str
    assumed_ordering: tuple[str, ...]
    score: float
    rationale: str


def _function_nodes(graph: ProgramGraph) -> tuple[GraphNode, ...]:
    return tuple(node for node in graph.nodes if node.kind == "function")


def _actions_by_function(
    manifest: TargetManifest,
) -> dict[str, tuple[ActionSpec, ...]]:
    deployment_contract = {
        deployment.id: deployment.artifact.rsplit(":", maxsplit=1)[-1]
        for deployment in manifest.deployments
    }
    grouped: dict[str, list[ActionSpec]] = {}
    for action in manifest.actions:
        contract = deployment_contract[action.target_id]
        grouped.setdefault(f"function:{contract}:{action.signature}", []).append(action)
    return {
        function_id: tuple(sorted(actions, key=lambda item: item.id))
        for function_id, actions in grouped.items()
    }


def _create(
    kind: str,
    actions: tuple[ActionSpec, ...],
    function_ids: tuple[str, ...],
    evidence: tuple[str, ...],
    provenance: tuple[str, ...],
    score: float,
    rationale: str,
) -> Hypothesis:
    evidence = tuple(sorted(set(evidence)))
    provenance = tuple(sorted(set(provenance)))
    payload = json.dumps(
        {
            "kind": kind,
            "functions": function_ids,
            "evidence": evidence,
            "provenance": provenance,
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    evidence_hash = hashlib.sha256(payload.encode()).hexdigest()
    return Hypothesis(
        id=f"hypothesis:{evidence_hash[:20]}",
        kind=kind,
        action_ids=tuple(action.id for action in actions),
        action_signatures=tuple(action.signature for action in actions),
        function_ids=function_ids,
        evidence=evidence,
        provenance=provenance,
        evidence_hash=evidence_hash,
        assumed_ordering=tuple(action.id for action in actions),
        score=round(min(1.0, max(0.0, score)), 6),
        rationale=rationale,
    )


def _dependency_candidates(
    graph: ProgramGraph,
    actions: dict[str, tuple[ActionSpec, ...]],
) -> tuple[tuple[GraphEdge, ActionSpec, ActionSpec], ...]:
    result: list[tuple[GraphEdge, ActionSpec, ActionSpec]] = []
    for edge in graph.edges:
        if edge.kind != "depends_on":
            continue
        for source_action in actions.get(edge.source, ()):
            for target_action in actions.get(edge.target, ()):
                result.append((edge, source_action, target_action))
    return tuple(result)


def _edge_evidence(edge: GraphEdge) -> tuple[str, ...]:
    storage = tuple(str(item) for item in edge.attributes.get("storage", ()))
    return (f"edge:{edge.source}->{edge.target}:depends_on",) + tuple(
        f"storage:{item}" for item in storage
    )


def generate_hypotheses(
    graph: ProgramGraph, manifest: TargetManifest
) -> tuple[Hypothesis, ...]:
    """Generate deterministic leads that prioritize executable regression tests."""

    actions = _actions_by_function(manifest)
    nodes = {node.id: node for node in _function_nodes(graph)}
    candidates: list[Hypothesis] = []
    dependencies = _dependency_candidates(graph, actions)

    for edge, predecessor, sink_action in dependencies:
        predecessor_node = nodes[edge.source]
        sink_node = nodes[edge.target]
        sink_attributes = sink_node.attributes
        pair = (predecessor, sink_action)
        function_ids = (edge.source, edge.target)
        base_evidence = _edge_evidence(edge)

        if sink_attributes.get("external_call_before_write") and sink_attributes.get(
            "value_flow"
        ):
            before_edges = tuple(
                before
                for call in graph.out_edges(edge.target, "calls")
                for before in graph.out_edges(call.target, "before")
            )
            evidence = base_evidence + tuple(
                f"edge:{item.source}->{item.target}:before" for item in before_edges
            )
            provenance = edge.provenance + tuple(
                value for item in before_edges for value in item.provenance
            )
            candidates.append(
                _create(
                    "external-call-before-state-write",
                    pair,
                    function_ids,
                    evidence,
                    provenance,
                    0.9 + 0.05 * graph.transition_benefit(edge.source, edge.target),
                    "Prioritize a state-establishing action before a value call "
                    "that precedes its state update; execution is required to "
                    "validate impact.",
                )
            )

        guard_storage = set(sink_attributes.get("role_guards", ()))
        dependency_storage = set(edge.attributes.get("storage", ()))
        if (
            guard_storage.intersection(dependency_storage)
            and sink_attributes.get("value_flow")
            and predecessor_node.attributes.get("visibility") in {"public", "external"}
        ):
            candidates.append(
                _create(
                    "authorization-writer-to-guarded-value-sink",
                    pair,
                    function_ids,
                    base_evidence + tuple(f"guard:{item}" for item in guard_storage),
                    edge.provenance,
                    0.8 + 0.05 * graph.transition_benefit(edge.source, edge.target),
                    "Prioritize an externally callable authorization writer before a "
                    "guarded value sink; this is not an access-control verdict.",
                )
            )

        if (
            predecessor_node.attributes.get("oracle_calls")
            and sink_attributes.get("value_flow")
            and dependency_storage.intersection(
                sink_attributes.get("transitive_storage_reads", ())
            )
        ):
            candidates.append(
                _create(
                    "price-writer-to-value-sink",
                    pair,
                    function_ids,
                    base_evidence
                    + tuple(
                        f"oracle:{item}"
                        for item in predecessor_node.attributes.get("oracle_calls", ())
                    ),
                    edge.provenance,
                    0.76 + 0.05 * graph.transition_benefit(edge.source, edge.target),
                    "Prioritize an oracle-fed state update before a dependent value "
                    "sink; source evidence alone cannot establish manipulation.",
                )
            )

        source_signature = str(predecessor_node.attributes.get("signature", "")).lower()
        target_signature = str(sink_node.attributes.get("signature", "")).lower()
        callback_source = predecessor_node.attributes.get("value_flow") or any(
            token in source_signature
            for token in ("flashloan", "flash_loan", "transfer")
        )
        accounting_sink = sink_attributes.get("value_flow") and any(
            token in target_signature for token in ("withdraw", "redeem", "claim")
        )
        if callback_source and accounting_sink:
            candidates.append(
                _create(
                    "callback-before-accounting-withdrawal",
                    pair,
                    function_ids,
                    base_evidence,
                    edge.provenance,
                    0.7 + 0.05 * graph.transition_benefit(edge.source, edge.target),
                    "Prioritize a callback-capable transfer or loan before an "
                    "accounting withdrawal; runtime traces must establish callback "
                    "reachability.",
                )
            )

        reusable_storage = {
            name
            for name in dependency_storage
            if any(
                token in name.lower()
                for token in ("nonce", "signature", "permit", "digest", "used")
            )
        }
        if reusable_storage and sink_attributes.get("value_flow"):
            candidates.append(
                _create(
                    "reusable-authorization-to-repeated-value-sink",
                    pair,
                    function_ids,
                    base_evidence
                    + tuple(f"authorization-state:{item}" for item in reusable_storage),
                    edge.provenance,
                    0.66 + 0.05 * graph.transition_benefit(edge.source, edge.target),
                    "Prioritize repeated use of authorization state before a value "
                    "sink; execution must show whether replay is actually accepted.",
                )
            )

    for sink_id, sink_actions in sorted(actions.items()):
        sink_node = nodes.get(sink_id)
        if sink_node is None:
            continue
        attributes = sink_node.attributes
        if (
            attributes.get("visibility") not in {"public", "external"}
            or not attributes.get("value_flow")
            or attributes.get("role_guards")
        ):
            continue
        flow_edges = graph.out_edges(sink_id, "transfers")
        evidence = tuple(
            f"edge:{edge.source}->{edge.target}:transfers" for edge in flow_edges
        ) or (f"function:{sink_id}:value-flow",)
        provenance = tuple(value for edge in flow_edges for value in edge.provenance)
        for action in sink_actions:
            candidates.append(
                _create(
                    "public-value-sink-with-weak-or-unknown-guard",
                    (action,),
                    (sink_id,),
                    evidence,
                    provenance or sink_node.provenance,
                    0.45 + 0.1 * graph.action_utility(sink_id),
                    "Prioritize this public value sink because no actor guard was "
                    "proven statically; absence of evidence is not evidence of "
                    "missing controls.",
                )
            )

    deduplicated = {candidate.evidence_hash: candidate for candidate in candidates}
    return tuple(sorted(deduplicated.values(), key=lambda item: (-item.score, item.id)))
