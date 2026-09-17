"""Property-directed resource slices for TRUST404 Track 04 search."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from qprover.trust404_property import PropertyAnalysis, PropertyFact

_DIRECTION_UNKNOWN = "unknown"
_DIRECTION_INCREASE = "increase"
_DIRECTION_DECREASE = "decrease"


@dataclass(frozen=True, slots=True, order=True)
class ResourceRef:
    kind: str
    identity: str
    provenance: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class PropertySlice:
    property_id: str
    resources: tuple[ResourceRef, ...]
    function_ids: tuple[str, ...]
    direction_hint: str
    provenance: tuple[str, ...]


def _provenance(fact: PropertyFact) -> tuple[str, ...]:
    return tuple(
        item
        for item in (fact.function_id, fact.source_span)
        if isinstance(item, str) and item
    )


def _balance_direction(fact: PropertyFact) -> str:
    candidates: set[str] = set()
    for operator, left, right in fact.comparison_hints:
        if left == "target.balance" and right == "constant":
            if operator in {">", ">="}:
                candidates.add(_DIRECTION_DECREASE)
            elif operator in {"<", "<="}:
                candidates.add(_DIRECTION_INCREASE)
        elif left == "constant" and right == "target.balance":
            if operator in {">", ">="}:
                candidates.add(_DIRECTION_INCREASE)
            elif operator in {"<", "<="}:
                candidates.add(_DIRECTION_DECREASE)
    if len(candidates) == 1:
        return next(iter(candidates))
    return _DIRECTION_UNKNOWN


def _resources_for_fact(
    fact: PropertyFact, *, root_target_identity: str
) -> tuple[ResourceRef, ...]:
    provenance = _provenance(fact)
    resources: set[ResourceRef] = set()
    if fact.target_balance_read:
        resources.add(
            ResourceRef(
                kind="native_balance",
                identity=root_target_identity,
                provenance=provenance,
            )
        )
    for member in fact.target_calls:
        resources.add(
            ResourceRef(
                kind="view_value",
                identity=f"{root_target_identity}:{member}",
                provenance=provenance,
            )
        )
    return tuple(sorted(resources))


def build_property_slices(
    properties: PropertyAnalysis,
    *,
    root_target_identity: str,
) -> tuple[PropertySlice, ...]:
    """Build conservative search slices from compiler-backed property facts."""

    slices: list[PropertySlice] = []
    for fact in properties.facts:
        slices.append(
            PropertySlice(
                property_id=fact.predicate_name,
                resources=_resources_for_fact(
                    fact, root_target_identity=root_target_identity
                ),
                function_ids=(),
                direction_hint=(
                    _balance_direction(fact)
                    if fact.target_balance_read
                    else _DIRECTION_UNKNOWN
                ),
                provenance=_provenance(fact),
            )
        )
    return tuple(slices)


def _native_value_direction(function: Any) -> frozenset[str]:
    directions: set[str] = set()
    for flow in getattr(function, "value_flows", ()):
        if getattr(flow, "asset", None) != "native":
            continue
        direction = getattr(flow, "direction", None)
        if direction in {"in", "out"}:
            directions.add(str(direction))
    return frozenset(directions)


def _storage_relevance(function: Any, resources: Sequence[ResourceRef]) -> float:
    storage_ids = {
        resource.identity for resource in resources if resource.kind == "storage"
    }
    if not storage_ids:
        return 0.0
    reads = set(getattr(function, "transitive_storage_reads", ()))
    writes = set(getattr(function, "transitive_storage_writes", ()))
    score = 0.0
    if writes & storage_ids:
        score += 0.8
    if reads & storage_ids:
        score += 0.2
    return score


def score_function_relevance(
    function: Any,
    slices: Sequence[PropertySlice],
) -> float:
    """Return a label-neutral property relevance prior for one function."""

    native_directions = _native_value_direction(function)
    score = 0.0
    for property_slice in slices:
        resources = property_slice.resources
        has_native_balance = any(
            resource.kind == "native_balance" for resource in resources
        )
        if has_native_balance:
            if (
                property_slice.direction_hint == _DIRECTION_DECREASE
                and "out" in native_directions
            ):
                score += 1.0
            elif (
                property_slice.direction_hint == _DIRECTION_INCREASE
                and "in" in native_directions
            ):
                score += 1.0
        score += _storage_relevance(function, resources)
    return round(score, 6)
