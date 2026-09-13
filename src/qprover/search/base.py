"""Shared lifecycle and immutable records for transaction-sequence search."""

from __future__ import annotations

import math
from collections import Counter
from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Protocol

from qprover.models import ActionStep, Candidate, Outcome
from qprover.parameters import ActionVariant
from qprover.search.bqm import SearchProblem


def freeze_json(value: object) -> object:
    """Recursively snapshot supported JSON-like data into immutable records."""

    if value is None or type(value) in (bool, int, str):
        return value
    if type(value) is float:
        if not math.isfinite(value):
            raise TypeError("JSON-like numeric values must be finite")
        return value
    if isinstance(value, (list, tuple)):
        return tuple(freeze_json(item) for item in value)
    if isinstance(value, Mapping):
        if any(type(key) is not str for key in value):
            raise TypeError("JSON-like mapping keys must be strings")
        return MappingProxyType({key: freeze_json(item) for key, item in value.items()})
    raise TypeError(f"unsupported JSON-like value: {type(value).__name__}")


def freeze_json_mapping(value: Mapping | None = None) -> MappingProxyType:
    frozen = freeze_json(dict(value or {}))
    if not isinstance(frozen, MappingProxyType):
        raise AssertionError("mapping freeze did not produce a mapping proxy")
    return frozen


def thaw_json(value: object) -> object:
    if isinstance(value, Mapping):
        return {key: thaw_json(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [thaw_json(item) for item in value]
    return value


def candidate_to_dict(candidate: Candidate) -> dict[str, object]:
    def thaw_argument(value: object) -> object:
        if isinstance(value, bytes):
            return f"0x{value.hex()}"
        if isinstance(value, tuple):
            return [thaw_argument(item) for item in value]
        return value

    return {
        "canonical_id": candidate.canonical_id,
        "steps": [
            {
                "action_id": step.action_id,
                "target_id": step.target_id,
                "signature": step.signature,
                "sender_slot": step.sender_slot,
                "args": [thaw_argument(item) for item in step.args],
                "value_wei": step.value_wei,
            }
            for step in candidate.steps
        ],
    }


@dataclass(frozen=True, slots=True)
class Evaluation:
    """Label-neutral result returned by a concrete local evaluator.

    The controller interprets ``transaction_count`` by outcome: successful and
    violating candidates must execute every step, a revert must execute a
    positive prefix, and infrastructure/inconclusive outcomes may occur before
    any transaction is sent.
    """

    outcome: Outcome
    transaction_count: int
    trace_features: frozenset[str] = frozenset()
    state_fingerprint: str | None = None
    metadata: Mapping[str, object] | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.outcome, Outcome):
            raise ValueError("outcome must be an Outcome")
        if type(self.transaction_count) is not int or self.transaction_count < 0:
            raise ValueError("transaction_count must be a nonnegative exact integer")
        features = frozenset(self.trace_features)
        if any(not isinstance(item, str) or not item for item in features):
            raise ValueError("trace_features must contain nonempty strings")
        if self.state_fingerprint is not None and (
            not isinstance(self.state_fingerprint, str) or not self.state_fingerprint
        ):
            raise ValueError("state_fingerprint must be a nonempty string or None")
        object.__setattr__(self, "trace_features", features)
        object.__setattr__(self, "metadata", freeze_json_mapping(self.metadata))

    def to_dict(self) -> dict[str, object]:
        return {
            "outcome": self.outcome.value,
            "transaction_count": self.transaction_count,
            "trace_features": sorted(self.trace_features),
            "state_fingerprint": self.state_fingerprint,
            "metadata": thaw_json(self.metadata),
        }


@dataclass(frozen=True, slots=True)
class StrategyStats:
    """Serializable strategy counters and inspectable policy metadata."""

    name: str
    counters: Mapping[str, int] | None = None
    metadata: Mapping[str, object] | None = None

    def __post_init__(self) -> None:
        counters = dict(self.counters or {})
        if any(
            not isinstance(key, str) or type(value) is not int or value < 0
            for key, value in counters.items()
        ):
            raise ValueError("strategy counters must be nonnegative exact integers")
        object.__setattr__(self, "counters", MappingProxyType(counters))
        object.__setattr__(self, "metadata", freeze_json_mapping(self.metadata))

    def to_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "counters": dict(self.counters),
            "metadata": thaw_json(self.metadata),
        }


class SearchStrategy(Protocol):
    """Exact common lifecycle implemented by every search policy."""

    def initialize(self, problem: SearchProblem, seed: int) -> None: ...

    def propose(self, remaining_transactions: int) -> Candidate | None: ...

    def observe(self, candidate: Candidate, result: Evaluation) -> None: ...


class CandidateEvaluator(Protocol):
    def evaluate(self, candidate: Candidate) -> Evaluation: ...


def step_from_variant(variant: ActionVariant) -> ActionStep:
    return ActionStep(
        action_id=variant.action_id,
        target_id=variant.target_id,
        signature=variant.signature,
        sender_slot=variant.sender_slot,
        args=variant.args,
        value_wei=variant.value_wei,
    )


def variants_by_action(
    problem: SearchProblem,
) -> Mapping[str, tuple[ActionVariant, ...]]:
    grouped: dict[str, list[ActionVariant]] = {action: [] for action in problem.actions}
    for variant in problem.variants:
        grouped[variant.action_id].append(variant)
    return MappingProxyType(
        {
            action: tuple(sorted(items, key=lambda item: item.canonical_id))
            for action, items in grouped.items()
        }
    )


def candidate_is_valid(problem: SearchProblem, candidate: Candidate) -> bool:
    if not candidate.steps or len(candidate.steps) > problem.max_sequence_length:
        return False
    allowed = {step_from_variant(variant) for variant in problem.variants}
    if any(step not in allowed for step in candidate.steps):
        return False
    counts = Counter(step.action_id for step in candidate.steps)
    return all(
        counts[action] <= problem.repetition_limits[action]
        for action in problem.actions
    )


def require_strategy_problem(problem: SearchProblem, seed: int) -> None:
    if not isinstance(problem, SearchProblem):
        raise ValueError("problem must be a SearchProblem")
    if not problem.variants:
        raise ValueError("search strategies require concrete action variants")
    if type(seed) is not int:
        raise ValueError("seed must be an exact integer")
