"""Shared lifecycle and immutable records for transaction-sequence search."""

from __future__ import annotations

from collections import Counter
from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Protocol

from qprover.models import ActionStep, Candidate, Outcome
from qprover.parameters import ActionVariant
from qprover.search.bqm import SearchProblem


def _mapping(value: Mapping | None = None) -> MappingProxyType:
    return MappingProxyType(dict(value or {}))


@dataclass(frozen=True, slots=True)
class Evaluation:
    """Label-neutral result returned by a concrete local evaluator."""

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
        object.__setattr__(self, "metadata", _mapping(self.metadata))


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
        object.__setattr__(self, "counters", _mapping(counters))
        object.__setattr__(self, "metadata", _mapping(self.metadata))

    def to_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "counters": dict(self.counters),
            "metadata": dict(self.metadata),
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
