"""State-local feedback and prefix frontier records for TRUST404 Track 04."""

from __future__ import annotations

from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any

_NON_SEARCH_FAILURES = frozenset(
    {
        "parameter_invalid",
        "codegen_error",
        "compile_error",
        "setup_error",
        "harness_error",
        "timeout",
        "infra_error",
    }
)


@dataclass(frozen=True, slots=True)
class AttemptFeedback:
    state_id: str
    candidate_id: str
    outcome: str
    revert_step: int | None
    revert_selector: str | None
    raw_revert_hash: str | None
    infrastructure: bool = False
    parameter_identity: str = ""


@dataclass(frozen=True, slots=True)
class FrontierProposal:
    source_state_id: str
    candidate_id: str
    prefix_action_ids: tuple[str, ...]
    failed_action_id: str
    revert_selector: str | None
    raw_revert_hash: str | None


@dataclass(slots=True)
class StateLocalFeedback:
    _revert_penalties: dict[tuple[str, str, str], float] = field(default_factory=dict)

    def revert_penalty(
        self,
        state_id: str,
        action_id: str,
        parameter_identity: str = "",
    ) -> float:
        return self._revert_penalties.get(
            (state_id, action_id, parameter_identity),
            0.0,
        )

    def record(
        self,
        feedback: AttemptFeedback,
        *,
        action_ids: tuple[str, ...],
    ) -> FrontierProposal | None:
        """Record search-relevant feedback without poisoning other states."""

        if feedback.infrastructure or feedback.outcome in _NON_SEARCH_FAILURES:
            return None
        if feedback.outcome != "candidate_revert":
            return None

        step = feedback.revert_step
        if step is None or step < 0 or step >= len(action_ids):
            return None

        failed_action = action_ids[step]
        key = (
            feedback.state_id,
            failed_action,
            feedback.parameter_identity,
        )
        self._revert_penalties[key] = self._revert_penalties.get(key, 0.0) + 1.0

        if step == 0:
            return None
        return FrontierProposal(
            source_state_id=feedback.state_id,
            candidate_id=feedback.candidate_id,
            prefix_action_ids=action_ids[:step],
            failed_action_id=failed_action,
            revert_selector=feedback.revert_selector,
            raw_revert_hash=feedback.raw_revert_hash,
        )


@dataclass(frozen=True, slots=True)
class SearchState:
    state_id: str
    fingerprint: str
    trace_action_ids: tuple[str, ...]
    property_observations: tuple[tuple[str, object], ...] = ()
    resource_observations: tuple[tuple[str, object], ...] = ()
    runtime_instances: tuple[object, ...] = ()
    feasible_actions: tuple[str, ...] = ()
    reverting_actions: tuple[str, ...] = ()
    novelty: float = 0.0

    @property
    def depth(self) -> int:
        return len(self.trace_action_ids)


@dataclass(slots=True)
class StateFrontier:
    _by_fingerprint: dict[str, SearchState] = field(default_factory=dict)

    def add(self, state: SearchState) -> bool:
        """Keep the shortest deterministic trace for each relevant fingerprint."""

        existing = self._by_fingerprint.get(state.fingerprint)
        if existing is None:
            self._by_fingerprint[state.fingerprint] = state
            return True
        old_key = (existing.depth, existing.trace_action_ids, existing.state_id)
        new_key = (state.depth, state.trace_action_ids, state.state_id)
        if new_key < old_key:
            self._by_fingerprint[state.fingerprint] = state
            return True
        return False

    def get(self, fingerprint: str) -> SearchState | None:
        return self._by_fingerprint.get(fingerprint)

    def states(self) -> tuple[SearchState, ...]:
        return tuple(
            sorted(
                self._by_fingerprint.values(),
                key=lambda item: (
                    item.depth,
                    -item.novelty,
                    item.fingerprint,
                    item.state_id,
                ),
            )
        )


@dataclass(slots=True)
class FeasibilityCache:
    _status: dict[tuple[str, str, str], str] = field(default_factory=dict)

    def set(
        self,
        state_fingerprint: str,
        action_id: str,
        parameter_identity: str,
        status: str,
    ) -> None:
        if status not in {"FEASIBLE", "REVERTS_NOW", "UNKNOWN"}:
            raise ValueError("invalid feasibility status")
        self._status[(state_fingerprint, action_id, parameter_identity)] = status

    def get(
        self,
        state_fingerprint: str,
        action_id: str,
        parameter_identity: str = "",
    ) -> str:
        return self._status.get(
            (state_fingerprint, action_id, parameter_identity),
            "UNKNOWN",
        )


@dataclass(slots=True)
class PlannerScheduler:
    seed: int
    planner_names: tuple[str, ...] = ("best_first", "qubo", "coverage")
    _proposals: dict[str, int] = field(init=False)
    _novel: dict[str, int] = field(init=False)
    _reverts: dict[str, int] = field(init=False)

    def __post_init__(self) -> None:
        if type(self.seed) is not int:
            raise ValueError("scheduler seed must be an integer")
        if not self.planner_names or len(set(self.planner_names)) != len(
            self.planner_names
        ):
            raise ValueError("planner names must be unique and nonempty")
        self._proposals = {name: 0 for name in self.planner_names}
        self._novel = {name: 0 for name in self.planner_names}
        self._reverts = {name: 0 for name in self.planner_names}

    def _tie_order(self) -> tuple[str, ...]:
        offset = self.seed % len(self.planner_names)
        return self.planner_names[offset:] + self.planner_names[:offset]

    def choose(self) -> str:
        weights = {"best_first": 2, "qubo": 2, "coverage": 1}
        order = self._tie_order()

        def score(name: str) -> tuple[float, int, int, int]:
            weight = weights.get(name, 1)
            load = self._proposals[name] / weight
            productivity = self._novel[name] - self._reverts[name]
            return (
                load,
                -productivity,
                self._reverts[name],
                order.index(name),
            )

        selected = min(self.planner_names, key=score)
        self._proposals[selected] += 1
        return selected

    def observe(
        self,
        planner: str,
        *,
        novel: bool,
        reverted: bool,
    ) -> None:
        if planner not in self._proposals:
            raise ValueError("unknown planner")
        if novel:
            self._novel[planner] += 1
        if reverted:
            self._reverts[planner] += 1

    @property
    def counters(self) -> MappingProxyType:
        return MappingProxyType(
            {
                name: {
                    "proposals": self._proposals[name],
                    "novel": self._novel[name],
                    "reverts": self._reverts[name],
                }
                for name in self.planner_names
            }
        )


class PortfolioStrategy:
    """Deterministic adapter sharing one problem and feedback across planners."""

    name = "portfolio"

    def __init__(self, planners: dict[str, Any], *, seed: int) -> None:
        if not planners:
            raise ValueError("portfolio requires at least one planner")
        self._planners = dict(planners)
        self._seed = seed
        self._scheduler = PlannerScheduler(seed, tuple(planners))
        self._origins: dict[str, str] = {}
        self._proposed: set[str] = set()
        self._feedback = StateLocalFeedback()
        self._initialized = False

    def initialize(self, problem: object, seed: int) -> None:
        if seed != self._seed:
            self._seed = seed
            self._scheduler = PlannerScheduler(seed, tuple(self._planners))
        for index, (name, planner) in enumerate(self._planners.items()):
            planner.initialize(problem, seed + index)
        self._initialized = True

    def propose(self, remaining_transactions: int):
        if not self._initialized:
            raise RuntimeError("portfolio is not initialized")
        exhausted: set[str] = set()
        for _ in range(max(1, len(self._planners) * 8)):
            name = self._scheduler.choose()
            if name in exhausted:
                if len(exhausted) == len(self._planners):
                    return None
                continue
            candidate = self._planners[name].propose(remaining_transactions)
            if candidate is None:
                exhausted.add(name)
                continue
            if candidate.canonical_id in self._proposed:
                continue
            self._proposed.add(candidate.canonical_id)
            self._origins[candidate.canonical_id] = name
            return candidate
        return None

    def observe(self, candidate: object, result: object) -> None:
        from qprover.models import Outcome
        from qprover.search.base import Evaluation

        origin = self._origins.get(getattr(candidate, "canonical_id", ""), "qubo")
        outcome = getattr(result, "outcome", None)
        reverted = outcome is Outcome.REVERT
        state_id = getattr(result, "state_fingerprint", None) or "state:baseline"
        if reverted:
            metadata = getattr(result, "metadata", {})
            step = max(0, int(getattr(result, "transaction_count", 1)) - 1)
            self._feedback.record(
                AttemptFeedback(
                    state_id=state_id,
                    candidate_id=str(getattr(candidate, "canonical_id", "")),
                    outcome="candidate_revert",
                    revert_step=step,
                    revert_selector=str(metadata.get("revert_selector") or "") or None,
                    raw_revert_hash=str(metadata.get("raw_revert_hash") or "") or None,
                    parameter_identity=str(getattr(candidate, "canonical_id", "")),
                ),
                action_ids=tuple(
                    str(getattr(step_record, "action_id", ""))
                    for step_record in getattr(candidate, "steps", ())
                ),
            )
            shared_result = Evaluation(
                outcome=Outcome.INCONCLUSIVE,
                transaction_count=int(getattr(result, "transaction_count", 0)),
                trace_features=frozenset(getattr(result, "trace_features", ())),
                state_fingerprint=getattr(result, "state_fingerprint", None),
                metadata=getattr(result, "metadata", {}),
            )
        else:
            shared_result = result

        for planner in self._planners.values():
            planner.observe(candidate, shared_result)

        novel = bool(getattr(result, "trace_features", ())) or (
            getattr(result, "state_fingerprint", None) is not None
        )
        self._scheduler.observe(origin, novel=novel, reverted=reverted)

    def revert_penalty(
        self,
        state_id: str,
        action_id: str,
        parameter_identity: str = "",
    ) -> float:
        return self._feedback.revert_penalty(
            state_id,
            action_id,
            parameter_identity,
        )

    @property
    def stats(self):
        from qprover.search.base import StrategyStats

        return StrategyStats(
            name=self.name,
            counters={
                "proposals": len(self._proposed),
                "planners": len(self._planners),
            },
            metadata={
                "scheduler": {
                    key: dict(value) for key, value in self._scheduler.counters.items()
                },
                "planner_stats": {
                    name: planner.stats.to_dict()
                    for name, planner in self._planners.items()
                },
            },
        )
