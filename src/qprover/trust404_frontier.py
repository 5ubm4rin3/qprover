"""State-local feedback and prefix frontier records for TRUST404 Track 04."""

from __future__ import annotations

from dataclasses import dataclass, field



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
    _revert_penalties: dict[tuple[str, str], float] = field(default_factory=dict)

    def revert_penalty(self, state_id: str, action_id: str) -> float:
        return self._revert_penalties.get((state_id, action_id), 0.0)

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
        key = (feedback.state_id, failed_action)
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
