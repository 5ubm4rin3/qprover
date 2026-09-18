from __future__ import annotations

from qprover.trust404_frontier import AttemptFeedback, StateLocalFeedback


def test_infrastructure_failure_does_not_learn_action_revert_penalty() -> None:
    memory = StateLocalFeedback()
    actions = ("call:alpha()", "call:beta()")

    proposal = memory.record(
        AttemptFeedback(
            state_id="state:0",
            candidate_id="candidate:compile-error",
            outcome="compile_error",
            revert_step=None,
            revert_selector=None,
            raw_revert_hash=None,
            infrastructure=True,
        ),
        action_ids=actions,
    )

    assert proposal is None
    assert memory.revert_penalty("state:0", "call:alpha()") == 0.0
    assert memory.revert_penalty("state:0", "call:beta()") == 0.0


def test_candidate_revert_penalizes_failed_action_and_preserves_prefix() -> None:
    memory = StateLocalFeedback()
    actions = (
        "call:alpha()",
        "call:beta()",
        "call:gamma()",
        "call:delta()",
        "call:epsilon()",
    )

    proposal = memory.record(
        AttemptFeedback(
            state_id="state:7",
            candidate_id="candidate:revert",
            outcome="candidate_revert",
            revert_step=3,
            revert_selector="0x08c379a0",
            raw_revert_hash="sha256:deadbeef",
            infrastructure=False,
        ),
        action_ids=actions,
    )

    assert memory.revert_penalty("state:7", "call:delta()") == 1.0
    assert memory.revert_penalty("state:7", "call:gamma()") == 0.0
    assert proposal is not None
    assert proposal.source_state_id == "state:7"
    assert proposal.candidate_id == "candidate:revert"
    assert proposal.prefix_action_ids == actions[:3]
    assert proposal.failed_action_id == "call:delta()"
    assert proposal.revert_selector == "0x08c379a0"
    assert proposal.raw_revert_hash == "sha256:deadbeef"
