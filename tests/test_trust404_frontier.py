from __future__ import annotations

from qprover.trust404_frontier import (
    AttemptFeedback,
    FeasibilityCache,
    PlannerScheduler,
    SearchState,
    StateFrontier,
    StateLocalFeedback,
)


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


def test_state_frontier_keeps_shortest_trace_for_equal_fingerprint() -> None:
    frontier = StateFrontier()
    long = SearchState(
        state_id="state:long",
        fingerprint="fp:1",
        trace_action_ids=("a", "b", "c"),
    )
    short = SearchState(
        state_id="state:short",
        fingerprint="fp:1",
        trace_action_ids=("a",),
    )

    assert frontier.add(long) is True
    assert frontier.add(short) is True
    assert frontier.get("fp:1") == short


def test_feasibility_is_state_and_parameter_local() -> None:
    cache = FeasibilityCache()
    cache.set("fp:0", "call:a(uint256)", "arg:1", "REVERTS_NOW")
    cache.set("fp:1", "call:a(uint256)", "arg:1", "FEASIBLE")

    assert cache.get("fp:0", "call:a(uint256)", "arg:1") == "REVERTS_NOW"
    assert cache.get("fp:1", "call:a(uint256)", "arg:1") == "FEASIBLE"
    assert cache.get("fp:0", "call:a(uint256)", "arg:2") == "UNKNOWN"


def test_planner_scheduler_is_deterministic_for_equal_seed_and_feedback() -> None:
    first = PlannerScheduler(11)
    second = PlannerScheduler(11)
    first_sequence = []
    second_sequence = []
    for index in range(12):
        left = first.choose()
        right = second.choose()
        first_sequence.append(left)
        second_sequence.append(right)
        novel = index % 3 == 0
        reverted = index % 4 == 0
        first.observe(left, novel=novel, reverted=reverted)
        second.observe(right, novel=novel, reverted=reverted)

    assert first_sequence == second_sequence
    assert set(first_sequence) == {"best_first", "qubo", "coverage"}
