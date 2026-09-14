from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from qprover.artifacts import build_target
from qprover.manifest import load_manifest
from qprover.pipeline import monotonic_events_to_evidence, prepare_search
from qprover.search.bqm import STOP, SearchFeedback, SequenceBQMBuilder
from qprover.search.controller import SearchEvent

ROOT = Path(__file__).parents[1]


def test_prepare_search_is_complete_canonical_and_nonflat_for_reentrancy_twins() -> (
    None
):
    prepared = []
    for suffix in ("a", "b"):
        manifest = load_manifest(ROOT / f"benchmarks/scenario_reentrancy_{suffix}.json")
        with build_target(manifest) as bundle:
            item = prepare_search(manifest, bundle)
        prepared.append(item)

        assert tuple(item.action_functions) == tuple(
            action.id for action in manifest.actions
        )
        assert set(item.problem.utilities) == {action.id for action in manifest.actions}
        assert all(
            item.action_functions[action.id].provenance for action in manifest.actions
        )
        mapped = item.action_functions
        for edge in item.graph.edges:
            if edge.kind != "depends_on":
                continue
            sources = [
                key for key, value in mapped.items() if value.function_id == edge.source
            ]
            targets = [
                key for key, value in mapped.items() if value.function_id == edge.target
            ]
            for source in sources:
                for target in targets:
                    assert (source, target) in item.problem.transitions

    first, second = prepared
    assert first.problem_sha256 == first.problem.sha256 == second.problem_sha256
    assert first.problem.utilities == second.problem.utilities
    assert first.problem.transitions == second.problem.transitions
    assert first.problem.utilities["step_beta"] > 0
    assert (
        first.problem.transitions[("step_alpha", "step_beta")]
        > first.problem.transitions[("step_beta", "step_alpha")]
    )

    bqm = SequenceBQMBuilder().build(first.problem, SearchFeedback.empty())
    forward = bqm.energy(bqm.encode(("step_alpha", "step_beta")))
    reverse = bqm.energy(bqm.encode(("step_beta", "step_alpha")))
    noise = bqm.energy(bqm.encode(("noise_two",)))
    assert forward < reverse
    assert forward < noise
    assert bqm.encode(("step_alpha",))[bqm.index(1, STOP)] == 1


def test_monotonic_events_become_ordered_utc_evidence() -> None:
    started = datetime(2026, 9, 14, 2, 3, 4, tzinfo=UTC)
    events = (
        SearchEvent("run", 0, 0.5, "initialization", "info", "search", {}),
        SearchEvent("run", 1, 0.5, "proposal", "info", "search", {}),
        SearchEvent("run", 2, 1.25, "execution", "info", "candidate", {}),
    )

    converted = monotonic_events_to_evidence(events, started)

    assert tuple(item.sequence for item in converted) == (1, 2, 3)
    assert tuple(item.timestamp for item in converted) == (
        started + timedelta(seconds=0.5),
        started + timedelta(seconds=0.5),
        started + timedelta(seconds=1.25),
    )
    assert all(item.timestamp.tzinfo is UTC for item in converted)


@pytest.mark.parametrize("offset", [-0.1, float("nan"), float("inf")])
def test_event_conversion_rejects_invalid_monotonic_offsets(offset: float) -> None:
    event = SearchEvent("run", 0, offset, "proposal", "info", "search", {})

    with pytest.raises(ValueError, match="offset"):
        monotonic_events_to_evidence((event,), datetime(2026, 9, 14, tzinfo=UTC))


def test_event_conversion_rejects_regressing_monotonic_offsets() -> None:
    events = (
        SearchEvent("run", 0, 1.0, "proposal", "info", "search", {}),
        SearchEvent("run", 1, 0.5, "execution", "info", "search", {}),
    )

    with pytest.raises(ValueError, match="ordered"):
        monotonic_events_to_evidence(events, datetime(2026, 9, 14, tzinfo=UTC))
