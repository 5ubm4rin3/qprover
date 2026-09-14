from __future__ import annotations

import dataclasses
import json
from copy import deepcopy
from datetime import UTC, datetime, timedelta
from pathlib import Path

import jsonschema
import pytest
from pydantic import ValidationError

import qprover.pipeline as pipeline_module
from qprover.artifacts import build_target
from qprover.manifest import load_manifest
from qprover.pipeline import (
    ProofRunResult,
    monotonic_events_to_evidence,
    prepare_search,
)
from qprover.safeio import SafeOutputError
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


def test_problem_hash_ignores_hypothesis_provenance_and_generation_order(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifest = load_manifest(ROOT / "benchmarks/scenario_reentrancy_a.json")
    with build_target(manifest) as bundle:
        original = pipeline_module.generate_hypotheses
        base = original(
            pipeline_module.build_program_graph(pipeline_module.analyze(bundle)),
            manifest,
        )[0]
        alpha = dataclasses.replace(
            base,
            id="source-span-a",
            evidence_hash="a" * 64,
            action_ids=("noise_one",),
            action_signatures=("donate()",),
            function_ids=(base.function_ids[0],),
            provenance=("source-a:1:2",),
            score=0.0,
        )
        beta = dataclasses.replace(
            base,
            id="source-span-b",
            evidence_hash="b" * 64,
            action_ids=("noise_two",),
            action_signatures=("touch(uint256)",),
            function_ids=(base.function_ids[0],),
            provenance=("source-b:3:4",),
            score=0.0,
        )
        monkeypatch.setattr(
            pipeline_module, "generate_hypotheses", lambda graph, target: (alpha, beta)
        )
        first = prepare_search(manifest, bundle)
        monkeypatch.setattr(
            pipeline_module,
            "generate_hypotheses",
            lambda graph, target: (
                dataclasses.replace(beta, provenance=("relocated-b:30:40",)),
                dataclasses.replace(alpha, provenance=("relocated-a:10:20",)),
            ),
        )
        second = prepare_search(manifest, bundle)

    assert first.problem.to_dict() == second.problem.to_dict()
    assert first.problem_sha256 == second.problem_sha256
    assert first.objective_provenance != second.objective_provenance


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


def test_qubo_json_writer_rejects_links_and_nonfinite_data(tmp_path: Path) -> None:
    victim = tmp_path / "victim"
    victim.write_text("untouched")
    linked = tmp_path / "qubo.json"
    linked.symlink_to(victim)

    with pytest.raises(SafeOutputError):
        pipeline_module._atomic_json({"ok": True}, linked)
    with pytest.raises(ValueError, match="JSON"):
        pipeline_module._atomic_json({"bad": float("nan")}, tmp_path / "bad.json")
    assert victim.read_text() == "untouched"


def _run_artifact(path: str = "certificate.json") -> dict[str, str]:
    return {"path": path, "sha256": "a" * 64}


def _valid_run_results() -> tuple[dict[str, object], ...]:
    common: dict[str, object] = {
        "schema_version": "1.0",
        "run_id": "run-1",
        "confirmation_status": "NOT_CONFIRMED",
        "disposition": "not_confirmed",
        "error": None,
        "artifacts": {"events": _run_artifact("events.jsonl")},
    }
    confirmed = deepcopy(common)
    confirmed.update(
        {
            "confirmation_status": "CONFIRMED",
            "disposition": "confirmed",
            "artifacts": {
                "certificate": _run_artifact(),
                "markdown": _run_artifact("certificate.md"),
                "poc": _run_artifact("QProverReplay.t.sol"),
                "events": _run_artifact("events.jsonl"),
                "qubo": _run_artifact("qubo.json"),
            },
        }
    )
    failed = deepcopy(common)
    failed.update(
        {"disposition": "failed", "error": "OSError: denied", "artifacts": {}}
    )
    return common, confirmed, failed


def _model_accepts(raw: dict[str, object]) -> bool:
    try:
        ProofRunResult.model_validate(raw)
    except ValidationError:
        return False
    return True


def _schema_accepts(raw: dict[str, object]) -> bool:
    schema = json.loads((ROOT / "schemas/proof-run-result.schema.json").read_text())
    return not tuple(jsonschema.Draft202012Validator(schema).iter_errors(raw))


def test_proof_run_result_model_and_schema_accept_the_same_complete_variants() -> None:
    for raw in _valid_run_results():
        assert _model_accepts(raw)
        assert _schema_accepts(raw)


def test_proof_run_result_model_and_schema_reject_exhaustive_invalid_matrix() -> None:
    not_confirmed, confirmed, failed = _valid_run_results()
    invalid: list[dict[str, object]] = []

    for field in (
        "schema_version",
        "run_id",
        "confirmation_status",
        "disposition",
        "error",
        "artifacts",
    ):
        case = deepcopy(not_confirmed)
        case.pop(field)
        invalid.append(case)
    for value in ("", "1.1", None):
        case = deepcopy(not_confirmed)
        case["schema_version"] = value
        invalid.append(case)

    for template, updates in (
        (confirmed, {"confirmation_status": "NOT_CONFIRMED"}),
        (confirmed, {"error": "unexpected"}),
        (not_confirmed, {"confirmation_status": "CONFIRMED"}),
        (not_confirmed, {"error": "unexpected"}),
        (failed, {"confirmation_status": "CONFIRMED"}),
        (failed, {"error": None}),
        (failed, {"error": ""}),
        (failed, {"error": "line one\nline two"}),
        (failed, {"artifacts": {"events": _run_artifact("events.jsonl")}}),
    ):
        case = deepcopy(template)
        case.update(updates)
        invalid.append(case)

    for required in ("certificate", "markdown", "poc", "events"):
        case = deepcopy(confirmed)
        case["artifacts"].pop(required)  # type: ignore[union-attr]
        invalid.append(case)
    for label in ("unknown", "../events", "https://labels.invalid/x"):
        case = deepcopy(not_confirmed)
        case["artifacts"] = {label: _run_artifact("events.jsonl")}
        invalid.append(case)
    for path in (
        "/tmp/evidence",
        "../evidence",
        "nested/../evidence",
        "https://example.invalid/evidence",
        "nested\\evidence",
        "./evidence",
        ".",
        "nested/./evidence",
        "evidence/",
        "C:/evidence",
        "file:evidence",
        "mailto:proof@example.invalid",
    ):
        case = deepcopy(not_confirmed)
        case["artifacts"] = {"events": _run_artifact(path)}
        invalid.append(case)
    case = deepcopy(not_confirmed)
    case["artifacts"] = {"certificate": _run_artifact()}
    invalid.append(case)
    case = deepcopy(confirmed)
    case["artifacts"]["unknown"] = _run_artifact("unknown")  # type: ignore[index]
    invalid.append(case)

    for index, raw in enumerate(invalid):
        assert not _model_accepts(raw), f"model accepted invalid case {index}: {raw}"
        assert not _schema_accepts(raw), f"schema accepted invalid case {index}: {raw}"
