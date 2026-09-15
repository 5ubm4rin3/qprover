from __future__ import annotations

import hashlib
import json
import multiprocessing
import os
from pathlib import Path

import jsonschema
import pytest
from pydantic import ValidationError

from qprover.benchmark import (
    BenchmarkConfig,
    BenchmarkMatrix,
    BenchmarkRun,
    BenchmarkScore,
    BenchmarkSuite,
    BenchmarkTargetIdentity,
    NotApplicableStrategyEvidence,
    RandomStrategyConfig,
    TimingEvidence,
    ToolchainIdentity,
    append_run,
    expected_run_keys,
    load_run_journal,
    score_complete_matrix,
    seal_run,
)
from qprover.models import SearchLimits

ROOT = Path(__file__).parents[1]
ZERO = "0" * 64


def _append_worker(path: str, raw_json: str, queue) -> None:
    try:
        row = BenchmarkRun.model_validate(json.loads(raw_json))
        append_run(Path(path), row)
    except ValueError as error:
        if "already committed" in str(error):
            queue.put("duplicate")
            return
        queue.put(f"error:{type(error).__name__}:{error}")
        return
    except BaseException as error:  # pragma: no cover - child diagnostic
        queue.put(f"error:{type(error).__name__}:{error}")
        return
    queue.put("ok")


def digest(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def limits() -> SearchLimits:
    return SearchLimits(
        max_sequence_length=3,
        max_variants=32,
        transaction_budget=24,
        candidate_budget=8,
        wall_seconds=20,
    )


def matrix() -> BenchmarkMatrix:
    target = BenchmarkTargetIdentity(
        public_target_id="scenario_access_control_b",
        manifest_path="scenario_access_control_b.json",
        manifest_sha256="1" * 64,
        source_closure_sha256="2" * 64,
        build_sha256="3" * 64,
        problem_sha256="4" * 64,
        effective_limits=limits(),
    )
    raw = {
        "schema_version": "1.0",
        "suite_sha256": digest(
            {
                "schema_version": "1.0",
                "manifests": ["scenario_access_control_b.json"],
                "seeds": [11],
            }
        ),
        "config_sha256": digest(
            {
                "schema_version": "1.0",
                "strategies": [{"name": "random", "proposal_attempts": 256}],
                "candidate_budget": 8,
                "transaction_budget": 24,
                "wall_seconds": 20,
                "manifest_subset": None,
                "seed_subset": None,
            }
        ),
        "qprover_source_sha256": "7" * 64,
        "lockfile_sha256": "8" * 64,
        "toolchain": ToolchainIdentity(
            python="3.14", uv="uv 1", forge="forge 1", anvil="anvil 1"
        ).model_dump(mode="json"),
        "git_revision": "abc",
        "git_dirty": False,
        "targets": [target.model_dump(mode="json")],
    }
    return BenchmarkMatrix(matrix_id=digest(raw), **raw)


def suite() -> BenchmarkSuite:
    return BenchmarkSuite(
        schema_version="1.0",
        manifests=("scenario_access_control_b.json",),
        seeds=(11,),
    )


def config() -> BenchmarkConfig:
    return BenchmarkConfig(
        schema_version="1.0",
        strategies=(RandomStrategyConfig(name="random"),),
        candidate_budget=8,
        transaction_budget=24,
        wall_seconds=20,
    )


def run(*, state: str = "completed", error: str | None = None) -> BenchmarkRun:
    mat = matrix()
    cfg = config()
    run_key = expected_run_keys(mat, suite(), cfg)[0]
    raw: dict[str, object] = {
        "schema_version": "1.0",
        "run_key": run_key,
        "matrix_id": mat.matrix_id,
        "public_target_id": "scenario_access_control_b",
        "manifest_sha256": "1" * 64,
        "source_closure_sha256": "2" * 64,
        "build_sha256": "3" * 64,
        "problem_sha256": "4" * 64,
        "qprover_source_sha256": "7" * 64,
        "lockfile_sha256": "8" * 64,
        "toolchain_sha256": digest(mat.toolchain.model_dump(mode="json")),
        "strategy": "random",
        "strategy_config_sha256": digest(cfg.strategies[0].model_dump(mode="json")),
        "seed": 11,
        "effective_limits": limits().model_dump(mode="json"),
        "state": state,
        "confirmation_status": "NOT_CONFIRMED",
        "stop_reason": "candidate_budget" if state == "completed" else None,
        "error": error,
        "executed_violation": False if state == "completed" else None,
        "search_hit": False if state == "completed" else None,
        "proof_attempted": False if state == "completed" else None,
        "hit_observation": "censored" if state == "completed" else None,
        "candidates_evaluated": 2 if state == "completed" else None,
        "duplicate_proposals": 0 if state == "completed" else None,
        "unique_trace_features": 0 if state == "completed" else None,
        "search_transactions": 3 if state == "completed" else None,
        "total_transactions": None,
        "minimized_steps": None,
        "first_hit_candidate": None,
        "first_hit_transactions": None,
        "outcome_counts": {"PASS": 2} if state == "completed" else {},
        "certificate_sha256": None,
        "cold_replays": None,
        "artifacts": {},
        "strategy_evidence": NotApplicableStrategyEvidence(
            kind="not_applicable"
        ).model_dump(mode="json"),
        "timings": TimingEvidence(
            total_seconds=1.0,
            search_seconds=0.5,
            setup_seconds=None,
            proof_seconds=None,
        ).model_dump(mode="json"),
    }
    return seal_run(raw)


def test_committed_public_suite_is_valid_and_has_no_labels() -> None:
    raw = json.loads((ROOT / "benchmarks/suite.json").read_text())
    loaded = BenchmarkSuite.model_validate(raw)
    assert len(loaded.manifests) == 12
    assert len(loaded.seeds) == 10
    assert "labels" not in loaded.model_dump(mode="json")
    assert "strategies" not in loaded.model_dump(mode="json")


def test_suite_rejects_duplicates_booleans_and_unknown_fields() -> None:
    with pytest.raises(ValidationError):
        BenchmarkSuite(
            schema_version="1.0",
            manifests=("a.json", "a.json"),
            seeds=(11,),
        )
    with pytest.raises(ValidationError):
        BenchmarkSuite.model_validate(
            {"schema_version": "1.0", "manifests": ["a.json"], "seeds": [True]}
        )
    with pytest.raises(ValidationError):
        BenchmarkSuite.model_validate(
            {
                "schema_version": "1.0",
                "manifests": ["a.json"],
                "seeds": [11],
                "labels": "labels.json",
            }
        )


def test_config_rejects_duplicate_strategies() -> None:
    with pytest.raises(ValidationError, match="duplicate benchmark strategy"):
        BenchmarkConfig(
            schema_version="1.0",
            strategies=(
                RandomStrategyConfig(name="random"),
                RandomStrategyConfig(name="random"),
            ),
        )


def test_run_is_self_hashed_and_label_free() -> None:
    row = run()
    assert row.row_sha256 == row.computed_row_sha256()
    dumped = row.model_dump(mode="json")
    forbidden = {"expected", "witness", "labels", "pair", "family"}
    assert forbidden.isdisjoint(dumped)
    with pytest.raises(ValidationError):
        BenchmarkRun.model_validate({**dumped, "expected": "negative"})


def test_schema_parity_for_suite_run_and_score() -> None:
    for filename, model in (
        ("benchmark-suite.schema.json", BenchmarkSuite),
        ("benchmark-run.schema.json", BenchmarkRun),
        ("benchmark-score.schema.json", BenchmarkScore),
    ):
        published = json.loads((ROOT / "schemas" / filename).read_text())
        assert published == model.model_json_schema()
        jsonschema.Draft202012Validator.check_schema(published)
        assert published["additionalProperties"] is False


def test_journal_rejects_duplicates_partial_lines_and_symlink_parent(
    tmp_path: Path,
) -> None:
    row = run()
    journal = tmp_path / "raw" / "runs.jsonl"
    append_run(journal, row)
    assert load_run_journal(journal, matrix_id=row.matrix_id) == (row,)
    with pytest.raises(ValueError, match="already committed"):
        append_run(journal, row)

    partial = tmp_path / "partial.jsonl"
    partial.write_text(json.dumps(row.model_dump(mode="json")))
    with pytest.raises(ValueError, match="partial trailing line"):
        load_run_journal(partial)

    real = tmp_path / "real"
    real.mkdir()
    link = tmp_path / "link"
    link.symlink_to(real, target_is_directory=True)
    with pytest.raises(ValueError, match="parent chain"):
        append_run(link / "runs.jsonl", row)


def test_journal_rejects_hardlinked_target(tmp_path: Path) -> None:
    row = run()
    first = tmp_path / "runs.jsonl"
    append_run(first, row)
    hard = tmp_path / "other.jsonl"
    os.link(first, hard)
    with pytest.raises(ValueError, match="single-link"):
        load_run_journal(hard)


def test_scoring_waits_for_complete_matrix_and_failure_is_not_true_negative(
    tmp_path: Path,
) -> None:
    mat = matrix()
    cfg = config()
    labels = {
        "scenario_access_control_b": {
            "expected": "negative",
            "family": "access_control",
            "pair": "b",
            "witness": ["claimRole()", "drain()"],
        }
    }
    labels_path = tmp_path / "labels.json"
    labels_path.write_text(json.dumps(labels))

    with pytest.raises(ValueError, match="full matrix"):
        score_complete_matrix(
            matrix=mat,
            suite=suite(),
            config=cfg,
            runs=(),
            labels_path=labels_path,
        )

    failed = run(state="failed", error="infrastructure failure")
    scores = score_complete_matrix(
        matrix=mat,
        suite=suite(),
        config=cfg,
        runs=(failed,),
        labels_path=labels_path,
    )
    assert scores[0].predicted == "failure"
    assert scores[0].correct is False
    assert "witness" not in scores[0].model_dump(mode="json")


def test_incomplete_matrix_does_not_open_labels(tmp_path: Path, monkeypatch) -> None:
    labels_path = tmp_path / "labels.json"
    labels_path.write_text("{}")
    touched = False
    original = Path.read_bytes

    def guarded(self: Path) -> bytes:
        nonlocal touched
        if self == labels_path:
            touched = True
        return original(self)

    monkeypatch.setattr(Path, "read_bytes", guarded)
    with pytest.raises(ValueError, match="full matrix"):
        score_complete_matrix(
            matrix=matrix(),
            suite=suite(),
            config=config(),
            runs=(),
            labels_path=labels_path,
        )
    assert touched is False


def test_journal_revalidates_artifact_hash_and_rejects_links(tmp_path: Path) -> None:
    artifact = tmp_path / "cells" / "proof.json"
    artifact.parent.mkdir()
    artifact.write_text("evidence")
    base = run().model_dump(mode="json")
    base.pop("row_sha256")
    base["artifacts"] = {
        "proof": {
            "path": "cells/proof.json",
            "sha256": hashlib.sha256(b"evidence").hexdigest(),
        }
    }
    row = seal_run(base)
    journal = tmp_path / "runs.jsonl"
    append_run(journal, row)
    assert load_run_journal(journal) == (row,)

    artifact.write_text("tampered")
    with pytest.raises(ValueError, match="hash validation"):
        load_run_journal(journal)

    artifact.unlink()
    victim = tmp_path / "victim"
    victim.write_text("evidence")
    artifact.symlink_to(victim)
    with pytest.raises(ValueError, match="single-link regular file"):
        load_run_journal(journal)


def test_run_key_is_bound_to_row_identity() -> None:
    dumped = run().model_dump(mode="json")
    dumped["problem_sha256"] = "f" * 64
    dumped.pop("row_sha256")
    dumped["row_sha256"] = digest(
        {key: value for key, value in dumped.items() if key != "row_sha256"}
    )
    with pytest.raises(ValidationError, match="run_key does not match run identity"):
        BenchmarkRun.model_validate(dumped)


def test_scoring_rejects_suite_or_config_drift_before_opening_labels(
    tmp_path: Path, monkeypatch
) -> None:
    mat = matrix()
    row = run()
    labels_path = tmp_path / "labels.json"
    labels_path.write_text(
        json.dumps(
            {
                "scenario_access_control_b": {
                    "expected": "negative",
                    "family": "access_control",
                    "pair": "b",
                    "witness": ["claimRole()", "drain()"],
                }
            }
        )
    )
    opened = False
    original = Path.read_bytes

    def guarded(self: Path) -> bytes:
        nonlocal opened
        if self == labels_path:
            opened = True
        return original(self)

    monkeypatch.setattr(Path, "read_bytes", guarded)
    drifted = BenchmarkSuite(
        schema_version="1.0",
        manifests=("scenario_access_control_b.json",),
        seeds=(11, 23),
    )
    with pytest.raises(ValueError, match="suite identity"):
        score_complete_matrix(
            matrix=mat,
            suite=drifted,
            config=config(),
            runs=(row,),
            labels_path=labels_path,
        )
    assert opened is False


def _rehash_run(raw: dict[str, object]) -> dict[str, object]:
    raw = dict(raw)
    raw.pop("row_sha256", None)
    raw["row_sha256"] = digest(raw)
    return raw


def _model_accepts_run(raw: dict[str, object]) -> bool:
    try:
        BenchmarkRun.model_validate(raw)
    except ValidationError:
        return False
    return True


def _schema_accepts_run(raw: dict[str, object]) -> bool:
    schema = json.loads((ROOT / "schemas/benchmark-run.schema.json").read_text())
    return not tuple(jsonschema.Draft202012Validator(schema).iter_errors(raw))


def test_run_schema_matches_structural_proof_state_rejections() -> None:
    base = run().model_dump(mode="json")
    cases: list[dict[str, object]] = []

    accepted_hit_without_confirmation = dict(base)
    accepted_hit_without_confirmation.update(
        {
            "search_hit": True,
            "proof_attempted": True,
            "hit_observation": "observed",
            "first_hit_candidate": 1,
            "first_hit_transactions": 1,
        }
    )
    cases.append(_rehash_run(accepted_hit_without_confirmation))

    unconfirmed_with_certificate = dict(base)
    unconfirmed_with_certificate["certificate_sha256"] = "f" * 64
    unconfirmed_with_certificate["cold_replays"] = 3
    cases.append(_rehash_run(unconfirmed_with_certificate))

    failed_with_certificate = run(
        state="failed", error="controlled infrastructure failure"
    ).model_dump(mode="json")
    failed_with_certificate["certificate_sha256"] = "e" * 64
    failed_with_certificate["cold_replays"] = 3
    cases.append(_rehash_run(failed_with_certificate))

    for raw in cases:
        assert _model_accepts_run(raw) is False
        assert _schema_accepts_run(raw) is False


def test_concurrent_journal_append_commits_exactly_one_duplicate_key(
    tmp_path: Path,
) -> None:
    row = run()
    journal = tmp_path / "runs.jsonl"
    raw_json = row.model_dump_json()
    context = multiprocessing.get_context("spawn")
    queue = context.Queue()
    processes = [
        context.Process(
            target=_append_worker,
            args=(str(journal), raw_json, queue),
        )
        for _ in range(2)
    ]
    for process in processes:
        process.start()
    for process in processes:
        process.join(10)
        assert process.exitcode == 0
    results = sorted(queue.get(timeout=2) for _ in processes)
    assert results == ["duplicate", "ok"]
    assert load_run_journal(journal) == (row,)


def test_append_rejects_artifact_tampering_before_committing_row(
    tmp_path: Path,
) -> None:
    artifact = tmp_path / "cells" / "proof.json"
    artifact.parent.mkdir()
    artifact.write_text("evidence")
    raw = run().model_dump(mode="json")
    raw.pop("row_sha256")
    raw["artifacts"] = {
        "proof": {
            "path": "cells/proof.json",
            "sha256": hashlib.sha256(b"evidence").hexdigest(),
        }
    }
    row = seal_run(raw)
    artifact.write_text("tampered")
    journal = tmp_path / "runs.jsonl"

    with pytest.raises(ValueError, match="hash validation"):
        append_run(journal, row)

    assert not journal.exists()


def test_confirmed_run_schema_requires_bound_artifacts_and_violation() -> None:
    raw = run().model_dump(mode="json")
    raw.update(
        {
            "confirmation_status": "CONFIRMED",
            "executed_violation": False,
            "search_hit": True,
            "proof_attempted": True,
            "hit_observation": "observed",
            "first_hit_candidate": 1,
            "first_hit_transactions": 1,
            "certificate_sha256": "f" * 64,
            "cold_replays": 3,
            "artifacts": {},
        }
    )
    raw = _rehash_run(raw)
    assert _model_accepts_run(raw) is False
    assert _schema_accepts_run(raw) is False


def test_confirmed_run_requires_executed_violation_flag() -> None:
    raw = run().model_dump(mode="json")
    artifact = {"path": "cells/proof.json", "sha256": "a" * 64}
    raw.update(
        {
            "confirmation_status": "CONFIRMED",
            "executed_violation": False,
            "search_hit": True,
            "proof_attempted": True,
            "hit_observation": "observed",
            "first_hit_candidate": 1,
            "first_hit_transactions": 1,
            "certificate_sha256": "f" * 64,
            "cold_replays": 3,
            "artifacts": {
                "result": artifact,
                "certificate": artifact,
                "poc": artifact,
                "events": artifact,
            },
        }
    )
    raw = _rehash_run(raw)
    assert _model_accepts_run(raw) is False
    assert _schema_accepts_run(raw) is False


def test_matrix_loader_rejects_duplicate_keys_and_link_targets(tmp_path: Path) -> None:
    from qprover.benchmark import load_matrix

    path = tmp_path / "matrix.json"
    raw = matrix().model_dump(mode="json")
    text = json.dumps(raw, separators=(",", ":"))
    duplicate = text[:-1] + f',"matrix_id":"{raw["matrix_id"]}"}}'
    path.write_text(duplicate)
    with pytest.raises(ValueError, match="duplicate JSON key"):
        load_matrix(path)

    path.unlink()
    target = tmp_path / "target.json"
    target.write_text(matrix().model_dump_json())
    path.symlink_to(target)
    with pytest.raises(ValueError, match="single-link regular file"):
        load_matrix(path)


def _qubo_fixture(problem_sha: str) -> dict[str, object]:
    model = {
        "problem_sha256": "b" * 64,
        "variables": ["x"],
        "linear": [[0, -1.0]],
        "quadratic": [],
        "offset": 0.0,
        "non_constraint_linear": [[0, -1.0]],
        "non_constraint_quadratic": [],
        "constraint_penalty": 2.0,
    }
    model_sha = digest(model)
    return {
        "schema_version": "1.0",
        "strategy": "qubo",
        "seed": 23,
        "problem_sha256": problem_sha,
        "prepared_problem_sha256": problem_sha,
        "problem": {},
        "solver_totals": {
            "calls": 1,
            "reads": 64,
            "sweeps": 120,
            "wall_seconds": 0.25,
            "compute_wall_seconds": 0.25,
            "decoded_feasible": 1,
            "decoded_infeasible": 0,
        },
        "fallback": {
            "calls": 0,
            "wall_seconds": 0.0,
            "records": [],
            "exact_fallbacks": 0,
            "feasible_count_exact": False,
            "feasible_space_count": 0,
            "fallback_space_bound": 0,
        },
        "builds": [
            {
                "build_index": 0,
                "problem_sha256": "b" * 64,
                "model_sha256": model_sha,
                "logical_bits": 1,
                "couplers": 0,
                "decoded_feasible": 1,
                "decoded_infeasible": 0,
                "solver": {
                    "backend": "simulated_annealing",
                    "logical_bits": 1,
                    "reads": 64,
                    "sweeps": 120,
                    "wall_seconds": 0.25,
                },
                "model": model,
                "best_objective_components": {},
            }
        ],
    }


def test_qubo_summary_recomputes_embedded_model_hash(tmp_path: Path) -> None:
    from qprover.benchmark import _qubo_summary

    problem_sha = "c" * 64
    raw = _qubo_fixture(problem_sha)
    path = tmp_path / "qubo.json"
    path.write_text(json.dumps(raw))
    assert _qubo_summary(path, None, expected_problem_sha256=problem_sha).kind == "qubo"

    raw["builds"][0]["model"]["offset"] = 9.0  # type: ignore[index]
    path.write_text(json.dumps(raw))
    with pytest.raises(ValueError, match="model hash"):
        _qubo_summary(path, None, expected_problem_sha256=problem_sha)
