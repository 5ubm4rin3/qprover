from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from qprover.certificate import ProofCertificate
from qprover.models import ConfirmationStatus, SearchLimits
from qprover.pipeline import prove_violation
from qprover.search.annealing import SimulatedAnnealingBackend
from qprover.search.qubo import QuboStrategy

ROOT = Path(__file__).parents[2]


def _strategy() -> QuboStrategy:
    return QuboStrategy(
        backend=SimulatedAnnealingBackend(),
        reads=128,
        feedback_batch_size=8,
        resample_attempts=0,
    )


def test_same_qubo_configuration_confirms_only_vulnerable_reentrancy_twin(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    original_read_bytes = Path.read_bytes
    original_read_text = Path.read_text

    def guarded_read_bytes(path: Path) -> bytes:
        if path.name in {"labels.json", "ScenarioWitnesses.t.sol"}:
            raise AssertionError("autonomous proof path read hidden benchmark evidence")
        return original_read_bytes(path)

    def guarded_read_text(path: Path, *args, **kwargs) -> str:
        if path.name in {"labels.json", "ScenarioWitnesses.t.sol"}:
            raise AssertionError("autonomous proof path read hidden benchmark evidence")
        return original_read_text(path, *args, **kwargs)

    monkeypatch.setattr(Path, "read_bytes", guarded_read_bytes)
    monkeypatch.setattr(Path, "read_text", guarded_read_text)
    limits = SearchLimits(
        max_sequence_length=3,
        transaction_budget=3,
        candidate_budget=1,
        wall_seconds=20,
    )
    vulnerable = prove_violation(
        ROOT / "benchmarks/scenario_reentrancy_a.json",
        strategy=_strategy(),
        seed=7,
        output=tmp_path / "a",
        workspace_root=ROOT,
        limits=limits,
    )
    sound = prove_violation(
        ROOT / "benchmarks/scenario_reentrancy_b.json",
        strategy=_strategy(),
        seed=7,
        output=tmp_path / "b",
        workspace_root=ROOT,
        limits=limits,
    )

    assert vulnerable.status is ConfirmationStatus.CONFIRMED
    assert vulnerable.search_run is not None
    assert vulnerable.search_run.strategy_stats.name == "qubo"
    assert vulnerable.search_run.candidates_evaluated == 1
    assert vulnerable.minimized_steps == 2
    assert vulnerable.certificate_path is not None
    certificate = ProofCertificate.model_validate_json(
        vulnerable.certificate_path.read_text()
    )
    assert certificate.confirmation_status is ConfirmationStatus.CONFIRMED
    assert len(certificate.replay.records) == 3
    assert vulnerable.qubo_path is not None
    qubo_evidence = json.loads(vulnerable.qubo_path.read_text())
    assert len(qubo_evidence["builds"]) >= 1
    assert (
        qubo_evidence["objective_provenance_sha256"]
        == hashlib.sha256(
            json.dumps(
                qubo_evidence["objective_provenance"],
                sort_keys=True,
                separators=(",", ":"),
            ).encode()
        ).hexdigest()
    )

    assert sound.status is ConfirmationStatus.NOT_CONFIRMED
    assert sound.certificate_path is None
    assert sound.search_run is not None
    assert sound.search_run.strategy_stats.name == "qubo"
    assert sound.search_run.candidates_evaluated == 1
    assert tuple(
        step.action_id for step in vulnerable.search_run.evaluations[0].candidate.steps
    ) == tuple(
        step.action_id for step in sound.search_run.evaluations[0].candidate.steps
    )


def test_pipeline_confirms_executed_invariant_only_violation_without_economic_claim(
    tmp_path: Path,
) -> None:
    result = prove_violation(
        ROOT / "benchmarks/invariant_only_fixture.json",
        strategy=QuboStrategy(
            backend=SimulatedAnnealingBackend(), reads=16, resample_attempts=0
        ),
        seed=3,
        output=tmp_path / "invariant-only",
        workspace_root=ROOT,
    )

    assert result.status is ConfirmationStatus.CONFIRMED, result.error
    assert result.certificate_path is not None
    certificate = ProofCertificate.model_validate_json(
        result.certificate_path.read_text()
    )
    assert certificate.confirmation_policy == "invariant_violation"
    assert certificate.invariant.value is False
    assert certificate.impact.applicability == "not_applicable"
    assert certificate.impact.attacker_delta is None
    assert "Attacker gain" not in result.markdown_path.read_text()


def test_pipeline_normalizes_a_tampered_live_certificate_field_to_not_confirmed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import qprover.pipeline as pipeline

    original = pipeline._certificate_data

    def tampered_certificate_data(**kwargs):
        data = original(**kwargs)
        impact = data["impact"]
        assert impact.attacker_delta is not None
        data["impact"] = impact.model_copy(
            update={"attacker_delta": impact.attacker_delta + 1}
        )
        return data

    monkeypatch.setattr(pipeline, "_certificate_data", tampered_certificate_data)
    result = prove_violation(
        ROOT / "benchmarks/scenario_reentrancy_a.json",
        strategy=_strategy(),
        seed=7,
        output=tmp_path / "tampered",
        workspace_root=ROOT,
        limits=SearchLimits(
            max_sequence_length=3,
            transaction_budget=3,
            candidate_budget=1,
            wall_seconds=20,
        ),
    )

    assert result.status is ConfirmationStatus.NOT_CONFIRMED
    assert result.certificate_path is None
    assert result.error is not None
    assert "delta does not match" in result.error
