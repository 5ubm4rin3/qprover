from __future__ import annotations

import subprocess
import tempfile
from pathlib import Path

import pytest
from task7_helpers import ZERO_HASH, digest, make_executed_certificate

from qprover.artifacts import build_target
from qprover.certificate import ProofCertificate, create_certificate, write_certificate
from qprover.evaluator import ScenarioEvaluator
from qprover.evm import LocalAnvil
from qprover.manifest import load_manifest
from qprover.minimizer import minimize
from qprover.models import ActionStep, Candidate, ConfirmationStatus
from qprover.replay import (
    ReplayError,
    cold_verify,
    foundry_poc_source,
    generate_foundry_poc,
)

ROOT = Path(__file__).parents[2]


def _candidate(manifest, family: str) -> Candidate:
    specs = {action.id: action for action in manifest.actions}
    witness = (
        (("step_alpha", (), 0), ("step_beta", (), 0))
        if family == "access_control"
        else (("step_alpha", (10**18,), 10**18), ("step_beta", (), 0))
    )
    return Candidate(
        tuple(
            ActionStep(
                action_id,
                specs[action_id].target_id,
                specs[action_id].signature,
                specs[action_id].sender_slots[0],
                args,
                value,
            )
            for action_id, args, value in witness
        )
    )


def _prepare(tmp_path: Path, family: str) -> Path:
    manifest_path = ROOT / f"benchmarks/scenario_{family}_a.json"
    manifest = load_manifest(manifest_path)
    with build_target(manifest) as bundle, LocalAnvil() as anvil:
        evaluator = ScenarioEvaluator(manifest, bundle, anvil)
        minimized = minimize(
            _candidate(manifest, family),
            evaluator,
            {action.id: action for action in manifest.actions},
        )
        provisional = make_executed_certificate(
            manifest=manifest,
            manifest_path=manifest_path,
            bundle=bundle,
            minimization=minimized,
            output_root=tmp_path,
            poc_sha256=ZERO_HASH,
        )
        source = foundry_poc_source(provisional, manifest)
        certificate = make_executed_certificate(
            manifest=manifest,
            manifest_path=manifest_path,
            bundle=bundle,
            minimization=minimized,
            output_root=tmp_path,
            poc_sha256=digest(source),
        )
        generate_foundry_poc(certificate, manifest, tmp_path)
        certificate_path = write_certificate(certificate, tmp_path / "certificate.json")
    return certificate_path


@pytest.mark.parametrize("family", ["access_control", "reentrancy"])
def test_cold_verify_runs_three_separate_offline_foundry_replays(
    tmp_path: Path, family: str
) -> None:
    certificate_path = _prepare(tmp_path, family)

    verification = cold_verify(certificate_path)

    assert verification.confirmation_status is ConfirmationStatus.CONFIRMED
    assert len(verification.records) == 3
    assert all(
        record.success and record.exit_code == 0 for record in verification.records
    )
    assert all(
        record.command[:3] == ("forge", "test", "--offline")
        for record in verification.records
    )
    assert len({record.stdout_sha256 for record in verification.records}) == 1
    assert len({record.stderr_sha256 for record in verification.records}) == 1
    assert len({record.command[-3] for record in verification.records}) == 3
    persisted = ProofCertificate.model_validate_json(certificate_path.read_text())
    assert persisted == verification.certificate
    assert persisted.certificate_sha256 == persisted.compute_hash()
    assert not tuple((ROOT / "benchmarks/foundry/test").glob(".qprover_replay_*.t.sol"))


def test_cold_verify_rejects_corruption_before_execution_and_cleans_paths(
    tmp_path: Path,
) -> None:
    certificate_path = _prepare(tmp_path, "access_control")
    certificate = ProofCertificate.model_validate_json(certificate_path.read_text())
    poc_path = tmp_path / certificate.poc.path
    poc_path.write_text(poc_path.read_text() + "// tampered\n")

    with pytest.raises(ReplayError, match="PoC hash"):
        cold_verify(certificate_path)

    assert not tuple((ROOT / "benchmarks/foundry/test").glob(".qprover_replay_*.t.sol"))


def test_failed_replays_remain_unconfirmed_and_clean_every_temporary_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    certificate_path = _prepare(tmp_path, "access_control")
    real_run = subprocess.run
    test_calls: list[tuple[str, ...]] = []
    temp_root = Path(tempfile.gettempdir())
    cold_directories_before = set(temp_root.glob("qprover-cold-*"))

    def fail_tests(command, **kwargs):
        if command[:2] == ("forge", "test"):
            test_calls.append(command)
            return subprocess.CompletedProcess(command, 1, "failed", "revert")
        return real_run(command, **kwargs)

    monkeypatch.setattr("qprover.replay.subprocess.run", fail_tests)
    verification = cold_verify(certificate_path)

    assert len(test_calls) == 3
    assert verification.confirmation_status is ConfirmationStatus.NOT_CONFIRMED
    assert all(not record.success for record in verification.records)
    assert not tuple((ROOT / "benchmarks/foundry/test").glob(".qprover_replay_*.t.sol"))
    assert set(temp_root.glob("qprover-cold-*")) == cold_directories_before


def test_cold_verify_rejects_artifact_identity_tampering(tmp_path: Path) -> None:
    certificate_path = _prepare(tmp_path, "access_control")
    certificate = ProofCertificate.model_validate_json(certificate_path.read_text())
    data = certificate.model_dump(mode="python")
    data.pop("certificate_identity_sha256")
    data.pop("certificate_sha256")
    wrong = "f" * 64
    data["artifacts"] = (
        certificate.artifacts[0].model_copy(update={"artifact_sha256": wrong}),
    )
    data["poc"] = certificate.poc.model_copy(update={"artifact_sha256": wrong})
    tampered = create_certificate(**data)
    write_certificate(tampered, certificate_path)

    with pytest.raises(ReplayError, match="artifact hash mismatch"):
        cold_verify(certificate_path)


def test_cold_verify_refuses_any_repeat_count_other_than_three(tmp_path: Path) -> None:
    certificate_path = _prepare(tmp_path, "access_control")
    with pytest.raises(ReplayError, match="exactly 3"):
        cold_verify(certificate_path, repeats=2)
