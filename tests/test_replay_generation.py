from __future__ import annotations

import shutil
from pathlib import Path

import pytest
from task7_helpers import ZERO_HASH, digest, make_executed_certificate

import qprover.replay as replay_module
from qprover.artifacts import build_target
from qprover.evaluator import ScenarioEvaluator
from qprover.evm import LocalAnvil
from qprover.manifest import load_manifest
from qprover.minimizer import minimize
from qprover.models import ActionStep, Candidate
from qprover.replay import ReplayError, foundry_poc_source, generate_foundry_poc
from qprover.runtime import ExecutionRuntime
from qprover.safeio import StaleOwnershipError

ROOT = Path(__file__).parents[1]


def test_replay_temp_cleanup_never_deletes_recreated_later_owner_path() -> None:
    with ExecutionRuntime.activate() as runtime:
        owned = replay_module._owned_temporary_directory("qprover-reuse-test-")
        detached = owned.path.with_name(f"{owned.path.name}-detached")
        owned.path.rename(detached)
        owned.path.mkdir()
        marker = owned.path / "later-owner"
        marker.write_text("survives")

        with pytest.raises(StaleOwnershipError, match="not proven cleaned"):
            owned.close()

        assert runtime.has_pending_cleanup is False
        assert runtime.cleanup_warnings

    assert marker.read_text() == "survives"
    assert detached.is_dir()
    shutil.rmtree(owned.path)
    shutil.rmtree(detached)


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


@pytest.mark.parametrize("family", ["access_control", "reentrancy"])
def test_generated_poc_is_exact_local_assertion_driven_fixture_replay(
    tmp_path: Path, family: str
) -> None:
    manifest_path = ROOT / f"benchmarks/scenario_{family}_a.json"
    manifest = load_manifest(manifest_path)
    candidate = _candidate(manifest, family)
    with build_target(manifest) as bundle, LocalAnvil() as anvil:
        evaluator = ScenarioEvaluator(manifest, bundle, anvil)
        minimized = minimize(candidate, evaluator, {a.id: a for a in manifest.actions})
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
        output = generate_foundry_poc(certificate, manifest, tmp_path)

    assert output == tmp_path / certificate.poc.path
    assert output.read_text() == source
    assert f"import {{{manifest.deployments[0].artifact.rsplit(':', 1)[1]}}}" in source
    assert "abi.encodeWithSignature" in source
    assert "test_qprover_replay" in source
    assert "assert(!" in source
    assert "final_protocol_assets >= initial_protocol_assets" in source
    assert "contract QProverActor" not in source
    assert "function prank(address msgSender, address txOrigin) external;" in source
    assert "address(uint160(0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266))" in source
    initial_assets = certificate.initial_state.values["protocol_assets"]
    final_assets = certificate.before_after.after.values["protocol_assets"]
    assert f"assert(initial_protocol_assets == {initial_assets});" in source
    assert f"assert(final_protocol_assets == {final_assets});" in source
    assert str(abs(certificate.impact.protocol_delta)) in source
    for forbidden in (
        "vm.store",
        "vm.load",
        "vm.etch",
        "ffi",
        "http://",
        "https://",
        "createFork",
        "selectFork",
        "private key",
        "vm.label",
    ):
        assert forbidden not in source
    assert source.count("vm.deal(") == len(manifest.actors)
    assert source.count("vm.prank(") == len(manifest.deployments) + len(
        certificate.transactions
    )


def test_poc_generation_rejects_hash_and_manifest_identity_mismatch(
    tmp_path: Path,
) -> None:
    manifest_path = ROOT / "benchmarks/scenario_access_control_a.json"
    manifest = load_manifest(manifest_path)
    with build_target(manifest) as bundle, LocalAnvil() as anvil:
        evaluator = ScenarioEvaluator(manifest, bundle, anvil)
        minimized = minimize(
            _candidate(manifest, "access_control"),
            evaluator,
            {a.id: a for a in manifest.actions},
        )
        certificate = make_executed_certificate(
            manifest=manifest,
            manifest_path=manifest_path,
            bundle=bundle,
            minimization=minimized,
            output_root=tmp_path,
        )
    with pytest.raises(ReplayError, match="PoC hash"):
        generate_foundry_poc(certificate, manifest, tmp_path)
    other = load_manifest(ROOT / "benchmarks/scenario_access_control_b.json")
    with pytest.raises(ReplayError, match="manifest identity"):
        foundry_poc_source(certificate, other)
