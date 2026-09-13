from __future__ import annotations

from pathlib import Path

import pytest
from task7_helpers import ZERO_HASH, digest, make_executed_certificate

from qprover.artifacts import build_target
from qprover.evaluator import ScenarioEvaluator
from qprover.evm import LocalAnvil
from qprover.manifest import load_manifest
from qprover.minimizer import minimize
from qprover.models import ActionStep, Candidate
from qprover.replay import ReplayError, foundry_poc_source, generate_foundry_poc

ROOT = Path(__file__).parents[1]


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
        "vm.prank",
        "vm.label",
    ):
        assert forbidden not in source
    assert source.count("vm.deal(") == len(manifest.actors)


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
