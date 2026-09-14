from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest
from task7_helpers import ZERO_HASH, digest, make_executed_certificate

import qprover.replay as replay_module
from qprover.artifacts import build_target
from qprover.certificate import (
    GasEvidence,
    ProofCertificate,
    create_certificate,
    write_certificate,
)
from qprover.evaluator import ScenarioEvaluator
from qprover.evm import LocalAnvil
from qprover.manifest import load_manifest
from qprover.minimizer import MinimizationResult, minimize
from qprover.models import ActionStep, Candidate, ConfirmationStatus
from qprover.replay import (
    ReplayError,
    cold_verify,
    foundry_poc_source,
    generate_foundry_poc,
    materialize_replay_recipe,
    parse_structured_replay_output,
)

ROOT = Path(__file__).parents[2]
DUPLICATE_SUITE_JSON = """{
  "test/QProverReplay.t.sol:QProverReplayTest": {
    "test_results": {
      "test_qprover_replay()": {
        "status": "Success", "reason": null, "counterexample": null
      }
    }
  },
  "test/QProverReplay.t.sol:QProverReplayTest": {
    "test_results": {
      "test_qprover_replay()": {
        "status": "Success", "reason": null, "counterexample": null
      }
    }
  }
}"""
DUPLICATE_TEST_JSON = """{
  "test/QProverReplay.t.sol:QProverReplayTest": {
    "test_results": {
      "test_qprover_replay()": {
        "status": "Success", "reason": null, "counterexample": null
      },
      "test_qprover_replay()": {
        "status": "Success", "reason": null, "counterexample": null
      }
    }
  }
}"""


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
    assert verification.certificate.replay.recipe is not None
    recipe = verification.certificate.replay.recipe
    assert recipe.argv_template[:3] == ("forge", "test", "--offline")
    assert recipe.execution_cwd == "{private_project}"
    assert recipe.staged_poc == "test/QProverReplay.t.sol"
    assert len({record.stdout_sha256 for record in verification.records}) == 1
    assert len({record.stderr_sha256 for record in verification.records}) == 1
    assert (
        len({record.structured_result_sha256 for record in verification.records}) == 1
    )
    assert len({record.execution_argv_sha256 for record in verification.records}) == 3
    assert len({record.execution_cwd_sha256 for record in verification.records}) == 3
    assert all(record.suite_count == 1 for record in verification.records)
    assert all(record.test_count == 1 for record in verification.records)
    assert all(
        record.executed_test == "test_qprover_replay()"
        and record.executed_status == "Success"
        for record in verification.records
    )
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

    monkeypatch.setattr("qprover.replay.subprocess.run", real_run)
    retried = cold_verify(certificate_path)
    assert retried.confirmation_status is ConfirmationStatus.CONFIRMED


def test_cold_verify_is_repeatable_for_published_confirmed_certificate(
    tmp_path: Path,
) -> None:
    certificate_path = _prepare(tmp_path, "access_control")
    first = cold_verify(certificate_path)

    second = cold_verify(certificate_path)

    assert first.confirmation_status is ConfirmationStatus.CONFIRMED
    assert second.confirmation_status is ConfirmationStatus.CONFIRMED
    assert (
        first.certificate.certificate_identity_sha256
        == second.certificate.certificate_identity_sha256
    )


def test_zero_exit_replays_with_distinct_output_remain_unconfirmed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A zero exit code cannot hide semantically divergent replay output."""

    certificate_path = _prepare(tmp_path, "access_control")
    real_run = subprocess.run
    test_index = 0

    def vary_test_output(command, **kwargs):
        nonlocal test_index
        if command[:2] == ("forge", "test"):
            test_index += 1
            return subprocess.CompletedProcess(command, 0, f"replay-{test_index}", "")
        return real_run(command, **kwargs)

    monkeypatch.setattr("qprover.replay.subprocess.run", vary_test_output)

    verification = cold_verify(certificate_path)

    assert test_index == 3
    assert verification.confirmation_status is ConfirmationStatus.NOT_CONFIRMED
    assert len({record.stdout_sha256 for record in verification.records}) == 3


@pytest.mark.parametrize(
    "stdout",
    (
        "{}",
        json.dumps(
            {
                "test/QProverReplay.t.sol:QProverReplayTest": {
                    "test_results": {"different_test()": {"status": "Success"}}
                }
            }
        ),
        json.dumps(
            {
                "test/QProverReplay.t.sol:QProverReplayTest": {
                    "test_results": {
                        "test_qprover_replay()": {"status": "Success"},
                        "extra_test()": {"status": "Success"},
                    }
                }
            }
        ),
        json.dumps(
            {
                "test/QProverReplay.t.sol:QProverReplayTest": {
                    "test_results": {
                        "test_qprover_replay()": {
                            "status": "Failure",
                            "reason": "assertion failed",
                            "counterexample": None,
                        }
                    }
                }
            }
        ),
        json.dumps(
            {
                "test/QProverReplay.t.sol:QProverReplayTest": {
                    "test_results": {
                        "test_qprover_replay()": {
                            "status": "Skipped",
                            "reason": None,
                            "counterexample": None,
                        }
                    }
                }
            }
        ),
        "not-json",
        DUPLICATE_SUITE_JSON,
        DUPLICATE_TEST_JSON,
    ),
)
def test_zero_exit_without_exact_structured_test_pass_is_unconfirmed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, stdout: str
) -> None:
    certificate_path = _prepare(tmp_path, "access_control")
    real_run = subprocess.run
    temp_root = Path(tempfile.gettempdir())
    cold_directories_before = set(temp_root.glob("qprover-cold-*"))

    def forged_result(command, **kwargs):
        if command[:2] == ("forge", "test"):
            return subprocess.CompletedProcess(command, 0, stdout, "")
        return real_run(command, **kwargs)

    monkeypatch.setattr("qprover.replay.subprocess.run", forged_result)

    verification = cold_verify(certificate_path)

    assert verification.confirmation_status is ConfirmationStatus.NOT_CONFIRMED
    assert all(not record.success for record in verification.records)
    assert set(temp_root.glob("qprover-cold-*")) == cold_directories_before


@pytest.mark.parametrize("stdout", (DUPLICATE_SUITE_JSON, DUPLICATE_TEST_JSON))
def test_structured_replay_parser_marks_duplicate_keys_malformed(stdout: str) -> None:
    parsed = parse_structured_replay_output(stdout, 0)

    assert parsed.success is False
    assert parsed.malformed is True
    assert parsed.suite_count == 0
    assert parsed.test_count == 0


def test_staged_poc_replacement_cannot_confirm_zero_tests(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    certificate_path = _prepare(tmp_path, "access_control")
    real_run = subprocess.run

    def replace_staged_poc(command, **kwargs):
        if command[:2] == ("forge", "test"):
            staged_poc = Path(command[4]) / command[6]
            staged_poc.write_text(
                "// SPDX-License-Identifier: Apache-2.0\n"
                "pragma solidity 0.8.34;\n"
                "contract NoReplayTest {}\n"
            )
        return real_run(command, **kwargs)

    monkeypatch.setattr("qprover.replay.subprocess.run", replace_staged_poc)

    verification = cold_verify(certificate_path)

    assert verification.confirmation_status is ConfirmationStatus.NOT_CONFIRMED
    assert all(not record.success for record in verification.records)
    assert not tuple((ROOT / "benchmarks/foundry/test").glob(".qprover_replay_*.t.sol"))


def test_post_execution_hash_rejects_same_process_staging_mutation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    certificate_path = _prepare(tmp_path, "access_control")
    valid_json = json.dumps(
        {
            "test/QProverReplay.t.sol:QProverReplayTest": {
                "test_results": {
                    "test_qprover_replay()": {
                        "status": "Success",
                        "reason": None,
                        "counterexample": None,
                    }
                }
            }
        }
    )

    def mutate_and_forge_success(command, **kwargs):
        assert command[:2] == ("forge", "test")
        staged_poc = Path(command[4]) / command[6]
        staged_poc.chmod(0o600)
        staged_poc.write_text("contract NoReplayTest {}\n")
        return subprocess.CompletedProcess(command, 0, valid_json, "")

    real_run = subprocess.run

    def dispatch(command, **kwargs):
        if command[:2] == ("forge", "test"):
            return mutate_and_forge_success(command, **kwargs)
        return real_run(command, **kwargs)

    monkeypatch.setattr("qprover.replay.subprocess.run", dispatch)

    verification = cold_verify(certificate_path)

    assert verification.confirmation_status is ConfirmationStatus.NOT_CONFIRMED
    assert all(not record.staging_unchanged for record in verification.records)


def test_persisted_replay_evidence_reproduces_the_named_test_after_relocation(
    tmp_path: Path,
) -> None:
    certificate_path = _prepare(tmp_path / "run", "access_control")
    verification = cold_verify(certificate_path)
    relocated = tmp_path / "clean-clone"
    shutil.copytree(ROOT / "benchmarks", relocated / "benchmarks")
    certificate = verification.certificate
    recipe = certificate.replay.recipe
    assert recipe is not None
    manifest = load_manifest(relocated / certificate.target.manifest_path)
    poc_bytes = (certificate_path.parent / certificate.poc.path).read_bytes()
    private_root = Path(tempfile.mkdtemp(prefix="qprover-recipe-test-"))
    try:
        materialization = materialize_replay_recipe(
            certificate, manifest, recipe, poc_bytes, private_root
        )
        result = subprocess.run(
            materialization.argv,
            cwd=materialization.project,
            capture_output=True,
            text=True,
            check=False,
        )
        structured = parse_structured_replay_output(result.stdout, result.returncode)
        assert structured.success
        assert structured.executed_test == "test_qprover_replay()"
    finally:
        replay_module._clean_directory(private_root)


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


def test_cold_verify_rejects_manifest_semantic_and_absolute_state_forgery(
    tmp_path: Path,
) -> None:
    certificate_path = _prepare(tmp_path, "access_control")
    certificate = ProofCertificate.model_validate_json(certificate_path.read_text())

    invariant_data = certificate.model_dump(mode="python")
    for field in ("certificate_identity_sha256", "certificate_sha256"):
        invariant_data.pop(field)
    invariant_data["invariant"] = certificate.invariant.model_copy(
        update={
            "id": "fabricated",
            "expression": "False",
            "description": "Fabricated invariant.",
            "foundry_assertion": "assert(false);",
        }
    )
    with pytest.raises(ValueError, match="baseline-true"):
        create_certificate(**invariant_data)

    certificate_path = _prepare(tmp_path / "state", "access_control")
    certificate = ProofCertificate.model_validate_json(certificate_path.read_text())
    state_data = certificate.model_dump(mode="python")
    for field in ("certificate_identity_sha256", "certificate_sha256"):
        state_data.pop(field)
    before_values = {
        key: value + 123
        for key, value in certificate.before_after.before.values.items()
    }
    after_values = {
        key: value + 123 for key, value in certificate.before_after.after.values.items()
    }
    from task7_helpers import state_evidence

    forged_before = state_evidence(before_values)
    forged_after = state_evidence(after_values)
    state_data["initial_state"] = forged_before
    state_data["before_after"] = certificate.before_after.model_copy(
        update={"before": forged_before, "after": forged_after}
    )
    transactions = list(certificate.transactions)
    transactions[-1] = transactions[-1].model_copy(
        update={"observation_state_sha256": forged_after.state_sha256}
    )
    state_data["transactions"] = tuple(transactions)
    forged_state = create_certificate(**state_data)
    write_certificate(forged_state, certificate_path)
    with pytest.raises(ReplayError, match="executed state evidence"):
        cold_verify(certificate_path)


@pytest.mark.parametrize(
    "tamper", ["artifact_path", "build_info_sha256", "build_command"]
)
def test_cold_verify_rejects_build_provenance_forgery(
    tmp_path: Path, tamper: str
) -> None:
    certificate_path = _prepare(tmp_path, "access_control")
    certificate = ProofCertificate.model_validate_json(certificate_path.read_text())
    data = certificate.model_dump(mode="python")
    for field in ("certificate_identity_sha256", "certificate_sha256"):
        data.pop(field)
    if tamper == "artifact_path":
        data["artifacts"] = (
            certificate.artifacts[0].model_copy(
                update={"artifact_path": "out/Fake.sol/AccessControlA.json"}
            ),
        )
        expected = "artifact path mismatch"
    elif tamper == "build_info_sha256":
        data["artifacts"] = (
            certificate.artifacts[0].model_copy(update={"build_info_sha256": "f" * 64}),
        )
        expected = "artifact build-info hash mismatch"
    else:
        data["build"] = certificate.build.model_copy(
            update={"command": ("forge", "build", "--offline")}
        )
        expected = "build command mismatch"
    forged = create_certificate(**data)
    write_certificate(forged, certificate_path)

    with pytest.raises(ReplayError, match=expected):
        cold_verify(certificate_path)


def test_cold_verify_refuses_any_repeat_count_other_than_three(tmp_path: Path) -> None:
    certificate_path = _prepare(tmp_path, "access_control")
    with pytest.raises(ReplayError, match="exactly 3"):
        cold_verify(certificate_path, repeats=2)


def test_draft_replays_from_a_clean_relocated_workspace(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    certificate_path = _prepare(tmp_path / "run", "access_control")
    relocated = tmp_path / "clean-clone"
    shutil.copytree(ROOT / "benchmarks", relocated / "benchmarks")
    real_preflight = replay_module._offline_preflight

    def relocated_preflight(certificate, manifest):
        assert manifest.target.project_root.resolve().is_relative_to(relocated)
        return real_preflight(certificate, manifest)

    monkeypatch.setattr(replay_module, "_offline_preflight", relocated_preflight)
    monkeypatch.chdir(relocated)

    verification = cold_verify(certificate_path)

    assert verification.confirmation_status is ConfirmationStatus.CONFIRMED
    assert verification.certificate.replay.recipe is not None
    assert verification.certificate.replay.recipe.source_project == "benchmarks/foundry"
    assert str(relocated) not in verification.certificate.canonical_json()


def test_cold_verify_rejects_preexisting_project_test_symlink(tmp_path: Path) -> None:
    certificate_path = _prepare(tmp_path / "run", "access_control")
    relocated = tmp_path / "clean-clone"
    shutil.copytree(ROOT / "benchmarks", relocated / "benchmarks")
    test_directory = relocated / "benchmarks/foundry/test"
    shutil.rmtree(test_directory)
    outside = tmp_path / "outside-tests"
    outside.mkdir()
    test_directory.symlink_to(outside, target_is_directory=True)

    with pytest.raises(ReplayError, match="symlink"):
        cold_verify(certificate_path, workspace_root=relocated)

    assert not tuple(outside.glob(".qprover_replay_*.t.sol"))


def test_replay_preserves_eoa_and_symbolic_constructor_semantics(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    project = workspace / "benchmarks/foundry"
    source_directory = project / "src"
    source_directory.mkdir(parents=True)
    (project / "foundry.toml").write_text(
        '[profile.default]\nsrc = "src"\ntest = "test"\nsolc = "0.8.34"\n'
        'evm_version = "prague"\n'
    )
    (source_directory / "EoaConstructor.sol").write_text(
        """// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.34;
contract Anchor {}
contract EoaConstructor {
    address public immutable owner;
    address public immutable linked;
    constructor(address expectedOwner, address linked_) payable {
        require(msg.sender == expectedOwner, "sender");
        require(tx.origin == expectedOwner, "origin");
        require(expectedOwner.code.length == 0, "eoa");
        require(linked_ != address(0), "linked");
        owner = msg.sender;
        linked = linked_;
    }
    function seize() external {
        (bool ok,) = msg.sender.call{value: address(this).balance}("");
        require(ok, "pay");
    }
    function protocolAssets() external view returns (uint256) {
        return address(this).balance;
    }
    function constructorBound() external view returns (bool) {
        return owner.code.length == 0 && linked != address(0);
    }
}
"""
    )
    manifest_path = workspace / "benchmarks/eoa_constructor.json"
    manifest_path.write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "target": {
                    "id": "eoa_constructor",
                    "project_root": "foundry",
                    "solidity_version": "0.8.34",
                    "evm_version": "prague",
                    "source_files": ["src/EoaConstructor.sol"],
                },
                "actors": [
                    {"id": "deployer", "slot": 0, "balance_wei": 10**20},
                    {"id": "attacker", "slot": 1, "balance_wei": 10**20},
                ],
                "deployments": [
                    {
                        "id": "anchor",
                        "artifact": "src/EoaConstructor.sol:Anchor",
                        "constructor_args": [],
                        "sender_slot": 0,
                        "value_wei": 0,
                    },
                    {
                        "id": "scenario",
                        "artifact": "src/EoaConstructor.sol:EoaConstructor",
                        "constructor_args": [
                            {"actor": "deployer"},
                            {"deployment": "anchor"},
                        ],
                        "sender_slot": 0,
                        "value_wei": 10**19,
                    },
                ],
                "actions": [
                    {
                        "id": "seize",
                        "target_id": "scenario",
                        "signature": "seize()",
                        "mutability": "nonpayable",
                        "sender_slots": [1],
                        "arguments": [],
                        "value_domain": {"kind": "finite", "values": [0]},
                        "max_repetitions": 1,
                    }
                ],
                "observations": [
                    {
                        "id": "protocol_assets",
                        "kind": "call",
                        "target_id": "scenario",
                        "signature": "protocolAssets()",
                        "args": [],
                    },
                    {
                        "id": "attacker_assets",
                        "kind": "native_balance",
                        "actor_id": "attacker",
                    },
                    {
                        "id": "constructor_bound",
                        "kind": "call",
                        "target_id": "scenario",
                        "signature": "constructorBound()",
                        "args": [],
                    },
                ],
                "invariants": [
                    {
                        "id": "assets_and_constructor",
                        "expression": (
                            "protocol_assets >= initial_protocol_assets and "
                            "constructor_bound"
                        ),
                        "description": (
                            "Construction stays EOA-bound and assets remain."
                        ),
                        "foundry_assertion": (
                            "assertGe(target.protocolAssets(), initialAssets);"
                        ),
                    }
                ],
                "impact": {
                    "attacker_asset_observation": "attacker_assets",
                    "protocol_asset_observation": "protocol_assets",
                    "unit": "wei",
                },
                "limits": {
                    "max_sequence_length": 1,
                    "transaction_budget": 10,
                    "candidate_budget": 10,
                    "wall_seconds": 10,
                },
            }
        )
    )
    manifest = load_manifest(manifest_path)
    action = manifest.actions[0]
    candidate = Candidate(
        (ActionStep(action.id, action.target_id, action.signature, 1, (), 0),)
    )
    with build_target(manifest) as bundle, LocalAnvil() as anvil:
        evaluator = ScenarioEvaluator(manifest, bundle, anvil)
        minimized = minimize(candidate, evaluator, manifest)
        provisional = make_executed_certificate(
            manifest=manifest,
            manifest_path=manifest_path,
            bundle=bundle,
            minimization=minimized,
            output_root=tmp_path / "run",
            poc_sha256=ZERO_HASH,
            workspace_root=workspace,
        )
        source = foundry_poc_source(provisional, manifest, workspace_root=workspace)
        certificate = make_executed_certificate(
            manifest=manifest,
            manifest_path=manifest_path,
            bundle=bundle,
            minimization=minimized,
            output_root=tmp_path / "run",
            poc_sha256=digest(source),
            workspace_root=workspace,
        )
        generate_foundry_poc(
            certificate,
            manifest,
            tmp_path / "run",
            workspace_root=workspace,
        )
        certificate_path = write_certificate(
            certificate, tmp_path / "run/certificate.json"
        )

    verification = cold_verify(certificate_path, workspace_root=workspace)

    assert verification.confirmation_status is ConfirmationStatus.CONFIRMED
    assert "new EoaConstructor{value:" in source
    assert "(actor_slot_0, target_anchor)" in source
    assert "assert(initial_constructor_bound == true);" in source
    assert "assert(final_constructor_bound == true);" in source


@pytest.mark.parametrize(
    "tamper",
    [
        "transaction_hash",
        "gas",
        "return_data",
        "trace_hash",
        "intermediate_state",
        "chain",
        "actor_address",
    ],
)
def test_cold_verify_rejects_forged_execution_metadata(
    tmp_path: Path, tamper: str
) -> None:
    certificate_path = _prepare(tmp_path, "access_control")
    certificate = ProofCertificate.model_validate_json(certificate_path.read_text())
    data = certificate.model_dump(mode="python")
    for field in ("certificate_identity_sha256", "certificate_sha256"):
        data.pop(field)
    transactions = list(certificate.transactions)
    if tamper == "transaction_hash":
        transactions[0] = transactions[0].model_copy(
            update={"transaction_sha256": "f" * 64}
        )
    elif tamper == "gas":
        transactions[0] = transactions[0].model_copy(
            update={"gas_used": transactions[0].gas_used + 1}
        )
        gas_values = tuple(item.gas_used for item in transactions)
        data["gas"] = GasEvidence(
            total_gas_used=sum(gas_values), per_transaction=gas_values
        )
    elif tamper == "return_data":
        transactions[0] = transactions[0].model_copy(update={"return_data": "0x01"})
    elif tamper == "trace_hash":
        transactions[0] = transactions[0].model_copy(update={"trace_sha256": "f" * 64})
    elif tamper == "intermediate_state":
        transactions[0] = transactions[0].model_copy(
            update={"observation_state_sha256": "f" * 64}
        )
    elif tamper == "chain":
        data["chain"] = certificate.chain.model_copy(update={"chain_id": 1})
    elif tamper == "actor_address":
        funding = list(certificate.funding)
        funding[0] = funding[0].model_copy(update={"address": "0x" + "11" * 20})
        data["funding"] = tuple(funding)
    data["transactions"] = tuple(transactions)
    forged = create_certificate(**data)
    write_certificate(forged, certificate_path)

    with pytest.raises(ReplayError, match="executed .* evidence|actor address"):
        cold_verify(certificate_path)


def test_cold_verify_reruns_single_delete_local_minimality(tmp_path: Path) -> None:
    manifest_path = ROOT / "benchmarks/scenario_access_control_a.json"
    manifest = load_manifest(manifest_path)
    actions = {action.id: action for action in manifest.actions}

    def step(action_id: str, args: tuple[object, ...] = ()) -> ActionStep:
        action = actions[action_id]
        return ActionStep(
            action.id,
            action.target_id,
            action.signature,
            action.sender_slots[0],
            args,
            0,
        )

    candidate = Candidate(
        (step("noise_two", (7,)), step("step_alpha"), step("step_beta"))
    )
    with build_target(manifest) as bundle, LocalAnvil() as anvil:
        evaluator = ScenarioEvaluator(manifest, bundle, anvil)
        evaluation = evaluator.evaluate(candidate)
        forged_minimization = MinimizationResult(
            candidate=candidate,
            final_evaluation=evaluation,
            original_step_count=3,
            minimized_step_count=3,
            attempts=(),
            evaluation_count=1,
            uncached_candidate_count=1,
            candidate_attempt_count=1,
            unique_candidate_count=1,
            cache_hits=0,
            transaction_count=3,
            attempted_operators=("single-delete-fixed-point",),
            locally_minimal=True,
            minimality_claim=(
                "Replay-verified local minimum under one-step deletion only."
            ),
        )
        provisional = make_executed_certificate(
            manifest=manifest,
            manifest_path=manifest_path,
            bundle=bundle,
            minimization=forged_minimization,
            output_root=tmp_path,
            poc_sha256=ZERO_HASH,
        )
        source = foundry_poc_source(provisional, manifest)
        certificate = make_executed_certificate(
            manifest=manifest,
            manifest_path=manifest_path,
            bundle=bundle,
            minimization=forged_minimization,
            output_root=tmp_path,
            poc_sha256=digest(source),
        )
        generate_foundry_poc(certificate, manifest, tmp_path)
        certificate_path = write_certificate(certificate, tmp_path / "certificate.json")

    with pytest.raises(ReplayError, match="local minimality evidence"):
        cold_verify(certificate_path)
