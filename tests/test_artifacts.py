import hashlib
import json
import shutil
from pathlib import Path
from typing import Any

import pytest

from qprover.artifacts import ArtifactError, build_target
from qprover.manifest import load_manifest


def _argument(name: str, abi_type: str) -> dict[str, Any]:
    return {
        "name": name,
        "type": abi_type,
        "domain": {
            "kind": "finite",
            "values": [
                "0x0000000000000000000000000000000000000001"
                if abi_type == "address"
                else 1
            ],
        },
    }


def fixture_manifest_data(project_root: str = "fixture") -> dict[str, Any]:
    actions = []
    for action_id, signature, mutability, arguments in (
        ("deposit", "deposit()", "payable", []),
        ("withdraw", "withdraw()", "nonpayable", []),
        (
            "set_operator",
            "setOperator(address)",
            "nonpayable",
            [_argument("new_operator", "address")],
        ),
        (
            "guarded_sink",
            "guardedSink(address,uint256)",
            "nonpayable",
            [_argument("recipient", "address"), _argument("amount", "uint256")],
        ),
        (
            "update_price",
            "updatePrice(address)",
            "nonpayable",
            [_argument("oracle", "address")],
        ),
        (
            "oracle_sink",
            "oracleSink(address)",
            "nonpayable",
            [_argument("recipient", "address")],
        ),
        (
            "uncorrelated_ordering",
            "uncorrelatedOrdering(address,address)",
            "nonpayable",
            [_argument("target", "address"), _argument("recipient", "address")],
        ),
    ):
        actions.append(
            {
                "id": action_id,
                "target_id": "fixture",
                "signature": signature,
                "mutability": mutability,
                "sender_slots": [1],
                "arguments": arguments,
                "value_domain": {
                    "kind": "finite",
                    "values": [0, 1] if mutability == "payable" else [0],
                },
                "max_repetitions": 2,
            }
        )
    return {
        "schema_version": "1.0",
        "target": {
            "id": "analysis-fixture",
            "project_root": project_root,
            "solidity_version": "0.8.34",
            "evm_version": "prague",
            "source_files": ["Fixture.sol"],
        },
        "actors": [
            {"id": "deployer", "slot": 0, "balance_wei": 10**20},
            {"id": "attacker", "slot": 1, "balance_wei": 10**18},
        ],
        "deployments": [
            {
                "id": "fixture",
                "artifact": "Fixture.sol:Fixture",
                "constructor_args": [],
                "sender_slot": 0,
                "value_wei": 0,
            }
        ],
        "actions": actions,
        "observations": [
            {
                "id": "protocol_assets",
                "kind": "native_balance",
                "actor_id": "deployer",
            },
            {
                "id": "attacker_assets",
                "kind": "native_balance",
                "actor_id": "attacker",
            },
        ],
        "invariants": [
            {
                "id": "assets_preserved",
                "expression": "protocol_assets >= initial_protocol_assets",
                "description": "Protocol assets must not decrease",
                "foundry_assertion": (
                    "assertGe(address(target).balance, initialAssets);"
                ),
            }
        ],
        "impact": {
            "attacker_asset_observation": "attacker_assets",
            "protocol_asset_observation": "protocol_assets",
            "unit": "wei",
        },
        "limits": {
            "max_sequence_length": 3,
            "max_variants": 32,
            "transaction_budget": 100,
            "candidate_budget": 50,
            "wall_seconds": 30,
        },
    }


@pytest.fixture
def analysis_manifest(tmp_path: Path) -> Path:
    source = Path(__file__).parent / "fixtures" / "analysis"
    project = tmp_path / "fixture"
    shutil.copytree(source, project)
    manifest_path = tmp_path / "target.json"
    manifest_path.write_text(json.dumps(fixture_manifest_data()), encoding="utf-8")
    return manifest_path


def test_build_target_preserves_compiler_evidence(analysis_manifest: Path) -> None:
    with build_target(load_manifest(analysis_manifest)) as bundle:
        assert bundle.compiler_version == "0.8.34"
        assert bundle.evm_version == "prague"
        assert bundle.build_command == (
            "forge",
            "build",
            "Fixture.sol",
            "--skip",
            "test",
            "--build-info",
            "--extra-output",
            "storageLayout",
        )
        assert bundle.tool_version.startswith("forge Version:")
        assert bundle.artifacts[0].ast["nodeType"] == "SourceUnit"
        assert bundle.artifacts[0].storage_layout["storage"]
        assert bundle.artifacts[0].abi
        assert dict(bundle.artifacts[0].method_identifiers)["withdraw()"] == "3ccfd60b"
        assert bundle.artifacts[0].bytecode.startswith("0x")
        assert len(bundle.source_sha256) == 64
        assert len(bundle.manifest_sha256) == 64
        assert len(bundle.build_info_sha256) == 64
        assert bundle.build_info_path.is_file()
        assert bundle.source_names == ("Fixture.sol",)
        assert len(bundle.artifacts[0].artifact_sha256) == 64
        assert len(bundle.artifacts[0].bytecode_sha256) == 64
        assert bundle.artifacts[0].compilation_target == "Fixture.sol:Fixture"
        assert bundle.artifacts[0].build_info_id == bundle.build_info_id


def test_build_target_source_hash_changes_with_source(
    analysis_manifest: Path,
) -> None:
    manifest = load_manifest(analysis_manifest)
    with build_target(manifest) as first:
        source = manifest.target.source_files[0]
        source.write_text(
            source.read_text(encoding="utf-8") + "\n", encoding="utf-8"
        )
        with build_target(manifest) as second:
            assert first.source_sha256 != second.source_sha256


def test_build_target_rejects_compiler_drift(analysis_manifest: Path) -> None:
    raw = json.loads(analysis_manifest.read_text(encoding="utf-8"))
    raw["target"]["solidity_version"] = "0.8.33"
    analysis_manifest.write_text(json.dumps(raw), encoding="utf-8")

    with pytest.raises(ArtifactError, match="compiler drift"):
        build_target(load_manifest(analysis_manifest))


def test_build_target_rejects_artifact_missing_required_evidence(
    analysis_manifest: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    manifest = load_manifest(analysis_manifest)
    bundle = build_target(manifest)
    artifact_path = bundle.artifacts[0].artifact_path
    build_root = bundle.evidence_root
    raw = json.loads(artifact_path.read_text(encoding="utf-8"))
    raw.pop("abi")
    artifact_path.write_text(json.dumps(raw), encoding="utf-8")

    def preserve_modified_artifact(*args: object, **kwargs: object) -> object:
        del kwargs
        command = args[0]
        stdout = "forge Version: test\n" if command == ("forge", "--version") else ""
        return type(
            "Completed", (), {"returncode": 0, "stdout": stdout, "stderr": ""}
        )()

    monkeypatch.setattr("qprover.artifacts.subprocess.run", preserve_modified_artifact)
    monkeypatch.setattr(
        "qprover.artifacts.tempfile.mkdtemp", lambda **kwargs: str(build_root)
    )

    try:
        with pytest.raises(ArtifactError, match="missing ABI"):
            build_target(manifest)
    finally:
        bundle.close()


def test_recorded_artifact_hash_matches_raw_file(analysis_manifest: Path) -> None:
    with build_target(load_manifest(analysis_manifest)) as bundle:
        artifact = bundle.artifacts[0]
        assert (
            artifact.artifact_sha256
            == hashlib.sha256(artifact.artifact_path.read_bytes()).hexdigest()
        )


def test_build_target_rejects_undeclared_deployment_source(
    analysis_manifest: Path,
) -> None:
    raw = json.loads(analysis_manifest.read_text(encoding="utf-8"))
    project = analysis_manifest.parent / "fixture"
    (project / "Extra.sol").write_text(
        "pragma solidity 0.8.34; contract Extra {}", encoding="utf-8"
    )
    raw["deployments"][0]["artifact"] = "Extra.sol:Extra"
    analysis_manifest.write_text(json.dumps(raw), encoding="utf-8")

    with pytest.raises(
        ArtifactError, match="deployment artifact source is not declared"
    ):
        build_target(load_manifest(analysis_manifest))


def test_source_hash_covers_transitive_compiler_inputs(
    analysis_manifest: Path,
) -> None:
    project = analysis_manifest.parent / "fixture"
    dependency = project / "Dependency.sol"
    dependency.write_text(
        "pragma solidity 0.8.34; library Dependency { uint256 constant X = 1; }",
        encoding="utf-8",
    )
    fixture = project / "Fixture.sol"
    fixture.write_text(
        'import "./Dependency.sol";\n' + fixture.read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    manifest = load_manifest(analysis_manifest)
    with build_target(manifest) as first:
        dependency.write_text(
            "pragma solidity 0.8.34; library Dependency { uint256 constant X = 2; }",
            encoding="utf-8",
        )
        with build_target(manifest) as second:
            assert first.source_sha256 != second.source_sha256
            assert first.source_names == ("Dependency.sol", "Fixture.sol")


def test_each_build_is_bound_to_fresh_isolated_build_info(
    analysis_manifest: Path,
) -> None:
    manifest = load_manifest(analysis_manifest)

    with build_target(manifest) as first, build_target(manifest) as second:
        assert first.build_info_path != second.build_info_path
        assert first.artifacts[0].artifact_path != second.artifacts[0].artifact_path
        assert first.build_info_sha256 == second.build_info_sha256


@pytest.mark.parametrize(
    "contract_name", ["../Escape", "Fixture/Other", "/tmp/Escape", "Fixture.json"]
)
def test_build_target_rejects_contract_path_escape(
    analysis_manifest: Path,
    contract_name: str,
) -> None:
    raw = json.loads(analysis_manifest.read_text(encoding="utf-8"))
    raw["deployments"][0]["artifact"] = f"Fixture.sol:{contract_name}"
    analysis_manifest.write_text(json.dumps(raw), encoding="utf-8")

    with pytest.raises(ArtifactError, match="invalid artifact contract identifier"):
        build_target(load_manifest(analysis_manifest))


def test_stateless_artifacts_accept_absent_empty_build_info_layout(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project = tmp_path / "stateless"
    project.mkdir()
    (project / "foundry.toml").write_text(
        '[profile.default]\nsrc="."\nout="out"\ncache_path="cache"\n'
        'solc_version="0.8.34"\nevm_version="prague"\n',
        encoding="utf-8",
    )
    (project / "Stateless.sol").write_text(
        "pragma solidity 0.8.34; contract Stateless { function ping() public {} }",
        encoding="utf-8",
    )
    (project / "Derived.sol").write_text(
        'pragma solidity 0.8.34; import "./Stateless.sol"; '
        "contract Derived is Stateless {}",
        encoding="utf-8",
    )
    raw = fixture_manifest_data("stateless")
    raw["target"]["source_files"] = ["Stateless.sol", "Derived.sol"]
    raw["deployments"] = [
        {
            "id": "stateless",
            "artifact": "Stateless.sol:Stateless",
            "constructor_args": [],
            "sender_slot": 0,
            "value_wei": 0,
        },
        {
            "id": "derived",
            "artifact": "Derived.sol:Derived",
            "constructor_args": [],
            "sender_slot": 0,
            "value_wei": 0,
        },
    ]
    raw["actions"] = [
        {
            "id": "ping",
            "target_id": "stateless",
            "signature": "ping()",
            "mutability": "nonpayable",
            "sender_slots": [1],
            "arguments": [],
            "value_domain": {"kind": "finite", "values": [0]},
            "max_repetitions": 1,
        }
    ]
    manifest_path = tmp_path / "target.json"
    manifest_path.write_text(json.dumps(raw), encoding="utf-8")

    import qprover.artifacts as artifact_module

    original = artifact_module._load_build_info

    def omit_empty_layout(output_root: Path, project_root: Path):
        build_info, path, raw_bytes = original(output_root, project_root)
        build_info["output"]["contracts"]["Stateless.sol"]["Stateless"].pop(
            "storageLayout", None
        )
        build_info["output"]["contracts"]["Derived.sol"]["Derived"].pop(
            "storageLayout", None
        )
        return build_info, path, raw_bytes

    monkeypatch.setattr(artifact_module, "_load_build_info", omit_empty_layout)

    with build_target(load_manifest(manifest_path)) as bundle:
        assert all(
            not artifact.storage_layout["storage"] for artifact in bundle.artifacts
        )


def test_stateful_artifact_rejects_absent_build_info_layout(
    analysis_manifest: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import qprover.artifacts as artifact_module

    original = artifact_module._load_build_info

    def omit_nonempty_layout(output_root: Path, project_root: Path):
        build_info, path, raw_bytes = original(output_root, project_root)
        build_info["output"]["contracts"]["Fixture.sol"]["Fixture"].pop(
            "storageLayout", None
        )
        return build_info, path, raw_bytes

    monkeypatch.setattr(artifact_module, "_load_build_info", omit_nonempty_layout)

    with pytest.raises(ArtifactError, match="does not match fresh build-info"):
        build_target(load_manifest(analysis_manifest))


def test_build_target_rejects_artifact_symlink_outside_isolated_output(
    analysis_manifest: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifest = load_manifest(analysis_manifest)
    bundle = build_target(manifest)
    artifact_path = bundle.artifacts[0].artifact_path
    external_artifact = tmp_path / "external-artifact.json"
    external_artifact.write_bytes(artifact_path.read_bytes())
    artifact_path.unlink()
    artifact_path.symlink_to(external_artifact)

    def preserve_existing_output(*args: object, **kwargs: object) -> object:
        del kwargs
        command = args[0]
        stdout = "forge Version: test\n" if command == ("forge", "--version") else ""
        return type(
            "Completed", (), {"returncode": 0, "stdout": stdout, "stderr": ""}
        )()

    monkeypatch.setattr("qprover.artifacts.subprocess.run", preserve_existing_output)
    monkeypatch.setattr(
        "qprover.artifacts.tempfile.mkdtemp",
        lambda **kwargs: str(bundle.evidence_root),
    )

    try:
        with pytest.raises(ArtifactError, match="artifact is outside project root"):
            build_target(manifest)
    finally:
        bundle.close()

    assert external_artifact.is_file()


def test_artifact_bundle_context_manager_cleans_evidence(
    analysis_manifest: Path,
) -> None:
    with build_target(load_manifest(analysis_manifest)) as bundle:
        evidence_root = bundle.evidence_root
        assert evidence_root.is_dir()
        assert bundle.closed is False

    assert bundle.closed is True
    assert not evidence_root.exists()
    bundle.close()


def test_artifact_bundle_close_does_not_claim_failed_removal(
    analysis_manifest: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bundle = build_target(load_manifest(analysis_manifest))
    evidence_root = bundle.evidence_root

    with monkeypatch.context() as filesystem:
        filesystem.setattr(
            "qprover.artifacts.shutil.rmtree", lambda *args, **kwargs: None
        )
        with pytest.raises(ArtifactError, match="could not remove artifact evidence"):
            bundle.close()

    assert bundle.closed is False
    assert evidence_root.is_dir()
    bundle.close()
    assert bundle.closed is True
    assert not evidence_root.exists()


def test_build_failure_cleans_evidence_workspace(
    analysis_manifest: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    evidence_root = tmp_path / "forced-evidence"

    def make_evidence(**kwargs: object) -> str:
        del kwargs
        evidence_root.mkdir()
        return str(evidence_root)

    monkeypatch.setattr("qprover.artifacts.tempfile.mkdtemp", make_evidence)
    monkeypatch.setattr(
        "qprover.artifacts._load_build_info",
        lambda *args: (_ for _ in ()).throw(ArtifactError("forced load failure")),
    )

    with pytest.raises(ArtifactError, match="forced load failure"):
        build_target(load_manifest(analysis_manifest))

    assert not evidence_root.exists()
