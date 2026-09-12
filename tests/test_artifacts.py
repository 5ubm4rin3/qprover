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
    bundle = build_target(load_manifest(analysis_manifest))

    assert bundle.compiler_version == "0.8.34"
    assert bundle.evm_version == "prague"
    assert bundle.build_command == (
        "forge",
        "build",
        "--build-info",
        "--extra-output",
        "storageLayout",
    )
    assert bundle.tool_version.startswith("forge Version:")
    assert bundle.artifacts[0].ast["nodeType"] == "SourceUnit"
    assert bundle.artifacts[0].storage_layout["storage"]
    assert bundle.artifacts[0].abi
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
    first = build_target(manifest)
    source = manifest.target.source_files[0]
    source.write_text(source.read_text(encoding="utf-8") + "\n", encoding="utf-8")

    second = build_target(manifest)

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
    build_root = bundle.build_info_path.parents[2]
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

    with pytest.raises(ArtifactError, match="missing ABI"):
        build_target(manifest)


def test_recorded_artifact_hash_matches_raw_file(analysis_manifest: Path) -> None:
    bundle = build_target(load_manifest(analysis_manifest))
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
    first = build_target(manifest)

    dependency.write_text(
        "pragma solidity 0.8.34; library Dependency { uint256 constant X = 2; }",
        encoding="utf-8",
    )
    second = build_target(manifest)

    assert first.source_sha256 != second.source_sha256
    assert first.source_names == ("Dependency.sol", "Fixture.sol")


def test_each_build_is_bound_to_fresh_isolated_build_info(
    analysis_manifest: Path,
) -> None:
    manifest = load_manifest(analysis_manifest)

    first = build_target(manifest)
    second = build_target(manifest)

    assert first.build_info_path != second.build_info_path
    assert first.artifacts[0].artifact_path != second.artifacts[0].artifact_path
    assert first.build_info_sha256 == second.build_info_sha256
