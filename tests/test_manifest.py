import json
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from qprover.manifest import ManifestError, load_manifest
from qprover.models import ActionStep, Candidate, TargetManifest


def minimal_manifest(tmp_path: Path) -> dict[str, Any]:
    project_root = tmp_path / "fixture"
    source_dir = project_root / "src"
    source_dir.mkdir(parents=True)
    (source_dir / "Vault.sol").write_text(
        "contract Vault { function deposit(uint256) external {} }",
        encoding="utf-8",
    )
    return {
        "schema_version": "1.0",
        "target": {
            "id": "fixture",
            "project_root": "fixture",
            "solidity_version": "0.8.34",
            "evm_version": "prague",
            "source_files": ["src/Vault.sol"],
        },
        "actors": [
            {"id": "deployer", "slot": 0, "balance_wei": 10**20},
            {"id": "attacker", "slot": 1, "balance_wei": 10**18},
        ],
        "deployments": [
            {
                "id": "vault",
                "artifact": "src/Vault.sol:Vault",
                "constructor_args": [],
                "sender_slot": 0,
                "value_wei": 0,
            }
        ],
        "actions": [
            {
                "id": "deposit",
                "target_id": "vault",
                "signature": "deposit(uint256)",
                "mutability": "payable",
                "sender_slots": [1],
                "arguments": [
                    {
                        "name": "amount",
                        "type": "uint256",
                        "domain": {
                            "kind": "integer",
                            "minimum": 0,
                            "maximum": 100,
                        },
                    }
                ],
                "value_domain": {"kind": "finite", "values": [0, 1]},
                "max_repetitions": 2,
            }
        ],
        "observations": [
            {
                "id": "protocol_assets",
                "kind": "call",
                "target_id": "vault",
                "signature": "protocolAssets()",
                "args": [],
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
            "max_sequence_length": 3,
            "max_variants": 32,
            "transaction_budget": 100,
            "candidate_budget": 50,
            "wall_seconds": 30,
        },
    }


def write_json(path: Path, raw: dict[str, Any]) -> Path:
    path.write_text(json.dumps(raw), encoding="utf-8")
    return path


def test_manifest_loads_exact_values_and_canonical_paths(tmp_path: Path) -> None:
    path = write_json(tmp_path / "target.json", minimal_manifest(tmp_path))

    manifest = load_manifest(path)

    assert isinstance(manifest, TargetManifest)
    assert manifest.schema_version == "1.0"
    assert manifest.target.id == "fixture"
    assert manifest.target.project_root == (tmp_path / "fixture").resolve()
    assert manifest.target.source_files == (
        (tmp_path / "fixture" / "src" / "Vault.sol").resolve(),
    )
    assert manifest.actions[0].arguments[0].domain.minimum == 0
    assert manifest.actions[0].arguments[0].domain.maximum == 100
    assert manifest.actions[0].value_domain.values == (0, 1)
    assert manifest.limits.transaction_budget == 100


def test_manifest_records_are_immutable(tmp_path: Path) -> None:
    manifest = load_manifest(
        write_json(tmp_path / "target.json", minimal_manifest(tmp_path))
    )

    with pytest.raises(ValidationError, match="frozen_instance"):
        manifest.target.id = "changed"  # type: ignore[misc]


def test_candidate_id_is_stable_and_sensitive_to_steps() -> None:
    first = Candidate(
        steps=(ActionStep("deposit", "vault", "deposit(uint256)", 1, (1,)),)
    )
    same = Candidate(
        steps=(ActionStep("deposit", "vault", "deposit(uint256)", 1, (1,)),)
    )
    different = Candidate(
        steps=(ActionStep("deposit", "vault", "deposit(uint256)", 1, (2,)),)
    )

    assert first.canonical_id == same.canonical_id
    assert first.canonical_id != different.canonical_id
    assert len(first.canonical_id) == 64


@pytest.mark.parametrize("field", ["rpc_url", "unexpected"])
def test_manifest_rejects_external_rpc_and_unknown_fields(
    tmp_path: Path, field: str
) -> None:
    raw = minimal_manifest(tmp_path)
    raw[field] = "https://example.invalid"
    path = write_json(tmp_path / "target.json", raw)

    with pytest.raises(ManifestError):
        load_manifest(path)


def test_manifest_rejects_path_escape(tmp_path: Path) -> None:
    raw = minimal_manifest(tmp_path)
    raw["target"]["project_root"] = "../outside"

    with pytest.raises(ManifestError, match="outside manifest directory"):
        load_manifest(write_json(tmp_path / "target.json", raw))


def test_manifest_rejects_source_path_escape(tmp_path: Path) -> None:
    raw = minimal_manifest(tmp_path)
    raw["target"]["source_files"] = ["../Outside.sol"]

    with pytest.raises(ManifestError, match="outside project root"):
        load_manifest(write_json(tmp_path / "target.json", raw))


def test_manifest_rejects_action_argument_without_domain(tmp_path: Path) -> None:
    raw = minimal_manifest(tmp_path)
    del raw["actions"][0]["arguments"][0]["domain"]

    with pytest.raises(ManifestError):
        load_manifest(write_json(tmp_path / "target.json", raw))


def test_manifest_rejects_non_state_changing_action(tmp_path: Path) -> None:
    raw = minimal_manifest(tmp_path)
    raw["actions"][0]["mutability"] = "view"

    with pytest.raises(ManifestError):
        load_manifest(write_json(tmp_path / "target.json", raw))


@pytest.mark.parametrize(
    "collection",
    ["actors", "deployments", "actions", "observations", "invariants"],
)
def test_manifest_rejects_duplicate_symbolic_ids(
    tmp_path: Path, collection: str
) -> None:
    raw = minimal_manifest(tmp_path)
    raw[collection].append(raw[collection][0].copy())

    with pytest.raises(ManifestError, match="duplicate symbolic id"):
        load_manifest(write_json(tmp_path / "target.json", raw))


@pytest.mark.parametrize(
    "signature",
    ["deposit(uint)", "deposit(address, uint256)", "deposit"],
)
def test_manifest_rejects_noncanonical_abi_signature(
    tmp_path: Path, signature: str
) -> None:
    raw = minimal_manifest(tmp_path)
    raw["actions"][0]["signature"] = signature

    with pytest.raises(ManifestError, match="canonical ABI signature"):
        load_manifest(write_json(tmp_path / "target.json", raw))


def test_manifest_rejects_no_invariants(tmp_path: Path) -> None:
    raw = minimal_manifest(tmp_path)
    raw["invariants"] = []

    with pytest.raises(ManifestError):
        load_manifest(write_json(tmp_path / "target.json", raw))


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("max_sequence_length", 0),
        ("max_variants", -1),
        ("transaction_budget", 0),
        ("candidate_budget", 0),
        ("wall_seconds", 0),
    ],
)
def test_manifest_rejects_nonpositive_limits(
    tmp_path: Path, field: str, value: int
) -> None:
    raw = minimal_manifest(tmp_path)
    raw["limits"][field] = value

    with pytest.raises(ManifestError):
        load_manifest(write_json(tmp_path / "target.json", raw))


def test_manifest_rejects_unknown_symbolic_references(tmp_path: Path) -> None:
    raw = minimal_manifest(tmp_path)
    raw["actions"][0]["target_id"] = "missing"

    with pytest.raises(ManifestError, match="unknown deployment"):
        load_manifest(write_json(tmp_path / "target.json", raw))


def test_published_schema_matches_model_schema() -> None:
    published = json.loads(
        Path("schemas/target-manifest.schema.json").read_text(encoding="utf-8")
    )

    assert published == TargetManifest.model_json_schema()
    assert published["additionalProperties"] is False
    assert set(published["required"]) == {
        "schema_version",
        "target",
        "actors",
        "deployments",
        "actions",
        "observations",
        "invariants",
        "impact",
        "limits",
    }
