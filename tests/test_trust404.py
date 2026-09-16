from __future__ import annotations

import json
from pathlib import Path

import pytest

from qprover.trust404 import ManifestContractError, Track04Manifest

OFFICIAL_SCHEMA = "trust404.track04.manifest/0.1"


def _manifest() -> dict[str, object]:
    return {
        "schema": OFFICIAL_SCHEMA,
        "target": {
            "name": "Demo",
            "src": "src/Demo.sol",
            "solc": "0.8.24",
            "evm_version": "cancun",
        },
        "deploy": {
            "mode": "local",
            "constructor_args": [],
            "value_wei": "10000000000000000000",
            "setup": "Setup.s.sol",
        },
        "determinism": {
            "block_number": 21_000_000,
            "block_timestamp": 1_735_689_600,
            "seed": 42,
        },
        "invariants": {
            "contract": "Invariants.sol",
            "predicates": ["vaultSolvent", "ownerUnchanged"],
        },
        "budget": {"timeout_sec": 300, "max_attempts": 5},
    }


def test_track04_manifest_loads_official_contract(tmp_path: Path) -> None:
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps(_manifest()), encoding="utf-8")

    manifest = Track04Manifest.load(path)

    assert manifest.schema == OFFICIAL_SCHEMA
    assert manifest.target_name == "Demo"
    assert manifest.target_src == "src/Demo.sol"
    assert manifest.solc == "0.8.24"
    assert manifest.evm_version == "cancun"
    assert manifest.deploy_value_wei == 10**19
    assert manifest.predicates == ("vaultSolvent", "ownerUnchanged")
    assert manifest.block_number == 21_000_000
    assert manifest.max_attempts == 5


def test_track04_manifest_rejects_unknown_schema(tmp_path: Path) -> None:
    raw = _manifest()
    raw["schema"] = "trust404.track04.manifest/9.9"
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps(raw), encoding="utf-8")

    with pytest.raises(ManifestContractError, match="schema"):
        Track04Manifest.load(path)


def test_track04_manifest_rejects_non_decimal_value_wei(tmp_path: Path) -> None:
    raw = _manifest()
    raw["deploy"]["value_wei"] = "1e18"  # type: ignore[index]
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps(raw), encoding="utf-8")

    with pytest.raises(ManifestContractError, match="value_wei"):
        Track04Manifest.load(path)


def test_track04_manifest_rejects_duplicate_predicates(tmp_path: Path) -> None:
    raw = _manifest()
    raw["invariants"]["predicates"] = ["same", "same"]  # type: ignore[index]
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps(raw), encoding="utf-8")

    with pytest.raises(ManifestContractError, match="duplicates"):
        Track04Manifest.load(path)
