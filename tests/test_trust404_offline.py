from __future__ import annotations

import json
import subprocess
from pathlib import Path

import qprover.trust404_harness as harness
from qprover.trust404 import Track04Manifest


def _manifest(tmp_path: Path) -> Track04Manifest:
    path = tmp_path / "manifest.json"
    path.write_text(
        json.dumps(
            {
                "schema": "trust404.track04.manifest/0.1",
                "target": {
                    "name": "Demo",
                    "src": "src/Demo.sol",
                    "solc": "0.8.24",
                    "evm_version": "cancun",
                },
                "deploy": {
                    "mode": "local",
                    "constructor_args": [],
                    "value_wei": "0",
                },
                "determinism": {
                    "block_number": 1,
                    "block_timestamp": 2,
                    "seed": 42,
                },
                "invariants": {
                    "contract": "Invariants.sol",
                    "predicates": ["healthy"],
                },
                "budget": {"timeout_sec": 30, "max_attempts": 5},
            }
        ),
        encoding="utf-8",
    )
    return Track04Manifest.load(path)


def test_verify_exploit_uses_exact_local_solc_offline(
    tmp_path: Path, monkeypatch
) -> None:
    hdir = tmp_path / "harness"
    (hdir / "src").mkdir(parents=True)
    (hdir / "test").mkdir()
    (hdir / "src" / "Harness.sol").write_text("contract Harness {}", encoding="utf-8")
    target = tmp_path / "src" / "Demo.sol"
    target.parent.mkdir()
    target.write_text("contract Demo {}", encoding="utf-8")
    invariants = tmp_path / "Invariants.sol"
    invariants.write_text("contract Invariants {}", encoding="utf-8")

    monkeypatch.setattr(harness, "_local_solc", lambda version: "/usr/local/bin/solc")
    seen: list[str] = []

    def runner(command, **kwargs):
        seen.extend(command)
        return subprocess.CompletedProcess(command, 0, "AGENT_RESULT NOT_PROVEN\n", "")

    result = harness.verify_exploit(
        hdir,
        target,
        invariants,
        "pragma solidity 0.8.24; contract Exploit { function run(address) external payable {} }",
        _manifest(tmp_path),
        timeout_seconds=12,
        runner=runner,
    )

    assert result.category == "not_proven"
    assert seen[-3:] == ["--use", "/usr/local/bin/solc", "--offline"]
