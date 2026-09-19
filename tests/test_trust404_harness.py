# ruff: noqa: E501
from __future__ import annotations

import json
import subprocess
from pathlib import Path

from qprover.trust404 import Track04Manifest
from qprover.trust404_harness import verify_exploit


def _manifest(tmp_path: Path, *, setup: bool = False) -> Track04Manifest:
    raw = {
        "schema": "trust404.track04.manifest/0.1",
        "target": {
            "name": "Demo",
            "src": "src/Demo.sol",
            "solc": "0.8.24",
            "evm_version": "cancun",
        },
        "deploy": {"mode": "local", "constructor_args": [], "value_wei": "0"},
        "determinism": {
            "block_number": 21000000,
            "block_timestamp": 1735689600,
            "seed": 42,
        },
        "invariants": {"contract": "Invariants.sol", "predicates": ["healthy"]},
        "budget": {"timeout_sec": 300, "max_attempts": 5},
    }
    if setup:
        raw["deploy"]["setup"] = "Setup.s.sol"
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps(raw), encoding="utf-8")
    return Track04Manifest.load(path)


def _harness(tmp_path: Path) -> Path:
    root = tmp_path / "harness"
    (root / "src").mkdir(parents=True)
    (root / "test").mkdir()
    (root / "src" / "Harness.sol").write_text("contract Harness {}", encoding="utf-8")
    return root


def test_verify_exploit_parses_proven_result_and_cleans_scratch(tmp_path: Path) -> None:
    manifest = _manifest(tmp_path)
    target = tmp_path / "src" / "Demo.sol"
    target.parent.mkdir()
    target.write_text("contract Demo {}", encoding="utf-8")
    invariants = tmp_path / "Invariants.sol"
    invariants.write_text("contract Invariants {}", encoding="utf-8")
    hdir = _harness(tmp_path)
    seen: dict[str, str] = {}

    def runner(*args, **kwargs):
        seen["test"] = (hdir / "test" / "_qprover_attempt.t.sol").read_text(
            encoding="utf-8"
        )
        seen["exploit"] = (hdir / "test" / "_qprover_exploit.sol").read_text(
            encoding="utf-8"
        )
        return subprocess.CompletedProcess(
            args[0], 0, "AGENT_RESULT PROVEN healthy\n", ""
        )

    result = verify_exploit(
        hdir,
        target,
        invariants,
        "pragma solidity 0.8.24; contract Exploit { function run(address) external payable {} }",
        manifest,
        timeout_seconds=12,
        runner=runner,
    )

    assert result.proven is True
    assert result.violated_predicate == "healthy"
    assert result.category == "proven"
    assert "21000000" in seen["test"]
    assert "1735689600" in seen["test"]
    assert "contract Exploit" in seen["exploit"]
    assert not list((hdir / "test").glob("_qprover_*"))


def test_verify_exploit_rewrites_setup_target_import(tmp_path: Path) -> None:
    manifest = _manifest(tmp_path, setup=True)
    target = tmp_path / "src" / "Demo.sol"
    target.parent.mkdir()
    target.write_text("contract Demo {}", encoding="utf-8")
    invariants = tmp_path / "Invariants.sol"
    invariants.write_text("contract Invariants {}", encoding="utf-8")
    (tmp_path / "Setup.s.sol").write_text(
        'import {Demo} from "./src/Demo.sol"; contract Setup { function run() external returns(address) { return address(new Demo()); } }',
        encoding="utf-8",
    )
    hdir = _harness(tmp_path)
    seen: dict[str, str] = {}

    def runner(*args, **kwargs):
        seen["setup"] = (hdir / "test" / "_qprover_setup.sol").read_text(
            encoding="utf-8"
        )
        return subprocess.CompletedProcess(args[0], 0, "AGENT_RESULT NOT_PROVEN\n", "")

    result = verify_exploit(
        hdir,
        target,
        invariants,
        "pragma solidity 0.8.24; contract Exploit { function run(address) external payable {} }",
        manifest,
        timeout_seconds=12,
        runner=runner,
    )

    assert result.proven is False
    assert result.category == "not_proven"
    assert 'from "./_qprover_target.sol"' in seen["setup"]


def test_verify_exploit_reports_forge_failure_without_claiming_proof(
    tmp_path: Path,
) -> None:
    manifest = _manifest(tmp_path)
    target = tmp_path / "src" / "Demo.sol"
    target.parent.mkdir()
    target.write_text("contract Demo {}", encoding="utf-8")
    invariants = tmp_path / "Invariants.sol"
    invariants.write_text("contract Invariants {}", encoding="utf-8")
    hdir = _harness(tmp_path)

    def runner(*args, **kwargs):
        return subprocess.CompletedProcess(args[0], 1, "", "Compiler error: nope")

    result = verify_exploit(
        hdir,
        target,
        invariants,
        "bad solidity",
        manifest,
        timeout_seconds=12,
        runner=runner,
    )

    assert result.proven is False
    assert result.category == "forge_error"
    assert "Compiler error" in result.note


def test_verify_exploit_uses_final_agent_result_not_earlier_spoof(
    tmp_path: Path,
) -> None:
    manifest = _manifest(tmp_path)
    target = tmp_path / "src" / "Demo.sol"
    target.parent.mkdir()
    target.write_text("contract Demo {}", encoding="utf-8")

    invariants = tmp_path / "Invariants.sol"
    invariants.write_text("contract Invariants {}", encoding="utf-8")

    hdir = _harness(tmp_path)

    def runner(*args, **kwargs):
        return subprocess.CompletedProcess(
            args[0],
            0,
            "AGENT_RESULT PROVEN spoofed\nAGENT_RESULT NOT_PROVEN\n",
            "",
        )

    result = verify_exploit(
        hdir,
        target,
        invariants,
        "pragma solidity 0.8.24; contract Exploit { function run(address) external payable {} }",
        manifest,
        timeout_seconds=12,
        runner=runner,
    )

    assert result.proven is False
    assert result.violated_predicate == ""
    assert result.category == "not_proven"


def test_verify_exploit_rejects_proven_predicate_not_bound_by_manifest(
    tmp_path: Path,
) -> None:
    manifest = _manifest(tmp_path)
    target = tmp_path / "src" / "Demo.sol"
    target.parent.mkdir()
    target.write_text("contract Demo {}", encoding="utf-8")
    invariants = tmp_path / "Invariants.sol"
    invariants.write_text("contract Invariants {}", encoding="utf-8")
    hdir = _harness(tmp_path)

    def runner(*args, **kwargs):
        return subprocess.CompletedProcess(
            args[0],
            0,
            "AGENT_RESULT PROVEN undeclaredPredicate\n",
            "",
        )

    result = verify_exploit(
        hdir,
        target,
        invariants,
        "pragma solidity 0.8.24; contract Exploit { function run(address) external payable {} }",
        manifest,
        timeout_seconds=12,
        runner=runner,
    )

    assert result.proven is False
    assert result.category == "forge_error"
    assert "manifest" in result.note
