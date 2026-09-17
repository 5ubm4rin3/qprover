# ruff: noqa: E501
from __future__ import annotations

import json
import sys
import types
from pathlib import Path
from types import SimpleNamespace

import pytest

import qprover.trust404 as trust404
from qprover.trust404_harness import VerificationResult


def _function(
    signature: str,
    *,
    parameters: tuple[str, ...] = (),
    mutability: str = "nonpayable",
    reads: tuple[str, ...] = (),
    writes: tuple[str, ...] = (),
) -> SimpleNamespace:
    return SimpleNamespace(
        signature=signature,
        visibility="external",
        state_mutability=mutability,
        function_selector="0x12345678",
        parameters=parameters,
        returns=(),
        canonical_id=f"function:Demo:{signature}",
        transitive_storage_reads=reads,
        transitive_storage_writes=writes,
        calls=(),
        value_flows=(),
        external_call_before_write=False,
        source_name="Demo.sol",
        source_span="0:1:0",
    )


def _analysis() -> SimpleNamespace:
    contract = SimpleNamespace(
        name="Demo",
        source_name="Demo.sol",
        functions=(
            _function("setOwner(address)", parameters=("address",), writes=("owner",)),
            _function("deposit()", mutability="payable", writes=("balances",)),
            _function("withdraw()", reads=("balances",), writes=("balances",)),
        ),
        storage=(),
        abi_signatures=(),
    )
    report = SimpleNamespace(
        contract=lambda *_args: contract,
        contracts=(contract,),
    )
    return SimpleNamespace(
        report=report,
        graph=SimpleNamespace(),
        source_name="Demo.sol",
        contract_name="Demo",
    )


@pytest.fixture(autouse=True)
def _compiler_facts(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        trust404, "compile_track04_target", lambda *_a, **_kw: _analysis()
    )


def _files(tmp_path: Path) -> tuple[Path, Path, Path]:
    target = tmp_path / "Demo.sol"
    target.write_text(
        """pragma solidity 0.8.24;
contract Demo {
    address public owner;
    function setOwner(address newOwner) external { owner = newOwner; }
}
""",
        encoding="utf-8",
    )
    invariants = tmp_path / "Invariants.sol"
    invariants.write_text(
        'contract Invariants { function checkAll(address) external pure returns(bool,string memory){ return (true, ""); } }',
        encoding="utf-8",
    )
    manifest = tmp_path / "manifest.json"
    manifest.write_text(
        json.dumps(
            {
                "schema": "trust404.track04.manifest/0.1",
                "target": {
                    "name": "Demo",
                    "src": "Demo.sol",
                    "solc": "0.8.24",
                    "evm_version": "cancun",
                },
                "deploy": {"mode": "local", "constructor_args": [], "value_wei": "0"},
                "determinism": {"block_number": 1, "block_timestamp": 2, "seed": 42},
                "invariants": {
                    "contract": "Invariants.sol",
                    "predicates": ["ownerUnchanged"],
                },
                "budget": {"timeout_sec": 30, "max_attempts": 5},
            }
        ),
        encoding="utf-8",
    )
    return target, invariants, manifest


def test_run_track04_writes_proven_exploit_and_deterministic_attempt_log(
    tmp_path: Path, monkeypatch
) -> None:
    monkeypatch.setitem(sys.modules, "z3", types.ModuleType("z3"))
    from qprover.trust404_runner import run_track04

    target, invariants, manifest = _files(tmp_path)
    out = tmp_path / "out"

    def verifier(_hdir, _target, _invariants, code, _manifest, **kwargs):
        assert kwargs["timeout_seconds"] > 0
        if "setOwner(address)" in code:
            return VerificationResult(True, "ownerUnchanged", "proven")
        return VerificationResult(False, "", "not_proven")

    code = run_track04(
        target,
        invariants,
        manifest,
        out,
        timeout_seconds=30,
        seed=7,
        max_attempts=5,
        harness_dir=tmp_path / "unused-harness",
        verifier=verifier,
    )

    assert code == 0
    exploit = (out / "Exploit.sol").read_text(encoding="utf-8")
    log = (out / "attempts.log").read_text(encoding="utf-8")
    assert "contract Exploit" in exploit
    assert "setOwner(address)" in exploit
    assert "result=PROVEN" in log
    assert "violated=ownerUnchanged" in log
    assert "stage=search" in log
    assert "stage=macro" not in log
    assert "stage=direct" not in log


def test_run_track04_returns_one_and_keeps_best_candidate_when_not_proven(
    tmp_path: Path, monkeypatch
) -> None:
    monkeypatch.setitem(sys.modules, "z3", types.ModuleType("z3"))
    from qprover.trust404_runner import run_track04

    target, invariants, manifest = _files(tmp_path)
    out = tmp_path / "out"

    def verifier(*args, **kwargs):
        return VerificationResult(False, "", "not_proven")

    code = run_track04(
        target,
        invariants,
        manifest,
        out,
        timeout_seconds=30,
        seed=7,
        max_attempts=2,
        harness_dir=tmp_path / "unused-harness",
        verifier=verifier,
    )

    assert code == 1
    assert "contract Exploit" in (out / "Exploit.sol").read_text(encoding="utf-8")
    lines = (out / "attempts.log").read_text(encoding="utf-8").splitlines()
    assert 1 <= len(lines) <= 2
    assert all("result=NOT_PROVEN" in line for line in lines)
    assert all("stage=search" in line for line in lines)


def test_run_track04_returns_two_for_harness_infrastructure_failure(
    tmp_path: Path, monkeypatch
) -> None:
    monkeypatch.setitem(sys.modules, "z3", types.ModuleType("z3"))
    from qprover.trust404_runner import run_track04

    target, invariants, manifest = _files(tmp_path)
    out = tmp_path / "out"

    def verifier(*args, **kwargs):
        return VerificationResult(False, "", "infrastructure", "forge missing")

    code = run_track04(
        target,
        invariants,
        manifest,
        out,
        timeout_seconds=30,
        seed=7,
        max_attempts=5,
        harness_dir=tmp_path / "broken-harness",
        verifier=verifier,
    )

    assert code == 2
    log = (out / "attempts.log").read_text(encoding="utf-8")
    assert "result=ERROR" in log
    assert "forge missing" in log


def test_submission_dockerfile_only_copies_existing_root_inputs() -> None:
    root = Path(__file__).resolve().parents[1]
    dockerfile = (root / "agent" / "Dockerfile").read_text(encoding="utf-8")
    assert "COPY pyproject.toml uv.lock README.md ./" not in dockerfile
    assert "COPY pyproject.toml uv.lock ./" in dockerfile


def test_forge_error_attempt_log_ignores_runtime_timing_noise(
    tmp_path: Path, monkeypatch
) -> None:
    monkeypatch.setitem(sys.modules, "z3", types.ModuleType("z3"))
    from qprover.trust404_runner import run_track04

    target, invariants, manifest = _files(tmp_path)

    def execute(out_name: str, note: str) -> str:
        out = tmp_path / out_name

        def verifier(*args, **kwargs):
            return VerificationResult(False, "", "forge_error", note)

        code = run_track04(
            target,
            invariants,
            manifest,
            out,
            timeout_seconds=30,
            seed=7,
            max_attempts=1,
            harness_dir=tmp_path / "unused-harness",
            verifier=verifier,
        )
        assert code == 1
        return (out / "attempts.log").read_text(encoding="utf-8")

    first = execute(
        "first",
        "Compiling 2 files with Solc 0.8.24 finished in 411.11ms gas: 123",
    )
    second = execute(
        "second",
        "Compiling 2 files with Solc 0.8.24 finished in 999.99ms gas: 456",
    )

    assert first == second
    assert "note=forge_error" in first


def test_run_track04_does_not_start_verification_after_deadline(
    tmp_path: Path, monkeypatch
) -> None:
    monkeypatch.setitem(sys.modules, "z3", types.ModuleType("z3"))
    from qprover.trust404_runner import run_track04

    target, invariants, manifest = _files(tmp_path)
    out = tmp_path / "out"

    clock_values = iter((0.0, 0.0, 2.0))

    def clock() -> float:
        return next(clock_values, 2.0)

    verifier_calls: list[int] = []

    def verifier(*args, **kwargs):
        verifier_calls.append(kwargs["timeout_seconds"])
        return VerificationResult(False, "", "not_proven")

    code = run_track04(
        target,
        invariants,
        manifest,
        out,
        timeout_seconds=1,
        seed=7,
        max_attempts=1,
        harness_dir=tmp_path / "unused-harness",
        verifier=verifier,
        clock=clock,
    )

    assert code == 1
    assert verifier_calls == []
