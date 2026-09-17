from __future__ import annotations

import json
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

import qprover.trust404 as trust404
import qprover.trust404_runner as runner
from qprover.trust404 import Track04Manifest, build_search_model
from qprover.trust404_harness import VerificationResult, verify_exploit


def _manifest(tmp_path: Path) -> Track04Manifest:
    path = tmp_path / "manifest.json"
    path.write_text(
        json.dumps(
            {
                "schema": "trust404.track04.manifest/0.1",
                "target": {
                    "name": "Demo",
                    "src": "Demo.sol",
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
                "budget": {"timeout_sec": 300, "max_attempts": 5},
            }
        ),
        encoding="utf-8",
    )
    return Track04Manifest.load(path)


def test_harness_extracts_generated_revert_step(tmp_path: Path) -> None:
    manifest = _manifest(tmp_path)
    target = tmp_path / "Demo.sol"
    target.write_text("pragma solidity 0.8.24; contract Demo {}", encoding="utf-8")
    invariants = tmp_path / "Invariants.sol"
    invariants.write_text("contract Invariants {}", encoding="utf-8")
    hdir = tmp_path / "harness"
    (hdir / "src").mkdir(parents=True)
    (hdir / "test").mkdir()
    (hdir / "src" / "Harness.sol").write_text("contract Harness {}", encoding="utf-8")

    def fake_runner(command, **kwargs):
        return subprocess.CompletedProcess(
            command,
            1,
            "",
            "[FAIL: QProverFailure(2)] test_attempt()",
        )

    result = verify_exploit(
        hdir,
        target,
        invariants,
        "pragma solidity 0.8.24; contract Exploit { function run(address) external payable {} }",
        manifest,
        timeout_seconds=10,
        runner=fake_runner,
    )

    assert result.category == "forge_error"
    assert result.note == "revert_step=2"


def test_runner_preserves_revert_step_and_converts_to_positive_prefix() -> None:
    verification = VerificationResult(False, "", "forge_error", "revert_step=2")

    assert runner._deterministic_note(verification) == "revert_step=2"
    helper = getattr(runner, "_revert_transaction_count", None)
    assert helper is not None
    assert helper("revert_step=2", 6) == 3


def _function(
    signature: str,
    *,
    calls: tuple[object, ...],
    value_flows: tuple[object, ...],
) -> SimpleNamespace:
    return SimpleNamespace(
        signature=signature,
        visibility="external",
        state_mutability="nonpayable",
        function_selector="0x12345678",
        parameters=(),
        returns=(),
        canonical_id=f"function:Demo.sol:Demo:{signature}",
        transitive_storage_reads=("state",),
        transitive_storage_writes=("state",),
        calls=calls,
        value_flows=value_flows,
        external_call_before_write=True,
        source_name="Demo.sol",
        source_span="0:1:0",
    )


def _analysis() -> SimpleNamespace:
    native = _function(
        "nativePath()",
        calls=(SimpleNamespace(kind="low_level", callee_id=None),),
        value_flows=(SimpleNamespace(asset="native", direction="out"),),
    )
    token = _function(
        "tokenPath()",
        calls=(SimpleNamespace(kind="external", callee_id=None),),
        value_flows=(SimpleNamespace(asset="token", direction="out"),),
    )
    contract = SimpleNamespace(
        name="Demo",
        source_name="Demo.sol",
        functions=(native, token),
        storage=(),
        abi_signatures=(),
    )
    report = SimpleNamespace(
        contracts=(contract,),
        contract=lambda *_identity: contract,
    )
    return SimpleNamespace(
        report=report,
        graph=SimpleNamespace(),
        source_name="Demo.sol",
        contract_name="Demo",
    )


def test_callback_mode_requires_native_low_level_value_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "Demo.sol"
    target.write_text("pragma solidity 0.8.24; contract Demo {}", encoding="utf-8")
    invariants = tmp_path / "Invariants.sol"
    invariants.write_text("contract Invariants {}", encoding="utf-8")
    monkeypatch.setattr(
        trust404,
        "compile_track04_target",
        lambda *_args, **_kwargs: _analysis(),
    )

    model = build_search_model(target, invariants, _manifest(tmp_path))
    callback_signatures = {
        action.signature for action in model.actions if action.callback_enabled
    }

    assert "nativePath()" in callback_signatures
    assert "tokenPath()" not in callback_signatures
