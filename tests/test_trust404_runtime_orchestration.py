from __future__ import annotations

import json
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace

import pytest

import qprover.trust404_runner as runner
from qprover.trust404 import Track04Action, Track04SearchModel, Track04Variant
from qprover.trust404_harness import VerificationResult


def _files(tmp_path: Path) -> tuple[Path, Path, Path]:
    target = tmp_path / "Demo.sol"
    target.write_text("pragma solidity 0.8.24; contract Demo {}", encoding="utf-8")
    invariants = tmp_path / "Invariants.sol"
    invariants.write_text(
        "pragma solidity 0.8.24; contract Invariants {"
        "function checkAll(address) external pure returns(bool,string memory){"
        'return (true, "");}}',
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
                    "predicates": ["checkAll"],
                },
                "budget": {"timeout_sec": 30, "max_attempts": 2},
            }
        ),
        encoding="utf-8",
    )
    return target, invariants, manifest


def _model() -> Track04SearchModel:
    action = Track04Action(
        id="call:alpha()",
        kind="call",
        signature="alpha()",
        function_id="function:Demo:alpha()",
        param_types=(),
        payable=False,
        utility=1.0,
        storage_reads=(),
        storage_writes=(),
        provenance=("Demo.sol", "0:1:0"),
    )
    return Track04SearchModel(
        actions=(action,),
        variants=(
            Track04Variant(
                action_id=action.id,
                signature=action.signature,
                args=(),
                value_wei=0,
            ),
        ),
        utilities={action.id: 1.0},
        transitions={},
        max_sequence_length=1,
        analysis=SimpleNamespace(),
    )


def test_run_track04_uses_persistent_runtime_then_final_organizer_proof(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target, invariants, manifest = _files(tmp_path)
    out = tmp_path / "out"
    fake_runtime = SimpleNamespace(target_address="0x" + "11" * 20)
    seen_runtime: list[object] = []
    final_proofs: list[str] = []

    monkeypatch.setattr(runner, "build_search_model", lambda *_args: _model())

    def fake_search(**kwargs):
        seen_runtime.append(kwargs["runtime"])
        kwargs["ledger"].winner_code = (
            "// SPDX-License-Identifier: MIT\n"
            "pragma solidity 0.8.24;\n"
            "contract Exploit { function run(address) external payable {} }\n"
        )
        return True

    monkeypatch.setattr(runner, "_run_search", fake_search)

    @contextmanager
    def runtime_factory(**_kwargs):
        yield fake_runtime

    def final_verifier(
        _harness_dir,
        _target,
        _invariants,
        code,
        _manifest,
        **_kwargs,
    ) -> VerificationResult:
        final_proofs.append(code)
        return VerificationResult(True, "checkAll", "proven")

    exit_code = runner.run_track04(
        target,
        invariants,
        manifest,
        out,
        timeout_seconds=30,
        seed=7,
        max_attempts=2,
        harness_dir=tmp_path,
        verifier=final_verifier,
        clock=lambda: 0.0,
        runtime_factory=runtime_factory,
    )

    assert exit_code == 0
    assert seen_runtime == [fake_runtime]
    assert len(final_proofs) == 1
    assert final_proofs[0] == (out / "Exploit.sol").read_text(encoding="utf-8")
