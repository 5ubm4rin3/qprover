from __future__ import annotations

import subprocess
from pathlib import Path

from qprover import trust404_analysis
from qprover.trust404_analysis import compile_track04_target


def test_track04_compiler_loads_auxiliary_contract_abi(tmp_path: Path) -> None:
    root = tmp_path / "target"
    src = root / "src"
    src.mkdir(parents=True)
    target = src / "Target.sol"
    target.write_text(
        """// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

contract Token {
    mapping(address => uint256) public balanceOf;
}

contract Target {
    Token public token;

    constructor() {
        token = new Token();
    }
}
""",
        encoding="utf-8",
    )

    analysis = compile_track04_target(
        target,
        target_name="Target",
        target_src="src/Target.sol",
        solc_version="0.8.24",
        evm_version="cancun",
    )

    token = analysis.report.contract("src/Target.sol", "Token")
    assert "balanceOf(address)" in token.abi_signatures


def test_track04_compiler_run_uses_global_analysis_timeout(
    tmp_path: Path, monkeypatch
) -> None:
    seen: dict[str, object] = {}

    def fake_run(command, **kwargs):
        seen["timeout"] = kwargs.get("timeout")
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setenv("QPROVER_ANALYSIS_TIMEOUT", "7")
    monkeypatch.setattr(trust404_analysis.subprocess, "run", fake_run)

    trust404_analysis._run(("forge", "build"), tmp_path)

    assert seen["timeout"] == 7
