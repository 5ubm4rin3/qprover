from __future__ import annotations

from pathlib import Path

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
