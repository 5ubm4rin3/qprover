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


def test_track04_compiler_includes_invariants_property_analysis(tmp_path: Path) -> None:
    root = tmp_path / "target"
    src = root / "src"
    src.mkdir(parents=True)
    target = src / "Target.sol"
    target.write_text(
        """// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

contract Target {
    constructor() payable {}
}
""",
        encoding="utf-8",
    )
    invariants = root / "Invariants.sol"
    invariants.write_text(
        """// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

contract Invariants {
    uint256 internal constant SEED = 10 ether;

    function vaultSolvent(address target) public view returns (bool) {
        return target.balance >= SEED;
    }

    function checkAll(address target)
        external
        view
        returns (bool allHold, string memory firstViolated)
    {
        if (!vaultSolvent(target)) return (false, "vaultSolvent");
        return (true, "");
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
        invariants_path=invariants,
        predicates=("vaultSolvent",),
    )

    assert "Invariants.sol" in {item.source_name for item in analysis.source_units}
    assert {artifact.compilation_target for artifact in analysis.artifacts} >= {
        "src/Target.sol:Target",
        "Invariants.sol:Invariants",
    }
    fact = analysis.property_analysis.fact("vaultSolvent")
    assert fact.known is True
    assert fact.target_balance_read is True
    assert fact.constants == (10 * 10**18,)
    assert fact.bound_from_check_all is True


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



def test_track04_compiler_extracts_bounded_parameter_constraint(tmp_path: Path) -> None:
    root = tmp_path / "target"
    src = root / "src"
    src.mkdir(parents=True)
    target = src / "Target.sol"
    target.write_text(
        """// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

contract Target {
    uint256 public last;

    function alpha(uint256 amount) external {
        require(amount >= 7);
        last = amount;
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

    function = analysis.report.function(
        "src/Target.sol",
        "Target",
        "alpha(uint256)",
    )
    assert len(function.parameter_constraints) == 1
    fact = function.parameter_constraints[0]
    assert fact.parameter_index == 0
    assert fact.operator == ">="
    assert fact.constant == 7
