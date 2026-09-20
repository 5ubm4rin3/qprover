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


def test_track04_compiler_retains_setup_source(tmp_path: Path) -> None:
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
    setup = root / "Setup.s.sol"
    setup.write_text(
        """// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {Target} from "./src/Target.sol";

contract Setup {
    function run() external returns (address target) {
        target = address(new Target());
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
        setup_path=setup,
    )

    assert analysis.setup_source == "Setup.s.sol"
    assert "Setup.s.sol:Setup" in {
        artifact.compilation_target for artifact in analysis.artifacts
    }


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


def test_track04_compiler_extracts_constant_state_transitions_and_derived_values(
    tmp_path: Path,
) -> None:
    root = tmp_path / "target"
    src = root / "src"
    src.mkdir(parents=True)
    target = src / "Neutral.sol"
    target.write_text(
        """// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

contract Stage {
    uint256 public phase;
    address public pending;

    function threshold() public view returns (uint256) {
        return phase + 6;
    }

    function advance(uint256 amount) external {
        require(phase == 1);
        require(amount == threshold() + 1);
        phase = 2;
    }

    function finish(uint256 amount) external {
        require(amount + 3 == phase);
        phase = 4;
    }

    function clear() external {
        require(pending != address(0));
        pending = address(0);
    }
}
""",
        encoding="utf-8",
    )

    analysis = compile_track04_target(
        target,
        target_name="Stage",
        target_src="src/Neutral.sol",
        solc_version="0.8.24",
        evm_version="cancun",
    )

    phase = analysis.report.storage("src/Neutral.sol", "Stage", "phase")
    threshold = analysis.report.function("src/Neutral.sol", "Stage", "threshold()")
    advance = analysis.report.function("src/Neutral.sol", "Stage", "advance(uint256)")
    finish = analysis.report.function("src/Neutral.sol", "Stage", "finish(uint256)")
    clear = analysis.report.function("src/Neutral.sol", "Stage", "clear()")
    pending = analysis.report.storage("src/Neutral.sol", "Stage", "pending")

    assert tuple(
        (fact.storage_id, fact.operator, fact.constant)
        for fact in advance.storage_guards
    ) == ((phase.canonical_id, "==", 1),)
    assert tuple(
        (fact.storage_id, fact.constant) for fact in advance.storage_assignments
    ) == ((phase.canonical_id, 2),)
    assert tuple(
        (
            fact.parameter_index,
            fact.operator,
            fact.source_kind,
            fact.source_id,
            fact.offset,
        )
        for fact in advance.parameter_expressions
    ) == ((0, "==", "function", threshold.canonical_id, 1),)
    assert tuple(
        (
            fact.parameter_index,
            fact.operator,
            fact.source_kind,
            fact.source_id,
            fact.offset,
        )
        for fact in finish.parameter_expressions
    ) == ((0, "==", "storage", phase.canonical_id, -3),)
    assert advance.comparison_constants == (1,)
    assert finish.comparison_constants == (3,)
    assert tuple(
        (fact.storage_id, fact.operator, fact.constant) for fact in clear.storage_guards
    ) == ((pending.canonical_id, "!=", 0),)
    assert tuple(
        (fact.storage_id, fact.constant) for fact in clear.storage_assignments
    ) == ((pending.canonical_id, 0),)
