# ruff: noqa: E402, E501
from __future__ import annotations

import json
from pathlib import Path

import pytest

from qprover.trust404 import ManifestContractError, Track04Manifest, scan_target

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


def test_scan_target_isolates_named_contract_and_visible_state_changers() -> None:
    source = """
pragma solidity 0.8.24;
contract Helper {
    function hiddenFromTarget(uint256 x) external { x; }
}
contract Demo {
    uint256 public total;
    function readOnly() external view returns (uint256) { return total; }
    function deposit() external payable { total += msg.value; }
    function setOwner(address newOwner) public { newOwner; total += 1; }
    function _internalOnly() internal { total += 2; }
}
"""

    scan = scan_target(source, "Demo")

    assert scan.contract_name == "Demo"
    assert [function.name for function in scan.functions] == ["deposit", "setOwner"]
    assert scan.functions[0].payable is True
    assert scan.functions[1].param_types == ("address",)
    assert "hiddenFromTarget" not in {function.name for function in scan.functions}


from qprover.trust404 import (
    OTHER_ADDRESS,
    SELF_ADDRESS,
    build_search_blueprint,
)


def _loaded_manifest(
    tmp_path: Path, *, value_wei: str = "10000000000000000000"
) -> Track04Manifest:
    raw = _manifest()
    raw["deploy"]["value_wei"] = value_wei  # type: ignore[index]
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps(raw), encoding="utf-8")
    return Track04Manifest.load(path)


def test_blueprint_prioritizes_unguarded_owner_and_value_paths(tmp_path: Path) -> None:
    source = """
pragma solidity 0.8.24;
contract Demo {
    address public owner;
    mapping(address => uint256) public balances;
    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "insufficient");
        balances[msg.sender] -= amount;
        (bool ok,) = msg.sender.call{value: amount}(""); require(ok);
    }
    function setOwner(address newOwner) external { owner = newOwner; }
    function rescue(address to, uint256 amount) external {
        (bool ok,) = to.call{value: amount}(""); require(ok);
    }
}
"""
    invariants = """
interface IView { function owner() external view returns (address); }
contract Invariants { function checkAll(address) external pure returns (bool,string memory) { return (true, ""); } }
"""
    manifest = _loaded_manifest(tmp_path)

    blueprint = build_search_blueprint(source, invariants, manifest)
    utility = blueprint.utilities

    assert utility["call:setOwner(address)"] > utility["call:withdraw(uint256)"]
    assert utility["call:rescue(address,uint256)"] > utility["call:withdraw(uint256)"]
    assert SELF_ADDRESS in {
        value
        for variant in blueprint.variants
        if variant.action_id == "call:setOwner(address)"
        for value in variant.args
    }


def test_blueprint_builds_unchecked_accounting_transition_and_macro(
    tmp_path: Path,
) -> None:
    source = """
pragma solidity 0.8.24;
contract Demo {
    mapping(address => uint256) public balanceOf;
    function transfer(address to, uint256 amount) external {
        unchecked { balanceOf[msg.sender] -= amount; balanceOf[to] += amount; }
    }
    function redeem(uint256 amount) external {
        require(balanceOf[msg.sender] >= amount, "credit");
        balanceOf[msg.sender] -= amount;
        (bool ok,) = msg.sender.call{value: amount}(""); require(ok);
    }
}
"""
    manifest = _loaded_manifest(tmp_path)

    first = build_search_blueprint(source, "contract Invariants {}", manifest)
    second = build_search_blueprint(source, "contract Invariants {}", manifest)

    assert (
        first.transitions[("call:transfer(address,uint256)", "call:redeem(uint256)")]
        > 0
    )
    macro_ids = {
        action.id for action in first.actions if action.kind == "unchecked_accounting"
    }
    assert macro_ids == {"macro:unchecked-accounting:transfer:redeem"}
    assert first == second

    transfer_variants = [
        variant
        for variant in first.variants
        if variant.action_id == "call:transfer(address,uint256)"
    ]
    assert any(variant.args == (OTHER_ADDRESS, 10**19) for variant in transfer_variants)


def test_blueprint_domains_are_bounded_and_payable_values_are_deterministic(
    tmp_path: Path,
) -> None:
    source = """
pragma solidity 0.8.24;
contract Demo {
    function enter(address who, uint256 amount, bool flag) external payable { who; amount; flag; }
}
"""
    manifest = _loaded_manifest(tmp_path)

    blueprint = build_search_blueprint(source, "contract Invariants {}", manifest)
    variants = [
        v
        for v in blueprint.variants
        if v.action_id == "call:enter(address,uint256,bool)"
    ]

    assert variants
    assert len(variants) <= 12
    assert {v.value_wei for v in variants}.issubset({0, 10**18})
    assert all(v.args[0] in {SELF_ADDRESS, OTHER_ADDRESS} for v in variants)


from dataclasses import dataclass

from qprover.trust404 import render_candidate


@dataclass(frozen=True)
class _Step:
    action_id: str
    signature: str
    args: tuple[object, ...] = ()
    value_wei: int = 0


@dataclass(frozen=True)
class _Candidate:
    steps: tuple[_Step, ...]


def test_render_candidate_emits_official_exploit_contract_for_direct_calls(
    tmp_path: Path,
) -> None:
    source = """
pragma solidity 0.8.24;
contract Demo {
    address public owner;
    function setOwner(address newOwner) external { owner = newOwner; }
}
"""
    blueprint = build_search_blueprint(
        source, "contract Invariants {}", _loaded_manifest(tmp_path)
    )
    candidate = _Candidate(
        (_Step("call:setOwner(address)", "setOwner(address)", (SELF_ADDRESS,)),)
    )

    rendered = render_candidate(blueprint, candidate)

    assert "contract Exploit" in rendered
    assert "function run(address target) external payable" in rendered
    assert 'abi.encodeWithSignature("setOwner(address)", address(this))' in rendered
    assert "import " not in rendered


def test_render_candidate_emits_reentrancy_callback_macro(tmp_path: Path) -> None:
    source = """
pragma solidity 0.8.24;
contract Demo {
    mapping(address => uint256) public balanceOf;
    function deposit() external payable { balanceOf[msg.sender] += msg.value; }
    function withdraw() external {
        uint256 amount = balanceOf[msg.sender];
        (bool ok,) = msg.sender.call{value: amount}(""); require(ok);
        balanceOf[msg.sender] = 0;
    }
}
"""
    blueprint = build_search_blueprint(
        source, "contract Invariants {}", _loaded_manifest(tmp_path)
    )
    macro = next(action for action in blueprint.actions if action.kind == "reentrancy")
    candidate = _Candidate((_Step(macro.id, macro.signature),))

    rendered = render_candidate(blueprint, candidate)

    assert "receive() external payable" in rendered
    assert 'abi.encodeWithSignature("deposit()")' in rendered
    assert 'abi.encodeWithSignature("withdraw()")' in rendered
    assert "_reentryHops < 3" in rendered


def test_render_candidate_emits_unchecked_accounting_macro(tmp_path: Path) -> None:
    source = """
pragma solidity 0.8.24;
contract Demo {
    mapping(address => uint256) public balanceOf;
    function transfer(address to, uint256 amount) external {
        unchecked { balanceOf[msg.sender] -= amount; balanceOf[to] += amount; }
    }
    function redeem(uint256 amount) external {
        require(balanceOf[msg.sender] >= amount, "credit");
        balanceOf[msg.sender] -= amount;
        (bool ok,) = msg.sender.call{value: amount}(""); require(ok);
    }
}
"""
    blueprint = build_search_blueprint(
        source, "contract Invariants {}", _loaded_manifest(tmp_path)
    )
    macro = next(
        action for action in blueprint.actions if action.kind == "unchecked_accounting"
    )
    candidate = _Candidate((_Step(macro.id, macro.signature),))

    rendered = render_candidate(blueprint, candidate)

    assert (
        'abi.encodeWithSignature("transfer(address,uint256)", address(0x000000000000000000000000000000000000bEEF)'
        in rendered
    )
    assert 'abi.encodeWithSignature("redeem(uint256)"' in rendered
    assert "10000000000000000000" in rendered
    assert "receive() external payable {}" in rendered


def test_blueprint_and_renderer_discover_spot_price_oracle_macro_from_structure(
    tmp_path: Path,
) -> None:
    source = """
pragma solidity 0.8.24;
contract Token {
    mapping(address=>uint256) public balanceOf;
    mapping(address=>mapping(address=>uint256)) public allowance;
    function approve(address spender,uint256 amount) external returns(bool) { allowance[msg.sender][spender]=amount; return true; }
    function transferFrom(address from,address to,uint256 amount) external returns(bool) { balanceOf[from]-=amount; balanceOf[to]+=amount; return true; }
    function transfer(address to,uint256 amount) external returns(bool) { balanceOf[msg.sender]-=amount; balanceOf[to]+=amount; return true; }
    function mint(address to,uint256 amount) external { balanceOf[to]+=amount; }
}
contract Pool {
    Token public col; Token public bor;
    uint256 public reserveCol; uint256 public reserveBor;
    function spotPrice() external view returns(uint256) { return (reserveBor * 1e18) / reserveCol; }
    function swapBorForCol(uint256 borIn) external {
        bor.transferFrom(msg.sender,address(this),borIn);
        uint256 colOut=(reserveCol*borIn)/(reserveBor+borIn);
        reserveBor += borIn; reserveCol -= colOut; col.transfer(msg.sender,colOut);
    }
}
contract Demo {
    Token public collateralToken; Token public borrowToken; Pool public pool;
    mapping(address=>uint256) public collateralOf; mapping(address=>uint256) public debtOf;
    uint256 public totalCollateral; uint256 public totalDebt;
    function faucet() external { borrowToken.mint(msg.sender,1000e18); }
    function depositCollateral(uint256 amount) external { collateralToken.transferFrom(msg.sender,address(this),amount); collateralOf[msg.sender]+=amount; totalCollateral+=amount; }
    function borrow(uint256 amount) external { uint256 price=pool.spotPrice(); uint256 value=collateralOf[msg.sender]*price/1e18; require(debtOf[msg.sender]+amount<=value); debtOf[msg.sender]+=amount; totalDebt+=amount; borrowToken.transfer(msg.sender,amount); }
}
"""
    blueprint = build_search_blueprint(
        source, "contract Invariants {}", _loaded_manifest(tmp_path, value_wei="0")
    )
    macro = next(
        action for action in blueprint.actions if action.kind == "spot_price_oracle"
    )
    candidate = _Candidate((_Step(macro.id, macro.signature),))

    rendered = render_candidate(blueprint, candidate)

    assert 'abi.encodeWithSignature("faucet()")' in rendered
    assert 'abi.encodeWithSignature("collateralToken()")' in rendered
    assert 'abi.encodeWithSignature("borrowToken()")' in rendered
    assert 'abi.encodeWithSignature("pool()")' in rendered
    assert 'abi.encodeWithSignature("swapBorForCol(uint256)"' in rendered
    assert 'abi.encodeWithSignature("depositCollateral(uint256)"' in rendered
    assert 'abi.encodeWithSignature("borrow(uint256)"' in rendered


def test_blueprint_converts_to_existing_qprover_search_problem(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import sys
    import types

    monkeypatch.setitem(sys.modules, "z3", types.ModuleType("z3"))
    from qprover.trust404 import to_qprover_problem

    source = """
pragma solidity 0.8.24;
contract Demo {
    mapping(address => uint256) public balanceOf;
    function transfer(address to, uint256 amount) external { unchecked { balanceOf[msg.sender]-=amount; balanceOf[to]+=amount; } }
    function redeem(uint256 amount) external { require(balanceOf[msg.sender]>=amount); balanceOf[msg.sender]-=amount; (bool ok,)=msg.sender.call{value:amount}(""); require(ok); }
}
"""
    blueprint = build_search_blueprint(
        source, "contract Invariants {}", _loaded_manifest(tmp_path)
    )
    problem = to_qprover_problem(blueprint)

    assert problem.max_sequence_length == 3
    assert set(problem.actions) == {action.id for action in blueprint.actions}
    assert problem.hypothesis_sequences == blueprint.hypothesis_sequences
    macro = next(
        action for action in blueprint.actions if action.kind == "unchecked_accounting"
    )
    assert problem.repetition_limits[macro.id] == 1
    assert any(variant.action_id == macro.id for variant in problem.variants)


def test_blueprint_builds_high_confidence_access_control_macro(tmp_path: Path) -> None:
    source = """
pragma solidity 0.8.24;
contract Demo {
    address public owner;
    function setOwner(address newOwner) external { owner = newOwner; }
    function guarded(address newOwner) external { require(msg.sender == owner); owner = newOwner; }
}
"""
    blueprint = build_search_blueprint(
        source, "contract Invariants {}", _loaded_manifest(tmp_path)
    )

    macros = [action for action in blueprint.actions if action.kind == "access_control"]
    assert [action.id for action in macros] == ["macro:access-control:setOwner"]
    candidate = _Candidate((_Step(macros[0].id, macros[0].signature),))
    rendered = render_candidate(blueprint, candidate)
    assert 'abi.encodeWithSignature("setOwner(address)", address(this))' in rendered
