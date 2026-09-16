from __future__ import annotations

import inspect
import json
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace

import pytest

import qprover.trust404 as trust404
from qprover.trust404 import (
    SELF_ADDRESS,
    Track04Manifest,
    build_search_model,
    render_candidate,
)


def _manifest(tmp_path: Path) -> Track04Manifest:
    raw = {
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
            "value_wei": "1000000000000000000",
            "setup": None,
        },
        "determinism": {
            "block_number": 21_000_000,
            "block_timestamp": 1_735_689_600,
            "seed": 42,
        },
        "invariants": {
            "contract": "Invariants.sol",
            "predicates": ["checkAll"],
        },
        "budget": {"timeout_sec": 300, "max_attempts": 5},
    }
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps(raw), encoding="utf-8")
    return Track04Manifest.load(path)


def _sources(tmp_path: Path) -> tuple[Path, Path]:
    src = tmp_path / "src"
    src.mkdir()
    target = src / "Demo.sol"
    target.write_text("pragma solidity 0.8.24; contract Demo {}", encoding="utf-8")
    invariants = tmp_path / "Invariants.sol"
    invariants.write_text(
        "pragma solidity 0.8.24; contract Invariants {}", encoding="utf-8"
    )
    return target, invariants


def _function(
    signature: str,
    *,
    parameters: tuple[str, ...] = (),
    mutability: str = "nonpayable",
    reads: tuple[str, ...] = (),
    writes: tuple[str, ...] = (),
    calls: tuple[object, ...] = (),
    value_flows: tuple[object, ...] = (),
) -> SimpleNamespace:
    return SimpleNamespace(
        signature=signature,
        visibility="external",
        state_mutability=mutability,
        function_selector="0x12345678",
        parameters=parameters,
        canonical_id=f"function:src/Demo.sol:Demo:{signature}",
        transitive_storage_reads=reads,
        transitive_storage_writes=writes,
        calls=calls,
        value_flows=value_flows,
        external_call_before_write=False,
        source_name="src/Demo.sol",
        source_span="0:1:0",
    )


def _analysis() -> SimpleNamespace:
    functions = (
        _function(
            "deposit()",
            mutability="payable",
            writes=("storage:credit",),
        ),
        _function(
            "setOwner(address)",
            parameters=("address",),
            writes=("storage:owner",),
        ),
        _function(
            "move(address,uint256)",
            parameters=("address", "uint256"),
            reads=("storage:credit",),
            writes=("storage:credit",),
        ),
        _function(
            "withdraw(uint256)",
            parameters=("uint256",),
            reads=("storage:credit",),
            writes=("storage:credit",),
            calls=(object(),),
            value_flows=(object(),),
        ),
    )
    contract = SimpleNamespace(functions=functions)
    report = SimpleNamespace(contract=lambda *_args: contract)
    return SimpleNamespace(
        report=report,
        graph=SimpleNamespace(),
        source_name="src/Demo.sol",
        contract_name="Demo",
    )


@pytest.fixture(autouse=True)
def _compiler_facts(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        trust404, "compile_track04_target", lambda *_a, **_kw: _analysis()
    )


def test_v2_search_model_contains_only_generic_call_actions(tmp_path: Path) -> None:
    target, invariants = _sources(tmp_path)
    model = build_search_model(target, invariants, _manifest(tmp_path))

    assert model.actions
    assert all(action.kind == "call" for action in model.actions)
    assert all(action.id.startswith("call:") for action in model.actions)
    assert not any("macro" in action.id.lower() for action in model.actions)
    assert {action.signature for action in model.actions} >= {
        "deposit()",
        "setOwner(address)",
        "move(address,uint256)",
        "withdraw(uint256)",
    }


def test_v2_dependency_transitions_are_label_neutral_and_deterministic(
    tmp_path: Path,
) -> None:
    target, invariants = _sources(tmp_path)
    manifest = _manifest(tmp_path)

    first = build_search_model(target, invariants, manifest)
    second = build_search_model(target, invariants, manifest)

    assert first.actions == second.actions
    assert first.variants == second.variants
    assert first.utilities == second.utilities
    assert first.transitions == second.transitions
    assert first.max_sequence_length == second.max_sequence_length
    assert (
        "call:move(address,uint256)",
        "call:withdraw(uint256)",
    ) in first.transitions
    assert all("reentr" not in key.lower() for key in first.utilities)
    assert all("oracle" not in key.lower() for key in first.utilities)


@dataclass(frozen=True)
class _Step:
    action_id: str
    signature: str
    args: tuple[object, ...]
    value_wei: int = 0


@dataclass(frozen=True)
class _Candidate:
    steps: tuple[_Step, ...]


def test_v2_renderer_is_generic_and_has_no_vulnerability_specific_branch(
    tmp_path: Path,
) -> None:
    target, invariants = _sources(tmp_path)
    model = build_search_model(target, invariants, _manifest(tmp_path))
    candidate = _Candidate(
        (
            _Step(
                "call:setOwner(address)",
                "setOwner(address)",
                (SELF_ADDRESS,),
            ),
        )
    )

    code = render_candidate(model, candidate)

    assert "contract Exploit" in code
    assert "function run(address target) external payable" in code
    assert 'abi.encodeWithSignature("setOwner(address)", address(this))' in code
    lowered = code.lower()
    assert "reentrancy" not in lowered
    assert "oracle" not in lowered
    assert "unchecked_accounting" not in lowered


def test_track04_production_module_contains_no_macro_generators() -> None:
    source = inspect.getsource(trust404)
    forbidden = (
        "_reentrancy_macros",
        "_access_control_macros",
        "_unchecked_accounting_macro",
        "_spot_price_oracle_macros",
        "macro:reentrancy",
        "macro:access-control",
        "macro:unchecked-accounting",
        "macro:spot-price-oracle",
    )
    assert not any(token in source for token in forbidden)
