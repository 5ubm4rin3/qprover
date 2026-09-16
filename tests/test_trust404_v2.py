from __future__ import annotations

import inspect
import json
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace

import pytest

import qprover.trust404 as trust404
from qprover.trust404 import (
    ADDRESS_REF_PREFIX,
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
    contract: str = "Demo",
    parameters: tuple[str, ...] = (),
    returns: tuple[str, ...] = (),
    mutability: str = "nonpayable",
    reads: tuple[str, ...] = (),
    writes: tuple[str, ...] = (),
    calls: tuple[object, ...] = (),
    value_flows: tuple[object, ...] = (),
    external_call_before_write: bool = False,
) -> SimpleNamespace:
    return SimpleNamespace(
        signature=signature,
        visibility="external",
        state_mutability=mutability,
        function_selector="0x12345678",
        parameters=parameters,
        returns=returns,
        canonical_id=f"function:src/Demo.sol:{contract}:{signature}",
        transitive_storage_reads=reads,
        transitive_storage_writes=writes,
        calls=calls,
        value_flows=value_flows,
        external_call_before_write=external_call_before_write,
        source_name="src/Demo.sol",
        source_span="0:1:0",
    )


def _storage(name: str, type_name: str) -> SimpleNamespace:
    return SimpleNamespace(name=name, type_name=type_name)


def _call(callee: SimpleNamespace) -> SimpleNamespace:
    return SimpleNamespace(callee_id=callee.canonical_id)


def _analysis() -> SimpleNamespace:
    peer_read = _function(
        "read()",
        contract="Peer",
        returns=("uint256",),
        mutability="view",
        reads=("storage:peer:value",),
    )
    peer_functions = (
        peer_read,
        _function(
            "configure(address,uint256)",
            contract="Peer",
            parameters=("address", "uint256"),
            writes=("storage:peer:value",),
        ),
        _function(
            "balanceOf(address)",
            contract="Peer",
            parameters=("address",),
            returns=("uint256",),
            mutability="view",
            reads=("storage:peer:value",),
        ),
    )
    root_functions = (
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
            external_call_before_write=True,
        ),
        _function(
            "consume()",
            calls=(_call(peer_read),),
            reads=(),
            writes=("storage:consumed",),
        ),
    )
    root = SimpleNamespace(
        name="Demo",
        source_name="src/Demo.sol",
        functions=root_functions,
        storage=(_storage("peer", "contract Peer"),),
        abi_signatures=("peer()",),
    )
    peer = SimpleNamespace(
        name="Peer",
        source_name="src/Demo.sol",
        functions=peer_functions,
        storage=(),
        abi_signatures=(
            "configure(address,uint256)",
            "read()",
            "balanceOf(address)",
        ),
    )
    contracts = (root, peer)

    def contract(*identity: str) -> SimpleNamespace:
        if len(identity) == 1:
            source = None
            name = identity[0]
        else:
            source, name = identity
        matches = [
            item
            for item in contracts
            if item.name == name
            and (source is None or item.source_name == source)
        ]
        if len(matches) != 1:
            raise KeyError(identity)
        return matches[0]

    report = SimpleNamespace(contract=contract, contracts=contracts)
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


def test_v2_discovers_reachable_contract_actions_and_cross_contract_dependencies(
    tmp_path: Path,
) -> None:
    target, invariants = _sources(tmp_path)
    model = build_search_model(target, invariants, _manifest(tmp_path))

    action = next(
        item
        for item in model.actions
        if item.signature == "configure(address,uint256)"
    )
    assert action.kind == "call"
    assert action.target_path == ("peer()",)
    assert action.id == "call:peer():configure(address,uint256)"
    assert (
        action.id,
        "call:consume()",
    ) in model.transitions

    dynamic_addresses = {
        argument
        for variant in model.variants
        for argument in variant.args
        if isinstance(argument, str) and argument.startswith(ADDRESS_REF_PREFIX)
    }
    assert dynamic_addresses


def test_v2_callback_mode_is_generic_search_action(tmp_path: Path) -> None:
    target, invariants = _sources(tmp_path)
    model = build_search_model(target, invariants, _manifest(tmp_path))

    callback = next(
        action
        for action in model.actions
        if action.signature == "withdraw(uint256)" and action.callback_enabled
    )
    assert callback.kind == "call"
    assert callback.id == "call:withdraw(uint256)@callback"
    assert "macro" not in callback.id

    candidate = _Candidate(
        (
            _Step(
                callback.id,
                callback.signature,
                (1,),
            ),
        )
    )
    code = render_candidate(model, candidate)
    assert "address private _callbackTarget" in code
    assert "bytes private _callbackData" in code
    assert "receive() external payable" in code
    assert "_callbackTarget.call(_callbackData)" in code
    assert "reentrancy" not in code.lower()


@dataclass(frozen=True)
class _Step:
    action_id: str
    signature: str
    args: tuple[object, ...]
    value_wei: int = 0


@dataclass(frozen=True)
class _Candidate:
    steps: tuple[_Step, ...]


def test_v2_renderer_resolves_reachable_contract_target(tmp_path: Path) -> None:
    target, invariants = _sources(tmp_path)
    model = build_search_model(target, invariants, _manifest(tmp_path))
    action = next(
        item
        for item in model.actions
        if item.signature == "configure(address,uint256)"
    )
    candidate = _Candidate(
        (
            _Step(
                action.id,
                action.signature,
                (SELF_ADDRESS, 1),
            ),
        )
    )

    code = render_candidate(model, candidate)
    assert '_readAddress(target, abi.encodeWithSignature("peer()"))' in code
    assert 'abi.encodeWithSignature("configure(address,uint256)"' in code


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
