from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

import qprover.trust404 as trust404
from qprover.trust404 import (
    ManifestContractError,
    Track04Manifest,
    build_search_model,
)
from qprover.trust404_property import PropertyAnalysis, PropertyFact


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
            "predicates": ["solvent"],
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
    writes: tuple[str, ...] = (),
    value_flows: tuple[object, ...] = (),
) -> SimpleNamespace:
    return SimpleNamespace(
        signature=signature,
        visibility="external",
        state_mutability="nonpayable",
        function_selector="0x12345678",
        parameters=(),
        returns=(),
        canonical_id=f"function:src/Demo.sol:Demo:{signature}",
        transitive_storage_reads=(),
        transitive_storage_writes=writes,
        calls=(),
        value_flows=value_flows,
        external_call_before_write=False,
        source_name="src/Demo.sol",
        source_span="0:1:0",
    )


def _analysis() -> SimpleNamespace:
    alpha = _function(
        "alpha()",
        value_flows=(
            SimpleNamespace(asset="native", direction="out", operation="call"),
        ),
    )
    beta = _function(
        "beta()",
        writes=("storage:src/Demo.sol:Demo:9:flag",),
    )
    root = SimpleNamespace(
        name="Demo",
        source_name="src/Demo.sol",
        functions=(alpha, beta),
        storage=(),
        abi_signatures=(),
    )

    def contract(*identity: str) -> SimpleNamespace:
        if identity in {("Demo",), ("src/Demo.sol", "Demo")}:
            return root
        raise KeyError(identity)

    properties = PropertyAnalysis(
        invariants_source_name="Invariants.sol",
        contract_name="Invariants",
        facts=(
            PropertyFact(
                predicate_name="solvent",
                function_id="function:Invariants.sol:Invariants:20:solvent(address)",
                target_parameter_index=0,
                target_balance_read=True,
                target_calls=(),
                constants=(10 * 10**18,),
                comparison_hints=((">=", "target.balance", "constant"),),
                source_span="20:20:0",
                bound_from_check_all=True,
                known=True,
            ),
        ),
    )
    return SimpleNamespace(
        report=SimpleNamespace(contract=contract, contracts=(root,)),
        graph=SimpleNamespace(),
        source_name="src/Demo.sol",
        contract_name="Demo",
        source_units=(),
        property_analysis=properties,
    )


def test_build_search_model_passes_invariant_compiler_inputs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target, invariants = _sources(tmp_path)
    manifest = _manifest(tmp_path)
    seen: dict[str, object] = {}

    def fake_compile(*_args: object, **kwargs: object) -> SimpleNamespace:
        seen.update(kwargs)
        return _analysis()

    monkeypatch.setattr(trust404, "compile_track04_target", fake_compile)

    build_search_model(target, invariants, manifest)

    assert Path(str(seen["invariants_path"])).resolve() == invariants.resolve()
    assert seen["predicates"] == ("solvent",)


def test_build_search_model_uses_property_relevance_in_action_utilities(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target, invariants = _sources(tmp_path)
    monkeypatch.setattr(
        trust404,
        "compile_track04_target",
        lambda *_args, **_kwargs: _analysis(),
    )

    model = build_search_model(target, invariants, _manifest(tmp_path))

    assert model.utilities["call:alpha()"] > model.utilities["call:beta()"]


@pytest.mark.parametrize(
    ("function_id", "bound_from_check_all"),
    ((None, False), ("function:Invariants.sol:Invariants:20:solvent(address)", False)),
)
def test_build_search_model_rejects_missing_or_unbound_manifest_predicate(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    function_id: str | None,
    bound_from_check_all: bool,
) -> None:
    target, invariants = _sources(tmp_path)
    analysis = _analysis()
    invalid_fact = PropertyFact(
        predicate_name="solvent",
        function_id=function_id,
        target_parameter_index=0,
        target_balance_read=True,
        target_calls=(),
        constants=(),
        comparison_hints=(),
        source_span=None,
        bound_from_check_all=bound_from_check_all,
        known=False,
    )
    analysis.property_analysis = PropertyAnalysis(
        invariants_source_name="Invariants.sol",
        contract_name="Invariants",
        facts=(invalid_fact,),
    )
    monkeypatch.setattr(
        trust404,
        "compile_track04_target",
        lambda *_args, **_kwargs: analysis,
    )

    with pytest.raises(ManifestContractError, match="predicate"):
        build_search_model(target, invariants, _manifest(tmp_path))


def test_build_search_model_rejects_manifest_predicate_order_mismatch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target, invariants = _sources(tmp_path)
    analysis = _analysis()
    analysis.property_analysis = PropertyAnalysis(
        invariants_source_name="Invariants.sol",
        contract_name="Invariants",
        facts=analysis.property_analysis.facts,
        check_all_predicates=("other", "solvent"),
    )
    monkeypatch.setattr(
        trust404,
        "compile_track04_target",
        lambda *_args, **_kwargs: analysis,
    )

    with pytest.raises(ManifestContractError, match="order"):
        build_search_model(target, invariants, _manifest(tmp_path))
