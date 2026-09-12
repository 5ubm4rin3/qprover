import json
import shutil
from pathlib import Path

import pytest
from test_artifacts import fixture_manifest_data

from qprover.analysis import AnalysisReport, analyze
from qprover.artifacts import ArtifactBundle, build_target
from qprover.manifest import load_manifest


def build_artifact_bundle(tmp_path: Path) -> ArtifactBundle:
    source = Path(__file__).parent / "fixtures" / "analysis"
    project = tmp_path / "fixture"
    shutil.copytree(source, project)
    manifest_path = tmp_path / "target.json"
    manifest_path.write_text(json.dumps(fixture_manifest_data()), encoding="utf-8")
    return build_target(load_manifest(manifest_path))


def build_analysis_report(tmp_path: Path) -> AnalysisReport:
    return analyze(build_artifact_bundle(tmp_path))


@pytest.fixture
def artifact_bundle(tmp_path: Path) -> ArtifactBundle:
    return build_artifact_bundle(tmp_path)


@pytest.fixture
def report(tmp_path: Path) -> AnalysisReport:
    return build_analysis_report(tmp_path)


def test_analysis_extracts_exact_functions_and_storage(report: AnalysisReport) -> None:
    fixture = report.contract("Fixture.sol", "Fixture")

    assert tuple(function.signature for function in fixture.functions) == (
        "_recordDeposit(address,uint256)",
        "createChild()",
        "deposit()",
        "guardedSink(address,uint256)",
        "oracleSink(address)",
        "pairwiseOrdering(address,address)",
        "setOperator(address)",
        "tokenTransfer(address,address,uint256)",
        "updatePrice(address)",
        "withdraw()",
    )
    assert tuple(storage.name for storage in fixture.storage) == (
        "balances",
        "cachedPrice",
        "operator",
    )
    assert fixture.storage[0].slot == "0"


def test_analysis_classifies_state_reads_and_writes(report: AnalysisReport) -> None:
    record = report.function(
        "Fixture.sol", "Fixture", "_recordDeposit(address,uint256)"
    )
    withdraw = report.function("Fixture.sol", "Fixture", "withdraw()")
    balances = report.storage("Fixture.sol", "Fixture", "balances")

    assert record.storage_reads == (balances.canonical_id,)
    assert record.storage_writes == (balances.canonical_id,)
    assert withdraw.storage_reads == (balances.canonical_id,)
    assert withdraw.storage_writes == (balances.canonical_id,)


def test_analysis_resolves_calls_and_cycle_safe_transitive_summary(
    report: AnalysisReport,
) -> None:
    deposit = report.function("Fixture.sol", "Fixture", "deposit()")
    record = report.function(
        "Fixture.sol", "Fixture", "_recordDeposit(address,uint256)"
    )
    balances = report.storage("Fixture.sol", "Fixture", "balances")

    assert tuple((call.kind, call.callee_signature) for call in deposit.calls) == (
        ("internal", "_recordDeposit(address,uint256)"),
    )
    assert deposit.calls[0].callee_id == record.canonical_id
    assert deposit.transitive_storage_reads == (balances.canonical_id,)
    assert deposit.transitive_storage_writes == (balances.canonical_id,)
    assert deposit.transitive_calls == (record.canonical_id,)


def test_analysis_retains_call_order_role_value_and_oracle_features(
    report: AnalysisReport,
) -> None:
    withdraw = report.function("Fixture.sol", "Fixture", "withdraw()")
    guarded = report.function("Fixture.sol", "Fixture", "guardedSink(address,uint256)")
    price_update = report.function("Fixture.sol", "Fixture", "updatePrice(address)")
    oracle_sink = report.function("Fixture.sol", "Fixture", "oracleSink(address)")
    operator = report.storage("Fixture.sol", "Fixture", "operator")
    cached_price = report.storage("Fixture.sol", "Fixture", "cachedPrice")

    assert withdraw.external_call_before_write is True
    assert tuple(call.member_name for call in withdraw.calls) == ("call", "require")
    assert guarded.role_guards == (operator.canonical_id,)
    assert guarded.value_flows[0].asset == "native"
    assert guarded.value_flows[0].operation == "call"
    assert tuple(call.member_name for call in price_update.calls) == ("getPrice",)
    assert price_update.oracle_calls == ("getPrice",)
    assert oracle_sink.storage_reads == (cached_price.canonical_id,)
    assert oracle_sink.value_flows[0].operation == "transfer"


def test_analysis_preserves_pairwise_call_before_write_facts(
    report: AnalysisReport,
) -> None:
    function = report.function(
        "Fixture.sol", "Fixture", "pairwiseOrdering(address,address)"
    )
    balances = report.storage("Fixture.sol", "Fixture", "balances")

    assert function.external_call_before_write is True
    assert len(function.ordered_call_writes) == 1
    assert function.ordered_call_writes[0].storage_id == balances.canonical_id
    assert function.ordered_call_writes[0].call_member_name == "call"


def test_analysis_distinguishes_token_transfer_from_native_transfer(
    report: AnalysisReport,
) -> None:
    token_transfer = report.function(
        "Fixture.sol", "Fixture", "tokenTransfer(address,address,uint256)"
    )
    native_transfer = report.function("Fixture.sol", "Fixture", "oracleSink(address)")
    token_call = next(
        call for call in token_transfer.calls if call.member_name == "transfer"
    )

    assert token_call.kind == "external"
    assert token_call.receiver_type == "contract IERC20"
    assert token_transfer.value_flows[0].asset == "token"
    assert token_transfer.value_flows[0].operation == "transfer"
    assert native_transfer.calls[-1].kind == "low_level"
    assert native_transfer.value_flows[0].asset == "native"


def test_analysis_extracts_contract_creation_with_provenance(
    report: AnalysisReport,
) -> None:
    function = report.function("Fixture.sol", "Fixture", "createChild()")

    assert len(function.calls) == 1
    assert function.calls[0].kind == "creation"
    assert function.calls[0].member_name == "new"
    assert function.calls[0].callee_contract == "Child"
    assert function.calls[0].source_span != "unknown"


def test_analysis_is_deterministic_for_same_bundle(
    artifact_bundle: ArtifactBundle,
) -> None:
    first = analyze(artifact_bundle)
    second = analyze(artifact_bundle)

    assert first.to_json() == second.to_json()


def _zero_arg_action(action_id: str, target_id: str, signature: str) -> dict:
    return {
        "id": action_id,
        "target_id": target_id,
        "signature": signature,
        "mutability": "nonpayable",
        "sender_slots": [1],
        "arguments": [],
        "value_domain": {"kind": "finite", "values": [0]},
        "max_repetitions": 1,
    }


def build_multi_source_report(tmp_path: Path) -> AnalysisReport:
    project = tmp_path / "multi"
    project.mkdir()
    (project / "foundry.toml").write_text(
        '[profile.default]\nsrc="."\nout="out"\ncache_path="cache"\n'
        'solc_version="0.8.34"\nevm_version="prague"\n',
        encoding="utf-8",
    )
    (project / "Base.sol").write_text(
        "pragma solidity 0.8.34; contract Base { uint256 internal total; "
        "function _credit() internal { total += 1; } }",
        encoding="utf-8",
    )
    (project / "Derived.sol").write_text(
        'pragma solidity 0.8.34; import "./Base.sol"; contract Derived is Base {'
        "function deposit() external { _credit(); } "
        "function withdraw() external view returns (uint256) { return total; } }",
        encoding="utf-8",
    )
    (project / "A.sol").write_text(
        "pragma solidity 0.8.34; contract Twin { uint256 x; "
        "function write() external { x = 1; } }",
        encoding="utf-8",
    )
    (project / "B.sol").write_text(
        "pragma solidity 0.8.34; contract Twin { uint256 x; "
        "function read() external view returns (uint256) { return x; } }",
        encoding="utf-8",
    )
    raw = fixture_manifest_data("multi")
    raw["target"]["source_files"] = ["A.sol", "B.sol", "Derived.sol"]
    raw["deployments"] = [
        {
            "id": "a",
            "artifact": "A.sol:Twin",
            "constructor_args": [],
            "sender_slot": 0,
            "value_wei": 0,
        },
        {
            "id": "b",
            "artifact": "B.sol:Twin",
            "constructor_args": [],
            "sender_slot": 0,
            "value_wei": 0,
        },
        {
            "id": "derived",
            "artifact": "Derived.sol:Derived",
            "constructor_args": [],
            "sender_slot": 0,
            "value_wei": 0,
        },
    ]
    raw["actions"] = [
        _zero_arg_action("a_write", "a", "write()"),
        _zero_arg_action("b_read", "b", "read()"),
        _zero_arg_action("deposit", "derived", "deposit()"),
        _zero_arg_action("withdraw", "derived", "withdraw()"),
    ]
    manifest_path = tmp_path / "target.json"
    manifest_path.write_text(json.dumps(raw), encoding="utf-8")
    return analyze(build_target(load_manifest(manifest_path)))


def test_analysis_resolves_inherited_storage_and_internal_calls(
    tmp_path: Path,
) -> None:
    report = build_multi_source_report(tmp_path)
    deposit = report.function("Derived.sol", "Derived", "deposit()")
    credit = report.function("Base.sol", "Base", "_credit()")
    total = report.storage("Base.sol", "Base", "total")

    assert deposit.calls[0].callee_id == credit.canonical_id
    assert deposit.transitive_storage_writes == (total.canonical_id,)
    assert deposit.transitive_calls == (credit.canonical_id,)


def test_analysis_keeps_duplicate_contract_names_source_qualified(
    tmp_path: Path,
) -> None:
    report = build_multi_source_report(tmp_path)

    first = report.contract("A.sol", "Twin")
    second = report.contract("B.sol", "Twin")

    assert first.canonical_id != second.canonical_id
    assert first.source_name == "A.sol"
    assert second.source_name == "B.sol"
