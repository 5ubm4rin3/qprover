import json
import shutil
from collections.abc import Iterator
from pathlib import Path

import pytest
from test_artifacts import fixture_manifest_data

from qprover.analysis import AnalysisReport, analyze
from qprover.artifacts import ArtifactBundle, build_target
from qprover.manifest import load_manifest
from qprover.models import TargetManifest


def build_artifact_bundle(tmp_path: Path) -> ArtifactBundle:
    source = Path(__file__).parent / "fixtures" / "analysis"
    project = tmp_path / "fixture"
    shutil.copytree(source, project)
    manifest_path = tmp_path / "target.json"
    manifest_path.write_text(json.dumps(fixture_manifest_data()), encoding="utf-8")
    return build_target(load_manifest(manifest_path))


def build_analysis_report(tmp_path: Path) -> AnalysisReport:
    with build_artifact_bundle(tmp_path) as bundle:
        return analyze(bundle)


@pytest.fixture
def artifact_bundle(tmp_path: Path) -> Iterator[ArtifactBundle]:
    bundle = build_artifact_bundle(tmp_path)
    try:
        yield bundle
    finally:
        bundle.close()


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
        "uncorrelatedOrdering(address,address)",
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


def _address_action(action_id: str, target_id: str, signature: str) -> dict:
    action = _zero_arg_action(action_id, target_id, signature)
    action["arguments"] = [
        {
            "name": "recipient",
            "type": "address",
            "domain": {
                "kind": "finite",
                "values": ["0x0000000000000000000000000000000000000001"],
            },
        }
    ]
    return action


def _selector_action(
    action_id: str, signature: str, parameter_types: tuple[str, ...]
) -> dict:
    action = _zero_arg_action(action_id, "selector", signature)
    action["arguments"] = [
        {
            "name": f"argument{index}",
            "type": type_name,
            "domain": {
                "kind": "finite",
                "values": [
                    (
                        "0x0000000000000000000000000000000000000001"
                        if type_name == "address"
                        else "[]"
                        if "[" in type_name or type_name.startswith("(")
                        else 0
                    )
                ],
            },
        }
        for index, type_name in enumerate(parameter_types)
    ]
    return action


def build_selector_target(
    tmp_path: Path,
) -> tuple[AnalysisReport, TargetManifest]:
    project = tmp_path / "selectors"
    project.mkdir()
    (project / "foundry.toml").write_text(
        '[profile.default]\nsrc="."\nout="out"\ncache_path="cache"\n'
        'solc_version="0.8.34"\nevm_version="prague"\n',
        encoding="utf-8",
    )
    (project / "Selector.sol").write_text(
        "pragma solidity 0.8.34; "
        "type Amount is uint256; "
        "interface Receiver {} "
        "contract SelectorBase { "
        "enum Choice { Zero, One } "
        "struct Payload { uint256 amount; address recipient; } "
        "function enumSink(Choice choice, address payable recipient) public { "
        "recipient.transfer(uint256(choice)); } "
        "function structSink(Payload memory payload) public { "
        "payable(payload.recipient).transfer(payload.amount); } "
        "function structArraySink(Payload[] memory payloads, "
        "address payable recipient) public { recipient.transfer(payloads.length); } "
        "function udvtSink(Amount amount, address payable recipient) public { "
        "recipient.transfer(Amount.unwrap(amount)); } "
        "function contractArraySink(Receiver[] memory receivers, "
        "address payable recipient) public { recipient.transfer(receivers.length); } "
        "function overloaded(uint8 amount, address payable recipient) public { "
        "recipient.transfer(amount); } "
        "function overloaded(uint256 amount, address payable recipient) public { "
        "recipient.transfer(amount); } "
        "} contract SelectorDerived is SelectorBase {}",
        encoding="utf-8",
    )
    raw = fixture_manifest_data("selectors")
    raw["target"]["source_files"] = ["Selector.sol"]
    raw["deployments"] = [
        {
            "id": "selector",
            "artifact": "Selector.sol:SelectorDerived",
            "constructor_args": [],
            "sender_slot": 0,
            "value_wei": 0,
        }
    ]
    raw["actions"] = [
        _selector_action("enum_sink", "enumSink(uint8,address)", ("uint8", "address")),
        _selector_action(
            "struct_sink",
            "structSink((uint256,address))",
            ("(uint256,address)",),
        ),
        _selector_action(
            "struct_array_sink",
            "structArraySink((uint256,address)[],address)",
            ("(uint256,address)[]", "address"),
        ),
        _selector_action(
            "udvt_sink", "udvtSink(uint256,address)", ("uint256", "address")
        ),
        _selector_action(
            "contract_array_sink",
            "contractArraySink(address[],address)",
            ("address[]", "address"),
        ),
        _selector_action(
            "overloaded_small",
            "overloaded(uint8,address)",
            ("uint8", "address"),
        ),
        _selector_action(
            "overloaded_large",
            "overloaded(uint256,address)",
            ("uint256", "address"),
        ),
    ]
    manifest_path = tmp_path / "selector-target.json"
    manifest_path.write_text(json.dumps(raw), encoding="utf-8")
    manifest = load_manifest(manifest_path)
    with build_target(manifest) as bundle:
        return analyze(bundle), manifest


def build_multi_source_target(
    tmp_path: Path,
) -> tuple[AnalysisReport, TargetManifest]:
    project = tmp_path / "multi"
    project.mkdir()
    (project / "foundry.toml").write_text(
        '[profile.default]\nsrc="."\nout="out"\ncache_path="cache"\n'
        'solc_version="0.8.34"\nevm_version="prague"\n',
        encoding="utf-8",
    )
    (project / "Base.sol").write_text(
        "pragma solidity 0.8.34; contract Base { uint256 internal total; "
        "function _credit() internal { total += 1; } "
        "function inheritedSink(address payable recipient) public { "
        "recipient.transfer(1); } "
        "function overriddenSink(address payable recipient) public virtual { "
        "recipient.transfer(1); } }",
        encoding="utf-8",
    )
    (project / "Derived.sol").write_text(
        'pragma solidity 0.8.34; import "./Base.sol"; contract Derived is Base {'
        "function deposit() external { _credit(); } "
        "function withdraw() external view returns (uint256) { return total; } "
        "function overriddenSink(address payable recipient) public override { "
        "recipient.transfer(1); } }",
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
        _address_action(
            "inherited_sink", "derived", "inheritedSink(address)"
        ),
        _address_action(
            "overridden_sink", "derived", "overriddenSink(address)"
        ),
    ]
    manifest_path = tmp_path / "target.json"
    manifest_path.write_text(json.dumps(raw), encoding="utf-8")
    manifest = load_manifest(manifest_path)
    with build_target(manifest) as bundle:
        return analyze(bundle), manifest


def build_multi_source_report(tmp_path: Path) -> AnalysisReport:
    report, _ = build_multi_source_target(tmp_path)
    return report


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


def test_unknown_source_offsets_never_create_ordering() -> None:
    import qprover.analysis as analysis_module

    assert analysis_module._known_before("unknown", "10:2:0") is False
    assert analysis_module._known_before("1:2:0", "unknown") is False


def test_analysis_retains_compiler_selectors_and_canonical_deployment_abi(
    tmp_path: Path,
) -> None:
    report, _ = build_selector_target(tmp_path)
    base = report.contract("Selector.sol", "SelectorBase")
    derived = report.contract("Selector.sol", "SelectorDerived")

    assert {function.function_selector for function in base.functions} == {
        "0bd843f7",
        "2e591303",
        "3e480099",
        "4c7f9a90",
        "5a54ea8a",
        "98fff606",
        "cf520c46",
    }
    assert derived.abi_function_selectors == (
        ("contractArraySink(address[],address)", "3e480099"),
        ("enumSink(uint8,address)", "cf520c46"),
        ("overloaded(uint256,address)", "98fff606"),
        ("overloaded(uint8,address)", "5a54ea8a"),
        ("structArraySink((uint256,address)[],address)", "4c7f9a90"),
        ("structSink((uint256,address))", "0bd843f7"),
        ("udvtSink(uint256,address)", "2e591303"),
    )
