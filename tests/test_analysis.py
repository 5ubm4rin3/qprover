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
    fixture = report.contract("Fixture")

    assert tuple(function.signature for function in fixture.functions) == (
        "_recordDeposit(address,uint256)",
        "deposit()",
        "guardedSink(address,uint256)",
        "oracleSink(address)",
        "setOperator(address)",
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
    record = report.function("Fixture", "_recordDeposit(address,uint256)")
    withdraw = report.function("Fixture", "withdraw()")

    assert record.storage_reads == ("balances",)
    assert record.storage_writes == ("balances",)
    assert withdraw.storage_reads == ("balances",)
    assert withdraw.storage_writes == ("balances",)


def test_analysis_resolves_calls_and_cycle_safe_transitive_summary(
    report: AnalysisReport,
) -> None:
    deposit = report.function("Fixture", "deposit()")

    assert tuple((call.kind, call.callee_signature) for call in deposit.calls) == (
        ("internal", "_recordDeposit(address,uint256)"),
    )
    assert deposit.transitive_storage_reads == ("balances",)
    assert deposit.transitive_storage_writes == ("balances",)
    assert deposit.transitive_calls == ("_recordDeposit(address,uint256)",)


def test_analysis_retains_call_order_role_value_and_oracle_features(
    report: AnalysisReport,
) -> None:
    withdraw = report.function("Fixture", "withdraw()")
    guarded = report.function("Fixture", "guardedSink(address,uint256)")
    price_update = report.function("Fixture", "updatePrice(address)")
    oracle_sink = report.function("Fixture", "oracleSink(address)")

    assert withdraw.external_call_before_write is True
    assert tuple(call.member_name for call in withdraw.calls) == ("call", "require")
    assert guarded.role_guards == ("operator",)
    assert guarded.value_flows[0].asset == "native"
    assert guarded.value_flows[0].operation == "call"
    assert tuple(call.member_name for call in price_update.calls) == ("getPrice",)
    assert price_update.oracle_calls == ("getPrice",)
    assert oracle_sink.storage_reads == ("cachedPrice",)
    assert oracle_sink.value_flows[0].operation == "transfer"


def test_analysis_is_deterministic_for_same_bundle(
    artifact_bundle: ArtifactBundle,
) -> None:
    first = analyze(artifact_bundle)
    second = analyze(artifact_bundle)

    assert first.to_json() == second.to_json()
