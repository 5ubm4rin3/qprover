import dataclasses

import pytest
from test_analysis import (
    build_analysis_report,
    build_multi_source_target,
    build_selector_target,
)
from test_artifacts import fixture_manifest_data

from qprover.analysis import AnalysisReport
from qprover.graph import build_program_graph
from qprover.hypotheses import generate_hypotheses
from qprover.models import TargetManifest


@pytest.fixture
def report(tmp_path) -> AnalysisReport:
    return build_analysis_report(tmp_path)


def fixture_manifest(report: AnalysisReport) -> TargetManifest:
    del report
    raw = fixture_manifest_data(".")
    raw["target"]["source_files"] = ["tests/fixtures/analysis/Fixture.sol"]
    return TargetManifest.model_validate(raw)


def test_graph_dependency_is_consumed_by_hypothesis(report: AnalysisReport) -> None:
    graph = build_program_graph(report)
    hypotheses = generate_hypotheses(graph, fixture_manifest(report))
    hypothesis = next(
        item for item in hypotheses if item.action_ids == ("deposit", "withdraw")
    )

    assert hypothesis.kind == "external-call-before-state-write"
    assert hypothesis.action_signatures == ("deposit()", "withdraw()")
    assert hypothesis.evidence
    assert hypothesis.provenance
    assert hypothesis.assumed_ordering == ("deposit", "withdraw")
    assert all(
        "Fixture.sol" in function_id for function_id in hypothesis.function_ids
    )


def test_hypotheses_cover_role_and_oracle_dependency_motifs(
    report: AnalysisReport,
) -> None:
    hypotheses = generate_hypotheses(
        build_program_graph(report), fixture_manifest(report)
    )
    by_kind = {hypothesis.kind: hypothesis for hypothesis in hypotheses}

    assert by_kind["authorization-writer-to-guarded-value-sink"].action_ids == (
        "set_operator",
        "guarded_sink",
    )
    assert by_kind["price-writer-to-value-sink"].action_ids == (
        "update_price",
        "oracle_sink",
    )


def test_hypotheses_are_ranked_deduplicated_non_verdict_records(
    report: AnalysisReport,
) -> None:
    hypotheses = generate_hypotheses(
        build_program_graph(report), fixture_manifest(report)
    )

    assert hypotheses
    assert len({hypothesis.evidence_hash for hypothesis in hypotheses}) == len(
        hypotheses
    )
    assert tuple(hypothesis.score for hypothesis in hypotheses) == tuple(
        sorted((hypothesis.score for hypothesis in hypotheses), reverse=True)
    )
    assert all(0 <= hypothesis.score <= 1 for hypothesis in hypotheses)
    assert all("confirmed" not in dataclasses.asdict(item) for item in hypotheses)


def test_hypothesis_deduplication_preserves_action_aliases(
    report: AnalysisReport,
) -> None:
    raw = fixture_manifest_data(".")
    raw["target"]["source_files"] = ["tests/fixtures/analysis/Fixture.sol"]
    alias = dict(
        next(action for action in raw["actions"] if action["id"] == "withdraw")
    )
    alias["id"] = "withdraw_alias"
    raw["actions"].append(alias)
    manifest = TargetManifest.model_validate(raw)

    hypotheses = generate_hypotheses(build_program_graph(report), manifest)
    weak_sink_actions = {
        hypothesis.action_ids
        for hypothesis in hypotheses
        if hypothesis.kind == "public-value-sink-with-weak-or-unknown-guard"
        and hypothesis.action_signatures == ("withdraw()",)
    }

    assert weak_sink_actions == {("withdraw",), ("withdraw_alias",)}


def test_hypotheses_map_inherited_and_overridden_deployment_actions(
    tmp_path,
) -> None:
    report, manifest = build_multi_source_target(tmp_path)
    graph = build_program_graph(report)
    hypotheses = generate_hypotheses(graph, manifest)
    weak = {
        hypothesis.action_ids[0]: hypothesis.function_ids[0]
        for hypothesis in hypotheses
        if hypothesis.kind == "public-value-sink-with-weak-or-unknown-guard"
    }

    assert weak["inherited_sink"] == report.function(
        "Base.sol", "Base", "inheritedSink(address)"
    ).canonical_id
    assert weak["overridden_sink"] == report.function(
        "Derived.sol", "Derived", "overriddenSink(address)"
    ).canonical_id


def test_hypotheses_fail_closed_for_unresolved_allowed_action(
    report: AnalysisReport,
) -> None:
    raw = fixture_manifest_data(".")
    raw["target"]["source_files"] = ["tests/fixtures/analysis/Fixture.sol"]
    raw["actions"].append(
        {
            "id": "missing",
            "target_id": "fixture",
            "signature": "missing()",
            "mutability": "nonpayable",
            "sender_slots": [1],
            "arguments": [],
            "value_domain": {"kind": "finite", "values": [0]},
            "max_repetitions": 1,
        }
    )
    manifest = TargetManifest.model_validate(raw)

    with pytest.raises(ValueError, match="allowed action.*missing"):
        generate_hypotheses(build_program_graph(report), manifest)


def test_hypotheses_fail_closed_for_ambiguous_deployment_artifact(
    report: AnalysisReport,
) -> None:
    fixture = report.contract("Fixture.sol", "Fixture")
    duplicate = dataclasses.replace(
        fixture, canonical_id=f"{fixture.canonical_id}:duplicate"
    )
    ambiguous = dataclasses.replace(report, contracts=report.contracts + (duplicate,))

    with pytest.raises(ValueError, match="ambiguous deployment artifact"):
        generate_hypotheses(
            build_program_graph(ambiguous), fixture_manifest(ambiguous)
        )


def test_external_call_before_write_hypothesis_requires_same_value_call(
    report: AnalysisReport,
) -> None:
    hypotheses = generate_hypotheses(
        build_program_graph(report), fixture_manifest(report)
    )

    assert not any(
        hypothesis.kind == "external-call-before-state-write"
        and hypothesis.action_ids[-1] == "uncorrelated_ordering"
        for hypothesis in hypotheses
    )


def test_hypotheses_resolve_canonical_abi_types_by_compiler_selector(
    tmp_path,
) -> None:
    report, manifest = build_selector_target(tmp_path)
    graph = build_program_graph(report)
    hypotheses = generate_hypotheses(graph, manifest)
    weak = {
        hypothesis.action_ids[0]: hypothesis.function_ids[0]
        for hypothesis in hypotheses
        if hypothesis.kind == "public-value-sink-with-weak-or-unknown-guard"
    }
    expected_selectors = {
        "enum_sink": "cf520c46",
        "struct_sink": "0bd843f7",
        "struct_array_sink": "4c7f9a90",
        "udvt_sink": "2e591303",
        "contract_array_sink": "3e480099",
        "overloaded_small": "5a54ea8a",
        "overloaded_large": "98fff606",
    }

    assert set(weak) == set(expected_selectors)
    assert {
        action_id: graph.node(function_id).attributes["function_selector"]
        for action_id, function_id in weak.items()
    } == expected_selectors
    assert weak["overloaded_small"] != weak["overloaded_large"]


def test_hypotheses_fail_closed_when_effective_selector_is_missing(
    tmp_path,
) -> None:
    report, manifest = build_selector_target(tmp_path)
    base = report.contract("Selector.sol", "SelectorBase")
    broken_base = dataclasses.replace(
        base,
        functions=tuple(
            dataclasses.replace(function, function_selector=None)
            if function.signature.startswith("enumSink(")
            else function
            for function in base.functions
        ),
    )
    broken_report = dataclasses.replace(
        report,
        contracts=tuple(
            broken_base if contract.canonical_id == base.canonical_id else contract
            for contract in report.contracts
        ),
    )

    with pytest.raises(ValueError, match="no effective function declaration"):
        generate_hypotheses(build_program_graph(broken_report), manifest)


def test_hypotheses_fail_closed_on_deployment_abi_selector_collision(
    tmp_path,
) -> None:
    report, manifest = build_selector_target(tmp_path)
    derived = report.contract("Selector.sol", "SelectorDerived")
    broken_derived = dataclasses.replace(
        derived,
        abi_function_selectors=derived.abi_function_selectors
        + (("colliding()", "cf520c46"),),
    )
    broken_report = dataclasses.replace(
        report,
        contracts=tuple(
            broken_derived
            if contract.canonical_id == derived.canonical_id
            else contract
            for contract in report.contracts
        ),
    )

    with pytest.raises(ValueError, match="ABI selector collision"):
        generate_hypotheses(build_program_graph(broken_report), manifest)
