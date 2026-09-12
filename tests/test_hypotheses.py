import dataclasses

import pytest
from test_analysis import build_analysis_report
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

    assert hypotheses[0].kind == "external-call-before-state-write"
    assert hypotheses[0].action_ids == ("deposit", "withdraw")
    assert hypotheses[0].action_signatures == ("deposit()", "withdraw()")
    assert hypotheses[0].evidence
    assert hypotheses[0].provenance
    assert hypotheses[0].assumed_ordering == ("deposit", "withdraw")


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
