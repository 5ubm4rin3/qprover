import json

import pytest
from test_analysis import build_analysis_report

from qprover.analysis import AnalysisReport
from qprover.graph import build_program_graph


@pytest.fixture
def report(tmp_path) -> AnalysisReport:
    return build_analysis_report(tmp_path)


def test_graph_contains_typed_analysis_nodes_and_edges(report: AnalysisReport) -> None:
    graph = build_program_graph(report)

    assert graph.node("contract:Fixture").kind == "contract"
    assert graph.node("function:Fixture:withdraw()").kind == "function"
    assert graph.node("storage:Fixture:balances").kind == "storage"
    assert {node.kind for node in graph.nodes} >= {
        "actor_guard",
        "external_call",
        "oracle",
        "value_flow",
    }
    assert graph.edge(
        "function:Fixture:withdraw()", "storage:Fixture:balances", "reads"
    ).provenance
    assert graph.edge(
        "function:Fixture:withdraw()", "storage:Fixture:balances", "writes"
    ).provenance


def test_graph_dependency_uses_transitive_write_read_intersection(
    report: AnalysisReport,
) -> None:
    graph = build_program_graph(report)

    edge = graph.edge(
        "function:Fixture:deposit()", "function:Fixture:withdraw()", "depends_on"
    )

    assert edge.kind == "depends_on"
    assert edge.attributes["storage"] == ("balances",)
    assert edge.provenance
    assert (
        graph.transition_benefit(
            "function:Fixture:deposit()", "function:Fixture:withdraw()"
        )
        > 0
    )


def test_graph_models_call_before_write_and_oracle_flow(report: AnalysisReport) -> None:
    graph = build_program_graph(report)
    withdraw_id = "function:Fixture:withdraw()"
    price_id = "function:Fixture:updatePrice(address)"

    call_edge = next(edge for edge in graph.out_edges(withdraw_id, "calls"))
    write_edge = graph.edge(withdraw_id, "storage:Fixture:balances", "writes")

    assert graph.edge(call_edge.target, write_edge.target, "before").provenance
    assert graph.out_edges(price_id, "prices_from")


def test_graph_json_and_scores_are_stable_and_bounded(report: AnalysisReport) -> None:
    first = build_program_graph(report)
    second = build_program_graph(report)

    assert first.to_json() == second.to_json()
    parsed = json.loads(first.to_json())
    assert parsed["nodes"] == sorted(parsed["nodes"], key=lambda item: item["id"])
    assert all(0 <= first.action_utility(node.id) <= 1 for node in first.nodes)
    assert all(
        -1 <= first.transition_benefit(edge.source, edge.target) <= 1
        for edge in first.edges
    )
