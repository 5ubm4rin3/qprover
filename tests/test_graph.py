import json

import pytest
from test_analysis import build_analysis_report, build_multi_source_report

from qprover.analysis import AnalysisReport
from qprover.graph import build_program_graph


@pytest.fixture
def report(tmp_path) -> AnalysisReport:
    return build_analysis_report(tmp_path)


def test_graph_contains_typed_analysis_nodes_and_edges(report: AnalysisReport) -> None:
    graph = build_program_graph(report)
    fixture = report.contract("Fixture.sol", "Fixture")
    withdraw = report.function("Fixture.sol", "Fixture", "withdraw()")
    balances = report.storage("Fixture.sol", "Fixture", "balances")

    assert graph.node(fixture.canonical_id).kind == "contract"
    assert graph.node(withdraw.canonical_id).kind == "function"
    assert graph.node(balances.canonical_id).kind == "storage"
    assert {node.kind for node in graph.nodes} >= {
        "actor_guard",
        "external_call",
        "oracle",
        "value_flow",
    }
    assert graph.edge(withdraw.canonical_id, balances.canonical_id, "reads").provenance
    assert graph.edge(withdraw.canonical_id, balances.canonical_id, "writes").provenance


def test_graph_dependency_uses_transitive_write_read_intersection(
    report: AnalysisReport,
) -> None:
    graph = build_program_graph(report)
    deposit = report.function("Fixture.sol", "Fixture", "deposit()")
    withdraw = report.function("Fixture.sol", "Fixture", "withdraw()")
    balances = report.storage("Fixture.sol", "Fixture", "balances")

    edge = graph.edge(deposit.canonical_id, withdraw.canonical_id, "depends_on")

    assert edge.kind == "depends_on"
    assert edge.attributes["storage"] == (balances.canonical_id,)
    assert edge.provenance
    assert graph.transition_benefit(deposit.canonical_id, withdraw.canonical_id) > 0


def test_graph_models_call_before_write_and_oracle_flow(report: AnalysisReport) -> None:
    graph = build_program_graph(report)
    withdraw_id = report.function("Fixture.sol", "Fixture", "withdraw()").canonical_id
    price_id = report.function(
        "Fixture.sol", "Fixture", "updatePrice(address)"
    ).canonical_id
    balances_id = report.storage("Fixture.sol", "Fixture", "balances").canonical_id

    call_edge = next(edge for edge in graph.out_edges(withdraw_id, "calls"))
    write_edge = graph.edge(withdraw_id, balances_id, "writes")

    assert graph.edge(call_edge.target, write_edge.target, "before").provenance
    assert graph.out_edges(price_id, "prices_from")


def test_graph_emits_only_explicit_call_before_write_pairs(
    report: AnalysisReport,
) -> None:
    graph = build_program_graph(report)
    function = report.function(
        "Fixture.sol", "Fixture", "pairwiseOrdering(address,address)"
    )
    before_edges = tuple(edge for edge in graph.edges if edge.kind == "before")
    function_before = tuple(
        edge for edge in before_edges if function.canonical_id in edge.source
    )

    assert len(function_before) == 1
    assert (
        function_before[0].target
        == report.storage("Fixture.sol", "Fixture", "balances").canonical_id
    )


def test_graph_has_no_cross_source_false_dependency_and_no_implicit_nodes(
    tmp_path,
) -> None:
    report = build_multi_source_report(tmp_path)
    graph = build_program_graph(report)
    a_write = report.function("A.sol", "Twin", "write()")
    b_read = report.function("B.sol", "Twin", "read()")
    deposit = report.function("Derived.sol", "Derived", "deposit()")
    withdraw = report.function("Derived.sol", "Derived", "withdraw()")

    assert not any(
        edge.kind == "depends_on"
        and edge.source == a_write.canonical_id
        and edge.target == b_read.canonical_id
        for edge in graph.edges
    )
    assert graph.edge(deposit.canonical_id, withdraw.canonical_id, "depends_on")
    assert all(node.kind in graph.node_kinds for node in graph.nodes)
    assert graph.to_json()


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
