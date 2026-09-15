from __future__ import annotations

import json
from pathlib import Path

from test_benchmark import config, matrix, run, suite

from qprover.benchmark import score_complete_matrix
from qprover.report import _restricted_mean_time, build_report, clopper_pearson


def test_clopper_pearson_zero_successes_retains_nonzero_upper_bound() -> None:
    low, high = clopper_pearson(0, 10)
    assert low == 0.0
    assert 0.30 < high < 0.32


def test_clopper_pearson_all_successes_retains_nonzero_lower_uncertainty() -> None:
    low, high = clopper_pearson(10, 10)
    assert 0.68 < low < 0.70
    assert high == 1.0


def test_report_hashes_runs_and_scores_independent_of_jsonl_order(
    tmp_path: Path,
) -> None:
    row = run()
    labels_path = tmp_path / "labels.json"
    labels_path.write_text(
        json.dumps(
            {
                "scenario_access_control_b": {
                    "expected": "negative",
                    "family": "access_control",
                    "pair": "b",
                    "witness": ["claimRole()", "drain()"],
                }
            }
        )
    )
    scores = score_complete_matrix(
        matrix=matrix(),
        suite=suite(),
        config=config(),
        runs=(row,),
        labels_path=labels_path,
    )
    suite_path = tmp_path / "suite.json"
    config_path = tmp_path / "config.json"
    runs_path = tmp_path / "runs.jsonl"
    scores_path = tmp_path / "scores.jsonl"
    suite_path.write_text(suite().model_dump_json())
    config_path.write_text(config().model_dump_json())
    runs_path.write_text("raw journal bytes are not report identity\n")
    scores_path.write_text("raw score order is not report identity\n")

    first = build_report(
        matrix=matrix(),
        runs=(row,),
        scores=scores,
        suite_path=suite_path,
        config_path=config_path,
        runs_path=runs_path,
        scores_path=scores_path,
        labels_path=labels_path,
    )
    runs_path.write_text("changed byte order/content\n")
    scores_path.write_text("changed byte order/content\n")
    second = build_report(
        matrix=matrix(),
        runs=(row,),
        scores=scores,
        suite_path=suite_path,
        config_path=config_path,
        runs_path=runs_path,
        scores_path=scores_path,
        labels_path=labels_path,
    )

    assert first == second
    strategy = first["strategies"]["random"]
    assert strategy["executed_violation"]["successes"] == 0
    assert "fixture_balanced_macro" in first


def test_incomplete_matrix_report_is_label_free() -> None:
    from qprover.report import build_completeness_report

    report = build_completeness_report(
        matrix=matrix(),
        suite=suite(),
        config=config(),
        runs=(),
    )
    assert report["complete"] is False
    assert report["labels_accessed"] is False
    assert report["expected_cells"] == 1
    assert len(report["missing_run_keys"]) == 1
    serialized = json.dumps(report, sort_keys=True)
    assert "witness" not in serialized
    assert 'expected"' not in serialized


def test_restricted_mean_time_accounts_for_right_censoring() -> None:
    # Two cells: one hits at t=1, one is right-censored at t=2.
    # Kaplan-Meier survival is 1 on [0,1) and 1/2 on [1,2], so RMST=1.5.
    assert _restricted_mean_time(((1.0, True), (2.0, False)), 2.0) == 1.5
