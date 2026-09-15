from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[2]


@pytest.mark.skipif(
    shutil.which("forge") is None or shutil.which("anvil") is None,
    reason="Foundry toolchain required for benchmark smoke integration",
)
def test_smoke_matrix_is_label_free_until_post_execution_scoring(
    tmp_path: Path,
) -> None:
    output = tmp_path / "benchmark"
    benchmark = subprocess.run(
        [
            "uv",
            "run",
            "qprover",
            "benchmark",
            "--json",
            "--workspace",
            str(ROOT),
            "--suite",
            str(ROOT / "benchmarks/suite.json"),
            "--config",
            str(ROOT / "benchmarks/config/smoke.json"),
            "--out",
            str(output),
        ],
        cwd=ROOT,
        text=True,
        capture_output=True,
        timeout=300,
        check=False,
    )
    assert benchmark.returncode == 0, benchmark.stderr
    payload = json.loads(benchmark.stdout)
    assert payload["ok"] is True
    assert payload["runs"] == 8

    raw_text = (output / "runs.jsonl").read_text(encoding="utf-8")
    for forbidden in ("witness", "labels_sha256", '"expected"', '"family"', '"pair"'):
        assert forbidden not in raw_text

    report = subprocess.run(
        [
            "uv",
            "run",
            "qprover",
            "report",
            "--json",
            "--input",
            str(output),
            "--suite",
            str(ROOT / "benchmarks/suite.json"),
            "--config",
            str(ROOT / "benchmarks/config/smoke.json"),
            "--labels",
            str(ROOT / "benchmarks/labels.json"),
        ],
        cwd=ROOT,
        text=True,
        capture_output=True,
        timeout=60,
        check=False,
    )
    assert report.returncode == 0, report.stderr
    report_payload = json.loads(report.stdout)
    assert report_payload["ok"] is True
    scores = (output / "scores.jsonl").read_text(encoding="utf-8")
    assert "witness" not in scores
    assert (output / "report.json").is_file()
    assert (output / "report.md").is_file()
