from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[2]


@pytest.mark.skipif(
    shutil.which("forge") is None or shutil.which("anvil") is None,
    reason="Foundry toolchain required for autonomous demo",
)
def test_autonomous_demo_is_label_independent_and_confirms_three_replays(
    tmp_path: Path,
) -> None:
    output = tmp_path / "demo"
    result = subprocess.run(
        [
            "uv",
            "run",
            "qprover",
            "demo",
            "--json",
            "--workspace",
            str(ROOT),
            "--out",
            str(output),
        ],
        cwd=ROOT,
        text=True,
        capture_output=True,
        timeout=180,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload["status"] == "CONFIRMED"
    assert payload["ok"] is True
    assert payload["objective_nonflat"] is True
    assert payload["search_steps"] >= 2
    assert payload["minimized_steps"] >= 2
    assert payload["cold_replays"] == 3
    assert payload["successful_cold_replays"] == 3
    assert payload["portable_paths"] is True
    certificate_path = output / payload["certificate_path"]
    certificate = json.loads(certificate_path.read_text())
    assert len(certificate["replay"]["records"]) == 3
    assert all(item["success"] for item in certificate["replay"]["records"])
