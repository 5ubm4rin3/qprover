from __future__ import annotations

import json
from pathlib import Path

import pytest
from test_benchmark import config, matrix, suite

from qprover.cli import _find_track04_file, build_parser, main


def test_cli_exposes_required_noninteractive_commands() -> None:
    parser = build_parser()
    choices = parser._subparsers._group_actions[0].choices  # type: ignore[attr-defined]
    assert set(choices) == {
        "doctor",
        "analyze",
        "search",
        "replay",
        "benchmark",
        "report",
        "track04",
        "demo",
    }


def test_track04_cli_defaults_to_local_workspace() -> None:
    args = build_parser().parse_args(["track04"])
    assert args.package is None
    assert args.out is None
    assert args.timeout is None
    assert args.seed is None
    assert args.max_attempts is None


def test_track04_file_discovery_prefers_direct_file(tmp_path: Path) -> None:
    direct = tmp_path / "manifest.json"
    nested = tmp_path / "nested" / "manifest.json"
    nested.parent.mkdir()
    direct.write_text("{}")
    nested.write_text("{}")
    assert _find_track04_file(tmp_path, "manifest.json") == direct.resolve()


def test_track04_cli_runs_default_workspace_and_manifest_budgets(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys
) -> None:
    package = tmp_path / "trust404" / "target"
    (package / "src").mkdir(parents=True)
    (package / "src" / "Demo.sol").write_text("contract Demo {}", encoding="utf-8")
    (package / "Invariants.sol").write_text(
        "contract Invariants {}",
        encoding="utf-8",
    )
    (package / "manifest.json").write_text(
        json.dumps(
            {
                "schema": "trust404.track04.manifest/0.1",
                "target": {
                    "name": "Demo",
                    "src": "src/Demo.sol",
                    "solc": "0.8.24",
                    "evm_version": "cancun",
                },
                "deploy": {
                    "mode": "local",
                    "constructor_args": [],
                    "value_wei": "0",
                },
                "determinism": {
                    "block_number": 1,
                    "block_timestamp": 2,
                    "seed": 77,
                },
                "invariants": {
                    "contract": "Invariants.sol",
                    "predicates": ["holds"],
                },
                "budget": {"timeout_sec": 123, "max_attempts": 9},
            }
        ),
        encoding="utf-8",
    )

    import qprover.trust404_runner as runner

    observed: dict[str, object] = {}

    def fake_run(contract, invariants, manifest, out, **kwargs):
        observed.update(
            {
                "contract": Path(contract),
                "invariants": Path(invariants),
                "manifest": Path(manifest),
                "out": Path(out),
                **kwargs,
            }
        )
        output = Path(out)
        output.mkdir(parents=True, exist_ok=True)
        (output / "Exploit.sol").write_text("contract Exploit {}", encoding="utf-8")
        (output / "attempts.log").write_text("", encoding="utf-8")
        (output / "result.json").write_text(
            json.dumps({"status": "PROVEN"}),
            encoding="utf-8",
        )
        return 0

    monkeypatch.setattr(runner, "run_track04", fake_run)

    code = main(["track04", "--workspace", str(tmp_path), "--json"])
    payload = json.loads(capsys.readouterr().out)

    assert code == 0
    assert observed["contract"] == (package / "src" / "Demo.sol").resolve()
    assert observed["invariants"] == (package / "Invariants.sol").resolve()
    assert observed["manifest"] == (package / "manifest.json").resolve()
    assert observed["out"] == (tmp_path / "trust404" / "results" / "latest")
    assert observed["timeout_seconds"] == 123
    assert observed["seed"] == 77
    assert observed["max_attempts"] == 9
    assert payload["status"] == "PROVEN"
    assert payload["output"] == str(
        (tmp_path / "trust404" / "results" / "latest").resolve()
    )


def test_doctor_json_emits_exactly_one_document(tmp_path: Path, capsys) -> None:
    code = main(["doctor", "--json", "--out", str(tmp_path / "doctor")])
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert code in {0, 1}
    assert payload["ok"] is (code == 0)
    assert set(payload["checks"]) == {
        "python",
        "uv",
        "forge",
        "anvil",
        "writable_output",
        "offline_build",
        "loopback_anvil_cleanup",
    }
    assert captured.out.count("\n") == 1


def test_cli_rejects_unknown_strategy_without_prompting() -> None:
    parser = build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(
            [
                "search",
                "--manifest",
                "target.json",
                "--strategy",
                "unknown",
                "--out",
                "out",
            ]
        )


def test_cli_rejects_unknown_qubo_backend() -> None:
    parser = build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(
            [
                "search",
                "--manifest",
                "target.json",
                "--strategy",
                "qubo",
                "--qubo-backend",
                "quantum-magic",
                "--out",
                "out",
            ]
        )


def test_report_cli_does_not_require_or_open_labels_for_incomplete_matrix(
    tmp_path: Path, capsys
) -> None:
    result_root = tmp_path / "result"
    result_root.mkdir()
    (result_root / "matrix.json").write_text(matrix().model_dump_json())
    suite_path = tmp_path / "suite.json"
    config_path = tmp_path / "config.json"
    suite_path.write_text(suite().model_dump_json())
    config_path.write_text(config().model_dump_json())
    missing_labels = tmp_path / "labels-do-not-exist.json"

    code = main(
        [
            "report",
            "--json",
            "--input",
            str(result_root),
            "--suite",
            str(suite_path),
            "--config",
            str(config_path),
            "--labels",
            str(missing_labels),
        ]
    )
    payload = json.loads(capsys.readouterr().out)
    assert code == 0
    assert payload["ok"] is True
    assert payload["complete"] is False
    assert payload["scores"] == 0
    assert not (result_root / "scores.jsonl").exists()


def test_incomplete_report_refuses_stale_label_derived_scores(
    tmp_path: Path, capsys
) -> None:
    result_root = tmp_path / "result"
    result_root.mkdir()
    (result_root / "matrix.json").write_text(matrix().model_dump_json())
    (result_root / "scores.jsonl").write_text("stale label-derived data\n")
    suite_path = tmp_path / "suite.json"
    config_path = tmp_path / "config.json"
    suite_path.write_text(suite().model_dump_json())
    config_path.write_text(config().model_dump_json())

    code = main(
        [
            "report",
            "--json",
            "--input",
            str(result_root),
            "--suite",
            str(suite_path),
            "--config",
            str(config_path),
            "--labels",
            str(tmp_path / "missing-labels.json"),
        ]
    )
    payload = json.loads(capsys.readouterr().out)
    assert code == 2
    assert payload["ok"] is False
    assert "stale" in payload["error"].lower()
