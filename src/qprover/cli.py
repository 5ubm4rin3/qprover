"""Non-interactive QProver command-line interface."""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


def _emit(payload: object, *, as_json: bool) -> None:
    if as_json:
        print(
            json.dumps(
                payload,
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            )
        )
    elif isinstance(payload, str):
        print(payload)
    else:
        print(
            json.dumps(
                payload,
                sort_keys=True,
                indent=2,
                allow_nan=False,
            )
        )


def _version(command: str) -> dict[str, object]:
    executable = shutil.which(command)
    if executable is None:
        return {"available": False, "version": None}
    try:
        result = subprocess.run(
            (executable, "--version"),
            text=True,
            capture_output=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return {"available": False, "version": None}
    text = (result.stdout or result.stderr).strip().splitlines()
    return {
        "available": result.returncode == 0,
        "version": text[0][:512] if text else None,
    }


def _doctor_offline_build(workspace: Path) -> dict[str, object]:
    if shutil.which("forge") is None:
        return {
            "available": False,
            "detail": "forge unavailable",
        }
    try:
        from qprover.artifacts import build_target
        from qprover.manifest import load_manifest

        manifest = load_manifest(workspace / "benchmarks/scenario_reentrancy_a.json")
        with build_target(manifest, offline=True) as bundle:
            artifacts = len(bundle.artifacts)
        return {
            "available": artifacts > 0,
            "artifacts": artifacts,
        }
    except Exception as error:
        return {
            "available": False,
            "detail": f"{type(error).__name__}: {error}"[:512],
        }


def _doctor_anvil_cleanup() -> dict[str, object]:
    if shutil.which("anvil") is None:
        return {
            "available": False,
            "detail": "anvil unavailable",
        }
    try:
        from qprover.evm import LocalAnvil
        from qprover.runtime import ExecutionRuntime

        anvil = LocalAnvil()
        with ExecutionRuntime.activate() as runtime:
            with anvil:
                loopback = anvil.rpc_url.startswith("http://127.0.0.1:")
                chain_id = anvil.chain_id
                process_id = anvil.process_id
                running = anvil.running
            cleaned = not anvil.running and not runtime.has_pending_cleanup
        available = loopback and chain_id == 31337 and running and cleaned
        return {
            "available": available,
            "loopback": loopback,
            "chain_id": chain_id,
            "process_id": process_id,
            "cleanup_verified": cleaned,
        }
    except Exception as error:
        return {
            "available": False,
            "detail": f"{type(error).__name__}: {error}"[:512],
        }


def _doctor(args: argparse.Namespace) -> int:
    workspace = Path(args.workspace).resolve()
    output = (
        Path(args.out).resolve()
        if args.out
        else Path(tempfile.gettempdir()).resolve() / "qprover-doctor"
    )
    writable = False
    try:
        output.mkdir(parents=True, exist_ok=True)
        probe = output / ".write-probe"
        probe.write_text("ok", encoding="utf-8")
        probe.unlink()
        writable = True
    except OSError:
        pass

    checks = {
        "python": {
            "available": sys.version_info >= (3, 12),
            "version": sys.version.split()[0],
        },
        "uv": _version("uv"),
        "forge": _version("forge"),
        "anvil": _version("anvil"),
        "writable_output": {
            "available": writable,
            "path": str(output),
        },
        "offline_build": _doctor_offline_build(workspace),
        "loopback_anvil_cleanup": _doctor_anvil_cleanup(),
    }
    ok = all(bool(item.get("available")) for item in checks.values())
    _emit({"ok": ok, "checks": checks}, as_json=args.json)
    return 0 if ok else 1


def _analyze(args: argparse.Namespace) -> int:
    from qprover.analysis import analyze
    from qprover.artifacts import build_target
    from qprover.manifest import load_manifest
    from qprover.safeio import safe_atomic_write

    manifest = load_manifest(Path(args.manifest).resolve())
    with build_target(manifest, offline=True) as bundle:
        report = analyze(bundle)
    payload = json.loads(report.to_json())
    if args.out:
        safe_atomic_write(
            Path(args.out),
            json.dumps(payload, sort_keys=True, indent=2) + "\n",
        )
    _emit(payload, as_json=args.json)
    return 0


def _strategy(
    name: str,
    *,
    qubo_backend: str = "annealing",
    qubo_reads: int = 64,
    qubo_sweeps: int = 200,
    qubo_exact_max_bits: int = 20,
):
    from qprover.benchmark import (
        CoverageStrategyConfig,
        QuboStrategyConfig,
        RandomStrategyConfig,
        RiskStrategyConfig,
        make_strategy,
    )

    if name == "random":
        config = RandomStrategyConfig(name="random")
    elif name == "coverage":
        config = CoverageStrategyConfig(name="coverage")
    elif name == "risk":
        config = RiskStrategyConfig(name="risk")
    else:
        config = QuboStrategyConfig(
            name="qubo",
            backend=qubo_backend,
            reads=qubo_reads,
            sweeps=qubo_sweeps,
            exact_max_bits=qubo_exact_max_bits,
        )
    return make_strategy(config)


def _search(args: argparse.Namespace) -> int:
    from qprover.manifest import load_manifest
    from qprover.models import SearchLimits
    from qprover.pipeline import prove_violation

    manifest_path = Path(args.manifest).resolve()
    manifest = load_manifest(manifest_path)
    limits = SearchLimits(
        max_sequence_length=manifest.limits.max_sequence_length,
        max_variants=manifest.limits.max_variants,
        candidate_budget=(args.candidate_budget or manifest.limits.candidate_budget),
        transaction_budget=(
            args.transaction_budget or manifest.limits.transaction_budget
        ),
        wall_seconds=args.wall_seconds or manifest.limits.wall_seconds,
    )
    result = prove_violation(
        manifest_path,
        strategy=_strategy(
            args.strategy,
            qubo_backend=args.qubo_backend,
            qubo_reads=args.qubo_reads,
            qubo_sweeps=args.qubo_sweeps,
            qubo_exact_max_bits=args.qubo_exact_max_bits,
        ),
        seed=args.seed,
        output=Path(args.out),
        workspace_root=Path(args.workspace).resolve(),
        limits=limits,
    )
    payload = {
        "status": result.status.value,
        "run_id": result.run_id,
        "output_root": str(result.output_root),
        "result_path": (str(result.result_path) if result.result_path else None),
        "certificate_path": (
            str(result.certificate_path) if result.certificate_path else None
        ),
        "error": result.error,
    }
    _emit(payload, as_json=args.json)
    return 2 if result.error else 0


def _replay(args: argparse.Namespace) -> int:
    from qprover.replay import cold_verify

    try:
        result = cold_verify(
            Path(args.certificate).resolve(),
            repeats=3,
            workspace_root=Path(args.workspace).resolve(),
        )
    except Exception as error:
        _emit(
            {"ok": False, "error": f"{type(error).__name__}: {error}"},
            as_json=args.json,
        )
        return 2
    ok = result.confirmation_status.value == "CONFIRMED"
    payload = {
        "ok": ok,
        "status": result.confirmation_status.value,
        "replays": len(result.records),
        "certificate_sha256": result.certificate.certificate_sha256,
    }
    _emit(payload, as_json=args.json)
    return 0 if ok else 2


def _benchmark(args: argparse.Namespace) -> int:
    from qprover.benchmark import run_benchmark

    try:
        matrix, rows = run_benchmark(
            suite_path=Path(args.suite).resolve(),
            config_path=Path(args.config).resolve(),
            output=Path(args.out),
            workspace_root=Path(args.workspace).resolve(),
        )
    except Exception as error:
        _emit(
            {"ok": False, "error": f"{type(error).__name__}: {error}"},
            as_json=args.json,
        )
        return 2
    payload = {
        "ok": True,
        "matrix_id": matrix.matrix_id,
        "runs": len(rows),
        "output": str(Path(args.out).resolve()),
    }
    _emit(payload, as_json=args.json)
    return 0


def _report(args: argparse.Namespace) -> int:
    from qprover.benchmark import (
        expected_run_keys,
        load_config,
        load_matrix,
        load_run_journal,
        load_suite,
        score_complete_matrix,
        write_scores,
    )
    from qprover.report import (
        build_completeness_report,
        build_report,
        write_completeness_report,
        write_report,
    )

    root = Path(args.input).resolve()
    suite_path = Path(args.suite).resolve()
    config_path = Path(args.config).resolve()
    labels_path = Path(args.labels).resolve()
    try:
        matrix = load_matrix(root / "matrix.json")
        suite = load_suite(suite_path)
        config = load_config(config_path)
        runs = load_run_journal(
            root / "runs.jsonl",
            matrix_id=matrix.matrix_id,
        )
        expected = set(expected_run_keys(matrix, suite, config))
        terminal = (
            {row.run_key for row in runs} == expected
            and len(runs) == len(expected)
            and all(row.state != "incomplete" for row in runs)
        )
        if not terminal:
            scores_path = root / "scores.jsonl"
            if scores_path.exists() or scores_path.is_symlink():
                raise ValueError(
                    "stale label-derived scores are present for an incomplete matrix"
                )
            report = build_completeness_report(
                matrix=matrix,
                suite=suite,
                config=config,
                runs=runs,
            )
            json_path, markdown_path = write_completeness_report(
                report,
                root / "report.json",
                root / "report.md",
            )
            _emit(
                {
                    "ok": True,
                    "complete": False,
                    "matrix_id": matrix.matrix_id,
                    "scores": 0,
                    "report_json": str(json_path),
                    "report_markdown": str(markdown_path),
                },
                as_json=args.json,
            )
            return 0

        scores = score_complete_matrix(
            matrix=matrix,
            suite=suite,
            config=config,
            runs=runs,
            labels_path=labels_path,
        )
        scores_path = write_scores(root / "scores.jsonl", scores)
        report = build_report(
            matrix=matrix,
            runs=runs,
            scores=scores,
            suite_path=suite_path,
            config_path=config_path,
            runs_path=root / "runs.jsonl",
            scores_path=scores_path,
            labels_path=labels_path,
        )
        json_path, markdown_path = write_report(
            report,
            root / "report.json",
            root / "report.md",
        )
    except Exception as error:
        _emit(
            {"ok": False, "error": f"{type(error).__name__}: {error}"},
            as_json=args.json,
        )
        return 2
    _emit(
        {
            "ok": True,
            "matrix_id": matrix.matrix_id,
            "scores": len(scores),
            "report_json": str(json_path),
            "report_markdown": str(markdown_path),
        },
        as_json=args.json,
    )
    return 0


def _demo_qubo_objective_is_nonflat(path: Path) -> bool:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return False
    problem = raw.get("problem") if isinstance(raw, dict) else None
    if not isinstance(problem, dict):
        return False
    utilities = problem.get("utilities")
    transitions = problem.get("transitions")
    if not isinstance(utilities, dict) or not isinstance(transitions, list):
        return False
    utility_values = [
        float(value) for value in utilities.values() if type(value) in (int, float)
    ]
    transition_values = [
        float(item.get("benefit"))
        for item in transitions
        if isinstance(item, dict) and type(item.get("benefit")) in (int, float)
    ]
    return len(set(utility_values)) > 1 or any(
        value != 0.0 for value in transition_values
    )


def _portable_output_path(path: Path | None, output_base: Path) -> str | None:
    if path is None:
        return None
    try:
        return path.resolve().relative_to(output_base.resolve()).as_posix()
    except ValueError:
        return None


def _demo(args: argparse.Namespace) -> int:
    from qprover.benchmark import QuboStrategyConfig, make_strategy
    from qprover.manifest import load_manifest
    from qprover.models import SearchLimits
    from qprover.pipeline import prove_violation

    workspace = Path(args.workspace).resolve()
    manifest_path = workspace / "benchmarks/scenario_reentrancy_a.json"
    manifest = load_manifest(manifest_path)
    limits = SearchLimits(
        max_sequence_length=manifest.limits.max_sequence_length,
        max_variants=manifest.limits.max_variants,
        candidate_budget=12,
        transaction_budget=36,
        wall_seconds=30,
    )
    config = QuboStrategyConfig(
        name="qubo",
        backend="annealing",
        reads=64,
        sweeps=200,
        temperature_start=10.0,
        temperature_end=0.01,
    )
    output_base = Path(args.out).resolve()
    result = prove_violation(
        manifest_path,
        strategy=make_strategy(config),
        seed=23,
        output=output_base,
        workspace_root=workspace,
        limits=limits,
    )
    search_steps = (
        len(result.search_run.violation.steps)
        if result.search_run is not None and result.search_run.violation is not None
        else 0
    )
    objective_nonflat = (
        result.qubo_path is not None
        and _demo_qubo_objective_is_nonflat(result.qubo_path)
    )
    replay_count = 0
    replay_successes = 0
    if result.certificate_path is not None and result.certificate_path.is_file():
        try:
            certificate = json.loads(
                result.certificate_path.read_text(encoding="utf-8")
            )
            replay = certificate.get("replay", {})
            records = replay.get("records", []) if isinstance(replay, dict) else []
            if isinstance(records, list):
                replay_count = len(records)
                replay_successes = sum(
                    isinstance(item, dict) and item.get("success") is True
                    for item in records
                )
        except (OSError, json.JSONDecodeError):
            pass
    portable_paths = all(
        path is None or _portable_output_path(path, output_base) is not None
        for path in (
            result.output_root,
            result.certificate_path,
            result.poc_path,
            result.qubo_path,
        )
    )
    ok = (
        result.status.value == "CONFIRMED"
        and result.error is None
        and search_steps >= 2
        and (result.minimized_steps or 0) >= 2
        and objective_nonflat
        and replay_count == 3
        and replay_successes == 3
        and portable_paths
    )
    payload = {
        "ok": ok,
        "status": result.status.value,
        "run_id": result.run_id,
        "output_root": _portable_output_path(result.output_root, output_base),
        "certificate_path": _portable_output_path(result.certificate_path, output_base),
        "poc_path": _portable_output_path(result.poc_path, output_base),
        "qubo_path": _portable_output_path(result.qubo_path, output_base),
        "search_steps": search_steps,
        "minimized_steps": result.minimized_steps,
        "objective_nonflat": objective_nonflat,
        "cold_replays": replay_count,
        "successful_cold_replays": replay_successes,
        "portable_paths": portable_paths,
        "error": result.error,
    }
    _emit(payload, as_json=args.json)
    return 0 if ok else 2


_TRACK04_FORGE_STD_REV = "bf647bd6046f2f7da30d0c2bf435e5c76a780c1b"


def _run_bootstrap_command(command: list[str], *, cwd: Path | None = None) -> None:
    try:
        result = subprocess.run(
            command,
            cwd=cwd,
            text=True,
            capture_output=True,
            check=False,
        )
    except OSError as error:
        raise ValueError(f"could not execute {command[0]!r}") from error
    if result.returncode == 0:
        return
    detail = (result.stderr or result.stdout).strip().splitlines()
    message = detail[-1] if detail else f"exit code {result.returncode}"
    raise ValueError(f"Track04 bootstrap failed: {message[:300]}")


def _ensure_track04_harness(workspace: Path) -> None:
    harness = workspace / "trust404" / "harness"
    artifact = harness / "out" / "SearchAttacker.sol" / "SearchAttacker.json"
    if artifact.is_file():
        return
    if shutil.which("forge") is None:
        raise ValueError("forge is required for Track04; install Foundry first")

    forge_std = harness / "lib" / "forge-std"
    git_dir = forge_std / ".git"
    if not git_dir.is_dir():
        if shutil.which("git") is None:
            raise ValueError("git is required to prepare pinned forge-std")
        print("[qprover] preparing pinned forge-std...", file=sys.stderr)
        shutil.rmtree(forge_std, ignore_errors=True)
        forge_std.mkdir(parents=True, exist_ok=True)
        _run_bootstrap_command(["git", "init", "-q"], cwd=forge_std)
        _run_bootstrap_command(
            [
                "git",
                "remote",
                "add",
                "origin",
                "https://github.com/foundry-rs/forge-std",
            ],
            cwd=forge_std,
        )
        _run_bootstrap_command(
            ["git", "fetch", "-q", "--depth", "1", "origin", _TRACK04_FORGE_STD_REV],
            cwd=forge_std,
        )
        _run_bootstrap_command(
            ["git", "checkout", "-q", "--detach", "FETCH_HEAD"], cwd=forge_std
        )
    else:
        current = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=forge_std,
            text=True,
            capture_output=True,
            check=False,
        ).stdout.strip()
        if current != _TRACK04_FORGE_STD_REV:
            print("[qprover] restoring pinned forge-std...", file=sys.stderr)
            _run_bootstrap_command(
                [
                    "git",
                    "fetch",
                    "-q",
                    "--depth",
                    "1",
                    "origin",
                    _TRACK04_FORGE_STD_REV,
                ],
                cwd=forge_std,
            )
            _run_bootstrap_command(
                ["git", "checkout", "-q", "--detach", "FETCH_HEAD"], cwd=forge_std
            )

    print("[qprover] building Track04 harness...", file=sys.stderr)
    _run_bootstrap_command(["forge", "build", "--root", str(harness)])
    if not artifact.is_file():
        raise ValueError(
            "Track04 harness build did not produce SearchAttacker artifact"
        )


def _find_track04_file(package: Path, name: str) -> Path:
    direct = package / name
    if direct.is_file():
        return direct.resolve()
    matches = tuple(
        sorted(path.resolve() for path in package.rglob(name) if path.is_file())
    )
    if not matches:
        raise ValueError(
            f"{name} not found under {package}. "
            "Place the organizer package in trust404/target/ "
            "or pass its directory explicitly."
        )
    if len(matches) != 1:
        rendered = ", ".join(str(path) for path in matches[:4])
        raise ValueError(f"multiple {name} files found under {package}: {rendered}")
    return matches[0]


def _run_track04_package(
    *,
    package: Path,
    output: Path,
    package_source: str,
    timeout_override: int | None,
    seed_override: int | None,
    max_attempts_override: int | None,
) -> tuple[int, dict[str, object]]:
    from qprover.trust404 import Track04Manifest
    from qprover.trust404_runner import _default_runtime_factory, run_track04

    if not package.is_dir():
        raise ValueError(f"Track04 package directory not found: {package}")

    manifest_path = _find_track04_file(package, "manifest.json")
    manifest = Track04Manifest.load(manifest_path)
    package_root = manifest_path.parent.resolve()

    contract = (package_root / manifest.target_src).resolve()
    try:
        contract.relative_to(package_root)
    except ValueError as error:
        raise ValueError("manifest target.src escapes the package directory") from error
    if not contract.is_file():
        raise ValueError(f"target source from manifest not found: {contract}")

    invariants = _find_track04_file(package_root, "Invariants.sol")
    output.mkdir(parents=True, exist_ok=True)

    timeout = timeout_override if timeout_override is not None else manifest.timeout_sec
    seed = seed_override if seed_override is not None else manifest.manifest_seed
    max_attempts = (
        max_attempts_override
        if max_attempts_override is not None
        else manifest.max_attempts
    )

    code = run_track04(
        contract,
        invariants,
        manifest_path,
        output,
        timeout_seconds=timeout,
        seed=seed,
        max_attempts=max_attempts,
        runtime_factory=_default_runtime_factory,
    )

    result_path = output / "result.json"
    result: dict[str, object] = {}
    if result_path.is_file():
        try:
            loaded = json.loads(result_path.read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                result = loaded
        except (OSError, json.JSONDecodeError):
            result = {}

    payload: dict[str, object] = {
        "target_name": manifest.target_name,
        "ok": code != 2,
        "proven": code == 0,
        "exit_code": code,
        "status": result.get(
            "status",
            "PROVEN" if code == 0 else "NOT_FOUND" if code == 1 else "ERROR",
        ),
        "package_source": package_source,
        "target": str(contract),
        "output": str(output),
        "result": str(result_path),
        "exploit": str(output / "Exploit.sol"),
        "attempts": str(output / "attempts.log"),
    }
    return code, payload


def _public_track04_packages(workspace: Path) -> tuple[Path, ...]:
    root = workspace / "trust404" / "targets"
    if not root.is_dir():
        return ()
    return tuple(
        path.resolve()
        for path in sorted(root.iterdir(), key=lambda item: item.name)
        if path.is_dir() and (path / "manifest.json").is_file()
    )


def _track04(args: argparse.Namespace) -> int:
    """Human-friendly runner for one organizer target or all public targets."""

    workspace = Path(args.workspace).resolve()
    _ensure_track04_harness(workspace)

    if args.package:
        package = Path(args.package).expanduser().resolve()
        output = (
            Path(args.out).expanduser().resolve()
            if args.out
            else workspace / "trust404" / "results" / "latest"
        )
        code, payload = _run_track04_package(
            package=package,
            output=output,
            package_source="explicit",
            timeout_override=args.timeout,
            seed_override=args.seed,
            max_attempts_override=args.max_attempts,
        )
        _emit(payload, as_json=args.json)
        return 2 if code == 2 else 0

    local_target = workspace / "trust404" / "target"
    has_local_manifest = (local_target / "manifest.json").is_file() or any(
        path.is_file() for path in local_target.rglob("manifest.json")
    )
    if has_local_manifest:
        output = (
            Path(args.out).expanduser().resolve()
            if args.out
            else workspace / "trust404" / "results" / "latest"
        )
        code, payload = _run_track04_package(
            package=local_target,
            output=output,
            package_source="trust404/target",
            timeout_override=args.timeout,
            seed_override=args.seed,
            max_attempts_override=args.max_attempts,
        )
        _emit(payload, as_json=args.json)
        return 2 if code == 2 else 0

    packages = _public_track04_packages(workspace)
    if not packages:
        raise ValueError(
            "no Track04 target package found; expected trust404/targets/<Name>/"
        )

    output_root = (
        Path(args.out).expanduser().resolve()
        if args.out
        else workspace / "trust404" / "results" / "latest"
    )
    output_root.mkdir(parents=True, exist_ok=True)

    runs: list[dict[str, object]] = []
    proven = 0
    not_found = 0
    errors = 0
    for package in packages:
        name = package.name
        code, payload = _run_track04_package(
            package=package,
            output=output_root / name,
            package_source=f"trust404/targets/{name}",
            timeout_override=args.timeout,
            seed_override=args.seed,
            max_attempts_override=args.max_attempts,
        )
        runs.append(payload)
        if code == 0:
            proven += 1
        elif code == 1:
            not_found += 1
        else:
            errors += 1

    summary = {
        "ok": errors == 0,
        "status": "COMPLETE" if errors == 0 else "ERROR",
        "mode": "public-targets",
        "targets": len(runs),
        "proven": proven,
        "not_found": not_found,
        "errors": errors,
        "output": str(output_root),
        "runs": runs,
    }
    summary_path = output_root / "summary.json"
    summary_path.write_text(
        json.dumps(summary, sort_keys=True, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    _emit(summary, as_json=args.json)
    return 2 if errors else 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="qprover",
        description="Optimization-guided smart-contract exploit prover",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    doctor = sub.add_parser("doctor")
    doctor.add_argument("--json", action="store_true")
    doctor.add_argument("--workspace", default=".")
    doctor.add_argument("--out")
    doctor.set_defaults(func=_doctor)

    analyze = sub.add_parser("analyze")
    analyze.add_argument("--manifest", required=True)
    analyze.add_argument("--out")
    analyze.add_argument("--json", action="store_true")
    analyze.set_defaults(func=_analyze)

    search = sub.add_parser("search")
    search.add_argument("--manifest", required=True)
    search.add_argument(
        "--strategy",
        choices=("random", "coverage", "risk", "qubo"),
        default="qubo",
    )
    search.add_argument("--seed", type=int, default=23)
    search.add_argument(
        "--qubo-backend",
        choices=("annealing", "exact"),
        default="annealing",
    )
    search.add_argument("--qubo-reads", type=int, default=64)
    search.add_argument("--qubo-sweeps", type=int, default=200)
    search.add_argument("--qubo-exact-max-bits", type=int, default=20)
    search.add_argument("--workspace", default=".")
    search.add_argument("--out", required=True)
    search.add_argument("--candidate-budget", type=int)
    search.add_argument("--transaction-budget", type=int)
    search.add_argument("--wall-seconds", type=int)
    search.add_argument("--json", action="store_true")
    search.set_defaults(func=_search)

    replay = sub.add_parser("replay")
    replay.add_argument("--certificate", required=True)
    replay.add_argument("--workspace", default=".")
    replay.add_argument("--json", action="store_true")
    replay.set_defaults(func=_replay)

    benchmark = sub.add_parser("benchmark")
    benchmark.add_argument("--suite", default="benchmarks/suite.json")
    benchmark.add_argument(
        "--config",
        default="benchmarks/config/smoke.json",
    )
    benchmark.add_argument("--workspace", default=".")
    benchmark.add_argument("--out", required=True)
    benchmark.add_argument("--json", action="store_true")
    benchmark.set_defaults(func=_benchmark)

    report = sub.add_parser("report")
    report.add_argument("--input", required=True)
    report.add_argument("--suite", default="benchmarks/suite.json")
    report.add_argument(
        "--config",
        default="benchmarks/config/smoke.json",
    )
    report.add_argument("--labels", default="benchmarks/labels.json")
    report.add_argument("--json", action="store_true")
    report.set_defaults(func=_report)

    track04 = sub.add_parser(
        "track04",
        help="Run one TRUST404 package or all bundled public targets",
    )
    track04.add_argument(
        "package",
        nargs="?",
        help="single package directory; omit to run trust404/targets/*",
    )
    track04.add_argument("--workspace", default=".")
    track04.add_argument("--out")
    track04.add_argument("--timeout", type=int)
    track04.add_argument("--seed", type=int)
    track04.add_argument("--max-attempts", type=int, dest="max_attempts")
    track04.add_argument("--json", action="store_true")
    track04.set_defaults(func=_track04)

    demo = sub.add_parser("demo")
    demo.add_argument("--workspace", default=".")
    demo.add_argument("--out", required=True)
    demo.add_argument("--json", action="store_true")
    demo.set_defaults(func=_demo)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except KeyboardInterrupt:
        print("qprover: interrupted", file=sys.stderr)
        return 130
    except Exception as error:
        _emit(
            {"ok": False, "error": f"{type(error).__name__}: {error}"},
            as_json=bool(getattr(args, "json", False)),
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
