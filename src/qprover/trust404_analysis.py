"""Compiler-backed analysis adapter for the official TRUST404 Track 04 inputs."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from qprover.analysis import AnalysisReport, analyze
from qprover.artifacts import ContractArtifact, SourceUnitArtifact
from qprover.graph import ProgramGraph, build_program_graph


class Track04AnalysisError(ValueError):
    """Raised when a Track 04 target cannot produce trustworthy compiler facts."""


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _analysis_timeout() -> int | None:
    raw = os.environ.get("QPROVER_ANALYSIS_TIMEOUT")
    if raw is None:
        return None
    try:
        value = int(raw)
    except ValueError as error:
        raise Track04AnalysisError(
            "QPROVER_ANALYSIS_TIMEOUT must be a positive integer"
        ) from error
    if value <= 0:
        raise Track04AnalysisError(
            "QPROVER_ANALYSIS_TIMEOUT must be a positive integer"
        )
    return value


def _run(command: tuple[str, ...], cwd: Path) -> subprocess.CompletedProcess[str]:
    environment = {
        key: os.environ[key]
        for key in ("HOME", "PATH", "TMPDIR", "LANG", "LC_ALL", "TERM")
        if key in os.environ
    }
    try:
        result = subprocess.run(
            command,
            cwd=cwd,
            env=environment,
            capture_output=True,
            text=True,
            check=False,
            timeout=_analysis_timeout(),
        )
    except subprocess.TimeoutExpired as error:
        raise Track04AnalysisError("compiler build timed out") from error
    except OSError as error:
        raise Track04AnalysisError(f"cannot execute {command[0]}: {error}") from error
    if result.returncode:
        detail = result.stderr.strip() or result.stdout.strip() or "unknown error"
        raise Track04AnalysisError(f"compiler build failed: {detail}")
    return result


def _local_solc(solc_version: str) -> str | None:
    """Return an exact local solc path when one matches the organizer version."""

    candidates = tuple(
        dict.fromkeys(
            item
            for item in (
                os.environ.get("QPROVER_SOLC"),
                "/usr/local/bin/solc",
                shutil.which("solc"),
            )
            if item
        )
    )
    for candidate in candidates:
        path = Path(candidate)
        if not path.is_file():
            continue
        try:
            result = subprocess.run(
                (str(path), "--version"),
                capture_output=True,
                text=True,
                check=False,
                timeout=5,
            )
        except (OSError, subprocess.TimeoutExpired):
            continue
        version_text = f"{result.stdout}\n{result.stderr}"
        match = re.search(r"Version:\s*(\d+\.\d+\.\d+)", version_text)
        if result.returncode == 0 and match and match.group(1) == solc_version:
            return str(path)
    return None


def _load_json(path: Path) -> dict[str, Any]:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise Track04AnalysisError(f"invalid compiler JSON: {path}") from error
    if not isinstance(raw, dict):
        raise Track04AnalysisError(f"invalid compiler JSON object: {path}")
    return raw


def _hash_sources(sources: dict[str, Any]) -> str:
    digest = hashlib.sha256()
    for source_name in sorted(sources):
        record = sources[source_name]
        content = record.get("content") if isinstance(record, dict) else None
        if not isinstance(content, str):
            raise Track04AnalysisError(f"compiler source lacks content: {source_name}")
        name_bytes = source_name.encode()
        source_bytes = content.encode()
        digest.update(len(name_bytes).to_bytes(8, "big"))
        digest.update(name_bytes)
        digest.update(len(source_bytes).to_bytes(8, "big"))
        digest.update(source_bytes)
    return digest.hexdigest()


def _method_identifiers(raw: dict[str, Any]) -> tuple[tuple[str, str], ...]:
    methods = raw.get("methodIdentifiers")
    if not isinstance(methods, dict):
        raise Track04AnalysisError("contract artifact is missing method identifiers")
    pairs: list[tuple[str, str]] = []
    for signature, selector in methods.items():
        if not isinstance(signature, str) or not isinstance(selector, str):
            raise Track04AnalysisError("invalid contract method identifier")
        pairs.append((signature, selector.lower()))
    return tuple(sorted(pairs))


def _source_units(build_info: dict[str, Any]) -> tuple[SourceUnitArtifact, ...]:
    input_sources = build_info.get("input", {}).get("sources")
    output_sources = build_info.get("output", {}).get("sources")
    if not isinstance(input_sources, dict) or not isinstance(output_sources, dict):
        raise Track04AnalysisError("build-info is missing source closure")
    units: list[SourceUnitArtifact] = []
    for source_name in sorted(input_sources):
        input_record = input_sources[source_name]
        output_record = output_sources.get(source_name)
        content = (
            input_record.get("content") if isinstance(input_record, dict) else None
        )
        ast = output_record.get("ast") if isinstance(output_record, dict) else None
        if not isinstance(content, str) or not isinstance(ast, dict):
            raise Track04AnalysisError(
                f"build-info source is incomplete: {source_name}"
            )
        units.append(
            SourceUnitArtifact(
                source_name=source_name,
                source_sha256=_sha256(content.encode()),
                ast=ast,
            )
        )
    return tuple(units)


def _artifact_identity(raw: dict[str, Any]) -> tuple[str, str] | None:
    metadata = raw.get("metadata")
    settings = metadata.get("settings") if isinstance(metadata, dict) else None
    target = settings.get("compilationTarget") if isinstance(settings, dict) else None
    if not isinstance(target, dict) or len(target) != 1:
        return None
    source_name, contract_name = next(iter(target.items()))
    if not isinstance(source_name, str) or not isinstance(contract_name, str):
        return None
    return source_name, contract_name


def _contract_artifact(
    path: Path,
    raw: dict[str, Any],
    source_name: str,
    contract_name: str,
    build_info_id: str,
) -> ContractArtifact:
    abi = raw.get("abi")
    bytecode_record = raw.get("bytecode")
    bytecode = (
        bytecode_record.get("object") if isinstance(bytecode_record, dict) else None
    )
    ast = raw.get("ast")
    layout = raw.get("storageLayout")
    if not isinstance(abi, list):
        raise Track04AnalysisError("contract artifact is missing ABI")
    if not isinstance(bytecode, str):
        raise Track04AnalysisError("contract artifact is missing bytecode")
    if not isinstance(ast, dict):
        raise Track04AnalysisError("contract artifact is missing AST")
    if not isinstance(layout, dict):
        raise Track04AnalysisError("contract artifact is missing storage layout")
    encoded = json.dumps(raw, sort_keys=True, separators=(",", ":")).encode()
    return ContractArtifact(
        source_name=source_name,
        contract_name=contract_name,
        compilation_target=f"{source_name}:{contract_name}",
        build_info_id=build_info_id,
        artifact_path=path,
        artifact_sha256=_sha256(encoded),
        bytecode_sha256=_sha256(bytecode.encode()),
        abi=tuple(abi),
        method_identifiers=_method_identifiers(raw),
        bytecode=bytecode,
        ast=ast,
        storage_layout=layout,
    )


def _contract_artifacts(
    output_root: Path,
    build_info_id: str,
) -> tuple[ContractArtifact, ...]:
    artifacts: dict[str, ContractArtifact] = {}
    for path in sorted(output_root.rglob("*.json")):
        if "build-info" in path.parts:
            continue
        raw = _load_json(path)
        identity = _artifact_identity(raw)
        if identity is None:
            continue
        source_name, contract_name = identity
        artifact = _contract_artifact(
            path,
            raw,
            source_name,
            contract_name,
            build_info_id,
        )
        existing = artifacts.get(artifact.compilation_target)
        if (
            existing is not None
            and existing.artifact_sha256 != artifact.artifact_sha256
        ):
            raise Track04AnalysisError(
                f"compiler artifact ambiguity for {artifact.compilation_target}"
            )
        artifacts[artifact.compilation_target] = artifact
    if not artifacts:
        raise Track04AnalysisError("compiler emitted no contract artifacts")
    return tuple(artifacts[key] for key in sorted(artifacts))


@dataclass(frozen=True, slots=True)
class Track04Analysis:
    report: AnalysisReport
    graph: ProgramGraph
    source_name: str
    contract_name: str


def compile_track04_target(
    contract_path: Path | str,
    *,
    target_name: str,
    target_src: str,
    solc_version: str,
    evm_version: str,
) -> Track04Analysis:
    """Compile one organizer target and reuse QProver's AST/graph analysis core."""

    contract = Path(contract_path).resolve()
    if not contract.is_file():
        raise FileNotFoundError(f"contract not found: {contract}")

    target_root = (
        contract.parent.parent if contract.parent.name == "src" else contract.parent
    )
    expected = (target_root / target_src).resolve()
    if expected != contract:
        raise Track04AnalysisError(
            f"contract path does not match manifest target.src: {target_src}"
        )

    with tempfile.TemporaryDirectory(prefix="qprover-track04-analysis-") as temporary:
        workspace = Path(temporary) / "target"
        shutil.copytree(target_root, workspace)
        foundry = workspace / "foundry.toml"
        if not foundry.exists():
            foundry.write_text(
                "\n".join(
                    (
                        "[profile.default]",
                        'src = "src"',
                        'out = "out"',
                        'cache_path = "cache"',
                        f'solc = "{solc_version}"',
                        f'evm_version = "{evm_version}"',
                        "optimizer = false",
                        "",
                    )
                ),
                encoding="utf-8",
            )
        local_solc = _local_solc(solc_version)
        compiler_args = (
            ("--use", local_solc, "--offline")
            if local_solc is not None
            else ("--use", solc_version)
        )
        command = (
            "forge",
            "build",
            target_src,
            "--root",
            str(workspace),
            "--skip",
            "test",
            "--build-info",
            "--extra-output",
            "storageLayout",
            *compiler_args,
        )
        _run(command, workspace)

        build_info_paths = sorted((workspace / "out" / "build-info").glob("*.json"))
        if len(build_info_paths) != 1:
            raise Track04AnalysisError(
                "compiler must emit exactly one build-info record"
            )
        build_info = _load_json(build_info_paths[0])
        compiler_version = build_info.get("solcVersion")
        input_evm = build_info.get("input", {}).get("settings", {}).get("evmVersion")
        if compiler_version != solc_version:
            raise Track04AnalysisError(
                f"compiler drift: expected {solc_version}, got {compiler_version}"
            )
        if input_evm != evm_version:
            raise Track04AnalysisError(
                f"EVM version drift: expected {evm_version}, got {input_evm}"
            )

        build_info_id = str(
            build_info.get("id") or _sha256(build_info_paths[0].read_bytes())[:16]
        )
        artifacts = _contract_artifacts(workspace / "out", build_info_id)
        target_key = f"{target_src}:{target_name}"
        if target_key not in {item.compilation_target for item in artifacts}:
            raise Track04AnalysisError(f"target artifact not found: {target_key}")

        input_sources = build_info.get("input", {}).get("sources")
        if not isinstance(input_sources, dict):
            raise Track04AnalysisError("build-info is missing input sources")
        bundle = SimpleNamespace(
            source_sha256=_hash_sources(input_sources),
            source_units=_source_units(build_info),
            artifacts=artifacts,
        )
        report = analyze(bundle)  # analyze() only consumes compiler evidence fields.
        graph = build_program_graph(report)
        report.contract(target_src, target_name)
        return Track04Analysis(
            report=report,
            graph=graph,
            source_name=target_src,
            contract_name=target_name,
        )
