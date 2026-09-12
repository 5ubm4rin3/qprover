"""Deterministic Foundry builds and compiler-evidence loading."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Any

from qprover.models import TargetManifest

BUILD_COMMAND = (
    "forge",
    "build",
    "--build-info",
    "--extra-output",
    "storageLayout",
)


class ArtifactError(ValueError):
    """Raised when a build cannot provide trustworthy compiler evidence."""


def _freeze(value: Any) -> Any:
    if isinstance(value, dict):
        return MappingProxyType({key: _freeze(item) for key, item in value.items()})
    if isinstance(value, list):
        return tuple(_freeze(item) for item in value)
    return value


@dataclass(frozen=True, slots=True)
class ContractArtifact:
    source_name: str
    contract_name: str
    artifact_path: Path
    artifact_sha256: str
    bytecode_sha256: str
    abi: tuple[Mapping[str, Any], ...]
    bytecode: str
    ast: Mapping[str, Any]
    storage_layout: Mapping[str, Any]


@dataclass(frozen=True, slots=True)
class ArtifactBundle:
    project_root: Path
    source_sha256: str
    manifest_sha256: str
    compiler_version: str
    evm_version: str
    tool_version: str
    build_command: tuple[str, ...]
    artifacts: tuple[ContractArtifact, ...]


def _inside(path: Path, root: Path, label: str) -> Path:
    resolved = path.resolve()
    try:
        resolved.relative_to(root)
    except ValueError as error:
        raise ArtifactError(f"{label} is outside project root: {resolved}") from error
    return resolved


def _scrubbed_environment() -> dict[str, str]:
    allowed = ("HOME", "PATH", "TMPDIR", "LANG", "LC_ALL", "TERM")
    return {name: os.environ[name] for name in allowed if name in os.environ}


def _run(command: tuple[str, ...], root: Path) -> subprocess.CompletedProcess[str]:
    try:
        result = subprocess.run(
            command,
            cwd=root,
            env=_scrubbed_environment(),
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError as error:
        raise ArtifactError(f"cannot execute {command[0]}: {error}") from error
    if result.returncode:
        detail = result.stderr.strip() or result.stdout.strip() or "unknown error"
        raise ArtifactError(f"Foundry build failed: {detail}")
    return result


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _canonical_manifest_hash(manifest: TargetManifest) -> str:
    payload = json.dumps(
        manifest.model_dump(mode="json"),
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    return _sha256(payload)


def _source_hash(manifest: TargetManifest, root: Path) -> str:
    digest = hashlib.sha256()
    for source in sorted(
        manifest.target.source_files, key=lambda item: item.as_posix()
    ):
        resolved = _inside(source, root, "source file")
        if not resolved.is_file():
            raise ArtifactError(f"source file is missing: {resolved}")
        relative = resolved.relative_to(root).as_posix().encode()
        digest.update(len(relative).to_bytes(8, "big"))
        digest.update(relative)
        content = resolved.read_bytes()
        digest.update(len(content).to_bytes(8, "big"))
        digest.update(content)
    return digest.hexdigest()


def _compiler_version(raw: Mapping[str, Any]) -> str:
    metadata = raw.get("metadata")
    if not isinstance(metadata, dict):
        raise ArtifactError("artifact is missing compiler metadata")
    compiler = metadata.get("compiler")
    if not isinstance(compiler, dict) or not isinstance(compiler.get("version"), str):
        raise ArtifactError("artifact is missing compiler version")
    return compiler["version"].split("+", maxsplit=1)[0]


def _load_artifact(
    artifact_path: Path, source_name: str, contract_name: str
) -> tuple[ContractArtifact, str, str]:
    artifact_bytes = artifact_path.read_bytes()
    try:
        raw = json.loads(artifact_bytes)
    except json.JSONDecodeError as error:
        raise ArtifactError(f"invalid artifact JSON: {artifact_path}") from error
    if "abi" not in raw or not isinstance(raw["abi"], list):
        raise ArtifactError(f"artifact is missing ABI: {artifact_path}")
    bytecode_record = raw.get("bytecode")
    bytecode = (
        bytecode_record.get("object") if isinstance(bytecode_record, dict) else None
    )
    if not isinstance(bytecode, str) or not bytecode.startswith("0x"):
        raise ArtifactError(f"artifact is missing bytecode: {artifact_path}")
    ast = raw.get("ast")
    if not isinstance(ast, dict) or ast.get("nodeType") != "SourceUnit":
        raise ArtifactError(f"artifact is missing AST: {artifact_path}")
    storage_layout = raw.get("storageLayout")
    if not isinstance(storage_layout, dict):
        raise ArtifactError(f"artifact is missing storage layout: {artifact_path}")
    metadata = raw.get("metadata")
    settings = metadata.get("settings") if isinstance(metadata, dict) else None
    evm_version = settings.get("evmVersion") if isinstance(settings, dict) else None
    if not isinstance(evm_version, str):
        raise ArtifactError(f"artifact is missing EVM version: {artifact_path}")
    return (
        ContractArtifact(
            source_name=source_name,
            contract_name=contract_name,
            artifact_path=artifact_path,
            artifact_sha256=_sha256(artifact_bytes),
            bytecode_sha256=_sha256(bytecode.encode()),
            abi=tuple(_freeze(item) for item in raw["abi"]),
            bytecode=bytecode,
            ast=_freeze(ast),
            storage_layout=_freeze(storage_layout),
        ),
        _compiler_version(raw),
        evm_version,
    )


def build_target(manifest: TargetManifest) -> ArtifactBundle:
    """Build a manifest target and retain the exact evidence used by analysis."""

    root = manifest.target.project_root.resolve()
    if not root.is_dir():
        raise ArtifactError(f"project root is missing: {root}")
    for source in manifest.target.source_files:
        _inside(source, root, "source file")

    _run(BUILD_COMMAND, root)
    version_result = _run(("forge", "--version"), root)
    tool_version = version_result.stdout.strip().splitlines()[0]
    if not tool_version:
        raise ArtifactError("Foundry did not report its version")

    requested = sorted({deployment.artifact for deployment in manifest.deployments})
    artifacts: list[ContractArtifact] = []
    compiler_versions: set[str] = set()
    evm_versions: set[str] = set()
    for reference in requested:
        try:
            source_name, contract_name = reference.rsplit(":", maxsplit=1)
        except ValueError as error:
            raise ArtifactError(f"invalid artifact reference: {reference}") from error
        expected = root / "out" / source_name / f"{contract_name}.json"
        matches = [
            candidate
            for candidate in (root / "out").rglob(f"{contract_name}.json")
            if candidate.resolve() == expected.resolve()
        ]
        if not matches:
            raise ArtifactError(f"requested artifact is missing: {reference}")
        if len(matches) != 1:
            raise ArtifactError(f"multiple requested artifacts found: {reference}")
        path = _inside(matches[0], root, "artifact")
        artifact, compiler_version, evm_version = _load_artifact(
            path, source_name, contract_name
        )
        artifacts.append(artifact)
        compiler_versions.add(compiler_version)
        evm_versions.add(evm_version)

    expected_compiler = manifest.target.solidity_version
    if compiler_versions != {expected_compiler}:
        actual = ", ".join(sorted(compiler_versions)) or "unknown"
        raise ArtifactError(
            "compiler drift: manifest requires "
            f"{expected_compiler}, build used {actual}"
        )
    expected_evm = manifest.target.evm_version
    if evm_versions != {expected_evm}:
        actual = ", ".join(sorted(evm_versions)) or "unknown"
        raise ArtifactError(
            f"EVM version drift: manifest requires {expected_evm}, build used {actual}"
        )

    return ArtifactBundle(
        project_root=root,
        source_sha256=_source_hash(manifest, root),
        manifest_sha256=_canonical_manifest_hash(manifest),
        compiler_version=expected_compiler,
        evm_version=expected_evm,
        tool_version=tool_version,
        build_command=BUILD_COMMAND,
        artifacts=tuple(artifacts),
    )
