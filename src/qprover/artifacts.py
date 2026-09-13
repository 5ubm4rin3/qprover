"""Deterministic Foundry builds and compiler-evidence loading."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType
from typing import Any, Self

from qprover.models import TargetManifest

BUILD_COMMAND = (
    "forge",
    "build",
    "--skip",
    "test",
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
class SourceUnitArtifact:
    source_name: str
    source_sha256: str
    ast: Mapping[str, Any]


@dataclass(frozen=True, slots=True)
class ContractArtifact:
    source_name: str
    contract_name: str
    compilation_target: str
    build_info_id: str
    artifact_path: Path
    artifact_sha256: str
    bytecode_sha256: str
    abi: tuple[Mapping[str, Any], ...]
    method_identifiers: tuple[tuple[str, str], ...]
    bytecode: str
    ast: Mapping[str, Any]
    storage_layout: Mapping[str, Any]


@dataclass(frozen=True, slots=True)
class ArtifactBundle:
    project_root: Path
    source_sha256: str
    source_names: tuple[str, ...]
    source_units: tuple[SourceUnitArtifact, ...]
    manifest_sha256: str
    build_info_id: str
    build_info_path: Path
    build_info_sha256: str
    compiler_version: str
    evm_version: str
    tool_version: str
    build_command: tuple[str, ...]
    artifacts: tuple[ContractArtifact, ...]
    _evidence_root: Path = field(repr=False, compare=False)
    _closed: bool = field(default=False, init=False, repr=False, compare=False)

    @property
    def evidence_root(self) -> Path:
        """Directory retaining fresh build evidence for this live bundle."""

        return self._evidence_root

    @property
    def closed(self) -> bool:
        return self._closed

    def close(self) -> None:
        """Remove retained compiler evidence, or report that it remains live."""

        if self._closed:
            return
        if not self._evidence_root.exists():
            object.__setattr__(self, "_closed", True)
            return
        try:
            shutil.rmtree(self._evidence_root)
        except OSError as error:
            raise ArtifactError(
                f"could not remove artifact evidence: {self._evidence_root}"
            ) from error
        if self._evidence_root.exists():
            raise ArtifactError(
                f"could not remove artifact evidence: {self._evidence_root}"
            )
        object.__setattr__(self, "_closed", True)

    def __enter__(self) -> Self:
        if self._closed:
            raise ArtifactError("artifact bundle is closed")
        return self

    def __exit__(self, *exc_info: object) -> None:
        if exc_info and exc_info[0] is not None:
            shutil.rmtree(self._evidence_root, ignore_errors=True)
            if not self._evidence_root.exists():
                object.__setattr__(self, "_closed", True)
            return
        self.close()


def _inside(path: Path, root: Path, label: str) -> Path:
    resolved = path.resolve()
    resolved_root = root.resolve()
    try:
        resolved.relative_to(resolved_root)
    except ValueError as error:
        raise ArtifactError(f"{label} is outside project root: {resolved}") from error
    return resolved


def _scrubbed_environment(overrides: Mapping[str, str] | None = None) -> dict[str, str]:
    allowed = ("HOME", "PATH", "TMPDIR", "LANG", "LC_ALL", "TERM")
    environment = {name: os.environ[name] for name in allowed if name in os.environ}
    environment.update(overrides or {})
    return environment


def _run(
    command: tuple[str, ...],
    root: Path,
    overrides: Mapping[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    try:
        result = subprocess.run(
            command,
            cwd=root,
            env=_scrubbed_environment(overrides),
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


def _hash_sources(sources: Mapping[str, Mapping[str, Any]]) -> str:
    digest = hashlib.sha256()
    for source_name in sorted(sources):
        content = sources[source_name].get("content")
        if not isinstance(content, str):
            raise ArtifactError(f"build-info source lacks content: {source_name}")
        encoded_name = source_name.encode()
        encoded_content = content.encode()
        digest.update(len(encoded_name).to_bytes(8, "big"))
        digest.update(encoded_name)
        digest.update(len(encoded_content).to_bytes(8, "big"))
        digest.update(encoded_content)
    return digest.hexdigest()


def _compiler_version(raw: Mapping[str, Any]) -> str:
    metadata = raw.get("metadata")
    if not isinstance(metadata, dict):
        raise ArtifactError("artifact is missing compiler metadata")
    compiler = metadata.get("compiler")
    if not isinstance(compiler, dict) or not isinstance(compiler.get("version"), str):
        raise ArtifactError("artifact is missing compiler version")
    return compiler["version"].split("+", maxsplit=1)[0]


def _load_json(path: Path, label: str) -> tuple[dict[str, Any], bytes]:
    try:
        raw_bytes = path.read_bytes()
        raw = json.loads(raw_bytes)
    except (OSError, json.JSONDecodeError) as error:
        raise ArtifactError(f"invalid {label} JSON: {path}") from error
    if not isinstance(raw, dict):
        raise ArtifactError(f"invalid {label} JSON object: {path}")
    return raw, raw_bytes


def _load_build_info(
    output_root: Path, project_root: Path
) -> tuple[dict[str, Any], Path, bytes]:
    paths = sorted((output_root / "build-info").glob("*.json"))
    if len(paths) != 1:
        raise ArtifactError("fresh build must emit exactly one build-info record")
    raw, raw_bytes = _load_json(paths[0], "build-info")
    sources = raw.get("input", {}).get("sources")
    output_sources = raw.get("output", {}).get("sources")
    if not isinstance(sources, dict) or not isinstance(output_sources, dict):
        raise ArtifactError("build-info is missing compiler source closure")
    for source_name, record in sources.items():
        if not isinstance(source_name, str) or not isinstance(record, dict):
            raise ArtifactError("build-info contains invalid compiler source")
        direct_source = project_root / source_name
        source_path = (
            direct_source
            if direct_source.is_file()
            else project_root / "src" / source_name
        )
        source_path = _inside(source_path, project_root, "compiler source")
        content = record.get("content")
        if (
            not isinstance(content, str)
            or source_path.read_text(encoding="utf-8") != content
        ):
            raise ArtifactError(f"build-info source content drift: {source_name}")
    return raw, paths[0], raw_bytes


def _source_units(build_info: Mapping[str, Any]) -> tuple[SourceUnitArtifact, ...]:
    input_sources = build_info["input"]["sources"]
    output_sources = build_info["output"]["sources"]
    records: list[SourceUnitArtifact] = []
    for source_name in sorted(input_sources):
        output_record = output_sources.get(source_name)
        ast = output_record.get("ast") if isinstance(output_record, dict) else None
        if not isinstance(ast, dict) or ast.get("nodeType") != "SourceUnit":
            raise ArtifactError(f"build-info source is missing AST: {source_name}")
        content = input_sources[source_name]["content"].encode()
        records.append(SourceUnitArtifact(source_name, _sha256(content), _freeze(ast)))
    return tuple(records)


def _load_artifact(
    artifact_path: Path,
    source_name: str,
    contract_name: str,
    build_info: Mapping[str, Any],
    build_info_id: str,
) -> tuple[ContractArtifact, str, str]:
    raw, artifact_bytes = _load_json(artifact_path, "artifact")
    if "abi" not in raw or not isinstance(raw["abi"], list):
        raise ArtifactError(f"artifact is missing ABI: {artifact_path}")
    method_identifiers = raw.get("methodIdentifiers")
    if not isinstance(method_identifiers, dict) or not all(
        isinstance(signature, str)
        and isinstance(selector, str)
        and re.fullmatch(r"[0-9a-fA-F]{8}", selector)
        for signature, selector in method_identifiers.items()
    ):
        raise ArtifactError(f"artifact is missing method identifiers: {artifact_path}")
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
    targets = settings.get("compilationTarget") if isinstance(settings, dict) else None
    if not isinstance(evm_version, str):
        raise ArtifactError(f"artifact is missing EVM version: {artifact_path}")
    if targets != {source_name: contract_name}:
        raise ArtifactError(
            f"artifact compilation target mismatch: {source_name}:{contract_name}"
        )
    compilation_source = source_name
    output_contract = (
        build_info.get("output", {})
        .get("contracts", {})
        .get(source_name, {})
        .get(contract_name)
    )
    if not isinstance(output_contract, dict):
        raise ArtifactError(
            "requested artifact absent from fresh build-info: "
            f"{source_name}:{contract_name}"
        )
    output_bytecode = output_contract.get("evm", {}).get("bytecode", {}).get("object")
    output_method_identifiers = output_contract.get("evm", {}).get(
        "methodIdentifiers"
    )
    build_storage_layout = output_contract.get("storageLayout")
    layout_matches = build_storage_layout == storage_layout or (
        build_storage_layout is None
        and storage_layout.get("storage") in ([], ())
        and storage_layout.get("types") in ({}, None)
    )
    if (
        output_contract.get("abi") != raw["abi"]
        or output_method_identifiers != method_identifiers
        or not layout_matches
        or output_bytecode != bytecode[2:]
        or build_info["output"]["sources"][compilation_source].get("ast") != ast
    ):
        raise ArtifactError(
            f"artifact does not match fresh build-info: {source_name}:{contract_name}"
        )
    return (
        ContractArtifact(
            source_name=compilation_source,
            contract_name=contract_name,
            compilation_target=f"{compilation_source}:{contract_name}",
            build_info_id=build_info_id,
            artifact_path=artifact_path,
            artifact_sha256=_sha256(artifact_bytes),
            bytecode_sha256=_sha256(bytecode.encode()),
            abi=tuple(_freeze(item) for item in raw["abi"]),
            method_identifiers=tuple(
                sorted(
                    (signature, selector.lower())
                    for signature, selector in method_identifiers.items()
                )
            ),
            bytecode=bytecode,
            ast=_freeze(ast),
            storage_layout=_freeze(storage_layout),
        ),
        _compiler_version(raw),
        evm_version,
    )


def _find_artifact_path(
    output_root: Path, source_name: str, contract_name: str
) -> Path:
    """Find one contained artifact by its exact canonical compilation target."""

    candidates: list[Path] = []
    for candidate in output_root.rglob(f"{contract_name}.json"):
        contained = _inside(candidate, output_root, "artifact")
        raw, _ = _load_json(contained, "artifact candidate")
        metadata = raw.get("metadata")
        settings = metadata.get("settings") if isinstance(metadata, dict) else None
        target = (
            settings.get("compilationTarget") if isinstance(settings, dict) else None
        )
        if target == {source_name: contract_name}:
            candidates.append(contained)
    if len(candidates) != 1:
        raise ArtifactError(
            f"artifact candidate ambiguity for {source_name}:{contract_name}"
        )
    return candidates[0]


def _build_target_in_workspace(
    manifest: TargetManifest,
    root: Path,
    parsed_requests: list[tuple[str, str]],
    build_root: Path,
) -> ArtifactBundle:
    output_root = build_root / "out"
    overrides = {
        "FOUNDRY_OUT": str(output_root),
        "FOUNDRY_CACHE_PATH": str(build_root / "cache"),
    }
    build_command = (
        *BUILD_COMMAND[:2],
        *manifest_source_paths(manifest, root),
        *BUILD_COMMAND[2:],
    )
    _run(build_command, root, overrides)
    build_info, build_info_path, build_info_bytes = _load_build_info(output_root, root)
    build_info_id = build_info.get("id")
    if not isinstance(build_info_id, str) or not build_info_id:
        raise ArtifactError("fresh build-info is missing identity")
    version_result = _run(("forge", "--version"), root)
    tool_version = version_result.stdout.strip().splitlines()[0]
    if not tool_version:
        raise ArtifactError("Foundry did not report its version")

    artifacts: list[ContractArtifact] = []
    compiler_versions: set[str] = set()
    evm_versions: set[str] = set()
    for source_name, contract_name in parsed_requests:
        path = _find_artifact_path(output_root, source_name, contract_name)
        artifact, compiler_version, evm_version = _load_artifact(
            path, source_name, contract_name, build_info, build_info_id
        )
        artifacts.append(artifact)
        compiler_versions.add(compiler_version)
        evm_versions.add(evm_version)

    expected_compiler = manifest.target.solidity_version
    build_info_compiler = build_info.get("solcVersion")
    if (
        compiler_versions != {expected_compiler}
        or build_info_compiler != expected_compiler
    ):
        actual = ", ".join(sorted(compiler_versions)) or "unknown"
        raise ArtifactError(
            "compiler drift: manifest requires "
            f"{expected_compiler}, build used {actual}/{build_info_compiler}"
        )
    expected_evm = manifest.target.evm_version
    input_evm = build_info.get("input", {}).get("settings", {}).get("evmVersion")
    if evm_versions != {expected_evm} or input_evm != expected_evm:
        actual = ", ".join(sorted(evm_versions)) or "unknown"
        raise ArtifactError(
            f"EVM version drift: manifest requires {expected_evm}, "
            f"build used {actual}/{input_evm}"
        )

    input_sources = build_info["input"]["sources"]
    return ArtifactBundle(
        project_root=root,
        source_sha256=_hash_sources(input_sources),
        source_names=tuple(sorted(input_sources)),
        source_units=_source_units(build_info),
        manifest_sha256=_canonical_manifest_hash(manifest),
        build_info_id=build_info_id,
        build_info_path=build_info_path,
        build_info_sha256=_sha256(build_info_bytes),
        compiler_version=expected_compiler,
        evm_version=expected_evm,
        tool_version=tool_version,
        build_command=build_command,
        artifacts=tuple(artifacts),
        _evidence_root=build_root,
    )


def build_target(manifest: TargetManifest) -> ArtifactBundle:
    """Build a target in isolated outputs and retain its compiler evidence."""

    root = manifest.target.project_root.resolve()
    if not root.is_dir():
        raise ArtifactError(f"project root is missing: {root}")
    declared_sources = {
        _inside(source, root, "source file").relative_to(root).as_posix()
        for source in manifest.target.source_files
    }
    requested = sorted({deployment.artifact for deployment in manifest.deployments})
    parsed_requests: list[tuple[str, str]] = []
    for reference in requested:
        try:
            source_name, contract_name = reference.rsplit(":", maxsplit=1)
        except ValueError as error:
            raise ArtifactError(f"invalid artifact reference: {reference}") from error
        if source_name not in declared_sources:
            raise ArtifactError(
                f"deployment artifact source is not declared: {source_name}"
            )
        if re.fullmatch(r"[A-Za-z_$][A-Za-z0-9_$]*", contract_name) is None:
            raise ArtifactError(
                f"invalid artifact contract identifier: {contract_name}"
            )
        parsed_requests.append((source_name, contract_name))

    build_root = Path(tempfile.mkdtemp(prefix="qprover-foundry-build-"))
    try:
        return _build_target_in_workspace(
            manifest, root, parsed_requests, build_root
        )
    except BaseException:
        shutil.rmtree(build_root, ignore_errors=True)
        raise


def manifest_source_paths(manifest: TargetManifest, root: Path) -> tuple[str, ...]:
    """Return validated canonical Forge inputs for one target's source closure."""

    return tuple(
        sorted(
            _inside(source, root, "source file").relative_to(root).as_posix()
            for source in manifest.target.source_files
        )
    )
