"""Strict, local-only target manifest loading."""

from __future__ import annotations

import ast
import json
import re
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from qprover.models import TargetManifest


class ManifestError(ValueError):
    """Raised when a target manifest is unsafe or invalid."""


_SIGNATURE_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*\((.*)\)$")
_INTEGER_RE = re.compile(r"u?int([0-9]+)")
_BYTES_RE = re.compile(r"bytes([0-9]+)")
_FIXED_RE = re.compile(r"u?fixed([0-9]+)x([0-9]+)")


def _is_canonical_base_type(value: str) -> bool:
    if value in {"address", "bool", "bytes", "function", "string"}:
        return True
    integer_match = _INTEGER_RE.fullmatch(value)
    if integer_match is not None:
        width_text = integer_match.group(1)
        width = int(width_text)
        return str(width) == width_text and 8 <= width <= 256 and width % 8 == 0
    bytes_match = _BYTES_RE.fullmatch(value)
    if bytes_match is not None:
        size_text = bytes_match.group(1)
        size = int(size_text)
        return str(size) == size_text and 1 <= size <= 32
    fixed_match = _FIXED_RE.fullmatch(value)
    if fixed_match is not None:
        width_text, precision_text = fixed_match.groups()
        width = int(width_text)
        precision = int(precision_text)
        return (
            str(width) == width_text
            and str(precision) == precision_text
            and 8 <= width <= 256
            and width % 8 == 0
            and 1 <= precision <= 80
        )
    return False


def _parse_abi_type(source: str, position: int) -> tuple[str, int]:
    start = position
    if position >= len(source):
        raise ValueError("missing ABI type")
    if source[position] == "(":
        position += 1
        if position >= len(source) or source[position] == ")":
            raise ValueError("empty tuple ABI type")
        while True:
            _, position = _parse_abi_type(source, position)
            if position >= len(source):
                raise ValueError("unterminated tuple ABI type")
            if source[position] == ")":
                position += 1
                break
            if source[position] != ",":
                raise ValueError("invalid tuple ABI type")
            position += 1
    else:
        base_start = position
        while position < len(source) and source[position].isalnum():
            position += 1
        base = source[base_start:position]
        if not _is_canonical_base_type(base):
            raise ValueError(f"noncanonical ABI base type: {base}")

    while position < len(source) and source[position] == "[":
        closing = source.find("]", position + 1)
        if closing < 0:
            raise ValueError("unterminated ABI array type")
        length_text = source[position + 1 : closing]
        if length_text:
            if not length_text.isdigit():
                raise ValueError("invalid ABI array length")
            length = int(length_text)
            if length <= 0 or str(length) != length_text:
                raise ValueError("noncanonical ABI array length")
        position = closing + 1
    return source[start:position], position


def _parse_abi_parameters(parameters: str) -> tuple[str, ...]:
    if parameters == "":
        return ()
    parsed: list[str] = []
    position = 0
    while position < len(parameters):
        abi_type, position = _parse_abi_type(parameters, position)
        parsed.append(abi_type)
        if position == len(parameters):
            break
        if parameters[position] != ",":
            raise ValueError("invalid ABI parameter separator")
        position += 1
        if position == len(parameters):
            raise ValueError("missing ABI parameter after comma")
    return tuple(parsed)


def _signature_types(signature: str) -> tuple[str, ...]:
    match = _SIGNATURE_RE.fullmatch(signature)
    if match is None or any(character.isspace() for character in signature):
        raise ValueError("invalid ABI function signature")
    return _parse_abi_parameters(match.group(1))


def _canonical_abi_type(value: str) -> bool:
    if any(character.isspace() for character in value):
        return False
    try:
        _, position = _parse_abi_type(value, 0)
    except ValueError:
        return False
    return position == len(value)


def _resolve_beneath(path: Path, root: Path, label: str) -> Path:
    if path.is_absolute():
        raise ManifestError(f"{label} must be a relative local path")
    resolved = (root / path).resolve()
    try:
        resolved.relative_to(root.resolve())
    except ValueError as error:
        root_name = root.name or "allowed root"
        raise ManifestError(f"{label} is outside {root_name}") from error
    return resolved


def _duplicates(values: list[str] | list[int]) -> set[str | int]:
    seen: set[str | int] = set()
    return {value for value in values if value in seen or seen.add(value)}


def _validate_ids_and_references(manifest: TargetManifest) -> None:
    collections = (
        manifest.actors,
        manifest.deployments,
        manifest.actions,
        manifest.observations,
        manifest.invariants,
    )
    for records in collections:
        duplicate_ids = _duplicates([record.id for record in records])
        if duplicate_ids:
            raise ManifestError(
                f"duplicate symbolic id: {sorted(duplicate_ids)[0]}"
            )

    duplicate_slots = _duplicates([actor.slot for actor in manifest.actors])
    if duplicate_slots:
        raise ManifestError(f"duplicate actor slot: {sorted(duplicate_slots)[0]}")

    actor_ids = {actor.id for actor in manifest.actors}
    actor_slots = {actor.slot for actor in manifest.actors}
    deployment_ids = {deployment.id for deployment in manifest.deployments}
    observation_ids = {observation.id for observation in manifest.observations}

    for deployment in manifest.deployments:
        if deployment.sender_slot not in actor_slots:
            raise ManifestError(
                f"deployment {deployment.id!r} references unknown actor slot"
            )
    for action in manifest.actions:
        if action.target_id not in deployment_ids:
            raise ManifestError(f"action {action.id!r} references unknown deployment")
        if not set(action.sender_slots).issubset(actor_slots):
            raise ManifestError(f"action {action.id!r} references unknown actor slot")
        try:
            signature_types = _signature_types(action.signature)
        except ValueError as error:
            raise ManifestError(
                f"action {action.id!r} must use a canonical ABI signature"
            ) from error
        if any(not _canonical_abi_type(argument.type) for argument in action.arguments):
            raise ManifestError(
                f"action {action.id!r} argument must use a canonical ABI type"
            )
        declared_types = tuple(argument.type for argument in action.arguments)
        if len(signature_types) != len(declared_types):
            raise ManifestError(
                f"action {action.id!r} signature and argument domains disagree"
            )
        if signature_types != declared_types:
            raise ManifestError(
                f"action {action.id!r} signature and declared argument types disagree"
            )
    for observation in manifest.observations:
        if observation.kind == "call":
            if observation.target_id not in deployment_ids:
                raise ManifestError(
                    f"observation {observation.id!r} references unknown deployment"
                )
            try:
                signature_types = _signature_types(observation.signature or "")
            except ValueError as error:
                raise ManifestError(
                    f"observation {observation.id!r} must use a canonical ABI signature"
                ) from error
            if len(signature_types) != len(observation.args):
                raise ManifestError(
                    f"observation call arity mismatch for {observation.id!r}"
                )
        elif observation.actor_id not in actor_ids:
            raise ManifestError(
                f"observation {observation.id!r} references unknown actor"
            )

    impact_references = {
        manifest.impact.attacker_asset_observation,
        manifest.impact.protocol_asset_observation,
    }
    if not impact_references.issubset(observation_ids):
        raise ManifestError("impact references unknown observation")

    allowed_names = observation_ids | {f"initial_{name}" for name in observation_ids}
    for invariant in manifest.invariants:
        try:
            parsed = ast.parse(invariant.expression, mode="eval")
        except SyntaxError as error:
            raise ManifestError(
                f"invariant {invariant.id!r} has invalid syntax"
            ) from error
        referenced_names = {
            node.id for node in ast.walk(parsed) if isinstance(node, ast.Name)
        }
        unknown_names = referenced_names - allowed_names
        if unknown_names:
            raise ManifestError(
                f"invariant {invariant.id!r} references unknown observation: "
                f"{sorted(unknown_names)[0]}"
            )


def load_manifest(path: Path) -> TargetManifest:
    """Load and validate a manifest, resolving all target paths locally."""

    manifest_path = path.resolve()
    try:
        raw: dict[str, Any] = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ManifestError(f"cannot read manifest {manifest_path}: {error}") from error

    if not isinstance(raw, dict):
        raise ManifestError("manifest root must be a JSON object")

    target = raw.get("target")
    if isinstance(target, dict):
        project_value = target.get("project_root")
        if isinstance(project_value, str):
            try:
                project_root = _resolve_beneath(
                    Path(project_value), manifest_path.parent, "project root"
                )
            except ManifestError as error:
                if "outside" in str(error):
                    raise ManifestError(
                        "project root is outside manifest directory"
                    ) from error
                raise
            target["project_root"] = str(project_root)
            source_values = target.get("source_files")
            if isinstance(source_values, list):
                resolved_sources = []
                for source in source_values:
                    if not isinstance(source, str):
                        resolved_sources.append(source)
                        continue
                    try:
                        resolved_sources.append(
                            str(
                                _resolve_beneath(
                                    Path(source), project_root, "source file"
                                )
                            )
                        )
                    except ManifestError as error:
                        if "outside" in str(error):
                            raise ManifestError(
                                "source file is outside project root"
                            ) from error
                        raise
                target["source_files"] = resolved_sources

    try:
        manifest = TargetManifest.model_validate(raw)
    except ValidationError as error:
        raise ManifestError(str(error)) from error
    _validate_ids_and_references(manifest)
    return manifest
