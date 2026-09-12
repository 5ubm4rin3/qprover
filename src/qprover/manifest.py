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
_INTEGER_ALIAS_RE = re.compile(r"(?:^|[(,])(u?int)(?:\[|,|\)|$)")


def _canonical_signature(signature: str) -> bool:
    match = _SIGNATURE_RE.fullmatch(signature)
    if match is None or any(character.isspace() for character in signature):
        return False
    parameters = match.group(1)
    if _INTEGER_ALIAS_RE.search(f"({parameters})"):
        return False
    depth = 0
    for character in parameters:
        if character == "(":
            depth += 1
        elif character == ")":
            depth -= 1
            if depth < 0:
                return False
    return depth == 0


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
        if not _canonical_signature(action.signature):
            raise ManifestError(
                f"action {action.id!r} must use a canonical ABI signature"
            )
        signature_match = _SIGNATURE_RE.fullmatch(action.signature)
        assert signature_match is not None
        parameter_text = signature_match.group(1)
        parameter_count = (
            0 if parameter_text == "" else _top_level_parameter_count(parameter_text)
        )
        if parameter_count != len(action.arguments):
            raise ManifestError(
                f"action {action.id!r} signature and argument domains disagree"
            )
    for observation in manifest.observations:
        if observation.kind == "call":
            if observation.target_id not in deployment_ids:
                raise ManifestError(
                    f"observation {observation.id!r} references unknown deployment"
                )
            if not _canonical_signature(observation.signature or ""):
                raise ManifestError(
                    f"observation {observation.id!r} must use a canonical ABI signature"
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


def _top_level_parameter_count(parameters: str) -> int:
    depth = 0
    count = 1
    for character in parameters:
        if character == "(":
            depth += 1
        elif character == ")":
            depth -= 1
        elif character == "," and depth == 0:
            count += 1
    return count


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
