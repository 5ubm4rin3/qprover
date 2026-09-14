"""Self-contained local Foundry PoC generation and cold verification."""

from __future__ import annotations

import ast
import hashlib
import json
import os
import re
import secrets
import shutil
import stat
import subprocess
import tempfile
import time
from collections.abc import Mapping, Sequence
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import jsonschema
from eth_abi import encode
from eth_abi.exceptions import EncodingError
from eth_utils import keccak, to_checksum_address
from eth_utils.abi import collapse_if_tuple

from qprover.artifacts import (
    BUILD_COMMAND,
    build_target,
    canonical_build_info_hash,
    manifest_source_paths,
)
from qprover.certificate import (
    REPLAY_ARGV_TEMPLATE,
    REPLAY_MATERIALIZATION,
    ProofCertificate,
    ReplayRecipe,
    ReplayRecord,
    _seal_certificate,
    write_certificate,
)
from qprover.evaluator import ScenarioEvaluator
from qprover.evm import LocalAnvil
from qprover.manifest import _signature_types, canonical_manifest_hash, load_manifest
from qprover.models import (
    ActionStep,
    Candidate,
    ConfirmationStatus,
    Outcome,
    TargetManifest,
)
from qprover.runtime import current_runtime
from qprover.safeio import SafeOutputError, safe_atomic_write


class ReplayError(RuntimeError):
    """Replay inputs cannot establish exact local evidence."""


@dataclass(frozen=True, slots=True)
class ReplayVerification:
    confirmation_status: ConfirmationStatus
    records: tuple[ReplayRecord, ...]
    certificate: ProofCertificate


@dataclass(frozen=True, slots=True)
class ReplayMaterialization:
    """One private, hash-verified realization of a portable replay recipe."""

    root: Path
    project: Path
    argv: tuple[str, ...]
    staging_tree_sha256: str


@dataclass(frozen=True, slots=True)
class StructuredReplayResult:
    success: bool
    normalized_sha256: str
    suite_count: int
    test_count: int
    executed_suite: str | None
    executed_test: str | None
    executed_status: str | None
    malformed: bool


def _digest(data: bytes | str) -> str:
    encoded = data.encode() if isinstance(data, str) else data
    return hashlib.sha256(encoded).hexdigest()


def _stable_output_digest(output: str) -> str:
    """Hash replay evidence after removing Forge's nondeterministic timings."""

    without_ansi = re.sub(r"\x1b\[[0-9;]*m", "", output)
    without_timings = re.sub(
        r"(?<![A-Za-z0-9_.])\d+(?:\.\d+)?(?:ns|[µμ]s|us|ms|s)\b",
        "<duration>",
        without_ansi,
    )
    normalized = "\n".join(line.rstrip() for line in without_timings.splitlines())
    return _digest(normalized)


def _manifest_hash(manifest: TargetManifest) -> str:
    return canonical_manifest_hash(manifest)


def _identifier(value: str) -> str:
    normalized = re.sub(r"[^A-Za-z0-9_]", "_", value)
    if not normalized or normalized[0].isdigit():
        normalized = f"item_{normalized}"
    return normalized


def _solidity_literal(value: object, abi_type: str | None = None) -> str:
    if type(value) is bool:
        return "true" if value else "false"
    if type(value) is int:
        if abi_type and abi_type.startswith("address"):
            return f"address(uint160({value}))"
        return str(value)
    if isinstance(value, str):
        if abi_type == "address":
            if re.fullmatch(r"0x[0-9a-fA-F]{40}", value) is None:
                raise ReplayError("invalid address argument in certificate")
            return f"address({value})"
        if abi_type and abi_type.startswith("bytes") and value.startswith("0x"):
            raw = value[2:]
            if re.fullmatch(r"[0-9a-fA-F]*", raw) is None or len(raw) % 2:
                raise ReplayError("invalid bytes argument in certificate")
            return f'hex"{raw}"'
        return json.dumps(value)
    if isinstance(value, (list, tuple)):
        return "[" + ",".join(_solidity_literal(item) for item in value) + "]"
    raise ReplayError("unsupported ABI argument in certificate")


_BINOPS = {
    ast.Add: "+",
    ast.Sub: "-",
    ast.Mult: "*",
    ast.FloorDiv: "/",
    ast.Mod: "%",
    ast.BitAnd: "&",
    ast.BitOr: "|",
    ast.BitXor: "^",
    ast.LShift: "<<",
    ast.RShift: ">>",
}
_COMPARISONS = {
    ast.Eq: "==",
    ast.NotEq: "!=",
    ast.Lt: "<",
    ast.LtE: "<=",
    ast.Gt: ">",
    ast.GtE: ">=",
}


def _render_invariant(
    expression: str, observations: set[str], *, current_prefix: str = "final"
) -> str:
    try:
        root = ast.parse(expression, mode="eval")
    except SyntaxError as error:
        raise ReplayError("invalid invariant expression") from error

    def render(node: ast.AST) -> str:
        if isinstance(node, ast.Expression):
            return render(node.body)
        if isinstance(node, ast.Name):
            if node.id.startswith("initial_"):
                observation = node.id[len("initial_") :]
                if observation in observations:
                    return node.id
            elif node.id in observations:
                return f"{current_prefix}_{node.id}"
            raise ReplayError("invariant references unknown observation")
        if isinstance(node, ast.Constant) and type(node.value) in (bool, int):
            return _solidity_literal(node.value)
        if isinstance(node, ast.UnaryOp):
            operator = {ast.Not: "!", ast.USub: "-", ast.UAdd: "+"}.get(type(node.op))
            if operator is None:
                raise ReplayError("unsupported invariant unary operation")
            return f"({operator}{render(node.operand)})"
        if isinstance(node, ast.BoolOp):
            operator = "&&" if isinstance(node.op, ast.And) else "||"
            return (
                "(" + f" {operator} ".join(render(item) for item in node.values) + ")"
            )
        if isinstance(node, ast.BinOp) and type(node.op) in _BINOPS:
            return (
                f"({render(node.left)} {_BINOPS[type(node.op)]} {render(node.right)})"
            )
        if isinstance(node, ast.Compare):
            parts: list[str] = []
            left = node.left
            for operator, right in zip(node.ops, node.comparators, strict=True):
                symbol = _COMPARISONS.get(type(operator))
                if symbol is None:
                    raise ReplayError("unsupported invariant comparison")
                parts.append(f"({render(left)} {symbol} {render(right)})")
                left = right
            return "(" + " && ".join(parts) + ")"
        raise ReplayError("unsupported invariant syntax for Foundry replay")

    return render(root)


def _validate_manifest_identity(
    certificate: ProofCertificate,
    manifest: TargetManifest,
    workspace_root: Path | None = None,
    manifest_path: Path | None = None,
) -> None:
    workspace = (workspace_root or Path.cwd()).resolve()
    project = _resolve_workspace_path(
        workspace, certificate.target.project_root, "project root"
    )
    expected_manifest = _resolve_workspace_path(
        workspace, certificate.target.manifest_path, "manifest path"
    )
    if (
        certificate.target.id != manifest.target.id
        or certificate.target.workspace_root != "."
        or project != manifest.target.project_root.resolve()
        or (manifest_path is not None and expected_manifest != manifest_path.resolve())
        or certificate.target.manifest_sha256 != _manifest_hash(manifest)
    ):
        raise ReplayError("certificate and manifest identity mismatch")
    sources = {item.path: item.sha256 for item in certificate.target.sources}
    for source in manifest.target.source_files:
        relative = source.resolve().relative_to(manifest.target.project_root.resolve())
        if relative.as_posix() not in sources:
            raise ReplayError("certificate source identity is incomplete")


def _resolve_workspace_path(root: Path, relative: str, label: str) -> Path:
    candidate = Path(relative)
    if candidate.is_absolute() or ".." in candidate.parts:
        raise ReplayError(f"{label} must be workspace-relative")
    resolved = (root / candidate).resolve()
    try:
        resolved.relative_to(root.resolve())
    except ValueError as error:
        raise ReplayError(f"{label} escapes the trusted workspace") from error
    return resolved


def validate_semantic_binding(
    certificate: ProofCertificate,
    manifest: TargetManifest,
    *,
    workspace_root: Path | None = None,
    manifest_path: Path | None = None,
) -> None:
    """Bind every manifest-derived certificate claim to one exact manifest."""

    _validate_manifest_identity(certificate, manifest, workspace_root, manifest_path)
    matching_invariants = tuple(
        item for item in manifest.invariants if item.id == certificate.invariant.id
    )
    if len(matching_invariants) != 1:
        raise ReplayError("certificate invariant semantics do not match manifest")
    declared = matching_invariants[0]
    if (
        certificate.invariant.expression != declared.expression
        or certificate.invariant.description != declared.description
        or certificate.invariant.foundry_assertion != declared.foundry_assertion
    ):
        raise ReplayError("certificate invariant semantics do not match manifest")
    if len(certificate.initial_invariants) != len(manifest.invariants):
        raise ReplayError(
            "certificate initial invariant semantics do not match manifest"
        )
    for initial, supplied in zip(
        certificate.initial_invariants, manifest.invariants, strict=True
    ):
        if (
            initial.id != supplied.id
            or initial.expression != supplied.expression
            or initial.description != supplied.description
            or initial.foundry_assertion != supplied.foundry_assertion
            or not initial.evaluated
            or initial.value is not True
            or initial.reason is not None
        ):
            raise ReplayError(
                "certificate initial invariant semantics do not match manifest"
            )
    if certificate.confirmation_policy != manifest.confirmation.kind:
        raise ReplayError("certificate confirmation policy does not match manifest")
    if manifest.confirmation.kind == "invariant_and_economic_impact":
        if manifest.impact is None:
            raise ReplayError("economic manifest omitted impact accounting")
        if (
            certificate.impact.applicability != "economic"
            or certificate.impact.attacker_observation
            != manifest.impact.attacker_asset_observation
            or certificate.impact.protocol_observation
            != manifest.impact.protocol_asset_observation
            or certificate.impact.unit != manifest.impact.unit
        ):
            raise ReplayError("certificate impact semantics do not match manifest")
    elif certificate.impact.applicability != "not_applicable":
        raise ReplayError("invariant-only certificate contains an economic claim")
    expected_funding = tuple(
        (actor.id, actor.slot, actor.balance_wei) for actor in manifest.actors
    )
    actual_funding = tuple(
        (item.actor_id, item.slot, item.balance_wei) for item in certificate.funding
    )
    if actual_funding != expected_funding:
        raise ReplayError("certificate funding semantics do not match manifest")
    if (
        certificate.toolchain.compiler_version != manifest.target.solidity_version
        or certificate.toolchain.evm_version != manifest.target.evm_version
    ):
        raise ReplayError("certificate compiler semantics do not match manifest")
    if any(
        artifact.build_info_sha256 != certificate.build.build_info_sha256
        for artifact in certificate.artifacts
    ):
        raise ReplayError("artifact build-info hash mismatch")
    sources = manifest_source_paths(manifest, manifest.target.project_root)
    expected_build_command = (
        *BUILD_COMMAND[:2],
        *sources,
        *BUILD_COMMAND[2:],
    )
    if certificate.build.command != expected_build_command:
        raise ReplayError("certificate build command mismatch")
    _validate_transactions(certificate, manifest)


def _validate_transactions(
    certificate: ProofCertificate, manifest: TargetManifest
) -> None:
    actions = {item.id: item for item in manifest.actions}
    for transaction in certificate.transactions:
        action = actions.get(transaction.action_id)
        if action is None or (
            transaction.target_id != action.target_id
            or transaction.signature != action.signature
            or transaction.sender_slot not in action.sender_slots
            or len(transaction.args) != len(action.arguments)
            or not any(
                type(transaction.value_wei) is type(value)
                and transaction.value_wei == value
                for value in action.value_domain.values
            )
        ):
            raise ReplayError(
                "certificate transaction is outside manifest action space"
            )
        for value, argument in zip(transaction.args, action.arguments, strict=True):
            domain = argument.domain
            if domain.kind == "finite" and not any(
                type(value) is type(allowed) and value == allowed
                for allowed in domain.values
            ):
                raise ReplayError("certificate argument is outside manifest domain")
            if domain.kind == "integer" and (
                type(value) is not int or not domain.minimum <= value <= domain.maximum
            ):
                raise ReplayError("certificate argument is outside manifest domain")
        try:
            calldata = keccak(text=action.signature)[:4] + encode(
                [argument.type for argument in action.arguments],
                list(transaction.args),
            )
        except (EncodingError, TypeError, ValueError) as error:
            raise ReplayError("certificate transaction is not ABI encodable") from error
        if _digest(calldata) != transaction.calldata_sha256:
            raise ReplayError("certificate calldata hash mismatch")


def foundry_poc_source(
    certificate: ProofCertificate,
    manifest: TargetManifest,
    *,
    workspace_root: Path | None = None,
) -> str:
    """Render one deterministic, network-free Solidity regression test."""

    certificate = ProofCertificate.model_validate(certificate.model_dump(mode="json"))
    validate_semantic_binding(certificate, manifest, workspace_root=workspace_root)
    artifacts = {item.compilation_target: item for item in certificate.artifacts}
    imports: list[str] = []
    contract_names: dict[str, str] = {}
    for deployment in manifest.deployments:
        if deployment.artifact not in artifacts:
            raise ReplayError("deployment artifact identity is absent")
        source_name, contract_name = deployment.artifact.rsplit(":", 1)
        contract_names[deployment.id] = contract_name
        imports.append(f'import {{{contract_name}}} from "../{source_name}";')

    actors = {actor.slot: actor for actor in manifest.actors}
    observation_names = {item.id for item in manifest.observations}
    invariant_expression = _render_invariant(
        certificate.invariant.expression, observation_names
    )
    baseline_invariant_expression = _render_invariant(
        certificate.invariant.expression,
        observation_names,
        current_prefix="initial",
    )
    lines = [
        "// SPDX-License-Identifier: Apache-2.0",
        f"pragma solidity {manifest.target.solidity_version};",
        "",
        *sorted(set(imports)),
        "",
        "interface QProverVm {",
        "    function deal(address account, uint256 newBalance) external;",
        "    function prank(address msgSender, address txOrigin) external;",
        "}",
        "",
        "contract QProverReplayTest {",
        "    QProverVm private constant vm = QProverVm(",
        '        address(uint160(uint256(keccak256("hevm cheat code"))))',
        "    );",
    ]
    for slot in sorted(actors):
        address = next(
            item.address for item in certificate.funding if item.slot == slot
        )
        lines.append(
            f"    address private constant actor_slot_{slot} = "
            f"address(uint160({to_checksum_address(address)}));"
        )
    for deployment in manifest.deployments:
        lines.append(f"    address private target_{_identifier(deployment.id)};")
    lines.extend(
        [
            "",
            "    function _observeUint(address target, bytes memory data)",
            "        private view returns (uint256 value)",
            "    {",
            "        (bool ok, bytes memory result) = target.staticcall(",
            "            data",
            "        );",
            '        require(ok && result.length == 32, "observation");',
            "        value = abi.decode(result, (uint256));",
            "    }",
            "",
            "    function _observeBool(address target, bytes memory data)",
            "        private view returns (bool value)",
            "    {",
            "        (bool ok, bytes memory result) = target.staticcall(data);",
            '        require(ok && result.length == 32, "observation");',
            "        value = abi.decode(result, (bool));",
            "    }",
            "",
            "    function test_qprover_replay() public {",
        ]
    )
    for slot, actor in sorted(actors.items()):
        funding = next(item for item in certificate.funding if item.slot == slot)
        lines.extend(
            [
                f"        vm.deal(actor_slot_{slot}, {actor.balance_wei});",
                f"        assert(actor_slot_{slot}.balance == {funding.balance_wei});",
            ]
        )
    for deployment in manifest.deployments:
        contract_name = contract_names[deployment.id]
        constructor_args = tuple(deployment.constructor_args)
        artifact = artifacts[deployment.artifact]
        if len(constructor_args) != len(artifact.constructor_types):
            raise ReplayError("constructor arguments do not match artifact ABI")
        encoded = ", ".join(
            _constructor_literal(
                value,
                abi_type,
                actors_by_id={item.id: item.slot for item in manifest.actors},
                prior_deployments={
                    item.id
                    for item in manifest.deployments
                    if manifest.deployments.index(item)
                    < manifest.deployments.index(deployment)
                },
            )
            for value, abi_type in zip(
                constructor_args, artifact.constructor_types, strict=True
            )
        )
        value_clause = (
            f"{{value: {deployment.value_wei}}}" if deployment.value_wei else ""
        )
        lines.extend(
            [
                f"        vm.prank(actor_slot_{deployment.sender_slot}, "
                f"actor_slot_{deployment.sender_slot});",
                f"        target_{_identifier(deployment.id)} = address("
                f"new {contract_name}{value_clause}({encoded}));",
            ]
        )
    for observation in manifest.observations:
        name = _identifier(observation.id)
        if observation.kind == "native_balance":
            actor = next(
                item for item in manifest.actors if item.id == observation.actor_id
            )
            expression = f"actor_slot_{actor.slot}.balance"
        else:
            calldata = _observation_calldata(
                observation.signature or "", observation.args
            )
            value = certificate.initial_state.values[observation.id]
            helper = "_observeBool" if type(value) is bool else "_observeUint"
            expression = (
                f"{helper}(target_{_identifier(observation.target_id or '')}, "
                f"{calldata})"
            )
        solidity_type = (
            "bool"
            if type(certificate.initial_state.values[observation.id]) is bool
            else "uint256"
        )
        lines.append(f"        {solidity_type} initial_{name} = {expression};")
        lines.append(
            f"        assert(initial_{name} == "
            f"{_solidity_literal(certificate.initial_state.values[observation.id])});"
        )
    lines.append(f"        assert({baseline_invariant_expression});")

    action_specs = {item.id: item for item in manifest.actions}
    for transaction in certificate.transactions:
        action = action_specs[transaction.action_id]
        argument_text = ""
        if transaction.args:
            rendered = [
                _solidity_literal(value, spec.type)
                for value, spec in zip(transaction.args, action.arguments, strict=True)
            ]
            argument_text = ", " + ", ".join(rendered)
        lines.extend(
            [
                f"        vm.prank(actor_slot_{transaction.sender_slot}, "
                f"actor_slot_{transaction.sender_slot});",
                f"        (bool success_{transaction.index},) = "
                f"target_{_identifier(transaction.target_id)}.call"
                f"{{value: {transaction.value_wei}}}(",
                f'            abi.encodeWithSignature("{transaction.signature}"'
                f"{argument_text})",
                "        );",
                f"        assert(success_{transaction.index} == "
                f"{'true' if transaction.expected_success else 'false'});",
            ]
        )
    for observation in manifest.observations:
        name = _identifier(observation.id)
        if observation.kind == "native_balance":
            actor = next(
                item for item in manifest.actors if item.id == observation.actor_id
            )
            expression = f"actor_slot_{actor.slot}.balance"
        else:
            calldata = _observation_calldata(
                observation.signature or "", observation.args
            )
            value = certificate.before_after.after.values[observation.id]
            helper = "_observeBool" if type(value) is bool else "_observeUint"
            expression = (
                f"{helper}(target_{_identifier(observation.target_id or '')}, "
                f"{calldata})"
            )
        solidity_type = (
            "bool"
            if type(certificate.before_after.after.values[observation.id]) is bool
            else "uint256"
        )
        lines.append(f"        {solidity_type} final_{name} = {expression};")
        lines.append(
            f"        assert(final_{name} == "
            f"{_solidity_literal(certificate.before_after.after.values[observation.id])});"
        )

    lines.append(f"        assert(!({invariant_expression}));")
    if certificate.confirmation_policy == "invariant_and_economic_impact":
        if manifest.impact is None:
            raise ReplayError("economic manifest omitted impact accounting")
        attacker = _identifier(manifest.impact.attacker_asset_observation)
        protocol = _identifier(manifest.impact.protocol_asset_observation)
        assert certificate.impact.attacker_delta is not None
        assert certificate.impact.protocol_delta is not None
        lines.extend(
            [
                f"        assert(final_{attacker} >= initial_{attacker});",
                f"        assert(final_{attacker} - initial_{attacker} == "
                f"{certificate.impact.attacker_delta});",
                f"        assert(initial_{protocol} >= final_{protocol});",
                f"        assert(initial_{protocol} - final_{protocol} == "
                f"{abs(certificate.impact.protocol_delta)});",
            ]
        )
    lines.extend(["    }", "}", ""])
    source = "\n".join(lines)
    forbidden = (
        "vm.store",
        "vm.load",
        "vm.etch",
        "ffi",
        "://",
        "createFork",
        "selectFork",
        "vm.label",
    )
    if any(item in source for item in forbidden):
        raise ReplayError("generated PoC contains prohibited capability")
    return source


def _observation_calldata(signature: str, args: tuple[object, ...]) -> str:
    types = _signature_types(signature)
    if len(types) != len(args):
        raise ReplayError("observation arguments do not match signature")
    rendered = [
        _solidity_literal(value, abi_type)
        for value, abi_type in zip(args, types, strict=True)
    ]
    suffix = "" if not rendered else ", " + ", ".join(rendered)
    return f'abi.encodeWithSignature("{signature}"{suffix})'


def _constructor_literal(
    value: object,
    abi_type: str,
    *,
    actors_by_id: Mapping[str, int],
    prior_deployments: set[str],
) -> str:
    if isinstance(value, Mapping):
        if abi_type != "address":
            raise ReplayError(
                "symbolic constructor references require address ABI type"
            )
        if set(value) == {"actor"} and isinstance(value["actor"], str):
            actor_id = value["actor"]
            if actor_id not in actors_by_id:
                raise ReplayError("unknown actor constructor reference")
            return f"actor_slot_{actors_by_id[actor_id]}"
        if set(value) == {"deployment"} and isinstance(value["deployment"], str):
            deployment_id = value["deployment"]
            if deployment_id not in prior_deployments:
                raise ReplayError("constructor deployment reference is not prior")
            return f"target_{_identifier(deployment_id)}"
        raise ReplayError("invalid symbolic constructor reference")
    return _solidity_literal(value, abi_type)


def generate_foundry_poc(
    certificate: ProofCertificate,
    manifest: TargetManifest,
    output: Path,
    *,
    workspace_root: Path | None = None,
) -> Path:
    """Write the exact run-local PoC atomically after identity/hash checks."""

    source = foundry_poc_source(certificate, manifest, workspace_root=workspace_root)
    if _digest(source) != certificate.poc.sha256:
        raise ReplayError("generated PoC hash does not match certificate PoC hash")
    root = output if output.is_absolute() else Path.cwd() / output
    relative = Path(certificate.poc.path)
    if relative.is_absolute() or ".." in relative.parts:
        raise ReplayError("PoC output escapes the run directory")
    destination = root / relative
    try:
        return safe_atomic_write(destination, source)
    except SafeOutputError as error:
        raise ReplayError("unsafe PoC output path") from error


def _safe_environment(overrides: dict[str, str]) -> dict[str, str]:
    allowed = ("HOME", "PATH", "TMPDIR", "LANG", "LC_ALL", "TERM")
    environment = {key: os.environ[key] for key in allowed if key in os.environ}
    environment.update(overrides)
    environment["FOUNDRY_OFFLINE"] = "true"
    return environment


def _run_owned(
    command: Sequence[str], *, cwd: Path, env: Mapping[str, str]
) -> subprocess.CompletedProcess[str]:
    runtime = current_runtime()
    if runtime is not None:
        return runtime.run(command, cwd=cwd, env=env)
    return subprocess.run(
        command,
        cwd=cwd,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )


def _tree_digest(entries: Mapping[str, bytes]) -> str:
    digest = hashlib.sha256()
    for name in sorted(entries):
        encoded_name = name.encode()
        content = entries[name]
        digest.update(len(encoded_name).to_bytes(8, "big"))
        digest.update(encoded_name)
        digest.update(len(content).to_bytes(8, "big"))
        digest.update(content)
    return digest.hexdigest()


def _staging_entries(
    certificate: ProofCertificate,
    manifest: TargetManifest,
    poc_bytes: bytes,
) -> dict[str, bytes]:
    project = manifest.target.project_root.resolve()
    config = project / "foundry.toml"
    if config.is_symlink() or not config.is_file():
        raise ReplayError("Foundry config must be one local regular file")
    entries = {"foundry.toml": config.read_bytes()}
    for source in certificate.target.sources:
        path = _resolve_workspace_path(project, source.path, "source path")
        if path.is_symlink() or not path.is_file():
            raise ReplayError("source closure entry must be one local regular file")
        content = path.read_bytes()
        if _digest(content) != source.sha256:
            raise ReplayError("source closure hash mismatch")
        entries[source.path] = content
    staged_poc = "test/QProverReplay.t.sol"
    if staged_poc in entries:
        raise ReplayError("PoC staging path collides with source closure")
    entries[staged_poc] = poc_bytes
    return entries


def build_replay_recipe(
    certificate: ProofCertificate,
    manifest: TargetManifest,
    poc_bytes: bytes,
) -> ReplayRecipe:
    """Derive the portable private-staging recipe from validated evidence."""

    if _digest(poc_bytes) != certificate.poc.sha256:
        raise ReplayError("PoC hash mismatch")
    entries = _staging_entries(certificate, manifest, poc_bytes)
    return ReplayRecipe(
        workspace_cwd=".",
        source_project=certificate.target.project_root,
        source_poc=certificate.poc.path,
        foundry_config="foundry.toml",
        foundry_config_sha256=_digest(entries["foundry.toml"]),
        source_sha256=certificate.target.source_sha256,
        poc_sha256=certificate.poc.sha256,
        staged_project="{private_project}",
        execution_cwd="{private_project}",
        staged_poc="test/QProverReplay.t.sol",
        materialization=REPLAY_MATERIALIZATION,
        argv_template=REPLAY_ARGV_TEMPLATE,
        staging_tree_sha256=_tree_digest(entries),
    )


def _staged_file_entries(project: Path) -> dict[str, bytes]:
    entries: dict[str, bytes] = {}
    for path in sorted(item for item in project.rglob("*") if item.is_file()):
        if path.is_symlink():
            raise ReplayError("private staging contains a symlink")
        entries[path.relative_to(project).as_posix()] = path.read_bytes()
    return entries


def _verify_private_staging(
    materialization: ReplayMaterialization, recipe: ReplayRecipe
) -> None:
    if _tree_digest(_staged_file_entries(materialization.project)) != (
        recipe.staging_tree_sha256
    ):
        raise ReplayError("private replay staging hash mismatch")


def _freeze_private_staging(project: Path) -> None:
    for path in sorted(project.rglob("*"), reverse=True):
        if path.is_file():
            path.chmod(stat.S_IRUSR)
        elif path.is_dir():
            path.chmod(stat.S_IRUSR | stat.S_IXUSR)
    project.chmod(stat.S_IRUSR | stat.S_IXUSR)


def materialize_replay_recipe(
    certificate: ProofCertificate,
    manifest: TargetManifest,
    recipe: ReplayRecipe,
    poc_bytes: bytes,
    destination: Path,
) -> ReplayMaterialization:
    """Materialize one recipe in a caller-owned, new private directory."""

    expected = build_replay_recipe(certificate, manifest, poc_bytes)
    if recipe != expected:
        raise ReplayError("persisted replay recipe does not match local evidence")
    if destination.is_symlink():
        raise ReplayError("private replay destination must not be a symlink")
    root = destination.resolve()
    if not root.is_dir() or any(root.iterdir()):
        raise ReplayError("private replay destination must be new and empty")
    root.chmod(stat.S_IRWXU)
    project = root / "project"
    project.mkdir(mode=0o700)
    try:
        for relative, content in _staging_entries(
            certificate, manifest, poc_bytes
        ).items():
            target = project / relative
            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            with target.open("xb") as handle:
                handle.write(content)
                handle.flush()
                os.fsync(handle.fileno())
        staging_hash = _tree_digest(_staged_file_entries(project))
        if staging_hash != recipe.staging_tree_sha256:
            raise ReplayError("private replay materialization hash mismatch")
        argv = tuple(
            item.format(
                private_project=str(project),
                private_out=str(root / "out"),
                private_cache=str(root / "cache"),
            )
            for item in recipe.argv_template
        )
        materialization = ReplayMaterialization(root, project, argv, staging_hash)
        _freeze_private_staging(project)
        _verify_private_staging(materialization, recipe)
        return materialization
    except BaseException:
        _clean_directory(root)
        raise


def _normalize_structured_json(value: object) -> object:
    """Remove only Forge timing/gas noise while retaining result semantics."""

    if isinstance(value, dict):
        return {
            key: _normalize_structured_json(item)
            for key, item in value.items()
            if key not in {"duration", "gas", "gas_snapshots"}
        }
    if isinstance(value, list):
        return [_normalize_structured_json(item) for item in value]
    return value


def _strict_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if not isinstance(key, str) or key in result:
            raise ValueError("structured replay JSON contains an ambiguous object")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"structured replay JSON contains non-standard value {value}")


def parse_structured_replay_output(
    stdout: str, exit_code: int
) -> StructuredReplayResult:
    """Require exactly one named suite/test with an explicit Success status."""

    try:
        parsed = json.loads(
            stdout,
            object_pairs_hook=_strict_json_object,
            parse_constant=_reject_json_constant,
        )
    except (TypeError, ValueError):
        normalized = {"malformed_stdout_sha256": _digest(stdout)}
        return StructuredReplayResult(
            False,
            _digest(json.dumps(normalized, sort_keys=True, separators=(",", ":"))),
            0,
            0,
            None,
            None,
            None,
            True,
        )
    normalized = _normalize_structured_json(parsed)
    normalized_hash = _digest(
        json.dumps(normalized, sort_keys=True, separators=(",", ":"))
    )
    if not isinstance(parsed, dict):
        return StructuredReplayResult(
            False, normalized_hash, 0, 0, None, None, None, True
        )
    suite_count = len(parsed)
    suite = next(iter(parsed)) if suite_count == 1 else None
    suite_record = parsed.get(suite) if suite is not None else None
    tests = suite_record.get("test_results") if isinstance(suite_record, dict) else None
    test_count = len(tests) if isinstance(tests, dict) else 0
    test = next(iter(tests)) if test_count == 1 else None
    test_record = tests.get(test) if isinstance(tests, dict) and test else None
    status = test_record.get("status") if isinstance(test_record, dict) else None
    success = (
        exit_code == 0
        and suite_count == 1
        and suite == "test/QProverReplay.t.sol:QProverReplayTest"
        and test_count == 1
        and test == "test_qprover_replay()"
        and status == "Success"
        and test_record.get("reason") is None
        and test_record.get("counterexample") is None
    )
    return StructuredReplayResult(
        success,
        normalized_hash,
        suite_count,
        test_count,
        suite,
        test,
        status if isinstance(status, str) else None,
        False,
    )


def _clean_directory(path: Path) -> None:
    if path.exists():
        for item in sorted(path.rglob("*"), reverse=True):
            with suppress(OSError):
                if item.is_symlink():
                    continue
                if item.is_dir():
                    item.chmod(stat.S_IRWXU)
                else:
                    item.chmod(stat.S_IRUSR | stat.S_IWUSR)
        with suppress(OSError):
            path.chmod(stat.S_IRWXU)
    try:
        shutil.rmtree(path)
    except FileNotFoundError:
        return
    except OSError as error:
        raise ReplayError(f"could not clean replay directory: {path}") from error
    if path.exists():
        raise ReplayError(f"replay directory remains after cleanup: {path}")


def _owned_temporary_directory(prefix: str) -> tuple[Path, int | None]:
    runtime = current_runtime()
    if runtime is None:
        return Path(tempfile.mkdtemp(prefix=prefix)), None
    target = Path(tempfile.gettempdir()) / f"{prefix}{secrets.token_hex(16)}"
    return runtime.own_path(
        target,
        lambda path: (path.mkdir(mode=0o700), path)[1],
        _clean_directory,
    )


def _release_temporary_directory(path: Path, cleanup_token: int | None) -> None:
    runtime = current_runtime()
    if runtime is not None and cleanup_token is not None:
        runtime.release(cleanup_token)
        return
    _clean_directory(path)


def _hash_compiler_sources(sources: dict[str, Any]) -> str:
    digest = hashlib.sha256()
    for name in sorted(sources):
        content = sources[name].get("content")
        if not isinstance(content, str):
            raise ReplayError("offline build source evidence is malformed")
        encoded_name, encoded_content = name.encode(), content.encode()
        digest.update(len(encoded_name).to_bytes(8, "big"))
        digest.update(encoded_name)
        digest.update(len(encoded_content).to_bytes(8, "big"))
        digest.update(encoded_content)
    return digest.hexdigest()


def _offline_preflight(certificate: ProofCertificate, manifest: TargetManifest) -> None:
    temporary, cleanup_token = _owned_temporary_directory("qprover-replay-preflight-")
    out = temporary / "out"
    cache = temporary / "cache"
    sources = tuple(
        sorted(
            path.resolve()
            .relative_to(manifest.target.project_root.resolve())
            .as_posix()
            for path in manifest.target.source_files
        )
    )
    command = (
        "forge",
        "build",
        *sources,
        "--build-info",
        "--extra-output",
        "storageLayout",
        "--offline",
    )
    try:
        result = _run_owned(
            command,
            cwd=manifest.target.project_root,
            env=_safe_environment(
                {"FOUNDRY_OUT": str(out), "FOUNDRY_CACHE_PATH": str(cache)}
            ),
        )
        if result.returncode:
            raise ReplayError("offline compiler preflight failed")
        build_infos = tuple((out / "build-info").glob("*.json"))
        if len(build_infos) != 1:
            raise ReplayError("offline compiler emitted ambiguous build evidence")
        build_bytes = build_infos[0].read_bytes()
        build_info = json.loads(build_bytes)
        semantic_build_hash = canonical_build_info_hash(build_info)
        if semantic_build_hash != certificate.build.build_info_sha256:
            raise ReplayError("build-info hash mismatch")
        build_info_id = semantic_build_hash[:16]
        if any(item.build_info_id != build_info_id for item in certificate.artifacts):
            raise ReplayError("build-info identity mismatch")
        if build_info.get("solcVersion") != certificate.toolchain.compiler_version:
            raise ReplayError("compiler version mismatch")
        input_evm = build_info.get("input", {}).get("settings", {}).get("evmVersion")
        if input_evm != certificate.toolchain.evm_version:
            raise ReplayError("EVM version mismatch")
        input_sources = build_info.get("input", {}).get("sources")
        if not isinstance(input_sources, dict):
            raise ReplayError("offline compiler omitted source evidence")
        if _hash_compiler_sources(input_sources) != certificate.target.source_sha256:
            raise ReplayError("source aggregate hash mismatch")
        expected_sources = {
            item.path: item.sha256 for item in certificate.target.sources
        }
        actual_sources = {
            name: _digest(record["content"])
            for name, record in input_sources.items()
            if isinstance(record, dict) and isinstance(record.get("content"), str)
        }
        if actual_sources != expected_sources:
            raise ReplayError("source closure hash mismatch")
        for expected in certificate.artifacts:
            source_name, contract_name = expected.compilation_target.rsplit(":", 1)
            candidates = tuple(out.rglob(f"{contract_name}.json"))
            matches = []
            for path in candidates:
                raw_bytes = path.read_bytes()
                raw = json.loads(raw_bytes)
                target = (
                    raw.get("metadata", {}).get("settings", {}).get("compilationTarget")
                )
                if target == {source_name: contract_name}:
                    matches.append((path, raw, raw_bytes))
            if len(matches) != 1:
                raise ReplayError("artifact identity is ambiguous")
            artifact_path, raw, raw_bytes = matches[0]
            actual_descriptor = artifact_path.relative_to(temporary).as_posix()
            if expected.artifact_path != actual_descriptor:
                raise ReplayError("artifact path mismatch")
            bytecode = raw.get("bytecode", {}).get("object")
            if (
                _digest(raw_bytes) != expected.artifact_sha256
                or not isinstance(bytecode, str)
                or _digest(bytecode) != expected.bytecode_sha256
            ):
                raise ReplayError("artifact hash mismatch")
        version = _run_owned(
            ("forge", "--version"),
            cwd=manifest.target.project_root,
            env=_safe_environment({}),
        )
        reported = version.stdout.strip().splitlines()
        if (
            version.returncode != 0
            or not reported
            or reported[0] != certificate.toolchain.forge_version
        ):
            raise ReplayError("Foundry version mismatch")
    except (OSError, json.JSONDecodeError) as error:
        raise ReplayError("offline compiler preflight could not run") from error
    finally:
        _release_temporary_directory(temporary, cleanup_token)


def _load_validated_certificate(path: Path) -> ProofCertificate:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
        schema_path = Path(__file__).parents[2] / "schemas/certificate.schema.json"
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        jsonschema.Draft202012Validator(schema).validate(raw)
        return ProofCertificate.model_validate(raw)
    except (
        OSError,
        json.JSONDecodeError,
        jsonschema.ValidationError,
        ValueError,
    ) as error:
        raise ReplayError("certificate or schema validation failed") from error


def _execution_trace_hash(record: Mapping[str, object]) -> str:
    payload = json.dumps(
        {
            "trace_struct_log_count": record["trace_struct_log_count"],
            "call_trace_count": record["call_trace_count"],
            "trace_failed": record["trace_failed"],
            "return_data": record["return_data"],
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return _digest(payload)


def _artifact_constructor_types(abi: tuple[Mapping[str, Any], ...]) -> tuple[str, ...]:
    constructors = tuple(entry for entry in abi if entry.get("type") == "constructor")
    if len(constructors) > 1:
        raise ReplayError("artifact contains ambiguous constructor ABI")
    if not constructors:
        return ()
    return tuple(
        collapse_if_tuple(dict(parameter))
        for parameter in constructors[0].get("inputs", ())
    )


def _verify_execution_binding(
    certificate: ProofCertificate, manifest: TargetManifest
) -> None:
    """Re-execute the minimized candidate and compare replay-provable evidence."""

    candidate = Candidate(
        tuple(
            ActionStep(
                item.action_id,
                item.target_id,
                item.signature,
                item.sender_slot,
                item.args,
                item.value_wei,
            )
            for item in certificate.transactions
        )
    )
    try:
        with build_target(manifest, offline=True) as bundle, LocalAnvil() as anvil:
            if (
                bundle.manifest_sha256 != certificate.target.manifest_sha256
                or bundle.source_sha256 != certificate.target.source_sha256
                or bundle.build_info_sha256 != certificate.build.build_info_sha256
                or bundle.compiler_version != certificate.toolchain.compiler_version
                or bundle.evm_version != certificate.toolchain.evm_version
                or bundle.tool_version != certificate.toolchain.forge_version
            ):
                raise ReplayError("executed build evidence mismatch")
            expected_sources = tuple(
                (item.path, item.sha256) for item in certificate.target.sources
            )
            actual_sources = tuple(
                (item.source_name, item.source_sha256) for item in bundle.source_units
            )
            if actual_sources != expected_sources:
                raise ReplayError("executed source evidence mismatch")
            expected_artifacts = {
                item.compilation_target: item for item in certificate.artifacts
            }
            actual_artifacts = {
                item.compilation_target: item for item in bundle.artifacts
            }
            if set(expected_artifacts) != set(actual_artifacts):
                raise ReplayError("executed artifact evidence mismatch")
            for target, expected in expected_artifacts.items():
                actual = actual_artifacts[target]
                descriptor = (
                    actual.artifact_path.resolve()
                    .relative_to(bundle.evidence_root.resolve())
                    .as_posix()
                )
                if (
                    expected.artifact_path != descriptor
                    or expected.artifact_sha256 != actual.artifact_sha256
                    or expected.bytecode_sha256 != actual.bytecode_sha256
                    or expected.build_info_id != actual.build_info_id
                    or expected.build_info_sha256 != bundle.build_info_sha256
                    or expected.constructor_types
                    != _artifact_constructor_types(actual.abi)
                ):
                    raise ReplayError("executed artifact evidence mismatch")

            evaluator = ScenarioEvaluator(manifest, bundle, anvil)
            actual_funding = tuple(
                (
                    actor.id,
                    actor.slot,
                    evaluator.actors[actor.slot].lower(),
                    actor.balance_wei,
                )
                for actor in manifest.actors
            )
            recorded_funding = tuple(
                (item.actor_id, item.slot, item.address, item.balance_wei)
                for item in certificate.funding
            )
            if actual_funding != recorded_funding:
                raise ReplayError("actor address evidence mismatch")
            chain = certificate.chain
            if (
                chain.chain_id != anvil.chain_id
                or chain.genesis_timestamp != anvil.genesis_timestamp
                or chain.base_fee_wei != anvil.base_fee_wei
                or chain.gas_price_wei != anvil.gas_price_wei
                or chain.external_rpc
            ):
                raise ReplayError("executed chain evidence mismatch")

            evaluation = evaluator.evaluate(candidate)
            metadata = evaluation.metadata
            if (
                evaluation.outcome is not Outcome.VIOLATION
                or evaluation.outcome is not certificate.final_evaluation_outcome
                or evaluation.state_fingerprint
                != certificate.before_after.after.state_sha256
                or dict(metadata.get("initial_observations", {}))
                != dict(certificate.initial_state.values)
                or dict(metadata.get("current_observations", {}))
                != dict(certificate.before_after.after.values)
            ):
                raise ReplayError("executed state evidence mismatch")
            impact = metadata.get("impact")
            if not isinstance(impact, Mapping) or (
                impact.get("attacker_delta") != certificate.impact.attacker_delta
                or impact.get("protocol_delta") != certificate.impact.protocol_delta
                or impact.get("unit") != certificate.impact.unit
                or impact.get("admissible") is not certificate.impact.admissible
            ):
                raise ReplayError("executed impact evidence mismatch")
            invariants = metadata.get("invariants")
            if not isinstance(invariants, Sequence) or isinstance(
                invariants, (str, bytes)
            ):
                raise ReplayError("executed invariant evidence mismatch")
            baseline_invariants = metadata.get("baseline_invariants")
            expected_baseline = tuple(
                {
                    "invariant_id": item.id,
                    "expression": item.expression,
                    "status": "evaluated",
                    "value": True,
                    "reason": None,
                }
                for item in manifest.invariants
            )
            actual_baseline = tuple(
                dict(item)
                for item in baseline_invariants or ()
                if isinstance(item, Mapping)
            )
            qualification = metadata.get("qualification")
            if (
                actual_baseline != expected_baseline
                or not isinstance(qualification, Mapping)
                or qualification.get("qualified") is not True
                or qualification.get("policy") != certificate.confirmation_policy
                or qualification.get("invariant_id") != certificate.invariant.id
            ):
                raise ReplayError("executed qualification evidence mismatch")
            matches = tuple(
                item
                for item in invariants
                if isinstance(item, Mapping)
                and item.get("invariant_id") == certificate.invariant.id
            )
            if len(matches) != 1 or (
                matches[0].get("expression") != certificate.invariant.expression
                or matches[0].get("value") is not certificate.invariant.value
                or matches[0].get("reason") != certificate.invariant.reason
            ):
                raise ReplayError("executed invariant evidence mismatch")
            step_records = metadata.get("steps")
            if (
                not isinstance(step_records, Sequence)
                or isinstance(step_records, (str, bytes))
                or len(step_records) != len(certificate.transactions)
            ):
                raise ReplayError("executed transaction evidence mismatch")
            actual_gas: list[int] = []
            for expected, actual in zip(
                certificate.transactions, step_records, strict=True
            ):
                if not isinstance(actual, Mapping):
                    raise ReplayError("executed transaction evidence mismatch")
                transaction_hash = actual.get("transaction_hash")
                normalized_hash = (
                    transaction_hash[2:]
                    if isinstance(transaction_hash, str)
                    and transaction_hash.startswith("0x")
                    else transaction_hash
                )
                gas_used = actual.get("gas_used")
                actual_gas.append(gas_used if type(gas_used) is int else -1)
                if (
                    actual.get("index") != expected.index
                    or actual.get("action_id") != expected.action_id
                    or actual.get("calldata_hash") != expected.calldata_sha256
                    or normalized_hash != expected.transaction_sha256
                    or actual.get("receipt_status") != expected.receipt_status
                    or (actual.get("receipt_status") == 1) != expected.expected_success
                    or gas_used != expected.gas_used
                    or actual.get("return_data") != expected.return_data
                    or actual.get("revert_data") != expected.revert_data
                    or actual.get("observation_state_hash")
                    != expected.observation_state_sha256
                    or _execution_trace_hash(actual) != expected.trace_sha256
                ):
                    raise ReplayError("executed transaction evidence mismatch")
            if tuple(actual_gas) != certificate.gas.per_transaction:
                raise ReplayError("executed gas evidence mismatch")

            if (
                not certificate.minimization.locally_minimal
                or "single-delete-fixed-point"
                not in certificate.minimization.attempted_operators
            ):
                raise ReplayError("executed local minimality evidence mismatch")
            if len(candidate.steps) > 1:
                for index in range(len(candidate.steps)):
                    reduced = Candidate(
                        candidate.steps[:index] + candidate.steps[index + 1 :]
                    )
                    reduced_evaluation = evaluator.evaluate(reduced)
                    reduced_impact = reduced_evaluation.metadata.get("impact")
                    reduced_qualification = reduced_evaluation.metadata.get(
                        "qualification"
                    )
                    reduced_satisfies = (
                        reduced_evaluation.outcome is Outcome.VIOLATION
                        and isinstance(reduced_qualification, Mapping)
                        and reduced_qualification.get("qualified") is True
                        and reduced_qualification.get("policy")
                        == certificate.confirmation_policy
                        and reduced_qualification.get("invariant_id")
                        == certificate.invariant.id
                    )
                    if (
                        certificate.confirmation_policy
                        == "invariant_and_economic_impact"
                    ):
                        reduced_satisfies = (
                            reduced_satisfies
                            and isinstance(reduced_impact, Mapping)
                            and reduced_impact.get("admissible") is True
                        )
                    if reduced_satisfies:
                        raise ReplayError("executed local minimality evidence mismatch")
    except ReplayError:
        raise
    except (OSError, RuntimeError, TypeError, ValueError) as error:
        raise ReplayError("local semantic re-execution failed") from error


def cold_verify(
    certificate_path: Path,
    repeats: int = 3,
    *,
    workspace_root: Path | None = None,
) -> ReplayVerification:
    """Run exactly three isolated offline Forge replays and update the certificate."""

    if type(repeats) is not int or repeats != 3:
        raise ReplayError("cold verification requires exactly 3 replays")
    path = certificate_path.resolve()
    certificate = _load_validated_certificate(path)
    trusted_workspace = (workspace_root or Path.cwd()).resolve()
    if not trusted_workspace.is_dir():
        raise ReplayError("trusted local workspace is missing")
    manifest_path = _resolve_workspace_path(
        trusted_workspace, certificate.target.manifest_path, "manifest path"
    )
    manifest = load_manifest(manifest_path)
    validate_semantic_binding(
        certificate,
        manifest,
        workspace_root=trusted_workspace,
        manifest_path=manifest_path,
    )
    _offline_preflight(certificate, manifest)
    _verify_execution_binding(certificate, manifest)
    poc_path = (path.parent / certificate.poc.path).resolve()
    try:
        poc_path.relative_to(path.parent)
    except ValueError as error:
        raise ReplayError("PoC path is not run-local") from error
    try:
        poc_bytes = poc_path.read_bytes()
    except OSError as error:
        raise ReplayError("PoC is missing") from error
    if _digest(poc_bytes) != certificate.poc.sha256:
        raise ReplayError("PoC hash mismatch")
    expected_source = foundry_poc_source(
        certificate, manifest, workspace_root=trusted_workspace
    ).encode()
    if poc_bytes != expected_source:
        raise ReplayError("PoC content does not match certificate evidence")
    project = manifest.target.project_root.resolve()
    test_directory = project / "test"
    if test_directory.is_symlink():
        raise ReplayError("project test directory must not be a symlink")
    recipe = build_replay_recipe(certificate, manifest, poc_bytes)
    records: list[ReplayRecord] = []
    for index in range(1, 4):
        run_root, cleanup_token = _owned_temporary_directory(f"qprover-cold-{index}-")
        try:
            materialization = materialize_replay_recipe(
                certificate, manifest, recipe, poc_bytes, run_root
            )
            _verify_private_staging(materialization, recipe)
            started = time.monotonic()
            try:
                result = _run_owned(
                    materialization.argv,
                    cwd=materialization.project,
                    env=_safe_environment({}),
                )
                exit_code = result.returncode
                stdout = result.stdout
                stderr = result.stderr
            except OSError as error:
                exit_code = -1
                stdout = ""
                stderr = type(error).__name__
            duration = float(time.monotonic() - started)
            try:
                _verify_private_staging(materialization, recipe)
                staging_unchanged = True
            except ReplayError:
                staging_unchanged = False
            structured = parse_structured_replay_output(stdout, exit_code)
            records.append(
                ReplayRecord(
                    index=index,
                    success=structured.success and staging_unchanged,
                    exit_code=exit_code,
                    stdout_sha256=structured.normalized_sha256,
                    stderr_sha256=_stable_output_digest(stderr),
                    structured_result_sha256=structured.normalized_sha256,
                    duration_seconds=duration,
                    recipe_sha256=recipe.compute_hash(),
                    execution_argv_sha256=_digest(
                        json.dumps(materialization.argv, separators=(",", ":"))
                    ),
                    execution_cwd_sha256=_digest(str(materialization.project)),
                    staging_tree_sha256=materialization.staging_tree_sha256,
                    staging_unchanged=staging_unchanged,
                    suite_count=structured.suite_count,
                    test_count=structured.test_count,
                    executed_suite=structured.executed_suite,
                    executed_test=structured.executed_test,
                    executed_status=structured.executed_status,
                    certificate_identity_sha256=(
                        certificate.certificate_identity_sha256
                    ),
                    poc_sha256=certificate.poc.sha256,
                    manifest_sha256=certificate.target.manifest_sha256,
                    source_sha256=certificate.target.source_sha256,
                    artifact_sha256=certificate.poc.artifact_sha256,
                )
            )
        finally:
            _release_temporary_directory(run_root, cleanup_token)

    updated = _seal_certificate(certificate, recipe, tuple(records))
    write_certificate(updated, path)
    return ReplayVerification(updated.confirmation_status, tuple(records), updated)


__all__ = [
    "ReplayError",
    "ReplayMaterialization",
    "ReplayVerification",
    "StructuredReplayResult",
    "build_replay_recipe",
    "cold_verify",
    "foundry_poc_source",
    "generate_foundry_poc",
    "materialize_replay_recipe",
    "parse_structured_replay_output",
    "validate_semantic_binding",
]
