"""Self-contained local Foundry PoC generation and cold verification."""

from __future__ import annotations

import ast
import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import jsonschema
from eth_abi import encode
from eth_abi.exceptions import EncodingError
from eth_utils import keccak

from qprover.certificate import (
    ProofCertificate,
    ReplayEvidence,
    ReplayRecord,
    create_certificate,
    write_certificate,
)
from qprover.manifest import load_manifest
from qprover.models import ConfirmationStatus, TargetManifest


class ReplayError(RuntimeError):
    """Replay inputs cannot establish exact local evidence."""


@dataclass(frozen=True, slots=True)
class ReplayVerification:
    confirmation_status: ConfirmationStatus
    records: tuple[ReplayRecord, ...]
    certificate: ProofCertificate


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
    return _digest(
        json.dumps(
            manifest.model_dump(mode="json"),
            sort_keys=True,
            separators=(",", ":"),
        )
    )


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


def _render_invariant(expression: str, observations: set[str]) -> str:
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
                return f"final_{node.id}"
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
    certificate: ProofCertificate, manifest: TargetManifest
) -> None:
    if (
        certificate.target.id != manifest.target.id
        or certificate.target.project_root.resolve()
        != manifest.target.project_root.resolve()
        or certificate.target.manifest_sha256 != _manifest_hash(manifest)
    ):
        raise ReplayError("certificate and manifest identity mismatch")
    sources = {item.path: item.sha256 for item in certificate.target.sources}
    for source in manifest.target.source_files:
        relative = source.resolve().relative_to(manifest.target.project_root.resolve())
        if relative.as_posix() not in sources:
            raise ReplayError("certificate source identity is incomplete")


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


def foundry_poc_source(certificate: ProofCertificate, manifest: TargetManifest) -> str:
    """Render one deterministic, network-free Solidity regression test."""

    certificate = ProofCertificate.model_validate(certificate.model_dump(mode="json"))
    _validate_manifest_identity(certificate, manifest)
    _validate_transactions(certificate, manifest)
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
    lines = [
        "// SPDX-License-Identifier: Apache-2.0",
        f"pragma solidity {manifest.target.solidity_version};",
        "",
        *sorted(set(imports)),
        "",
        "interface QProverVm {",
        "    function deal(address account, uint256 newBalance) external;",
        "}",
        "",
        "contract QProverActor {",
        "    receive() external payable {}",
        "",
        "    function invoke(address target, bytes memory data, uint256 value)",
        "        external returns (bool success, bytes memory result)",
        "    {",
        "        (success, result) = target.call{value: value}(data);",
        "    }",
        "",
        "    function deploy(bytes memory code, uint256 value)",
        "        external returns (address deployed)",
        "    {",
        "        assembly { deployed := create(value, add(code, 0x20), mload(code)) }",
        '        require(deployed != address(0), "deployment");',
        "    }",
        "}",
        "",
        "contract QProverReplayTest {",
        "    QProverVm private constant vm = QProverVm(",
        '        address(uint160(uint256(keccak256("hevm cheat code"))))',
        "    );",
    ]
    for slot in sorted(actors):
        lines.append(f"    QProverActor private actor_slot_{slot};")
    for deployment in manifest.deployments:
        lines.append(f"    address private target_{_identifier(deployment.id)};")
    lines.extend(
        [
            "",
            "    function _observeUint(address target, string memory signature)",
            "        private view returns (uint256 value)",
            "    {",
            "        (bool ok, bytes memory result) = target.staticcall(",
            "            abi.encodeWithSignature(signature)",
            "        );",
            '        require(ok && result.length == 32, "observation");',
            "        value = abi.decode(result, (uint256));",
            "    }",
            "",
            "    function test_qprover_replay() public {",
        ]
    )
    for slot, actor in sorted(actors.items()):
        lines.extend(
            [
                f"        actor_slot_{slot} = new QProverActor();",
                f"        vm.deal(address(actor_slot_{slot}), {actor.balance_wei});",
            ]
        )
    for deployment in manifest.deployments:
        contract_name = contract_names[deployment.id]
        constructor_args = tuple(deployment.constructor_args)
        if constructor_args:
            encoded = ", ".join(
                _constructor_literal(value) for value in constructor_args
            )
            code = (
                f"abi.encodePacked(type({contract_name}).creationCode, "
                f"abi.encode({encoded}))"
            )
        else:
            code = f"type({contract_name}).creationCode"
        lines.append(
            f"        target_{_identifier(deployment.id)} = "
            f"actor_slot_{deployment.sender_slot}.deploy({code}, "
            f"{deployment.value_wei});"
        )
    for observation in manifest.observations:
        name = _identifier(observation.id)
        if observation.kind == "native_balance":
            actor = next(
                item for item in manifest.actors if item.id == observation.actor_id
            )
            expression = f"address(actor_slot_{actor.slot}).balance"
        else:
            if observation.args:
                raise ReplayError(
                    "PoC call observations with arguments are unsupported"
                )
            expression = (
                f"_observeUint(target_{_identifier(observation.target_id or '')}, "
                f'"{observation.signature}")'
            )
        lines.append(f"        uint256 initial_{name} = {expression};")

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
                f"        (bool success_{transaction.index},) = "
                f"actor_slot_{transaction.sender_slot}.invoke(",
                f"            target_{_identifier(transaction.target_id)},",
                f'            abi.encodeWithSignature("{transaction.signature}"'
                f"{argument_text}),",
                f"            {transaction.value_wei}",
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
            expression = f"address(actor_slot_{actor.slot}).balance"
        else:
            expression = (
                f"_observeUint(target_{_identifier(observation.target_id or '')}, "
                f'"{observation.signature}")'
            )
        lines.append(f"        uint256 final_{name} = {expression};")

    attacker = _identifier(manifest.impact.attacker_asset_observation)
    protocol = _identifier(manifest.impact.protocol_asset_observation)
    lines.extend(
        [
            f"        assert(!({invariant_expression}));",
            f"        assert(final_{attacker} >= initial_{attacker});",
            f"        assert(final_{attacker} - initial_{attacker} == "
            f"{certificate.impact.attacker_delta});",
            f"        assert(initial_{protocol} >= final_{protocol});",
            f"        assert(initial_{protocol} - final_{protocol} == "
            f"{abs(certificate.impact.protocol_delta)});",
            "    }",
            "}",
            "",
        ]
    )
    source = "\n".join(lines)
    forbidden = (
        "vm.store",
        "vm.load",
        "vm.etch",
        "ffi",
        "://",
        "createFork",
        "selectFork",
        "vm.prank",
        "vm.label",
    )
    if any(item in source for item in forbidden):
        raise ReplayError("generated PoC contains prohibited capability")
    return source


def _constructor_literal(value: object) -> str:
    if isinstance(value, dict):
        raise ReplayError("mutable constructor references are prohibited")
    # Pydantic freezes constructor references behind MappingProxyType. Resolve
    # only the two manifest-declared symbolic forms at generation call sites.
    if hasattr(value, "keys"):
        keys = set(value.keys())  # type: ignore[union-attr]
        if keys == {"actor"}:
            raise ReplayError("actor constructor references require typed ABI data")
        if keys == {"deployment"}:
            raise ReplayError(
                "deployment constructor references require typed ABI data"
            )
    return _solidity_literal(value)


def generate_foundry_poc(
    certificate: ProofCertificate,
    manifest: TargetManifest,
    output: Path,
) -> Path:
    """Write the exact run-local PoC atomically after identity/hash checks."""

    source = foundry_poc_source(certificate, manifest)
    if _digest(source) != certificate.poc.sha256:
        raise ReplayError("generated PoC hash does not match certificate PoC hash")
    root = output.resolve()
    destination = (root / certificate.poc.path).resolve()
    try:
        destination.relative_to(root)
    except ValueError as error:
        raise ReplayError("PoC output escapes the run directory") from error
    destination.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{destination.name}.", suffix=".tmp", dir=destination.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(source)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, destination)
    finally:
        temporary.unlink(missing_ok=True)
    return destination


def _safe_environment(overrides: dict[str, str]) -> dict[str, str]:
    allowed = ("HOME", "PATH", "TMPDIR", "LANG", "LC_ALL", "TERM")
    environment = {key: os.environ[key] for key in allowed if key in os.environ}
    environment.update(overrides)
    environment["FOUNDRY_OFFLINE"] = "true"
    return environment


def _clean_directory(path: Path) -> None:
    try:
        shutil.rmtree(path)
    except FileNotFoundError:
        return
    except OSError as error:
        raise ReplayError(f"could not clean replay directory: {path}") from error
    if path.exists():
        raise ReplayError(f"replay directory remains after cleanup: {path}")


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
    temporary = Path(tempfile.mkdtemp(prefix="qprover-replay-preflight-"))
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
        result = subprocess.run(
            command,
            cwd=manifest.target.project_root,
            env=_safe_environment(
                {"FOUNDRY_OUT": str(out), "FOUNDRY_CACHE_PATH": str(cache)}
            ),
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode:
            raise ReplayError("offline compiler preflight failed")
        build_infos = tuple((out / "build-info").glob("*.json"))
        if len(build_infos) != 1:
            raise ReplayError("offline compiler emitted ambiguous build evidence")
        build_bytes = build_infos[0].read_bytes()
        build_info = json.loads(build_bytes)
        if _digest(build_bytes) != certificate.build.build_info_sha256:
            raise ReplayError("build-info hash mismatch")
        build_info_id = build_info.get("id")
        if not isinstance(build_info_id, str) or any(
            item.build_info_id != build_info_id for item in certificate.artifacts
        ):
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
                    matches.append((raw, raw_bytes))
            if len(matches) != 1:
                raise ReplayError("artifact identity is ambiguous")
            raw, raw_bytes = matches[0]
            bytecode = raw.get("bytecode", {}).get("object")
            if (
                _digest(raw_bytes) != expected.artifact_sha256
                or not isinstance(bytecode, str)
                or _digest(bytecode) != expected.bytecode_sha256
            ):
                raise ReplayError("artifact hash mismatch")
        version = subprocess.run(
            ("forge", "--version"),
            cwd=manifest.target.project_root,
            env=_safe_environment({}),
            capture_output=True,
            text=True,
            check=False,
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
        _clean_directory(temporary)


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


def cold_verify(certificate_path: Path, repeats: int = 3) -> ReplayVerification:
    """Run exactly three isolated offline Forge replays and update the certificate."""

    if type(repeats) is not int or repeats != 3:
        raise ReplayError("cold verification requires exactly 3 replays")
    path = certificate_path.resolve()
    certificate = _load_validated_certificate(path)
    trusted_workspace = Path(__file__).parents[2].resolve()
    if certificate.target.workspace_root.resolve() != trusted_workspace:
        raise ReplayError("certificate target is outside the trusted local workspace")
    manifest = load_manifest(certificate.target.manifest_path)
    _validate_manifest_identity(certificate, manifest)
    _validate_transactions(certificate, manifest)
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
    expected_source = foundry_poc_source(certificate, manifest).encode()
    if poc_bytes != expected_source:
        raise ReplayError("PoC content does not match certificate evidence")
    _offline_preflight(certificate, manifest)

    project = manifest.target.project_root.resolve()
    test_directory = project / "test"
    created_test_directory = not test_directory.exists()
    test_directory.mkdir(parents=True, exist_ok=True)
    temporary_test = test_directory / f".qprover_replay_{uuid.uuid4().hex}.t.sol"
    records: list[ReplayRecord] = []
    try:
        with temporary_test.open("xb") as handle:
            handle.write(poc_bytes)
        relative_test = temporary_test.relative_to(project).as_posix()
        for index in range(1, 4):
            run_root = Path(tempfile.mkdtemp(prefix=f"qprover-cold-{index}-"))
            command = (
                "forge",
                "test",
                "--offline",
                "--root",
                str(project),
                "--match-path",
                relative_test,
                "--match-test",
                "test_qprover_replay",
                "--out",
                str(run_root / "out"),
                "--cache-path",
                str(run_root / "cache"),
            )
            started = time.monotonic()
            try:
                result = subprocess.run(
                    command,
                    cwd=project,
                    env=_safe_environment({}),
                    capture_output=True,
                    text=True,
                    check=False,
                )
                exit_code = result.returncode
                stdout = result.stdout
                stderr = result.stderr
            except OSError as error:
                exit_code = -1
                stdout = ""
                stderr = type(error).__name__
            finally:
                duration = float(time.monotonic() - started)
                _clean_directory(run_root)
            records.append(
                ReplayRecord(
                    index=index,
                    success=exit_code == 0,
                    command=command,
                    exit_code=exit_code,
                    stdout_sha256=_stable_output_digest(stdout),
                    stderr_sha256=_stable_output_digest(stderr),
                    duration_seconds=duration,
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
        temporary_test.unlink(missing_ok=True)
        if created_test_directory:
            try:
                test_directory.rmdir()
            except OSError as error:
                raise ReplayError("could not clean temporary test directory") from error

    confirmed = all(record.success for record in records)
    data = certificate.model_dump(mode="python")
    for field in ("certificate_identity_sha256", "certificate_sha256"):
        data.pop(field)
    data["confirmation_status"] = (
        ConfirmationStatus.CONFIRMED if confirmed else ConfirmationStatus.NOT_CONFIRMED
    )
    data["replay"] = ReplayEvidence(
        local_only=True, required_repeats=3, records=tuple(records)
    )
    updated = create_certificate(**data)
    write_certificate(updated, path)
    return ReplayVerification(updated.confirmation_status, tuple(records), updated)


__all__ = [
    "ReplayError",
    "ReplayVerification",
    "cold_verify",
    "foundry_poc_source",
    "generate_foundry_poc",
]
