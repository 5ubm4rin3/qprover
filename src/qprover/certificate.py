"""Strict immutable proof-certificate records and safe artifact rendering."""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from types import MappingProxyType
from typing import Annotated, Any, Literal, Self

from pydantic import (
    Field,
    StrictBool,
    StrictFloat,
    StrictInt,
    StrictStr,
    ValidationInfo,
    field_serializer,
    field_validator,
    model_validator,
)

from qprover.models import ConfirmationStatus, Outcome, StrictModel
from qprover.search.base import freeze_json_mapping, thaw_json

Sha256 = Annotated[StrictStr, Field(pattern=r"^[0-9a-f]{64}$")]
NonNegativeInt = Annotated[StrictInt, Field(ge=0)]
PositiveInt = Annotated[StrictInt, Field(gt=0)]
_ZERO_HASH = "0" * 64


def _freeze_abi(value: object) -> object:
    if value is None or type(value) in (bool, int, str):
        return value
    if isinstance(value, (list, tuple)):
        return tuple(_freeze_abi(item) for item in value)
    raise TypeError("certificate ABI values must be immutable JSON scalars or arrays")


def _thaw(value: object) -> object:
    if isinstance(value, Mapping):
        return {key: _thaw(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_thaw(item) for item in value]
    return value


def _canonical(data: Mapping[str, object]) -> str:
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _digest(data: str | bytes) -> str:
    encoded = data.encode() if isinstance(data, str) else data
    return hashlib.sha256(encoded).hexdigest()


class SourceEvidence(StrictModel):
    path: StrictStr = Field(min_length=1)
    sha256: Sha256

    @field_validator("path")
    @classmethod
    def path_is_project_relative(cls, value: str) -> str:
        parsed = PurePosixPath(value)
        if "://" in value or parsed.is_absolute() or ".." in parsed.parts:
            raise ValueError("source path must be project-relative and local")
        return value


class TargetEvidence(StrictModel):
    id: StrictStr = Field(min_length=1)
    workspace_root: Path
    project_root: Path
    revision: StrictStr = Field(min_length=1)
    manifest_path: Path
    manifest_sha256: Sha256
    source_sha256: Sha256
    sources: tuple[SourceEvidence, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def paths_are_local(self) -> Self:
        workspace = self.workspace_root.resolve()
        for path, label in (
            (self.project_root, "project root"),
            (self.manifest_path, "manifest path"),
        ):
            try:
                path.resolve().relative_to(workspace)
            except ValueError as error:
                raise ValueError(
                    f"{label} must be inside the local workspace"
                ) from error
        return self


class ArtifactEvidence(StrictModel):
    compilation_target: StrictStr = Field(min_length=1)
    artifact_path: StrictStr = Field(min_length=1)
    artifact_sha256: Sha256
    bytecode_sha256: Sha256
    build_info_id: StrictStr = Field(min_length=1)
    build_info_sha256: Sha256


class BuildEvidence(StrictModel):
    command: tuple[StrictStr, ...] = Field(min_length=1)
    manifest_sha256: Sha256
    source_sha256: Sha256
    build_info_sha256: Sha256


class ToolchainEvidence(StrictModel):
    qprover_version: StrictStr = Field(min_length=1)
    forge_version: StrictStr = Field(min_length=1)
    compiler_version: StrictStr = Field(min_length=1)
    evm_version: StrictStr = Field(min_length=1)


class ChainEvidence(StrictModel):
    kind: Literal["local"]
    chain_id: PositiveInt
    genesis_timestamp: NonNegativeInt
    base_fee_wei: NonNegativeInt
    gas_price_wei: NonNegativeInt
    external_rpc: StrictBool


class FundingEvidence(StrictModel):
    actor_id: StrictStr = Field(min_length=1)
    slot: NonNegativeInt
    balance_wei: NonNegativeInt


class AssumptionEvidence(StrictModel):
    id: StrictStr = Field(min_length=1)
    description: StrictStr = Field(min_length=1)


class StateEvidence(StrictModel):
    values: Mapping[StrictStr, StrictInt | StrictBool]
    state_sha256: Sha256

    @field_validator("values", mode="after")
    @classmethod
    def freeze_values(cls, value: Mapping[str, int | bool]) -> Mapping[str, int | bool]:
        return MappingProxyType(dict(value))

    @model_validator(mode="after")
    def state_hash_matches_values(self) -> Self:
        expected = _digest(_canonical(dict(self.values)))
        if self.state_sha256 != expected:
            raise ValueError("state hash does not match observation values")
        return self

    @field_serializer("values")
    def serialize_values(
        self, value: Mapping[str, int | bool]
    ) -> dict[str, int | bool]:
        return dict(value)


class TransactionEvidence(StrictModel):
    index: PositiveInt
    action_id: StrictStr = Field(min_length=1)
    target_id: StrictStr = Field(min_length=1)
    signature: StrictStr = Field(min_length=1)
    sender_slot: NonNegativeInt
    args: tuple[Any, ...]
    value_wei: NonNegativeInt
    calldata_sha256: Sha256
    transaction_sha256: Sha256
    expected_success: StrictBool
    receipt_status: Annotated[StrictInt, Field(ge=0, le=1)]
    gas_used: NonNegativeInt
    return_data: StrictStr | None
    revert_data: StrictStr | None
    trace_sha256: Sha256
    observation_state_sha256: Sha256 | None

    @field_validator("args", mode="after")
    @classmethod
    def freeze_args(cls, value: tuple[Any, ...]) -> tuple[object, ...]:
        return tuple(_freeze_abi(item) for item in value)

    @field_serializer("args")
    def serialize_args(self, value: tuple[object, ...]) -> list[object]:
        return [_thaw(item) for item in value]

    @model_validator(mode="after")
    def status_matches_expectation(self) -> Self:
        if self.expected_success != (self.receipt_status == 1):
            raise ValueError("receipt status must match expected call success")
        if self.receipt_status == 1 and self.observation_state_sha256 is None:
            raise ValueError("successful transaction requires observation evidence")
        return self


class BeforeAfterEvidence(StrictModel):
    before: StateEvidence
    after: StateEvidence


class InvariantEvidence(StrictModel):
    id: StrictStr = Field(min_length=1)
    expression: StrictStr = Field(min_length=1)
    description: StrictStr = Field(min_length=1)
    foundry_assertion: StrictStr = Field(min_length=1)
    evaluated: StrictBool
    value: StrictBool | None
    reason: StrictStr | None


class ImpactEvidence(StrictModel):
    attacker_observation: StrictStr = Field(min_length=1)
    protocol_observation: StrictStr = Field(min_length=1)
    attacker_delta: StrictInt
    protocol_delta: StrictInt
    unit: StrictStr = Field(min_length=1)
    admissible: StrictBool
    executed: StrictBool


class GasEvidence(StrictModel):
    total_gas_used: NonNegativeInt
    per_transaction: tuple[NonNegativeInt, ...]

    @model_validator(mode="after")
    def total_matches(self) -> Self:
        if self.total_gas_used != sum(self.per_transaction):
            raise ValueError("total gas must equal transaction gas")
        return self


class MinimizationEvidence(StrictModel):
    original_steps: PositiveInt
    minimized_steps: PositiveInt
    evaluation_count: PositiveInt
    uncached_candidate_count: PositiveInt
    candidate_attempt_count: PositiveInt
    unique_candidate_count: PositiveInt
    cache_hits: NonNegativeInt
    transaction_count: NonNegativeInt
    attempted_operators: tuple[StrictStr, ...] = Field(min_length=1)
    locally_minimal: StrictBool
    minimality_claim: StrictStr = Field(min_length=1)
    final_outcome: Outcome

    @model_validator(mode="after")
    def validate_counts(self) -> Self:
        if self.minimized_steps > self.original_steps:
            raise ValueError("minimization cannot increase sequence length")
        if self.unique_candidate_count > self.candidate_attempt_count:
            raise ValueError("unique candidates cannot exceed attempts")
        if self.uncached_candidate_count != self.evaluation_count:
            raise ValueError("uncached candidate and evaluation counts must match")
        if "global" in self.minimality_claim.lower():
            raise ValueError("minimization evidence cannot claim a global minimum")
        return self


class PoCEvidence(StrictModel):
    path: StrictStr = Field(min_length=1)
    sha256: Sha256
    manifest_sha256: Sha256
    source_sha256: Sha256
    artifact_sha256: Sha256
    test_name: Literal["test_qprover_replay"]

    @field_validator("path")
    @classmethod
    def path_is_run_local(cls, value: str) -> str:
        if (
            "://" in value
            or PurePosixPath(value).is_absolute()
            or ".." in PurePosixPath(value).parts
        ):
            raise ValueError("PoC path must be a run-local relative path")
        return value


class ReplayRecord(StrictModel):
    index: PositiveInt
    success: StrictBool
    command: tuple[StrictStr, ...] = Field(min_length=1)
    exit_code: StrictInt
    stdout_sha256: Sha256
    stderr_sha256: Sha256
    duration_seconds: Annotated[StrictFloat, Field(ge=0)]
    certificate_identity_sha256: Sha256
    poc_sha256: Sha256
    manifest_sha256: Sha256
    source_sha256: Sha256
    artifact_sha256: Sha256

    @model_validator(mode="after")
    def command_is_local_offline_foundry(self) -> Self:
        if self.command[0] != "forge" or "--offline" not in self.command:
            raise ValueError("replay command must be offline Foundry")
        if any("://" in item or "--fork-url" in item for item in self.command):
            raise ValueError("replay command must not use a network or fork")
        return self


class ReplayEvidence(StrictModel):
    local_only: StrictBool
    required_repeats: Literal[3]
    records: tuple[ReplayRecord, ...]


class EvidenceEvent(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    run_id: StrictStr = Field(min_length=1)
    sequence: PositiveInt
    timestamp: datetime
    kind: Literal[
        "search", "minimization", "poc_generation", "cold_replay", "confirmation"
    ]
    details: Mapping[StrictStr, Any]

    @field_validator("timestamp")
    @classmethod
    def require_utc(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() != UTC.utcoffset(value):
            raise ValueError("event timestamp must be RFC3339 UTC")
        return value.astimezone(UTC)

    @field_serializer("timestamp")
    def serialize_time(self, value: datetime) -> str:
        return value.isoformat().replace("+00:00", "Z")

    @field_validator("details", mode="after")
    @classmethod
    def freeze_details(cls, value: Mapping[str, object]) -> Mapping[str, object]:
        return freeze_json_mapping(value)

    @field_serializer("details")
    def serialize_details(self, value: Mapping[str, object]) -> object:
        return thaw_json(value)


class ProofCertificate(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    run_id: StrictStr = Field(min_length=1)
    generated_at: datetime
    confirmation_status: ConfirmationStatus
    source_kind: Literal["executed", "static_lead"]
    final_evaluation_outcome: Outcome
    target: TargetEvidence
    artifacts: tuple[ArtifactEvidence, ...] = Field(min_length=1)
    build: BuildEvidence
    toolchain: ToolchainEvidence
    chain: ChainEvidence
    funding: tuple[FundingEvidence, ...] = Field(min_length=1)
    assumptions: tuple[AssumptionEvidence, ...] = Field(min_length=1)
    initial_state: StateEvidence
    transactions: tuple[TransactionEvidence, ...] = Field(min_length=1)
    before_after: BeforeAfterEvidence
    invariant: InvariantEvidence
    impact: ImpactEvidence
    gas: GasEvidence
    minimization: MinimizationEvidence
    poc: PoCEvidence
    replay_command: StrictStr = Field(min_length=1)
    replay: ReplayEvidence
    certificate_identity_sha256: Sha256
    certificate_sha256: Sha256

    @field_validator("generated_at")
    @classmethod
    def require_utc(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() != UTC.utcoffset(value):
            raise ValueError("certificate timestamp must be RFC3339 UTC")
        return value.astimezone(UTC)

    @field_serializer("generated_at")
    def serialize_time(self, value: datetime) -> str:
        return value.isoformat().replace("+00:00", "Z")

    def _hash_payload(self) -> dict[str, object]:
        payload = self.model_dump(mode="json")
        payload.pop("certificate_sha256", None)
        return payload

    def _identity_payload(self) -> dict[str, object]:
        payload = self._hash_payload()
        payload.pop("certificate_identity_sha256", None)
        payload.pop("confirmation_status", None)
        payload.pop("replay", None)
        return payload

    def compute_hash(self) -> str:
        return _digest(_canonical(self._hash_payload()))

    def compute_identity(self) -> str:
        return _digest(_canonical(self._identity_payload()))

    def canonical_json(self) -> str:
        return _canonical(self.model_dump(mode="json")) + "\n"

    @model_validator(mode="after")
    def validate_evidence(self, info: ValidationInfo) -> Self:
        allow_unsealed = bool(info.context and info.context.get("allow_unsealed"))
        if not allow_unsealed and (
            self.certificate_identity_sha256 != self.compute_identity()
        ):
            raise ValueError("certificate identity hash mismatch")
        if not allow_unsealed and (self.certificate_sha256 != self.compute_hash()):
            raise ValueError("certificate hash mismatch")
        if self.build.manifest_sha256 != self.target.manifest_sha256:
            raise ValueError("build manifest identity mismatch")
        if self.build.source_sha256 != self.target.source_sha256:
            raise ValueError("build source identity mismatch")
        if self.poc.manifest_sha256 != self.target.manifest_sha256:
            raise ValueError("PoC manifest identity mismatch")
        if self.poc.source_sha256 != self.target.source_sha256:
            raise ValueError("PoC source identity mismatch")
        if self.poc.artifact_sha256 not in {
            artifact.artifact_sha256 for artifact in self.artifacts
        }:
            raise ValueError("PoC artifact identity mismatch")
        if len(self.transactions) != self.minimization.minimized_steps:
            raise ValueError("transaction sequence and minimization size mismatch")
        if tuple(item.index for item in self.transactions) != tuple(
            range(1, len(self.transactions) + 1)
        ):
            raise ValueError("transaction indices must be consecutive")
        if self.gas.per_transaction != tuple(
            item.gas_used for item in self.transactions
        ):
            raise ValueError("gas evidence must match transactions")
        if self.initial_state != self.before_after.before:
            raise ValueError("initial and before state evidence must match")
        if (
            self.transactions[-1].observation_state_sha256
            != self.before_after.after.state_sha256
        ):
            raise ValueError("final transaction and after state evidence must match")
        before = self.before_after.before.values
        after = self.before_after.after.values
        attacker = self.impact.attacker_observation
        protocol = self.impact.protocol_observation
        if attacker not in before or attacker not in after:
            raise ValueError("attacker impact observation is missing")
        if protocol not in before or protocol not in after:
            raise ValueError("protocol impact observation is missing")
        if (
            type(before[attacker]) is not int
            or type(after[attacker]) is not int
            or type(before[protocol]) is not int
            or type(after[protocol]) is not int
        ):
            raise ValueError("impact observations must be integers")
        if self.impact.attacker_delta != after[attacker] - before[attacker]:
            raise ValueError("attacker impact delta does not match observations")
        if self.impact.protocol_delta != after[protocol] - before[protocol]:
            raise ValueError("protocol impact delta does not match observations")
        if self.confirmation_status is ConfirmationStatus.CONFIRMED:
            self._validate_confirmation()
        return self

    def _validate_confirmation(self) -> None:
        failed = (
            self.source_kind != "executed"
            or self.final_evaluation_outcome is not Outcome.VIOLATION
            or self.minimization.final_outcome is not Outcome.VIOLATION
            or not self.minimization.locally_minimal
            or not self.invariant.evaluated
            or self.invariant.value is not False
            or not self.impact.executed
            or not self.impact.admissible
            or self.impact.attacker_delta <= 0
            or self.impact.protocol_delta >= 0
            or self.chain.external_rpc
            or not self.replay.local_only
            or len(self.replay.records) != 3
            or "://" in self.replay_command
            or "--fork-url" in self.replay_command
        )
        if failed:
            raise ValueError("CONFIRMED requires complete executed local evidence")
        expected_indices = (1, 2, 3)
        if tuple(item.index for item in self.replay.records) != expected_indices:
            raise ValueError("CONFIRMED requires exactly three ordered cold replays")
        artifact_hashes = {item.artifact_sha256 for item in self.artifacts}
        for record in self.replay.records:
            identities_match = (
                record.certificate_identity_sha256 == self.certificate_identity_sha256
                and record.poc_sha256 == self.poc.sha256
                and record.manifest_sha256 == self.target.manifest_sha256
                and record.source_sha256 == self.target.source_sha256
                and record.artifact_sha256 in artifact_hashes
            )
            if not record.success or record.exit_code != 0 or not identities_match:
                raise ValueError(
                    "CONFIRMED requires successful identity-matched replays"
                )


def create_certificate(**data: object) -> ProofCertificate:
    """Validate, identity-bind, and self-hash a certificate."""

    unsigned = ProofCertificate.model_validate(
        {
            **data,
            "confirmation_status": ConfirmationStatus.NOT_CONFIRMED,
            "replay": ReplayEvidence(local_only=True, required_repeats=3, records=()),
            "certificate_identity_sha256": _ZERO_HASH,
            "certificate_sha256": _ZERO_HASH,
        },
        context={"allow_unsealed": True},
    )
    identity = unsigned.compute_identity()
    identified = ProofCertificate.model_validate(
        {
            **data,
            "certificate_identity_sha256": identity,
            "certificate_sha256": _ZERO_HASH,
        },
        context={"allow_unsealed": True},
    )
    return ProofCertificate.model_validate(
        {
            **data,
            "certificate_identity_sha256": identity,
            "certificate_sha256": identified.compute_hash(),
        }
    )


def write_certificate(certificate: ProofCertificate, output: Path) -> Path:
    """Atomically replace a certificate with canonical validated JSON."""

    validated = ProofCertificate.model_validate(certificate.model_dump(mode="json"))
    destination = output.resolve()
    destination.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{destination.name}.", suffix=".tmp", dir=destination.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(validated.canonical_json())
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, destination)
    finally:
        temporary.unlink(missing_ok=True)
    return destination


def render_markdown(certificate: ProofCertificate | Mapping[str, object]) -> str:
    """Render only data that has passed the complete certificate validator."""

    validated = (
        ProofCertificate.model_validate(certificate)
        if isinstance(certificate, Mapping)
        else ProofCertificate.model_validate(certificate.model_dump(mode="json"))
    )
    impact = validated.impact
    return (
        f"# QProver proof certificate `{validated.run_id}`\n\n"
        f"- Status: `{validated.confirmation_status.value}`\n"
        f"- Target: `{validated.target.id}` at `{validated.target.revision}`\n"
        f"- Final outcome: `{validated.final_evaluation_outcome.value}`\n"
        f"- Invariant: `{validated.invariant.id}`\n"
        f"- Attacker gain: {impact.attacker_delta:,} {impact.unit}\n"
        f"- Protocol delta: {impact.protocol_delta:,} {impact.unit}\n"
        f"- Gas used: {validated.gas.total_gas_used:,}\n"
        f"- Minimized steps: {validated.minimization.minimized_steps:,}\n"
        f"- Cold replays: {len(validated.replay.records):,}\n"
        f"- Certificate SHA-256: `{validated.certificate_sha256}`\n"
    )


def write_markdown(certificate: ProofCertificate, output: Path) -> Path:
    destination = output.resolve()
    destination.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{destination.name}.", suffix=".tmp", dir=destination.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(render_markdown(certificate))
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, destination)
    finally:
        temporary.unlink(missing_ok=True)
    return destination


def write_events(events: tuple[EvidenceEvent, ...], output: Path) -> Path:
    """Atomically write validated canonical JSON Lines evidence."""

    validated = tuple(
        EvidenceEvent.model_validate(event.model_dump(mode="json")) for event in events
    )
    if tuple(event.sequence for event in validated) != tuple(
        range(1, len(validated) + 1)
    ):
        raise ValueError("event sequence numbers must be consecutive")
    destination = output.resolve()
    destination.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{destination.name}.", suffix=".tmp", dir=destination.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            for event in validated:
                handle.write(_canonical(event.model_dump(mode="json")) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, destination)
    finally:
        temporary.unlink(missing_ok=True)
    return destination


__all__ = [
    "ArtifactEvidence",
    "AssumptionEvidence",
    "BeforeAfterEvidence",
    "BuildEvidence",
    "ChainEvidence",
    "EvidenceEvent",
    "FundingEvidence",
    "GasEvidence",
    "ImpactEvidence",
    "InvariantEvidence",
    "MinimizationEvidence",
    "PoCEvidence",
    "ProofCertificate",
    "ReplayEvidence",
    "ReplayRecord",
    "SourceEvidence",
    "StateEvidence",
    "TargetEvidence",
    "ToolchainEvidence",
    "TransactionEvidence",
    "create_certificate",
    "render_markdown",
    "write_certificate",
    "write_events",
    "write_markdown",
]
