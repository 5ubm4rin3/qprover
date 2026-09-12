"""Immutable records shared across QProver's analysis and execution pipeline."""

from __future__ import annotations

import dataclasses
import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, PositiveInt, model_validator


class StrictModel(BaseModel):
    """Base model for input records: unknown fields fail closed."""

    model_config = ConfigDict(extra="forbid", frozen=True)


class TargetIdentity(StrictModel):
    id: str = Field(min_length=1, pattern=r"^[A-Za-z_][A-Za-z0-9_.-]*$")
    project_root: Path
    solidity_version: str = Field(min_length=1)
    evm_version: str = Field(min_length=1)
    source_files: tuple[Path, ...] = Field(min_length=1)


class ActorSpec(StrictModel):
    id: str = Field(min_length=1, pattern=r"^[A-Za-z_][A-Za-z0-9_.-]*$")
    slot: int = Field(ge=0)
    balance_wei: int = Field(ge=0)


class DeploymentSpec(StrictModel):
    id: str = Field(min_length=1, pattern=r"^[A-Za-z_][A-Za-z0-9_.-]*$")
    artifact: str = Field(min_length=1)
    constructor_args: tuple[Any, ...]
    sender_slot: int = Field(ge=0)
    value_wei: int = Field(ge=0)


class FiniteDomain(StrictModel):
    kind: Literal["finite"]
    values: tuple[int | bool | str, ...] = Field(min_length=1)


class IntegerDomain(StrictModel):
    kind: Literal["integer"]
    minimum: int
    maximum: int
    include_boundaries: bool = True
    constraints: tuple[str, ...] = ()

    @model_validator(mode="after")
    def validate_interval(self) -> IntegerDomain:
        if self.minimum > self.maximum:
            raise ValueError("integer domain minimum exceeds maximum")
        return self


ArgumentDomain = Annotated[
    FiniteDomain | IntegerDomain,
    Field(discriminator="kind"),
]


class ArgumentSpec(StrictModel):
    name: str = Field(min_length=1, pattern=r"^[A-Za-z_][A-Za-z0-9_]*$")
    type: str = Field(min_length=1)
    domain: ArgumentDomain


class ActionSpec(StrictModel):
    id: str = Field(min_length=1, pattern=r"^[A-Za-z_][A-Za-z0-9_.-]*$")
    target_id: str = Field(min_length=1)
    signature: str = Field(min_length=1)
    mutability: Literal["nonpayable", "payable"]
    sender_slots: tuple[int, ...] = Field(min_length=1)
    arguments: tuple[ArgumentSpec, ...]
    value_domain: FiniteDomain
    max_repetitions: PositiveInt

    @model_validator(mode="after")
    def validate_call_value(self) -> ActionSpec:
        if not all(
            isinstance(value, int) and value >= 0
            for value in self.value_domain.values
        ):
            raise ValueError("call value domain must contain only nonnegative integers")
        if self.mutability == "nonpayable" and any(self.value_domain.values):
            raise ValueError("nonpayable actions can only use zero call value")
        return self


class ObservationSpec(StrictModel):
    id: str = Field(min_length=1, pattern=r"^[A-Za-z_][A-Za-z0-9_.-]*$")
    kind: Literal["call", "native_balance"]
    target_id: str | None = None
    signature: str | None = None
    args: tuple[int | bool | str, ...] = ()
    actor_id: str | None = None

    @model_validator(mode="after")
    def validate_kind_fields(self) -> ObservationSpec:
        if self.kind == "call":
            if (
                self.target_id is None
                or self.signature is None
                or self.actor_id is not None
            ):
                raise ValueError("call observation requires target_id/signature only")
        elif (
            self.actor_id is None
            or self.target_id is not None
            or self.signature is not None
            or self.args
        ):
            raise ValueError("native_balance observation requires actor_id only")
        return self


class InvariantSpec(StrictModel):
    id: str = Field(min_length=1, pattern=r"^[A-Za-z_][A-Za-z0-9_.-]*$")
    expression: str = Field(min_length=1)
    description: str
    foundry_assertion: str = Field(min_length=1)


class ImpactSpec(StrictModel):
    attacker_asset_observation: str = Field(min_length=1)
    protocol_asset_observation: str = Field(min_length=1)
    unit: str = Field(min_length=1)


class SearchLimits(StrictModel):
    max_sequence_length: PositiveInt
    max_variants: PositiveInt = 64
    transaction_budget: PositiveInt
    candidate_budget: PositiveInt
    wall_seconds: PositiveInt


class TargetManifest(StrictModel):
    schema_version: Literal["1.0"]
    target: TargetIdentity
    actors: tuple[ActorSpec, ...] = Field(min_length=1)
    deployments: tuple[DeploymentSpec, ...] = Field(min_length=1)
    actions: tuple[ActionSpec, ...] = Field(min_length=1)
    observations: tuple[ObservationSpec, ...] = Field(min_length=1)
    invariants: tuple[InvariantSpec, ...] = Field(min_length=1)
    impact: ImpactSpec
    limits: SearchLimits


class Outcome(str, Enum):  # noqa: UP042 - exact public interface from the plan
    PASS = "PASS"
    VIOLATION = "VIOLATION"
    REVERT = "REVERT"
    INCONCLUSIVE = "INCONCLUSIVE"
    INFRA_ERROR = "INFRA_ERROR"


class ConfirmationStatus(str, Enum):  # noqa: UP042 - exact public interface
    NOT_CONFIRMED = "NOT_CONFIRMED"
    CANDIDATE_VIOLATION = "CANDIDATE_VIOLATION"
    CONFIRMED = "CONFIRMED"


@dataclass(frozen=True, slots=True)
class ActionStep:
    action_id: str
    target_id: str
    signature: str
    sender_slot: int
    args: tuple[object, ...]
    value_wei: int = 0


@dataclass(frozen=True, slots=True)
class Candidate:
    steps: tuple[ActionStep, ...]

    @property
    def canonical_id(self) -> str:
        payload = json.dumps(
            dataclasses.asdict(self), sort_keys=True, separators=(",", ":")
        )
        return hashlib.sha256(payload.encode()).hexdigest()


@dataclass(frozen=True, slots=True)
class ObservationSnapshot:
    values: Mapping[str, int | bool]
    state_hash: str


@dataclass(frozen=True, slots=True)
class InvariantResult:
    invariant_id: str
    expression: str
    outcome: Outcome
    value: bool | None = None
    reason: str | None = None
