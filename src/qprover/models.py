"""Immutable records shared across QProver's analysis and execution pipeline."""

from __future__ import annotations

import dataclasses
import hashlib
import json
import keyword
from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from types import MappingProxyType
from typing import Annotated, Any, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictBool,
    StrictInt,
    StrictStr,
    field_serializer,
    field_validator,
    model_validator,
)

NonNegativeInt = Annotated[StrictInt, Field(ge=0)]
StrictPositiveInt = Annotated[StrictInt, Field(gt=0)]


def _freeze_nested(value: object, *, allow_mappings: bool) -> object:
    if value is None or type(value) in (bool, int, str, bytes):
        return value
    if isinstance(value, (list, tuple)):
        return tuple(
            _freeze_nested(item, allow_mappings=allow_mappings) for item in value
        )
    if isinstance(value, Mapping):
        if not allow_mappings:
            raise TypeError("mapping action arguments are not supported")
        if not all(isinstance(key, str) for key in value):
            raise TypeError("constructor argument mapping keys must be strings")
        return MappingProxyType(
            {
                key: _freeze_nested(item, allow_mappings=True)
                for key, item in value.items()
            }
        )
    raise TypeError(f"unsupported mutable or non-ABI value: {type(value).__name__}")


def _thaw_nested(value: object) -> object:
    if isinstance(value, Mapping):
        return {key: _thaw_nested(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return tuple(_thaw_nested(item) for item in value)
    return value


class StrictModel(BaseModel):
    """Base model for input records: unknown fields fail closed."""

    model_config = ConfigDict(extra="forbid", frozen=True)


class TargetIdentity(StrictModel):
    id: StrictStr = Field(min_length=1, pattern=r"^[A-Za-z_][A-Za-z0-9_.-]*$")
    project_root: Path
    solidity_version: StrictStr = Field(min_length=1)
    evm_version: StrictStr = Field(min_length=1)
    source_files: tuple[Path, ...] = Field(min_length=1)


class ActorSpec(StrictModel):
    id: StrictStr = Field(min_length=1, pattern=r"^[A-Za-z_][A-Za-z0-9_.-]*$")
    slot: NonNegativeInt
    balance_wei: NonNegativeInt


class DeploymentSpec(StrictModel):
    id: StrictStr = Field(min_length=1, pattern=r"^[A-Za-z_][A-Za-z0-9_.-]*$")
    artifact: StrictStr = Field(min_length=1)
    constructor_args: tuple[Any, ...]
    sender_slot: NonNegativeInt
    value_wei: NonNegativeInt

    @field_validator("constructor_args", mode="after")
    @classmethod
    def freeze_constructor_args(cls, value: tuple[Any, ...]) -> tuple[Any, ...]:
        return tuple(_freeze_nested(item, allow_mappings=True) for item in value)

    @field_serializer("constructor_args")
    def serialize_constructor_args(self, value: tuple[Any, ...]) -> tuple[object, ...]:
        return tuple(_thaw_nested(item) for item in value)


class FiniteDomain(StrictModel):
    kind: Literal["finite"]
    values: tuple[StrictInt | StrictBool | StrictStr, ...] = Field(min_length=1)


class IntegerDomain(StrictModel):
    kind: Literal["integer"]
    minimum: StrictInt
    maximum: StrictInt
    include_boundaries: StrictBool = True
    constraints: tuple[StrictStr, ...] = ()

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
    name: StrictStr = Field(min_length=1, pattern=r"^[A-Za-z_][A-Za-z0-9_]*$")
    type: StrictStr = Field(min_length=1)
    domain: ArgumentDomain


class ActionSpec(StrictModel):
    id: StrictStr = Field(min_length=1, pattern=r"^[A-Za-z_][A-Za-z0-9_.-]*$")
    target_id: StrictStr = Field(min_length=1)
    signature: StrictStr = Field(min_length=1)
    mutability: Literal["nonpayable", "payable"]
    sender_slots: tuple[StrictInt, ...] = Field(min_length=1)
    arguments: tuple[ArgumentSpec, ...]
    value_domain: FiniteDomain
    max_repetitions: StrictPositiveInt

    @model_validator(mode="after")
    def validate_call_value(self) -> ActionSpec:
        if not all(
            type(value) is int and value >= 0 for value in self.value_domain.values
        ):
            raise ValueError("call value domain must contain only nonnegative integers")
        if self.mutability == "nonpayable" and any(self.value_domain.values):
            raise ValueError("nonpayable actions can only use zero call value")
        return self


class ObservationSpec(StrictModel):
    id: StrictStr = Field(min_length=1, pattern=r"^[A-Za-z_][A-Za-z0-9_.-]*$")
    kind: Literal["call", "native_balance"]
    target_id: StrictStr | None = None
    signature: StrictStr | None = None
    args: tuple[StrictInt | StrictBool | StrictStr, ...] = ()
    actor_id: StrictStr | None = None

    @field_validator("id")
    @classmethod
    def reserve_initial_namespace(cls, value: str) -> str:
        if (
            not value.isidentifier()
            or keyword.iskeyword(value)
            or value in {"True", "False", "None"}
        ):
            raise ValueError("observation IDs must be valid expression identifiers")
        if value.startswith("initial_"):
            raise ValueError("observation IDs cannot use the reserved initial_ prefix")
        return value

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
    id: StrictStr = Field(min_length=1, pattern=r"^[A-Za-z_][A-Za-z0-9_.-]*$")
    expression: StrictStr = Field(min_length=1)
    description: StrictStr
    foundry_assertion: StrictStr = Field(min_length=1)


class ImpactSpec(StrictModel):
    attacker_asset_observation: StrictStr = Field(min_length=1)
    protocol_asset_observation: StrictStr = Field(min_length=1)
    unit: StrictStr = Field(min_length=1)


class ConfirmationSpec(StrictModel):
    """Manifest-bound condition required for an executed violation outcome."""

    kind: Literal["invariant_and_economic_impact", "invariant_violation"] = (
        "invariant_and_economic_impact"
    )


class SearchLimits(StrictModel):
    max_sequence_length: StrictPositiveInt
    max_variants: StrictPositiveInt = 64
    transaction_budget: StrictPositiveInt
    candidate_budget: StrictPositiveInt
    wall_seconds: StrictPositiveInt


class TargetManifest(StrictModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        json_schema_extra={
            "allOf": [
                {
                    "if": {
                        "properties": {
                            "confirmation": {
                                "properties": {
                                    "kind": {"const": "invariant_and_economic_impact"}
                                }
                            }
                        }
                    },
                    "then": {"required": ["impact"]},
                },
                {
                    "if": {
                        "properties": {
                            "confirmation": {
                                "properties": {"kind": {"const": "invariant_violation"}}
                            }
                        },
                        "required": ["confirmation"],
                    },
                    "then": {"properties": {"impact": {"type": "null"}}},
                },
            ]
        },
    )
    schema_version: Literal["1.0"]
    target: TargetIdentity
    actors: tuple[ActorSpec, ...] = Field(min_length=1)
    deployments: tuple[DeploymentSpec, ...] = Field(min_length=1)
    actions: tuple[ActionSpec, ...] = Field(min_length=1)
    observations: tuple[ObservationSpec, ...] = Field(min_length=1)
    invariants: tuple[InvariantSpec, ...] = Field(min_length=1)
    confirmation: ConfirmationSpec = ConfirmationSpec()
    impact: ImpactSpec | None = None
    limits: SearchLimits

    @model_validator(mode="after")
    def confirmation_shape_is_explicit(self) -> TargetManifest:
        if (
            self.confirmation.kind == "invariant_and_economic_impact"
            and self.impact is None
        ):
            raise ValueError("economic confirmation requires impact accounting")
        if self.confirmation.kind == "invariant_violation" and self.impact is not None:
            raise ValueError("invariant-only confirmation must omit impact accounting")
        return self


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

    def __post_init__(self) -> None:
        frozen = tuple(_freeze_nested(item, allow_mappings=False) for item in self.args)
        object.__setattr__(self, "args", frozen)


@dataclass(frozen=True, slots=True)
class Candidate:
    steps: tuple[ActionStep, ...]

    def __post_init__(self) -> None:
        frozen_steps = tuple(self.steps)
        if not all(isinstance(step, ActionStep) for step in frozen_steps):
            raise TypeError("candidate steps must be ActionStep records")
        object.__setattr__(self, "steps", frozen_steps)

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

    def __post_init__(self) -> None:
        copied = MappingProxyType(dict(self.values))
        object.__setattr__(self, "values", copied)


@dataclass(frozen=True, slots=True)
class InvariantResult:
    invariant_id: str
    expression: str
    outcome: Outcome
    value: bool | None = None
    reason: str | None = None
