"""Label-isolated benchmark execution, immutable journals, and scoring."""

from __future__ import annotations

import errno
import fcntl
import hashlib
import json
import os
import platform
import shutil
import stat
import subprocess
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Annotated, Literal

from pydantic import (
    ConfigDict,
    Field,
    StrictBool,
    StrictFloat,
    StrictInt,
    StrictStr,
    field_validator,
    model_validator,
)

from qprover.manifest import canonical_manifest_hash, load_manifest
from qprover.models import (
    ConfirmationStatus,
    SearchLimits,
    StrictModel,
    StrictPositiveInt,
)
from qprover.safeio import safe_atomic_write

Sha256 = Annotated[
    StrictStr,
    Field(min_length=64, max_length=64, pattern=r"^[0-9a-f]{64}$"),
]
StrategyName = Literal["random", "coverage", "risk", "qubo"]


def _sha256(data: bytes | str) -> str:
    if isinstance(data, str):
        data = data.encode()
    return hashlib.sha256(data).hexdigest()


def _canonical(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def _json_loads_strict(text: str) -> object:
    def pairs(items: list[tuple[str, object]]) -> dict[str, object]:
        out: dict[str, object] = {}
        for key, value in items:
            if key in out:
                raise ValueError(f"duplicate JSON key: {key}")
            out[key] = value
        return out

    def reject_constant(value: str) -> object:
        raise ValueError(f"non-standard JSON constant: {value}")

    return json.loads(text, object_pairs_hook=pairs, parse_constant=reject_constant)


def _safe_relative(value: str, *, suffix: str | None = None) -> str:
    candidate = Path(value)
    if (
        not value
        or candidate.is_absolute()
        or candidate.as_posix() != value
        or value.startswith("./")
        or "\\" in value
        or "://" in value
        or any(part in {"", ".", ".."} for part in candidate.parts)
        or any(ord(ch) < 32 or ord(ch) == 127 for ch in value)
        or (suffix is not None and candidate.suffix != suffix)
    ):
        raise ValueError("path must be a canonical safe relative path")
    return value


class BenchmarkSuite(StrictModel):
    """Public targets and seeds. Labels are deliberately absent."""

    schema_version: Literal["1.0"]
    manifests: tuple[StrictStr, ...] = Field(min_length=1)
    seeds: tuple[StrictInt, ...] = Field(min_length=1)

    @field_validator("manifests")
    @classmethod
    def validate_manifests(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if len(set(values)) != len(values):
            raise ValueError("duplicate benchmark manifest")
        for value in values:
            _safe_relative(value, suffix=".json")
        return values

    @field_validator("seeds")
    @classmethod
    def validate_seeds(cls, values: tuple[int, ...]) -> tuple[int, ...]:
        if len(set(values)) != len(values):
            raise ValueError("duplicate benchmark seed")
        return values


class RandomStrategyConfig(StrictModel):
    name: Literal["random"]
    proposal_attempts: StrictPositiveInt = 256


class CoverageStrategyConfig(StrictModel):
    name: Literal["coverage"]
    proposal_attempts: StrictPositiveInt = 256


class RiskStrategyConfig(StrictModel):
    name: Literal["risk"]
    beam_width: StrictPositiveInt = 32


class QuboStrategyConfig(StrictModel):
    name: Literal["qubo"]
    backend: Literal["annealing", "exact"] = "annealing"
    reads: StrictPositiveInt = 64
    sweeps: StrictPositiveInt = 200
    temperature_start: StrictFloat = Field(default=10.0, gt=0, allow_inf_nan=False)
    temperature_end: StrictFloat = Field(default=0.01, gt=0, allow_inf_nan=False)
    feedback_batch_size: StrictPositiveInt = 8
    resample_attempts: Annotated[StrictInt, Field(ge=0)] = 3
    max_exact_fallback_sequences: Annotated[StrictInt, Field(ge=0)] = 4096
    exact_max_bits: StrictPositiveInt = 20

    @model_validator(mode="after")
    def temperatures_ordered(self) -> QuboStrategyConfig:
        if self.temperature_end > self.temperature_start:
            raise ValueError("temperature_end cannot exceed temperature_start")
        return self


StrategyConfig = Annotated[
    RandomStrategyConfig
    | CoverageStrategyConfig
    | RiskStrategyConfig
    | QuboStrategyConfig,
    Field(discriminator="name"),
]


class BenchmarkConfig(StrictModel):
    schema_version: Literal["1.0"]
    strategies: tuple[StrategyConfig, ...] = Field(min_length=1)
    candidate_budget: StrictPositiveInt | None = None
    transaction_budget: StrictPositiveInt | None = None
    wall_seconds: StrictPositiveInt | None = None
    manifest_subset: tuple[StrictStr, ...] | None = None
    seed_subset: tuple[StrictInt, ...] | None = None

    @model_validator(mode="after")
    def unique_strategies(self) -> BenchmarkConfig:
        names = [item.name for item in self.strategies]
        if len(set(names)) != len(names):
            raise ValueError("duplicate benchmark strategy")
        if self.manifest_subset is not None:
            if not self.manifest_subset or len(set(self.manifest_subset)) != len(
                self.manifest_subset
            ):
                raise ValueError("manifest_subset must be nonempty and unique")
            for value in self.manifest_subset:
                _safe_relative(value, suffix=".json")
        if self.seed_subset is not None and (
            not self.seed_subset or len(set(self.seed_subset)) != len(self.seed_subset)
        ):
            raise ValueError("seed_subset must be nonempty and unique")
        return self


class ToolchainIdentity(StrictModel):
    python: StrictStr = Field(min_length=1)
    uv: StrictStr = Field(min_length=1)
    forge: StrictStr = Field(min_length=1)
    anvil: StrictStr = Field(min_length=1)


class BenchmarkTargetIdentity(StrictModel):
    public_target_id: StrictStr = Field(min_length=1)
    manifest_path: StrictStr = Field(min_length=1)
    manifest_sha256: Sha256
    source_closure_sha256: Sha256
    build_sha256: Sha256
    problem_sha256: Sha256
    effective_limits: SearchLimits

    @field_validator("manifest_path")
    @classmethod
    def validate_path(cls, value: str) -> str:
        return _safe_relative(value, suffix=".json")


class BenchmarkMatrix(StrictModel):
    schema_version: Literal["1.0"]
    matrix_id: Sha256
    suite_sha256: Sha256
    config_sha256: Sha256
    qprover_source_sha256: Sha256
    lockfile_sha256: Sha256
    toolchain: ToolchainIdentity
    git_revision: StrictStr
    git_dirty: StrictBool
    targets: tuple[BenchmarkTargetIdentity, ...] = Field(min_length=1)

    def identity_payload(self) -> dict[str, object]:
        raw = self.model_dump(mode="json")
        raw.pop("matrix_id", None)
        return raw

    @model_validator(mode="after")
    def matrix_hash_matches(self) -> BenchmarkMatrix:
        manifest_paths = [item.manifest_path for item in self.targets]
        target_ids = [item.public_target_id for item in self.targets]
        if len(set(manifest_paths)) != len(manifest_paths):
            raise ValueError("benchmark matrix contains duplicate target manifests")
        if len(set(target_ids)) != len(target_ids):
            raise ValueError("benchmark matrix contains duplicate public target IDs")
        if self.matrix_id != _sha256(_canonical(self.identity_payload())):
            raise ValueError("matrix_id does not match matrix identity payload")
        return self


class BenchmarkArtifact(StrictModel):
    path: StrictStr = Field(min_length=1)
    sha256: Sha256

    @field_validator("path")
    @classmethod
    def validate_path(cls, value: str) -> str:
        return _safe_relative(value)


class TimingEvidence(StrictModel):
    total_seconds: StrictFloat = Field(ge=0, allow_inf_nan=False)
    strategy_initialization_seconds: StrictFloat | None = Field(
        default=None, ge=0, allow_inf_nan=False
    )
    search_seconds: StrictFloat | None = Field(default=None, ge=0, allow_inf_nan=False)
    setup_seconds: StrictFloat | None = Field(default=None, ge=0, allow_inf_nan=False)
    proof_seconds: StrictFloat | None = Field(default=None, ge=0, allow_inf_nan=False)


class NotApplicableStrategyEvidence(StrictModel):
    kind: Literal["not_applicable"]


class QuboStrategyEvidence(StrictModel):
    kind: Literal["qubo"]
    evidence_sha256: Sha256
    builds: Annotated[StrictInt, Field(ge=0)]
    solver_calls: Annotated[StrictInt, Field(ge=0)]
    reads: Annotated[StrictInt, Field(ge=0)]
    sweeps: Annotated[StrictInt, Field(ge=0)]
    solver_seconds: StrictFloat = Field(ge=0, allow_inf_nan=False)
    fallback_calls: Annotated[StrictInt, Field(ge=0)]
    fallback_seconds: StrictFloat = Field(ge=0, allow_inf_nan=False)
    max_logical_bits: Annotated[StrictInt, Field(ge=0)]
    max_couplers: Annotated[StrictInt, Field(ge=0)]


class QuboUnavailableEvidence(StrictModel):
    kind: Literal["qubo_unavailable"]
    reason: StrictStr = Field(min_length=1, max_length=512)


StrategyEvidence = Annotated[
    NotApplicableStrategyEvidence | QuboStrategyEvidence | QuboUnavailableEvidence,
    Field(discriminator="kind"),
]


class BenchmarkRun(StrictModel):
    """One immutable label-free raw benchmark row."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        json_schema_extra={
            "allOf": [
                {
                    "if": {
                        "properties": {"state": {"const": "completed"}},
                        "required": ["state"],
                    },
                    "then": {
                        "required": [
                            "stop_reason",
                            "executed_violation",
                            "search_hit",
                            "proof_attempted",
                            "hit_observation",
                            "candidates_evaluated",
                            "search_transactions",
                        ],
                        "properties": {
                            "error": {"type": "null"},
                            "confirmation_status": {
                                "enum": ["NOT_CONFIRMED", "CONFIRMED"]
                            },
                            "stop_reason": {"type": "string", "minLength": 1},
                            "executed_violation": {"type": "boolean"},
                            "search_hit": {"type": "boolean"},
                            "proof_attempted": {"type": "boolean"},
                            "hit_observation": {"enum": ["observed", "censored"]},
                            "candidates_evaluated": {
                                "type": "integer",
                                "minimum": 0,
                            },
                            "search_transactions": {
                                "type": "integer",
                                "minimum": 0,
                            },
                        },
                    },
                },
                {
                    "if": {
                        "properties": {"state": {"const": "failed"}},
                        "required": ["state"],
                    },
                    "then": {
                        "required": ["error"],
                        "properties": {
                            "confirmation_status": {"const": "NOT_CONFIRMED"},
                            "error": {"type": "string", "minLength": 1},
                        },
                    },
                },
                {
                    "if": {
                        "properties": {"state": {"const": "incomplete"}},
                        "required": ["state"],
                    },
                    "then": {
                        "properties": {
                            "confirmation_status": {"const": "NOT_CONFIRMED"},
                            "certificate_sha256": {"type": "null"},
                            "cold_replays": {"type": "null"},
                        },
                    },
                },
                {
                    "if": {
                        "properties": {"strategy": {"const": "qubo"}},
                        "required": ["strategy"],
                    },
                    "then": {
                        "properties": {
                            "strategy_evidence": {
                                "properties": {
                                    "kind": {"enum": ["qubo", "qubo_unavailable"]}
                                },
                                "required": ["kind"],
                            }
                        }
                    },
                    "else": {
                        "properties": {
                            "strategy_evidence": {
                                "properties": {"kind": {"const": "not_applicable"}},
                                "required": ["kind"],
                            }
                        }
                    },
                },
                {
                    "if": {
                        "properties": {"confirmation_status": {"const": "CONFIRMED"}},
                        "required": ["confirmation_status"],
                    },
                    "then": {
                        "properties": {
                            "state": {"const": "completed"},
                            "executed_violation": {"const": True},
                            "search_hit": {"const": True},
                            "proof_attempted": {"const": True},
                            "hit_observation": {"const": "observed"},
                            "certificate_sha256": {
                                "type": "string",
                                "minLength": 64,
                                "maxLength": 64,
                                "pattern": "^[0-9a-f]{64}$",
                            },
                            "cold_replays": {"const": 3},
                            "artifacts": {
                                "type": "object",
                                "required": [
                                    "result",
                                    "certificate",
                                    "poc",
                                    "events",
                                ],
                            },
                        }
                    },
                },
                {
                    "if": {
                        "properties": {"search_hit": {"const": True}},
                        "required": ["search_hit"],
                    },
                    "then": {
                        "required": [
                            "first_hit_candidate",
                            "first_hit_transactions",
                        ],
                        "properties": {
                            "proof_attempted": {"const": True},
                            "hit_observation": {"const": "observed"},
                            "first_hit_candidate": {
                                "type": "integer",
                                "minimum": 1,
                            },
                            "first_hit_transactions": {
                                "type": "integer",
                                "minimum": 1,
                            },
                        },
                    },
                },
                {
                    "if": {
                        "properties": {"search_hit": {"const": False}},
                        "required": ["search_hit"],
                    },
                    "then": {
                        "properties": {
                            "proof_attempted": {"const": False},
                            "hit_observation": {"const": "censored"},
                            "first_hit_candidate": {"type": "null"},
                            "first_hit_transactions": {"type": "null"},
                        }
                    },
                },
                {
                    "if": {
                        "properties": {"state": {"const": "failed"}},
                        "required": ["state"],
                    },
                    "then": {
                        "properties": {
                            "certificate_sha256": {"type": "null"},
                            "cold_replays": {"type": "null"},
                        }
                    },
                },
                {
                    "if": {
                        "allOf": [
                            {
                                "properties": {"state": {"const": "completed"}},
                                "required": ["state"],
                            },
                            {
                                "properties": {
                                    "confirmation_status": {"const": "NOT_CONFIRMED"}
                                },
                                "required": ["confirmation_status"],
                            },
                        ]
                    },
                    "then": {
                        "properties": {
                            "search_hit": {"const": False},
                            "proof_attempted": {"const": False},
                            "hit_observation": {"const": "censored"},
                            "certificate_sha256": {"type": "null"},
                            "cold_replays": {"type": "null"},
                        }
                    },
                },
                {
                    "if": {
                        "allOf": [
                            {
                                "properties": {"state": {"const": "completed"}},
                                "required": ["state"],
                            },
                            {
                                "properties": {"strategy": {"const": "qubo"}},
                                "required": ["strategy"],
                            },
                        ]
                    },
                    "then": {
                        "properties": {
                            "strategy_evidence": {
                                "properties": {"kind": {"const": "qubo"}},
                                "required": ["kind"],
                            }
                        }
                    },
                },
            ]
        },
    )

    schema_version: Literal["1.0"]
    row_sha256: Sha256
    run_key: Sha256
    matrix_id: Sha256
    public_target_id: StrictStr = Field(min_length=1)
    manifest_sha256: Sha256
    source_closure_sha256: Sha256
    build_sha256: Sha256
    problem_sha256: Sha256
    qprover_source_sha256: Sha256
    lockfile_sha256: Sha256
    toolchain_sha256: Sha256
    strategy: StrategyName
    strategy_config_sha256: Sha256
    seed: StrictInt
    effective_limits: SearchLimits
    state: Literal["completed", "failed", "incomplete"]
    confirmation_status: ConfirmationStatus
    stop_reason: StrictStr | None = None
    error: StrictStr | None = None
    executed_violation: StrictBool | None = None
    search_hit: StrictBool | None = None
    proof_attempted: StrictBool | None = None
    hit_observation: Literal["observed", "censored"] | None = None
    candidates_evaluated: Annotated[StrictInt, Field(ge=0)] | None = None
    duplicate_proposals: Annotated[StrictInt, Field(ge=0)] | None = None
    unique_trace_features: Annotated[StrictInt, Field(ge=0)] | None = None
    search_transactions: Annotated[StrictInt, Field(ge=0)] | None = None
    total_transactions: Annotated[StrictInt, Field(ge=0)] | None = None
    minimized_steps: Annotated[StrictInt, Field(ge=1)] | None = None
    first_hit_candidate: Annotated[StrictInt, Field(ge=1)] | None = None
    first_hit_transactions: Annotated[StrictInt, Field(ge=1)] | None = None
    outcome_counts: Mapping[StrictStr, Annotated[StrictInt, Field(ge=0)]] = Field(
        default_factory=dict
    )
    certificate_sha256: Sha256 | None = None
    cold_replays: Annotated[StrictInt, Field(ge=0)] | None = None
    artifacts: Mapping[StrictStr, BenchmarkArtifact] = Field(default_factory=dict)
    strategy_evidence: StrategyEvidence
    timings: TimingEvidence

    def payload_without_hash(self) -> dict[str, object]:
        data = self.model_dump(mode="json")
        data.pop("row_sha256", None)
        return data

    def computed_row_sha256(self) -> str:
        return _sha256(_canonical(self.payload_without_hash()))

    def run_identity_payload(self) -> dict[str, object]:
        return {
            "matrix_id": self.matrix_id,
            "target": self.public_target_id,
            "strategy": self.strategy,
            "strategy_config_sha256": self.strategy_config_sha256,
            "seed": self.seed,
            "limits": self.effective_limits.model_dump(mode="json"),
            "manifest_sha256": self.manifest_sha256,
            "source_closure_sha256": self.source_closure_sha256,
            "build_sha256": self.build_sha256,
            "problem_sha256": self.problem_sha256,
            "qprover_source_sha256": self.qprover_source_sha256,
            "lockfile_sha256": self.lockfile_sha256,
            "toolchain_sha256": self.toolchain_sha256,
        }

    def computed_run_key(self) -> str:
        return _sha256(_canonical(self.run_identity_payload()))

    @model_validator(mode="after")
    def consistent(self) -> BenchmarkRun:
        if self.row_sha256 != self.computed_row_sha256():
            raise ValueError("row_sha256 does not match row contents")
        if self.run_key != self.computed_run_key():
            raise ValueError("run_key does not match run identity")

        allowed_outcomes = {
            "PASS",
            "VIOLATION",
            "REVERT",
            "INCONCLUSIVE",
            "INFRA_ERROR",
        }
        if not set(self.outcome_counts).issubset(allowed_outcomes):
            raise ValueError("outcome_counts contains an unknown outcome")

        if self.strategy == "qubo":
            if self.strategy_evidence.kind not in {
                "qubo",
                "qubo_unavailable",
            }:
                raise ValueError(
                    "QUBO run requires QUBO evidence or explicit unavailability"
                )
            if self.state == "completed" and self.strategy_evidence.kind != "qubo":
                raise ValueError("completed QUBO run requires cumulative QUBO evidence")
        elif self.strategy_evidence.kind != "not_applicable":
            raise ValueError("non-QUBO run must mark QUBO evidence not applicable")

        if self.candidates_evaluated is not None and (
            sum(self.outcome_counts.values()) != self.candidates_evaluated
        ):
            raise ValueError("outcome counts must sum to evaluated candidates")
        if self.candidates_evaluated is None and self.outcome_counts:
            raise ValueError("outcome counts require candidates_evaluated")

        if self.state == "failed":
            if (
                not self.error
                or self.confirmation_status is not ConfirmationStatus.NOT_CONFIRMED
            ):
                raise ValueError("failed row requires an error and NOT_CONFIRMED")
            if self.certificate_sha256 is not None or self.cold_replays is not None:
                raise ValueError("failed row cannot claim confirmed proof evidence")
        elif self.state == "incomplete":
            if self.confirmation_status is not ConfirmationStatus.NOT_CONFIRMED:
                raise ValueError("incomplete row cannot be confirmed")
            if self.certificate_sha256 is not None or self.cold_replays is not None:
                raise ValueError("incomplete row cannot claim proof confirmation")
        else:
            if self.error is not None:
                raise ValueError("completed row cannot carry an error")
            if not self.stop_reason:
                raise ValueError("completed row requires a stop reason")
            if (
                self.executed_violation is None
                or self.search_hit is None
                or self.proof_attempted is None
                or self.hit_observation is None
            ):
                raise ValueError("completed row requires violation/hit/proof evidence")
            if self.candidates_evaluated is None or self.search_transactions is None:
                raise ValueError("completed row requires search accounting")
            if self.confirmation_status is ConfirmationStatus.CANDIDATE_VIOLATION:
                raise ValueError("terminal benchmark rows cannot remain candidate-only")

            if self.search_hit:
                if (
                    self.proof_attempted is not True
                    or self.hit_observation != "observed"
                    or self.first_hit_candidate is None
                    or self.first_hit_transactions is None
                ):
                    raise ValueError(
                        "accepted search hit requires observed first-hit/proof evidence"
                    )
            elif (
                self.proof_attempted is not False
                or self.hit_observation != "censored"
                or self.first_hit_candidate is not None
                or self.first_hit_transactions is not None
            ):
                raise ValueError(
                    "completed miss requires censored evidence and no first-hit "
                    "counters"
                )

            if self.confirmation_status is ConfirmationStatus.NOT_CONFIRMED:
                if self.search_hit:
                    raise ValueError(
                        "a completed accepted hit must either confirm or fail the "
                        "proof gate"
                    )
                if self.certificate_sha256 is not None or self.cold_replays is not None:
                    raise ValueError(
                        "not-confirmed row cannot claim proof confirmation"
                    )

        if self.confirmation_status is ConfirmationStatus.CONFIRMED:
            if (
                self.state != "completed"
                or self.executed_violation is not True
                or self.search_hit is not True
                or self.proof_attempted is not True
                or self.hit_observation != "observed"
            ):
                raise ValueError("CONFIRMED requires an accepted in-budget search hit")
            if self.certificate_sha256 is None or self.cold_replays != 3:
                raise ValueError(
                    "CONFIRMED requires a certificate and three cold replays"
                )
            required_artifacts = {"result", "certificate", "poc", "events"}
            if not required_artifacts.issubset(self.artifacts):
                raise ValueError("CONFIRMED row is missing bound proof artifacts")

        if self.first_hit_candidate is not None and (
            self.candidates_evaluated is None
            or self.first_hit_candidate > self.candidates_evaluated
        ):
            raise ValueError("first-hit candidate exceeds evaluated candidates")
        if self.first_hit_transactions is not None and (
            self.search_transactions is None
            or self.first_hit_transactions > self.search_transactions
        ):
            raise ValueError("first-hit transactions exceed search transactions")
        if (
            self.total_transactions is not None
            and self.search_transactions is not None
            and self.total_transactions < self.search_transactions
        ):
            raise ValueError("total transactions cannot be below search transactions")
        return self


class BenchmarkLabel(StrictModel):
    expected: Literal["positive", "negative"]
    family: StrictStr = Field(min_length=1)
    pair: Literal["a", "b"]
    witness: tuple[StrictStr, ...] = Field(min_length=1)


class BenchmarkScore(StrictModel):
    schema_version: Literal["1.0"]
    score_sha256: Sha256
    run_key: Sha256
    matrix_id: Sha256
    public_target_id: StrictStr = Field(min_length=1)
    strategy: StrategyName
    seed: StrictInt
    expected: Literal["positive", "negative"]
    predicted: Literal["positive", "negative", "failure", "incomplete"]
    correct: StrictBool
    false_confirmed: StrictBool
    family: StrictStr = Field(min_length=1)
    pair: Literal["a", "b"]
    raw_row_sha256: Sha256
    labels_sha256: Sha256

    def payload_without_hash(self) -> dict[str, object]:
        data = self.model_dump(mode="json")
        data.pop("score_sha256", None)
        return data

    @model_validator(mode="after")
    def score_hash_matches(self) -> BenchmarkScore:
        if self.score_sha256 != _sha256(_canonical(self.payload_without_hash())):
            raise ValueError("score_sha256 does not match score contents")
        expected_correct = (
            self.expected == "positive" and self.predicted == "positive"
        ) or (self.expected == "negative" and self.predicted == "negative")
        if self.correct != expected_correct:
            raise ValueError("score correctness does not match prediction")
        if self.false_confirmed != (
            self.expected == "negative" and self.predicted == "positive"
        ):
            raise ValueError("false_confirmed flag is inconsistent")
        return self


def load_suite(path: Path) -> BenchmarkSuite:
    raw = _json_loads_strict(path.read_text(encoding="utf-8"))
    return BenchmarkSuite.model_validate(raw)


def load_config(path: Path) -> BenchmarkConfig:
    raw = _json_loads_strict(path.read_text(encoding="utf-8"))
    return BenchmarkConfig.model_validate(raw)


def _file_sha(path: Path) -> str:
    return _sha256(path.read_bytes())


def _tree_sha(paths: Sequence[Path], root: Path) -> str:
    records = []
    for path in sorted((item.resolve() for item in paths), key=lambda p: p.as_posix()):
        rel = path.relative_to(root.resolve()).as_posix()
        records.append((rel, _file_sha(path)))
    return _sha256(_canonical(records))


def _tool_version(command: str) -> str:
    executable = shutil.which(command)
    if executable is None:
        return "unavailable"
    try:
        result = subprocess.run(
            (executable, "--version"),
            text=True,
            capture_output=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return "unavailable"
    text = (result.stdout or result.stderr).strip().splitlines()
    return text[0][:512] if text else "unknown"


def _git_state(workspace_root: Path) -> tuple[str, bool]:
    shadow = workspace_root / ".qprover-git"
    prefix = ["git"]
    if shadow.is_dir():
        prefix += [f"--git-dir={shadow}", f"--work-tree={workspace_root}"]
    try:
        rev = subprocess.run(
            (*prefix, "rev-parse", "HEAD"),
            cwd=workspace_root,
            text=True,
            capture_output=True,
            timeout=10,
            check=False,
        )
        status = subprocess.run(
            (*prefix, "status", "--porcelain"),
            cwd=workspace_root,
            text=True,
            capture_output=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return "unavailable", True
    revision = (
        rev.stdout.strip()
        if rev.returncode == 0 and rev.stdout.strip()
        else "unavailable"
    )
    return revision, status.returncode != 0 or bool(status.stdout.strip())


def selected_matrix_axes(
    suite: BenchmarkSuite, config: BenchmarkConfig
) -> tuple[tuple[str, ...], tuple[int, ...]]:
    manifests = config.manifest_subset or suite.manifests
    seeds = config.seed_subset or suite.seeds
    if not set(manifests).issubset(set(suite.manifests)):
        raise ValueError("config manifest_subset is not contained in the public suite")
    if not set(seeds).issubset(set(suite.seeds)):
        raise ValueError("config seed_subset is not contained in the public suite")
    return tuple(manifests), tuple(seeds)


def effective_limits(
    manifest_limits: SearchLimits, config: BenchmarkConfig
) -> SearchLimits:
    return SearchLimits(
        max_sequence_length=manifest_limits.max_sequence_length,
        max_variants=manifest_limits.max_variants,
        candidate_budget=config.candidate_budget or manifest_limits.candidate_budget,
        transaction_budget=(
            config.transaction_budget or manifest_limits.transaction_budget
        ),
        wall_seconds=config.wall_seconds or manifest_limits.wall_seconds,
    )


def _strategy_config_hash(config: StrategyConfig) -> str:
    return _sha256(_canonical(config.model_dump(mode="json")))


def make_strategy(config: StrategyConfig):
    """Create a fresh built-in strategy from public configuration only."""
    if config.name == "random":
        from qprover.search.random import RandomStrategy

        return RandomStrategy(proposal_attempts=config.proposal_attempts)
    if config.name == "coverage":
        from qprover.search.coverage import CoverageGuidedStrategy

        return CoverageGuidedStrategy(proposal_attempts=config.proposal_attempts)
    if config.name == "risk":
        from qprover.search.risk import RiskGuidedStrategy

        return RiskGuidedStrategy(beam_width=config.beam_width)
    from qprover.search.qubo import QuboStrategy

    if config.backend == "annealing":
        from qprover.search.annealing import SimulatedAnnealingBackend

        class _ConfiguredAnnealingBackend(SimulatedAnnealingBackend):
            def sample(self, bqm, config_obj=None, **overrides):
                if config_obj is not None:
                    return super().sample(bqm, config_obj)
                return super().sample(
                    bqm,
                    seed=overrides.get("seed", 0),
                    reads=overrides.get("reads", config.reads),
                    sweeps=config.sweeps,
                    temperature_start=config.temperature_start,
                    temperature_end=config.temperature_end,
                )

        backend = _ConfiguredAnnealingBackend()
    else:
        from qprover.search.exact import ExactBackend

        backend = ExactBackend(max_bits=config.exact_max_bits)
    return QuboStrategy(
        backend=backend,
        reads=config.reads,
        feedback_batch_size=config.feedback_batch_size,
        resample_attempts=config.resample_attempts,
        max_exact_fallback_sequences=config.max_exact_fallback_sequences,
    )


def _source_identity(workspace_root: Path) -> str:
    paths = tuple((workspace_root / "src/qprover").rglob("*.py"))
    return _tree_sha(paths, workspace_root)


def _build_matrix(
    suite_path: Path, config_path: Path, workspace_root: Path
) -> BenchmarkMatrix:
    """Freeze label-neutral execution identity before any benchmark cell runs."""
    from qprover.artifacts import build_target
    from qprover.pipeline import prepare_search

    suite = load_suite(suite_path)
    config = load_config(config_path)
    benchmark_root = suite_path.parent.resolve()
    targets: list[BenchmarkTargetIdentity] = []
    selected_manifests, _ = selected_matrix_axes(suite, config)
    for rel in selected_manifests:
        manifest_path = (benchmark_root / rel).resolve()
        manifest = load_manifest(manifest_path)
        limits = effective_limits(manifest.limits, config)
        with build_target(manifest, offline=True) as bundle:
            prepared = prepare_search(manifest, bundle)
            build_payload = [
                {
                    "source": artifact.source_name,
                    "contract": artifact.contract_name,
                    "artifact_sha256": artifact.artifact_sha256,
                    "bytecode_sha256": artifact.bytecode_sha256,
                }
                for artifact in bundle.artifacts
            ]
        targets.append(
            BenchmarkTargetIdentity(
                public_target_id=manifest.target.id,
                manifest_path=rel,
                manifest_sha256=canonical_manifest_hash(manifest),
                source_closure_sha256=_sha256(
                    _canonical(
                        sorted(
                            (unit.source_name, unit.source_sha256)
                            for unit in bundle.source_units
                        )
                    )
                ),
                build_sha256=_sha256(_canonical(build_payload)),
                problem_sha256=prepared.problem_sha256,
                effective_limits=limits,
            )
        )
    toolchain = ToolchainIdentity(
        python=platform.python_version(),
        uv=_tool_version("uv"),
        forge=_tool_version("forge"),
        anvil=_tool_version("anvil"),
    )
    revision, dirty = _git_state(workspace_root)
    raw = {
        "schema_version": "1.0",
        "suite_sha256": _sha256(_canonical(suite.model_dump(mode="json"))),
        "config_sha256": _sha256(_canonical(config.model_dump(mode="json"))),
        "qprover_source_sha256": _source_identity(workspace_root),
        "lockfile_sha256": _file_sha(workspace_root / "uv.lock"),
        "toolchain": toolchain.model_dump(mode="json"),
        "git_revision": revision,
        "git_dirty": dirty,
        "targets": [item.model_dump(mode="json") for item in targets],
    }
    return BenchmarkMatrix(matrix_id=_sha256(_canonical(raw)), **raw)


def write_matrix(matrix: BenchmarkMatrix, path: Path) -> Path:
    payload = _canonical(matrix.model_dump(mode="json")) + "\n"
    _verify_parent_chain(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    _verify_parent_chain(path)
    if path.exists() or path.is_symlink():
        record = os.lstat(path)
        if not stat.S_ISREG(record.st_mode) or record.st_nlink != 1:
            raise ValueError("matrix target must be a single-link regular file")
        existing = BenchmarkMatrix.model_validate(
            _json_loads_strict(path.read_text(encoding="utf-8"))
        )
        if existing != matrix:
            raise ValueError("existing matrix identity differs; refusing overwrite")
        return path
    safe_atomic_write(path, payload, replace=False)
    return path


def _verify_parent_chain(path: Path) -> None:
    current = path.absolute().parent
    components = list(current.parents)[::-1] + [current]
    for item in components:
        if not item.exists():
            continue
        record = os.lstat(item)
        if stat.S_ISLNK(record.st_mode) or not stat.S_ISDIR(record.st_mode):
            raise ValueError("journal parent chain must contain only real directories")


def _validate_journal_target(path: Path) -> None:
    _verify_parent_chain(path)
    if not path.exists():
        return
    record = os.lstat(path)
    if not stat.S_ISREG(record.st_mode) or record.st_nlink != 1:
        raise ValueError("journal must be a single-link regular file")


def load_matrix(path: Path) -> BenchmarkMatrix:
    """Load one frozen matrix through the same strict local-file boundary."""

    _verify_parent_chain(path)
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except FileNotFoundError as error:
        raise ValueError("benchmark matrix is missing") from error
    except OSError as error:
        if error.errno in {errno.ELOOP, errno.ENOTDIR}:
            raise ValueError(
                "benchmark matrix must be a single-link regular file"
            ) from error
        raise
    try:
        _verify_open_regular(path, descriptor, "benchmark matrix")
        chunks: list[bytes] = []
        while True:
            chunk = os.read(descriptor, 65536)
            if not chunk:
                break
            chunks.append(chunk)
        _verify_open_regular(path, descriptor, "benchmark matrix")
    finally:
        os.close(descriptor)
    raw = _json_loads_strict(b"".join(chunks).decode())
    return BenchmarkMatrix.model_validate(raw)


def _validate_row_artifacts(row: BenchmarkRun, artifact_root: Path) -> None:
    root = artifact_root.resolve()
    for artifact in row.artifacts.values():
        lexical_artifact = root / artifact.path
        _verify_parent_chain(lexical_artifact)
        try:
            record = os.lstat(lexical_artifact)
        except FileNotFoundError as error:
            raise ValueError("journal artifact is missing") from error
        if not stat.S_ISREG(record.st_mode) or record.st_nlink != 1:
            raise ValueError("journal artifact must be a single-link regular file")
        artifact_path = lexical_artifact.resolve()
        try:
            artifact_path.relative_to(root)
        except ValueError as error:
            raise ValueError("journal artifact escaped benchmark root") from error
        if _file_sha(artifact_path) != artifact.sha256:
            raise ValueError("journal artifact hash validation failed")


def load_run_journal(
    path: Path, *, matrix_id: str | None = None
) -> tuple[BenchmarkRun, ...]:
    _verify_parent_chain(path)
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except FileNotFoundError:
        return ()
    except OSError as error:
        if error.errno in {errno.ELOOP, errno.ENOTDIR}:
            raise ValueError("journal must be a single-link regular file") from error
        raise
    try:
        _verify_open_regular(path, descriptor, "journal")
        chunks: list[bytes] = []
        while True:
            chunk = os.read(descriptor, 65536)
            if not chunk:
                break
            chunks.append(chunk)
        _verify_open_regular(path, descriptor, "journal")
    finally:
        os.close(descriptor)
    data = b"".join(chunks)
    if data and not data.endswith(b"\n"):
        raise ValueError("journal has a partial trailing line")
    rows: list[BenchmarkRun] = []
    seen: set[str] = set()
    seen_matrix: str | None = None
    for raw_line in data.splitlines():
        if not raw_line:
            raise ValueError("journal contains an empty row")
        raw = _json_loads_strict(raw_line.decode())
        row = BenchmarkRun.model_validate(raw)
        _validate_row_artifacts(row, path.parent)
        if row.run_key in seen:
            raise ValueError("duplicate/conflicting benchmark run key")
        seen.add(row.run_key)
        if seen_matrix is None:
            seen_matrix = row.matrix_id
        elif row.matrix_id != seen_matrix:
            raise ValueError("journal mixes matrix identities")
        if matrix_id is not None and row.matrix_id != matrix_id:
            raise ValueError("journal row belongs to another matrix")
        rows.append(row)
    return tuple(rows)


def _verify_open_regular(path: Path, descriptor: int, label: str) -> None:
    opened = os.fstat(descriptor)
    visible = os.lstat(path)
    if (
        not stat.S_ISREG(opened.st_mode)
        or opened.st_nlink != 1
        or not stat.S_ISREG(visible.st_mode)
        or visible.st_nlink != 1
        or (opened.st_dev, opened.st_ino) != (visible.st_dev, visible.st_ino)
    ):
        raise ValueError(f"{label} must remain one single-link regular file")


def append_run(path: Path, row: BenchmarkRun) -> None:
    """Append one validated self-hashed row under an advisory lock."""

    # Check existing ancestors before creation so a pre-existing symlink cannot
    # redirect mkdir into another tree. Recheck after creation for fail-closed
    # behavior under cooperative races.
    _verify_parent_chain(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    _validate_journal_target(path)
    _validate_row_artifacts(row, path.parent)

    lock = path.with_name(path.name + ".lock")
    _validate_journal_target(lock)
    lock_flags = os.O_RDWR | os.O_CREAT
    if hasattr(os, "O_NOFOLLOW"):
        lock_flags |= os.O_NOFOLLOW
    lock_fd = os.open(lock, lock_flags, 0o600)
    try:
        _verify_open_regular(lock, lock_fd, "journal lock")
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
        existing = load_run_journal(path, matrix_id=row.matrix_id)
        if any(item.run_key == row.run_key for item in existing):
            raise ValueError("benchmark run key is already committed")

        # Validate the new evidence again while holding the journal lock.
        _validate_row_artifacts(row, path.parent)
        flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        fd = os.open(path, flags, 0o600)
        try:
            _verify_open_regular(path, fd, "journal")
            payload = (_canonical(row.model_dump(mode="json")) + "\n").encode()
            written = os.write(fd, payload)
            if written != len(payload):
                raise OSError("short journal append")
            os.fsync(fd)
        finally:
            os.close(fd)
    finally:
        fcntl.flock(lock_fd, fcntl.LOCK_UN)
        os.close(lock_fd)


def _artifact_hashes(result, benchmark_root: Path) -> dict[str, dict[str, str]]:
    paths = {
        "result": result.result_path,
        "certificate": result.certificate_path,
        "markdown": result.markdown_path,
        "poc": result.poc_path,
        "events": result.events_path,
        "qubo": result.qubo_path,
    }
    records: dict[str, dict[str, str]] = {}
    base = benchmark_root.resolve()
    for name, path in paths.items():
        if path is None or not path.is_file():
            continue
        resolved = path.resolve()
        try:
            relative = resolved.relative_to(base).as_posix()
        except ValueError as error:
            raise ValueError("proof artifact escaped benchmark output root") from error
        records[name] = {"path": relative, "sha256": _file_sha(resolved)}
    return records


def _exact_nonnegative_int(value: object, field: str) -> int:
    if type(value) is not int or value < 0:
        raise ValueError(f"{field} must be a nonnegative exact integer")
    return value


def _finite_nonnegative(value: object, field: str) -> float:
    if type(value) not in (int, float):
        raise ValueError(f"{field} must be a finite nonnegative number")
    converted = float(value)
    if not (converted >= 0.0 and converted < float("inf")):
        raise ValueError(f"{field} must be a finite nonnegative number")
    return converted


def _qubo_summary(
    path: Path | None,
    error: str | None,
    *,
    expected_problem_sha256: str,
) -> StrategyEvidence:
    if path is None:
        return QuboUnavailableEvidence(
            kind="qubo_unavailable",
            reason=(error or "QUBO evidence was not produced")[:512],
        )

    raw = _json_loads_strict(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError("QUBO evidence must be a JSON object")
    if raw.get("schema_version") != "1.0" or raw.get("strategy") != "qubo":
        raise ValueError("QUBO evidence has an unexpected schema or strategy")
    if raw.get("problem_sha256") != expected_problem_sha256:
        raise ValueError("QUBO evidence is bound to another search problem")
    if raw.get("prepared_problem_sha256") != expected_problem_sha256:
        raise ValueError("published QUBO evidence lost prepared-problem binding")

    builds = raw.get("builds")
    if not isinstance(builds, list):
        raise ValueError("QUBO evidence builds must be a list")
    reads = 0
    sweeps = 0
    solver_seconds = 0.0
    max_bits = 0
    max_couplers = 0
    decoded_feasible = 0
    decoded_infeasible = 0
    model_hashes: set[str] = set()
    for index, item in enumerate(builds):
        if not isinstance(item, dict):
            raise ValueError("QUBO build evidence must contain objects")
        model_sha = item.get("model_sha256")
        problem_sha = item.get("problem_sha256")
        if (
            type(model_sha) is not str
            or len(model_sha) != 64
            or any(ch not in "0123456789abcdef" for ch in model_sha)
            or type(problem_sha) is not str
            or len(problem_sha) != 64
            or any(ch not in "0123456789abcdef" for ch in problem_sha)
        ):
            raise ValueError("QUBO build evidence contains an invalid model hash")
        if model_sha in model_hashes and item.get("build_index") != index:
            raise ValueError("QUBO build evidence has inconsistent build indices")
        model_hashes.add(model_sha)
        if _exact_nonnegative_int(item.get("build_index"), "QUBO build index") != index:
            raise ValueError("QUBO build evidence indices are not contiguous")
        logical_bits = _exact_nonnegative_int(
            item.get("logical_bits"), "QUBO logical bits"
        )
        couplers = _exact_nonnegative_int(item.get("couplers"), "QUBO couplers")
        model = item.get("model")
        if not isinstance(model, dict):
            raise ValueError("QUBO build omitted embedded model evidence")
        if model.get("problem_sha256") != problem_sha:
            raise ValueError("QUBO embedded model lost problem-hash binding")
        if _sha256(_canonical(model)) != model_sha:
            raise ValueError("QUBO embedded model hash does not match model_sha256")
        variables = model.get("variables")
        quadratic = model.get("quadratic")
        if not isinstance(variables, list) or len(variables) != logical_bits:
            raise ValueError("QUBO logical-bit count disagrees with embedded model")
        if not isinstance(quadratic, list) or len(quadratic) != couplers:
            raise ValueError("QUBO coupler count disagrees with embedded model")
        max_bits = max(max_bits, logical_bits)
        max_couplers = max(max_couplers, couplers)
        decoded_feasible += _exact_nonnegative_int(
            item.get("decoded_feasible"), "QUBO decoded feasible"
        )
        decoded_infeasible += _exact_nonnegative_int(
            item.get("decoded_infeasible"), "QUBO decoded infeasible"
        )
        solver = item.get("solver")
        if not isinstance(solver, dict):
            raise ValueError("QUBO build omitted solver evidence")
        if (
            _exact_nonnegative_int(
                solver.get("logical_bits"), "QUBO solver logical bits"
            )
            != logical_bits
        ):
            raise ValueError("QUBO solver logical bits disagree with embedded model")
        build_reads = solver.get("reads", solver.get("reads_requested"))
        reads += _exact_nonnegative_int(build_reads, "QUBO solver reads")
        if "sweeps" in solver:
            sweeps += _exact_nonnegative_int(solver["sweeps"], "QUBO solver sweeps")
        solver_seconds += _finite_nonnegative(
            solver.get("wall_seconds"), "QUBO solver wall time"
        )

    totals = raw.get("solver_totals")
    if not isinstance(totals, dict):
        raise ValueError("QUBO evidence omitted cumulative solver totals")
    if _exact_nonnegative_int(totals.get("calls"), "QUBO solver calls") != len(builds):
        raise ValueError("QUBO solver call total disagrees with build evidence")
    if _exact_nonnegative_int(totals.get("reads"), "QUBO total reads") != reads:
        raise ValueError("QUBO read total disagrees with build evidence")
    if _exact_nonnegative_int(totals.get("sweeps"), "QUBO total sweeps") != sweeps:
        raise ValueError("QUBO sweep total disagrees with build evidence")
    if (
        _exact_nonnegative_int(
            totals.get("decoded_feasible"), "QUBO total decoded feasible"
        )
        != decoded_feasible
    ):
        raise ValueError("QUBO decoded-feasible total disagrees with build evidence")
    if (
        _exact_nonnegative_int(
            totals.get("decoded_infeasible"), "QUBO total decoded infeasible"
        )
        != decoded_infeasible
    ):
        raise ValueError("QUBO decoded-infeasible total disagrees with build evidence")
    recorded_solver_seconds = _finite_nonnegative(
        totals.get("wall_seconds"), "QUBO total solver wall time"
    )
    recorded_compute_seconds = _finite_nonnegative(
        totals.get("compute_wall_seconds"), "QUBO total compute wall time"
    )
    # Timing is accumulated from the same per-build metadata; tolerate only tiny
    # floating-point summation differences.
    if abs(recorded_solver_seconds - solver_seconds) > 1e-9 * max(
        1.0, recorded_solver_seconds, solver_seconds
    ):
        raise ValueError("QUBO solver time total disagrees with build evidence")

    fallback = raw.get("fallback")
    if not isinstance(fallback, dict):
        raise ValueError("QUBO evidence omitted fallback accounting")
    fallback_calls = _exact_nonnegative_int(
        fallback.get("calls"), "QUBO fallback calls"
    )
    fallback_seconds = _finite_nonnegative(
        fallback.get("wall_seconds"), "QUBO fallback wall time"
    )
    records = fallback.get("records")
    if not isinstance(records, list) or len(records) != fallback_calls:
        raise ValueError("QUBO fallback records disagree with fallback call total")
    expected_compute = recorded_solver_seconds + fallback_seconds
    if abs(recorded_compute_seconds - expected_compute) > 1e-9 * max(
        1.0, recorded_compute_seconds, expected_compute
    ):
        raise ValueError("QUBO compute time disagrees with solver/fallback evidence")

    return QuboStrategyEvidence(
        kind="qubo",
        evidence_sha256=_file_sha(path),
        builds=len(builds),
        solver_calls=len(builds),
        reads=reads,
        sweeps=sweeps,
        solver_seconds=recorded_solver_seconds,
        fallback_calls=fallback_calls,
        fallback_seconds=fallback_seconds,
        max_logical_bits=max_bits,
        max_couplers=max_couplers,
    )


def seal_run(raw: dict[str, object]) -> BenchmarkRun:
    if "row_sha256" in raw:
        raise ValueError("seal_run input must not contain row_sha256")
    digest = _sha256(_canonical(raw))
    return BenchmarkRun.model_validate({**raw, "row_sha256": digest})


def expected_run_keys(
    matrix: BenchmarkMatrix, suite: BenchmarkSuite, config: BenchmarkConfig
) -> tuple[str, ...]:
    targets = {item.manifest_path: item for item in matrix.targets}
    keys = []
    toolchain_sha = _sha256(_canonical(matrix.toolchain.model_dump(mode="json")))
    selected_manifests, selected_seeds = selected_matrix_axes(suite, config)
    for rel in selected_manifests:
        target = targets[rel]
        for seed in selected_seeds:
            for strategy in config.strategies:
                identity = {
                    "matrix_id": matrix.matrix_id,
                    "target": target.public_target_id,
                    "strategy": strategy.name,
                    "strategy_config_sha256": _strategy_config_hash(strategy),
                    "seed": seed,
                    "limits": target.effective_limits.model_dump(mode="json"),
                    "manifest_sha256": target.manifest_sha256,
                    "source_closure_sha256": target.source_closure_sha256,
                    "build_sha256": target.build_sha256,
                    "problem_sha256": target.problem_sha256,
                    "qprover_source_sha256": matrix.qprover_source_sha256,
                    "lockfile_sha256": matrix.lockfile_sha256,
                    "toolchain_sha256": toolchain_sha,
                }
                keys.append(_sha256(_canonical(identity)))
    return tuple(keys)


def run_benchmark(
    *,
    suite_path: Path,
    config_path: Path,
    output: Path,
    workspace_root: Path,
) -> tuple[BenchmarkMatrix, tuple[BenchmarkRun, ...]]:
    """Execute the label-free matrix. This function has no labels argument by design."""
    import time

    from qprover.pipeline import prove_violation
    from qprover.runtime import ExecutionRuntime

    suite = load_suite(suite_path)
    config = load_config(config_path)
    workspace_root = workspace_root.resolve()
    output = output.resolve()
    matrix = _build_matrix(suite_path.resolve(), config_path.resolve(), workspace_root)
    output.mkdir(parents=True, exist_ok=True)
    write_matrix(matrix, output / "matrix.json")
    journal = output / "runs.jsonl"
    committed = {
        row.run_key: row
        for row in load_run_journal(journal, matrix_id=matrix.matrix_id)
    }
    target_by_rel = {item.manifest_path: item for item in matrix.targets}
    toolchain_sha = _sha256(_canonical(matrix.toolchain.model_dump(mode="json")))

    with ExecutionRuntime.activate():
        selected_manifests, selected_seeds = selected_matrix_axes(suite, config)
        for target_index, rel in enumerate(selected_manifests):
            target = target_by_rel[rel]
            manifest_path = (suite_path.parent / rel).resolve()
            for seed_index, seed in enumerate(selected_seeds):
                # Deterministic counterbalancing rotates strategy order per
                # target/seed block.
                strategies = list(config.strategies)
                rotation = (target_index + seed_index) % len(strategies)
                strategies = strategies[rotation:] + strategies[:rotation]
                for strategy_config in strategies:
                    sc_hash = _strategy_config_hash(strategy_config)
                    key_payload = {
                        "matrix_id": matrix.matrix_id,
                        "target": target.public_target_id,
                        "strategy": strategy_config.name,
                        "strategy_config_sha256": sc_hash,
                        "seed": seed,
                        "limits": target.effective_limits.model_dump(mode="json"),
                        "manifest_sha256": target.manifest_sha256,
                        "source_closure_sha256": target.source_closure_sha256,
                        "build_sha256": target.build_sha256,
                        "problem_sha256": target.problem_sha256,
                        "qprover_source_sha256": matrix.qprover_source_sha256,
                        "lockfile_sha256": matrix.lockfile_sha256,
                        "toolchain_sha256": toolchain_sha,
                    }
                    run_key = _sha256(_canonical(key_payload))
                    if run_key in committed:
                        continue
                    strategy = make_strategy(strategy_config)
                    cell_output = output / "cells" / run_key
                    started = time.monotonic()
                    result = prove_violation(
                        manifest_path,
                        strategy=strategy,
                        seed=seed,
                        output=cell_output,
                        workspace_root=workspace_root,
                        limits=target.effective_limits,
                    )
                    total_seconds = time.monotonic() - started
                    search = result.search_run
                    artifacts = _artifact_hashes(result, output)
                    hit = (
                        bool(search.violation is not None)
                        if search is not None
                        else None
                    )
                    observation = (
                        "observed"
                        if hit
                        else "censored"
                        if search is not None
                        else None
                    )
                    if result.error is not None:
                        state = "failed"
                        confirmation = ConfirmationStatus.NOT_CONFIRMED
                    else:
                        state = "completed"
                        confirmation = result.status
                    evidence: StrategyEvidence
                    if strategy_config.name == "qubo":
                        evidence = _qubo_summary(
                            result.qubo_path,
                            result.error,
                            expected_problem_sha256=target.problem_sha256,
                        )
                    else:
                        evidence = NotApplicableStrategyEvidence(kind="not_applicable")
                    counts = (
                        {
                            outcome.value: count
                            for outcome, count in search.outcome_counts.items()
                        }
                        if search is not None
                        else {}
                    )
                    executed_violation = (
                        any(
                            item.evaluation.outcome.value == "VIOLATION"
                            for item in search.evaluations
                        )
                        if search is not None
                        else None
                    )
                    first_hit_candidate = (
                        search.candidates_evaluated
                        if hit and search is not None
                        else None
                    )
                    first_hit_transactions = (
                        search.evm_transactions if hit and search is not None else None
                    )
                    raw = {
                        "schema_version": "1.0",
                        "run_key": run_key,
                        "matrix_id": matrix.matrix_id,
                        "public_target_id": target.public_target_id,
                        "manifest_sha256": target.manifest_sha256,
                        "source_closure_sha256": target.source_closure_sha256,
                        "build_sha256": target.build_sha256,
                        "problem_sha256": target.problem_sha256,
                        "qprover_source_sha256": matrix.qprover_source_sha256,
                        "lockfile_sha256": matrix.lockfile_sha256,
                        "toolchain_sha256": toolchain_sha,
                        "strategy": strategy_config.name,
                        "strategy_config_sha256": sc_hash,
                        "seed": seed,
                        "effective_limits": target.effective_limits.model_dump(
                            mode="json"
                        ),
                        "state": state,
                        "confirmation_status": confirmation.value,
                        "stop_reason": (
                            search.stop_reason if search is not None else None
                        ),
                        "error": result.error,
                        "executed_violation": executed_violation,
                        "search_hit": hit,
                        "proof_attempted": (bool(hit) if search is not None else None),
                        "hit_observation": observation,
                        "candidates_evaluated": (
                            search.candidates_evaluated if search is not None else None
                        ),
                        "duplicate_proposals": (
                            search.duplicate_proposals if search is not None else None
                        ),
                        "unique_trace_features": (
                            len(
                                set().union(
                                    *(
                                        item.evaluation.trace_features
                                        for item in search.evaluations
                                    )
                                )
                            )
                            if search is not None and search.evaluations
                            else (0 if search is not None else None)
                        ),
                        "search_transactions": (
                            search.evm_transactions if search is not None else None
                        ),
                        "total_transactions": None,
                        "minimized_steps": result.minimized_steps,
                        "first_hit_candidate": first_hit_candidate,
                        "first_hit_transactions": first_hit_transactions,
                        "outcome_counts": counts,
                        "certificate_sha256": result.certificate_sha256,
                        "cold_replays": (
                            3 if result.status is ConfirmationStatus.CONFIRMED else None
                        ),
                        "artifacts": artifacts,
                        "strategy_evidence": evidence.model_dump(mode="json"),
                        "timings": {
                            "total_seconds": float(total_seconds),
                            "strategy_initialization_seconds": (
                                float(search.initialization_seconds)
                                if search is not None
                                else None
                            ),
                            "search_seconds": (
                                float(search.search_seconds)
                                if search is not None
                                else None
                            ),
                            "setup_seconds": None,
                            "proof_seconds": None,
                        },
                    }
                    row = seal_run(raw)
                    append_run(journal, row)
                    committed[run_key] = row
    rows = load_run_journal(journal, matrix_id=matrix.matrix_id)
    expected = set(expected_run_keys(matrix, suite, config))
    if {row.run_key for row in rows} != expected:
        raise ValueError("benchmark matrix is incomplete after execution")
    return matrix, rows


def load_labels(path: Path) -> tuple[dict[str, BenchmarkLabel], str]:
    raw_bytes = path.read_bytes()
    raw = _json_loads_strict(raw_bytes.decode())
    if not isinstance(raw, dict):
        raise ValueError("labels must be an object")
    labels = {key: BenchmarkLabel.model_validate(value) for key, value in raw.items()}
    return labels, _sha256(raw_bytes)


def score_complete_matrix(
    *,
    matrix: BenchmarkMatrix,
    suite: BenchmarkSuite,
    config: BenchmarkConfig,
    runs: Sequence[BenchmarkRun],
    labels_path: Path,
) -> tuple[BenchmarkScore, ...]:
    suite_sha = _sha256(_canonical(suite.model_dump(mode="json")))
    config_sha = _sha256(_canonical(config.model_dump(mode="json")))
    if suite_sha != matrix.suite_sha256:
        raise ValueError("suite identity does not match the frozen benchmark matrix")
    if config_sha != matrix.config_sha256:
        raise ValueError("config identity does not match the frozen benchmark matrix")

    expected = set(expected_run_keys(matrix, suite, config))
    by_key = {row.run_key: row for row in runs}
    if set(by_key) != expected or len(by_key) != len(runs):
        raise ValueError("labels cannot be opened until the full matrix is terminal")
    if any(row.state == "incomplete" for row in runs):
        raise ValueError("incomplete matrix cannot be scored")
    labels, labels_sha = load_labels(labels_path)
    scores: list[BenchmarkScore] = []
    for row in sorted(runs, key=lambda item: item.run_key):
        label = labels.get(row.public_target_id)
        if label is None:
            raise ValueError(f"missing scorer label for {row.public_target_id}")
        if row.state == "failed":
            predicted = "failure"
        elif row.confirmation_status is ConfirmationStatus.CONFIRMED:
            predicted = "positive"
        else:
            predicted = "negative"
        raw = {
            "schema_version": "1.0",
            "run_key": row.run_key,
            "matrix_id": row.matrix_id,
            "public_target_id": row.public_target_id,
            "strategy": row.strategy,
            "seed": row.seed,
            "expected": label.expected,
            "predicted": predicted,
            "correct": (
                (label.expected == "positive" and predicted == "positive")
                or (label.expected == "negative" and predicted == "negative")
            ),
            "false_confirmed": label.expected == "negative" and predicted == "positive",
            "family": label.family,
            "pair": label.pair,
            "raw_row_sha256": row.row_sha256,
            "labels_sha256": labels_sha,
        }
        digest = _sha256(_canonical(raw))
        scores.append(BenchmarkScore(score_sha256=digest, **raw))
    return tuple(scores)


def write_scores(path: Path, scores: Sequence[BenchmarkScore]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = "".join(
        _canonical(item.model_dump(mode="json")) + "\n"
        for item in sorted(scores, key=lambda item: item.run_key)
    )
    safe_atomic_write(path, payload)
    return path


def write_published_schemas(schema_dir: Path) -> None:
    schema_dir.mkdir(parents=True, exist_ok=True)
    for name, model in (
        ("benchmark-suite.schema.json", BenchmarkSuite),
        ("benchmark-run.schema.json", BenchmarkRun),
        ("benchmark-score.schema.json", BenchmarkScore),
    ):
        payload = json.dumps(model.model_json_schema(), indent=2, sort_keys=True) + "\n"
        (schema_dir / name).write_text(payload, encoding="utf-8")


__all__ = [
    "BenchmarkArtifact",
    "BenchmarkConfig",
    "BenchmarkLabel",
    "BenchmarkMatrix",
    "BenchmarkRun",
    "BenchmarkScore",
    "BenchmarkSuite",
    "append_run",
    "effective_limits",
    "expected_run_keys",
    "load_config",
    "load_labels",
    "load_matrix",
    "load_run_journal",
    "load_suite",
    "make_strategy",
    "run_benchmark",
    "seal_run",
    "selected_matrix_axes",
    "score_complete_matrix",
    "write_matrix",
    "write_published_schemas",
    "write_scores",
]
