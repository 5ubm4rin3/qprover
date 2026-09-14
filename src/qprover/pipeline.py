"""Production orchestration from label-neutral manifests to executable evidence."""

from __future__ import annotations

import hashlib
import importlib.metadata
import json
import math
import secrets
import subprocess
import uuid
from collections.abc import Callable, Mapping
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import MappingProxyType
from typing import Literal

from eth_utils.abi import collapse_if_tuple
from pydantic import Field, StrictStr, model_validator

from qprover.analysis import AnalysisReport, analyze
from qprover.artifacts import ArtifactBundle, build_target
from qprover.certificate import (
    REPLAY_INVOCATION_TEMPLATE,
    ArtifactEvidence,
    AssumptionEvidence,
    AssuranceEvidence,
    BeforeAfterEvidence,
    BuildEvidence,
    ChainEvidence,
    EvidenceEvent,
    FundingEvidence,
    GasEvidence,
    ImpactEvidence,
    InvariantEvidence,
    MinimizationEvidence,
    PoCEvidence,
    SourceEvidence,
    StateEvidence,
    TargetEvidence,
    ToolchainEvidence,
    TransactionEvidence,
    create_certificate,
    write_certificate,
    write_events,
    write_markdown,
)
from qprover.evaluator import ScenarioEvaluator
from qprover.evm import LocalAnvil
from qprover.graph import ProgramGraph, build_program_graph
from qprover.hypotheses import (
    ActionFunction,
    Hypothesis,
    action_function_mapping,
    generate_hypotheses,
)
from qprover.manifest import load_manifest
from qprover.minimizer import MinimizationResult, minimize
from qprover.models import (
    Candidate,
    ConfirmationStatus,
    Outcome,
    SearchLimits,
    StrictModel,
    TargetManifest,
)
from qprover.parameters import expand_action_variants
from qprover.replay import cold_verify, foundry_poc_source, generate_foundry_poc
from qprover.runtime import ExecutionRuntime, current_runtime
from qprover.safeio import (
    SafeOutputError,
    create_private_directory,
    publish_private_directory,
    remove_private_directory,
    safe_atomic_write,
    validated_private_tree,
)
from qprover.search.base import SearchStrategy, candidate_is_valid, thaw_json
from qprover.search.bqm import SearchProblem
from qprover.search.controller import SearchController, SearchEvent, SearchRun


@dataclass(frozen=True, slots=True)
class PreparedSearch:
    report: AnalysisReport
    graph: ProgramGraph
    hypotheses: tuple[Hypothesis, ...]
    problem: SearchProblem
    problem_sha256: str
    action_functions: Mapping[str, ActionFunction]
    objective_provenance: Mapping[str, object]


@dataclass(frozen=True, slots=True)
class SearchExecution:
    prepared: PreparedSearch
    search_run: SearchRun
    started_at: datetime
    finished_at: datetime
    strategy_evidence: Mapping[str, object] | None


@dataclass(frozen=True, slots=True)
class ProofBundleResult:
    status: ConfirmationStatus
    output_root: Path
    search_run: SearchRun | None = None
    problem_sha256: str | None = None
    certificate_path: Path | None = None
    markdown_path: Path | None = None
    poc_path: Path | None = None
    events_path: Path | None = None
    qubo_path: Path | None = None
    certificate_sha256: str | None = None
    minimized_steps: int | None = None
    result_path: Path | None = None
    run_id: str | None = None
    error: str | None = None
    durability_warning: str | None = None


class ProofRunArtifact(StrictModel):
    path: StrictStr = Field(min_length=1)
    sha256: StrictStr = Field(pattern=r"^[0-9a-f]{64}$")


class ProofRunResult(StrictModel):
    schema_version: Literal["1.0"]
    run_id: StrictStr = Field(min_length=1)
    confirmation_status: ConfirmationStatus
    disposition: Literal["confirmed", "not_confirmed", "failed"]
    error: StrictStr | None
    artifacts: Mapping[StrictStr, ProofRunArtifact]

    @model_validator(mode="after")
    def consistent(self) -> ProofRunResult:
        names = set(self.artifacts)
        proof = {"certificate", "markdown", "poc"}
        if self.disposition == "confirmed":
            if (
                self.confirmation_status is not ConfirmationStatus.CONFIRMED
                or self.error
            ):
                raise ValueError("confirmed result must be confirmed without error")
            allowed = {"certificate", "markdown", "poc", "events", "qubo"}
            if not proof <= names or "events" not in names or not names <= allowed:
                raise ValueError("confirmed result is missing required proof artifacts")
        elif self.disposition == "not_confirmed":
            if (
                self.confirmation_status is not ConfirmationStatus.NOT_CONFIRMED
                or names & proof
                or self.error is not None
            ):
                raise ValueError("not-confirmed result cannot carry proof artifacts")
        elif self.disposition == "failed":
            if (
                self.confirmation_status is not ConfirmationStatus.NOT_CONFIRMED
                or not self.error
                or names
            ):
                raise ValueError("failed result requires an error and no artifacts")
        else:
            raise ValueError("invalid result disposition")
        return self


def monotonic_events_to_evidence(
    events: tuple[SearchEvent, ...], started_at: datetime
) -> tuple[EvidenceEvent, ...]:
    """Anchor ordered monotonic offsets to one captured UTC wall timestamp."""

    if started_at.tzinfo is None or started_at.utcoffset() != timedelta(0):
        raise ValueError("search start timestamp must be UTC")
    anchored = started_at.astimezone(UTC)
    converted: list[EvidenceEvent] = []
    prior_offset = 0.0
    for index, event in enumerate(events, start=1):
        offset = event.timestamp_offset
        if type(offset) not in (int, float) or not math.isfinite(offset) or offset < 0:
            raise ValueError("search event offset must be finite and nonnegative")
        if offset < prior_offset:
            raise ValueError("search event offsets must remain ordered")
        converted.append(
            EvidenceEvent(
                run_id=event.run_id,
                sequence=index,
                timestamp=anchored + timedelta(seconds=offset),
                kind="search",
                details=event.to_dict(),
            )
        )
        prior_offset = offset
    return tuple(converted)


def prepare_search(
    manifest: TargetManifest,
    bundle: ArtifactBundle,
) -> PreparedSearch:
    """Create the complete public optimization input from compiler evidence."""

    if bundle.closed:
        raise ValueError("artifact bundle must be live")
    report = analyze(bundle)
    graph = build_program_graph(report)
    mapping = action_function_mapping(graph, manifest)
    hypotheses = generate_hypotheses(graph, manifest)
    action_ids = tuple(action.id for action in manifest.actions)

    membership: dict[str, float] = {action_id: 0.0 for action_id in action_ids}
    for hypothesis in hypotheses:
        for action_id in hypothesis.action_ids:
            membership[action_id] = max(membership[action_id], hypothesis.score)
    utilities = {
        action_id: round(
            min(
                1.0,
                graph.action_utility(mapping[action_id].function_id)
                + 0.25 * membership[action_id],
            ),
            6,
        )
        for action_id in action_ids
    }

    actions_by_function: dict[str, tuple[str, ...]] = {}
    for action_id, resolved in mapping.items():
        actions_by_function[resolved.function_id] = (
            *actions_by_function.get(resolved.function_id, ()),
            action_id,
        )
    transitions: dict[tuple[str, str], float] = {}
    transition_sources: dict[str, list[str]] = {}
    for edge in graph.edges:
        if edge.kind != "depends_on":
            continue
        for source in actions_by_function.get(edge.source, ()):
            for target in actions_by_function.get(edge.target, ()):
                key = (source, target)
                transitions[key] = max(
                    transitions.get(key, 0.0),
                    graph.transition_benefit(edge.source, edge.target),
                )
                transition_sources.setdefault(f"{source}->{target}", []).extend(
                    edge.provenance
                )
    for hypothesis in hypotheses:
        for source, target in zip(
            hypothesis.action_ids, hypothesis.action_ids[1:], strict=False
        ):
            key = (source, target)
            transitions[key] = max(transitions.get(key, 0.0), hypothesis.score)
            transition_sources.setdefault(f"{source}->{target}", []).extend(
                hypothesis.provenance
            )

    problem = SearchProblem(
        actions=action_ids,
        max_sequence_length=manifest.limits.max_sequence_length,
        utilities=utilities,
        transitions=transitions,
        repetition_limits={
            action.id: action.max_repetitions for action in manifest.actions
        },
        discounts=tuple(
            1.0 / (position + 1)
            for position in range(manifest.limits.max_sequence_length)
        ),
        variants=expand_action_variants(manifest, report),
        hypothesis_sequences=tuple(
            sorted({hypothesis.action_ids for hypothesis in hypotheses})
        ),
    )
    provenance: Mapping[str, object] = MappingProxyType(
        {
            "utility": MappingProxyType(
                {
                    action_id: (
                        *mapping[action_id].provenance,
                        *tuple(
                            hypothesis.evidence_hash
                            for hypothesis in hypotheses
                            if action_id in hypothesis.action_ids
                        ),
                        *tuple(
                            item
                            for hypothesis in hypotheses
                            if action_id in hypothesis.action_ids
                            for item in hypothesis.provenance
                        ),
                    )
                    for action_id in action_ids
                }
            ),
            "transition": MappingProxyType(
                {
                    key: tuple(sorted(set(values)))
                    for key, values in sorted(transition_sources.items())
                }
            ),
        }
    )
    return PreparedSearch(
        report=report,
        graph=graph,
        hypotheses=hypotheses,
        problem=problem,
        problem_sha256=problem.sha256,
        action_functions=MappingProxyType(dict(mapping)),
        objective_provenance=provenance,
    )


def run_search(
    manifest: TargetManifest,
    bundle: ArtifactBundle,
    *,
    strategy: SearchStrategy,
    seed: int,
    limits: SearchLimits | None = None,
    anvil_factory: Callable[[], LocalAnvil] = LocalAnvil,
    run_id: str | None = None,
) -> SearchExecution:
    """Prepare and execute one strategy entirely against an owned local Anvil."""

    prepared = prepare_search(manifest, bundle)
    effective_limits = limits or manifest.limits
    if effective_limits.max_sequence_length != prepared.problem.max_sequence_length:
        raise ValueError("search limit horizon must match the prepared problem")
    started_at = datetime.now(UTC)
    with anvil_factory() as anvil:
        evaluator = ScenarioEvaluator(manifest, bundle, anvil)

        def validator(candidate: Candidate) -> bool:
            return candidate_is_valid(prepared.problem, candidate)

        if run_id is not None:
            if not run_id or any(
                character not in "0123456789abcdef" for character in run_id
            ):
                raise ValueError("run_id must be nonempty lowercase hexadecimal")
            controller = SearchController(
                candidate_validator=validator, run_id_factory=lambda: run_id
            )
        else:
            controller = SearchController(candidate_validator=validator)
        run = controller.run(
            strategy,
            evaluator,
            effective_limits,
            problem=prepared.problem,
            seed=seed,
        )
    finished_at = datetime.now(UTC)
    raw_evidence = getattr(strategy, "evidence", None)
    strategy_evidence = (
        MappingProxyType(dict(raw_evidence))
        if isinstance(raw_evidence, Mapping)
        else None
    )
    return SearchExecution(
        prepared=prepared,
        search_run=run,
        started_at=started_at,
        finished_at=finished_at,
        strategy_evidence=strategy_evidence,
    )


def _digest(value: bytes | str) -> str:
    data = value.encode() if isinstance(value, str) else value
    return hashlib.sha256(data).hexdigest()


def _state(values: Mapping[str, int | bool]) -> StateEvidence:
    plain = dict(values)
    return StateEvidence(
        values=plain,
        state_sha256=_digest(json.dumps(plain, sort_keys=True, separators=(",", ":"))),
    )


def _trace_hash(record: Mapping[str, object]) -> str:
    return _digest(
        json.dumps(
            {
                "trace_struct_log_count": record["trace_struct_log_count"],
                "call_trace_count": record["call_trace_count"],
                "trace_failed": record["trace_failed"],
                "return_data": record["return_data"],
            },
            sort_keys=True,
            separators=(",", ":"),
        )
    )


def _atomic_json(value: Mapping[str, object], output: Path) -> Path:
    payload = (
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
        + "\n"
    )
    return safe_atomic_write(output, payload)


def _revision(workspace_root: Path) -> str:
    commands: list[tuple[str, ...]] = []
    shadow = workspace_root / ".qprover-git"
    if shadow.is_dir():
        commands.append(
            (
                "git",
                f"--git-dir={shadow}",
                f"--work-tree={workspace_root}",
            )
        )
    commands.append(("git", "-C", str(workspace_root)))
    for prefix in commands:
        try:
            head = subprocess.run(
                (*prefix, "rev-parse", "HEAD"),
                capture_output=True,
                text=True,
                check=True,
            ).stdout.strip()
            dirty = bool(
                subprocess.run(
                    (*prefix, "status", "--porcelain"),
                    capture_output=True,
                    text=True,
                    check=True,
                ).stdout.strip()
            )
        except (OSError, subprocess.CalledProcessError):
            continue
        if len(head) == 40:
            return f"{head}{'+dirty' if dirty else '+clean'}"
    return "unavailable+unverified"


def _transaction_evidence(
    candidate: Candidate, evaluation_metadata: Mapping[str, object]
) -> tuple[TransactionEvidence, ...]:
    records = evaluation_metadata.get("steps")
    if not isinstance(records, (tuple, list)) or len(records) != len(candidate.steps):
        raise ValueError("final evaluation omitted exact transaction records")
    result: list[TransactionEvidence] = []
    for step, raw in zip(candidate.steps, records, strict=True):
        if not isinstance(raw, Mapping):
            raise ValueError("final evaluation contains malformed transaction evidence")
        transaction_hash = raw.get("transaction_hash")
        if not isinstance(transaction_hash, str) or not transaction_hash.startswith(
            "0x"
        ):
            raise ValueError("final evaluation contains malformed transaction hash")
        result.append(
            TransactionEvidence(
                index=raw["index"],
                action_id=step.action_id,
                target_id=step.target_id,
                signature=step.signature,
                sender_slot=step.sender_slot,
                args=step.args,
                value_wei=step.value_wei,
                calldata_sha256=raw["calldata_hash"],
                transaction_sha256=transaction_hash[2:],
                expected_success=raw["receipt_status"] == 1,
                receipt_status=raw["receipt_status"],
                gas_used=raw["gas_used"],
                return_data=raw["return_data"],
                revert_data=raw["revert_data"],
                trace_sha256=_trace_hash(raw),
                observation_state_sha256=raw["observation_state_hash"],
            )
        )
    return tuple(result)


def _certificate_data(
    *,
    manifest: TargetManifest,
    manifest_path: Path,
    workspace_root: Path,
    output_root: Path,
    bundle: ArtifactBundle,
    run: SearchRun,
    generated_at: datetime,
    minimization: MinimizationResult,
    final_evaluation: object,
    evaluator: ScenarioEvaluator,
    anvil: LocalAnvil,
    poc_sha256: str,
) -> dict[str, object]:
    if not hasattr(final_evaluation, "metadata"):
        raise ValueError("final evaluation evidence is unavailable")
    evaluation = final_evaluation
    metadata = evaluation.metadata
    if evaluation.outcome is not Outcome.VIOLATION:
        raise ValueError("final fresh evaluation is not a violation")
    if metadata.get("confirmation_policy") != manifest.confirmation.kind:
        raise ValueError("final evaluation confirmation policy mismatch")
    initial = metadata.get("initial_observations")
    current = metadata.get("current_observations")
    invariants = metadata.get("invariants")
    impact = metadata.get("impact")
    if not all(isinstance(item, Mapping) for item in (initial, current, impact)):
        raise ValueError("final evaluation omitted state or impact evidence")
    if not isinstance(invariants, (tuple, list)):
        raise ValueError("final evaluation omitted invariant evidence")
    false_records = tuple(
        item
        for item in invariants
        if isinstance(item, Mapping) and item.get("value") is False
    )
    if not false_records:
        raise ValueError("final evaluation omitted a false supplied invariant")
    selected_invariant_id = metadata.get("violated_invariant_id")
    invariant_record = next(
        (
            item
            for item in false_records
            if item.get("invariant_id") == selected_invariant_id
        ),
        None,
    )
    if invariant_record is None:
        raise ValueError("final evaluation changed the selected invariant")
    invariant = next(
        item
        for item in manifest.invariants
        if item.id == invariant_record.get("invariant_id")
    )
    transactions = _transaction_evidence(minimization.candidate, metadata)
    sources = tuple(
        SourceEvidence(path=unit.source_name, sha256=unit.source_sha256)
        for unit in bundle.source_units
    )
    artifacts = tuple(
        ArtifactEvidence(
            compilation_target=item.compilation_target,
            artifact_path=item.artifact_path.resolve()
            .relative_to(bundle.evidence_root.resolve())
            .as_posix(),
            artifact_sha256=item.artifact_sha256,
            bytecode_sha256=item.bytecode_sha256,
            build_info_id=item.build_info_id,
            build_info_sha256=bundle.build_info_sha256,
            constructor_types=tuple(
                collapse_if_tuple(dict(parameter))
                for entry in item.abi
                if entry.get("type") == "constructor"
                for parameter in entry.get("inputs", ())
            ),
        )
        for item in bundle.artifacts
    )
    primary_artifact = next(
        item
        for item in artifacts
        if item.compilation_target == manifest.deployments[0].artifact
    )
    initial_state = _state(initial)
    after_state = _state(current)
    if after_state.state_sha256 != evaluation.state_fingerprint:
        raise ValueError("final state hash does not match evaluator evidence")
    baseline_records = metadata.get("baseline_invariants")
    if not isinstance(baseline_records, (tuple, list)):
        raise ValueError("final evaluation omitted initial invariant evidence")
    baseline_by_id = {
        record.get("invariant_id"): record
        for record in baseline_records
        if isinstance(record, Mapping) and isinstance(record.get("invariant_id"), str)
    }
    if tuple(baseline_by_id) != tuple(item.id for item in manifest.invariants):
        raise ValueError("initial invariant evidence changed manifest order or set")
    initial_invariants_list: list[InvariantEvidence] = []
    for item in manifest.invariants:
        record = baseline_by_id[item.id]
        if (
            record.get("expression") != item.expression
            or record.get("status") != "evaluated"
            or record.get("value") is not True
        ):
            raise ValueError("initial invariant evidence is not baseline true")
        reason = record.get("reason")
        if reason is not None and not isinstance(reason, str):
            raise ValueError("initial invariant evidence has malformed reason")
        initial_invariants_list.append(
            InvariantEvidence(
                id=item.id,
                expression=item.expression,
                description=item.description,
                foundry_assertion=item.foundry_assertion,
                evaluated=True,
                value=True,
                reason=reason,
            )
        )
    initial_invariants = tuple(initial_invariants_list)
    if manifest.confirmation.kind == "invariant_and_economic_impact":
        if manifest.impact is None:
            raise ValueError("economic policy omitted impact accounting")
        impact_evidence = ImpactEvidence(
            applicability="economic",
            attacker_observation=manifest.impact.attacker_asset_observation,
            protocol_observation=manifest.impact.protocol_asset_observation,
            attacker_delta=impact["attacker_delta"],
            protocol_delta=impact["protocol_delta"],
            unit=impact["unit"],
            admissible=impact["admissible"],
            executed=True,
        )
    else:
        impact_evidence = ImpactEvidence(
            applicability="not_applicable",
            attacker_observation=None,
            protocol_observation=None,
            attacker_delta=None,
            protocol_delta=None,
            unit=None,
            admissible=False,
            executed=False,
        )
    try:
        version = importlib.metadata.version("qprover")
    except importlib.metadata.PackageNotFoundError:
        version = "0.1.0"
    return {
        "run_id": run.run_id,
        "generated_at": generated_at,
        "confirmation_status": ConfirmationStatus.NOT_CONFIRMED,
        "source_kind": "executed",
        "final_evaluation_outcome": evaluation.outcome,
        "confirmation_policy": manifest.confirmation.kind,
        "target": TargetEvidence(
            id=manifest.target.id,
            workspace_root=".",
            project_root=manifest.target.project_root.resolve()
            .relative_to(workspace_root.resolve())
            .as_posix(),
            revision=_revision(workspace_root),
            revision_proven=False,
            manifest_path=manifest_path.resolve()
            .relative_to(workspace_root.resolve())
            .as_posix(),
            manifest_sha256=bundle.manifest_sha256,
            source_sha256=bundle.source_sha256,
            sources=sources,
        ),
        "artifacts": artifacts,
        "build": BuildEvidence(
            command=bundle.build_command,
            manifest_sha256=bundle.manifest_sha256,
            source_sha256=bundle.source_sha256,
            build_info_sha256=bundle.build_info_sha256,
        ),
        "toolchain": ToolchainEvidence(
            qprover_version=version,
            forge_version=bundle.tool_version,
            compiler_version=bundle.compiler_version,
            evm_version=bundle.evm_version,
        ),
        "chain": ChainEvidence(
            kind="local",
            chain_id=anvil.chain_id,
            genesis_timestamp=anvil.genesis_timestamp,
            base_fee_wei=anvil.base_fee_wei,
            gas_price_wei=anvil.gas_price_wei,
            external_rpc=False,
        ),
        "funding": tuple(
            FundingEvidence(
                actor_id=actor.id,
                slot=actor.slot,
                address=evaluator.actors[actor.slot],
                balance_wei=actor.balance_wei,
            )
            for actor in manifest.actors
        ),
        "assumptions": (
            AssumptionEvidence(
                id="manifest-bounded-local-execution",
                description=(
                    "Search is bounded to the manifest-declared actors, funding, "
                    "actions, argument domains, invariants, and local execution "
                    "budgets."
                ),
            ),
        ),
        "initial_state": initial_state,
        "transactions": transactions,
        "before_after": BeforeAfterEvidence(before=initial_state, after=after_state),
        "initial_invariants": initial_invariants,
        "invariant": InvariantEvidence(
            id=invariant.id,
            expression=invariant.expression,
            description=invariant.description,
            foundry_assertion=invariant.foundry_assertion,
            evaluated=True,
            value=False,
            reason=invariant_record.get("reason"),
        ),
        "impact": impact_evidence,
        "gas": GasEvidence(
            total_gas_used=sum(item.gas_used for item in transactions),
            per_transaction=tuple(item.gas_used for item in transactions),
        ),
        "minimization": MinimizationEvidence(
            original_steps=minimization.original_step_count,
            minimized_steps=minimization.minimized_step_count,
            evaluation_count=minimization.evaluation_count,
            uncached_candidate_count=minimization.uncached_candidate_count,
            candidate_attempt_count=minimization.candidate_attempt_count,
            unique_candidate_count=minimization.unique_candidate_count,
            cache_hits=minimization.cache_hits,
            transaction_count=minimization.transaction_count,
            attempted_operators=minimization.attempted_operators,
            locally_minimal=minimization.locally_minimal,
            minimality_claim=minimization.minimality_claim,
            final_outcome=minimization.final_evaluation.outcome,
        ),
        "poc": PoCEvidence(
            path=f"poc/QProverReplay_{run.run_id}.t.sol",
            sha256=poc_sha256,
            manifest_sha256=bundle.manifest_sha256,
            source_sha256=bundle.source_sha256,
            artifact_sha256=primary_artifact.artifact_sha256,
            test_name="test_qprover_replay",
        ),
        "replay_invocation_template": REPLAY_INVOCATION_TEMPLATE,
        "assurance": AssuranceEvidence(
            replay_proven_scope=(
                "manifest/source/build/artifact identities; local chain and actor "
                "funding; transaction execution, receipts, gas, traces, intermediate "
                "and final observations; invariant and impact; single-delete local "
                "minimality; three private staged offline Foundry executions of "
                "exactly one named passing test with stable structured results"
            ),
            historical_search_metadata_scope=(
                "revision label; assumptions; run identifier and timestamp; search "
                "and minimization counters and attempted-operator history"
            ),
            invocation_template_scope=(
                "replay_invocation_template contains unresolved placeholders and is "
                "not executable until resolved by a conforming QProver CLI"
            ),
            trusted_local_execution_boundary=(
                "Forge, Solc, and Anvil executables are trusted local tool boundaries; "
                "the privileged local host is trusted; no cryptographic attestation "
                "protects against a compromised executable or privileged host"
            ),
            cryptographic_attestation=False,
        ),
    }


class _FreshEvaluator:
    def __init__(self, manifest: TargetManifest, bundle: ArtifactBundle) -> None:
        self._manifest = manifest
        self._bundle = bundle
        self._anvil: LocalAnvil | None = None
        self._evaluator: ScenarioEvaluator | None = None

    def __enter__(self) -> ScenarioEvaluator:
        self._anvil = LocalAnvil()
        self._anvil.start()
        try:
            self._evaluator = ScenarioEvaluator(
                self._manifest, self._bundle, self._anvil
            )
        except Exception:
            self._anvil.close()
            raise
        return self._evaluator

    def __exit__(self, *exc_info: object) -> None:
        if self._anvil is not None:
            self._anvil.close()


def _admissible_violation(
    evaluation: object,
    confirmation_policy: str,
    invariant_id: str | None = None,
) -> bool:
    if (
        not hasattr(evaluation, "outcome")
        or evaluation.outcome is not Outcome.VIOLATION
    ):
        return False
    if evaluation.metadata.get("confirmation_policy") != confirmation_policy:
        return False
    qualification = evaluation.metadata.get("qualification")
    return (
        isinstance(qualification, Mapping)
        and qualification.get("qualified") is True
        and qualification.get("policy") == confirmation_policy
        and isinstance(qualification.get("invariant_id"), str)
        and (invariant_id is None or qualification.get("invariant_id") == invariant_id)
    )


def _new_run_id() -> str:
    return uuid.uuid4().hex


def _new_staging_directory(output_base: Path, run_id: str) -> tuple[Path, int | None]:
    path = output_base / "runs" / f".{run_id}.{secrets.token_hex(12)}.staging"
    runtime = current_runtime()
    if runtime is None:
        return create_private_directory(path), None
    owned, token = runtime.own_path(
        create=lambda: create_private_directory(path),
        cleanup=remove_private_directory,
    )
    return owned, token


def _publish_run(
    *,
    output_base: Path,
    staging: Path,
    run_id: str,
    status: ConfirmationStatus,
    disposition: str,
    error: str | None,
    artifacts: Mapping[str, Path],
) -> tuple[Path, Path, Mapping[str, Path]]:
    """Write the canonical result last, then atomically expose one run directory."""

    if disposition not in {"confirmed", "not_confirmed", "failed"}:
        raise ValueError("invalid publication disposition")
    artifact_records: dict[str, dict[str, str]] = {}
    relative_paths: dict[str, Path] = {}
    tree = validated_private_tree(staging)
    for label, path in sorted(artifacts.items()):
        try:
            relative = path.relative_to(staging)
        except ValueError as exc:
            raise SafeOutputError("artifact is outside private run staging") from exc
        if ".." in relative.parts or relative.as_posix() not in tree:
            raise SafeOutputError("artifact is not a safe staged regular file")
        relative_paths[label] = relative
        artifact_records[label] = {
            "path": relative.as_posix(),
            "sha256": tree[relative.as_posix()],
        }
    result = ProofRunResult(
        schema_version="1.0",
        run_id=run_id,
        confirmation_status=status,
        disposition=disposition,
        error=error,
        artifacts={
            label: ProofRunArtifact(**record)
            for label, record in artifact_records.items()
        },
    )
    safe_atomic_write(
        staging / "result.json",
        json.dumps(
            result.model_dump(mode="json"),
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
        + "\n",
        replace=False,
    )
    publication = publish_private_directory(staging, output_base / "runs" / run_id)
    destination = publication.destination
    published = MappingProxyType(
        {label: destination / relative for label, relative in relative_paths.items()}
    )
    return destination, destination / "result.json", published


def _prove_violation_active(
    manifest_path: Path,
    *,
    strategy: SearchStrategy,
    seed: int,
    output: Path,
    workspace_root: Path,
    limits: SearchLimits | None = None,
) -> ProofBundleResult:
    """Search, minimize, certificate-bind, and cold replay one local target.

    Every exception after entering the proof boundary becomes an explicit
    ``NOT_CONFIRMED`` result.  It is never interpreted as evidence of safety.
    """

    root = workspace_root.resolve()
    manifest_file = manifest_path.resolve()
    output_base = output if output.is_absolute() else Path.cwd() / output
    publication_run_id = _new_run_id()
    staging: Path | None = None
    staging_token: int | None = None
    search_execution: SearchExecution | None = None
    events_path: Path | None = None
    qubo_path: Path | None = None
    certificate_path: Path | None = None
    markdown_path: Path | None = None
    poc_path: Path | None = None
    minimization: MinimizationResult | None = None
    evidence_events: tuple[EvidenceEvent, ...] = ()
    try:
        staging, staging_token = _new_staging_directory(output_base, publication_run_id)
        manifest_file.relative_to(root)
        manifest = load_manifest(manifest_file)
        with build_target(manifest) as bundle:
            search_execution = run_search(
                manifest,
                bundle,
                strategy=strategy,
                seed=seed,
                limits=limits,
                run_id=publication_run_id,
            )
            run = search_execution.search_run
            evidence_events = monotonic_events_to_evidence(
                run.events, search_execution.started_at
            )
            events_path = write_events(evidence_events, staging / "events.jsonl")
            if search_execution.strategy_evidence is not None:
                objective_provenance = thaw_json(
                    search_execution.prepared.objective_provenance
                )
                qubo_evidence = {
                    **thaw_json(search_execution.strategy_evidence),
                    "objective_provenance": objective_provenance,
                    "objective_provenance_sha256": _digest(
                        json.dumps(
                            objective_provenance,
                            sort_keys=True,
                            separators=(",", ":"),
                        )
                    ),
                    "prepared_problem_sha256": search_execution.prepared.problem_sha256,
                }
                qubo_path = _atomic_json(qubo_evidence, staging / "qubo.json")
            if run.violation is None:
                artifact_paths = {"events": events_path}
                if qubo_path is not None:
                    artifact_paths["qubo"] = qubo_path
                published_root, result_path, published = _publish_run(
                    output_base=output_base,
                    staging=staging,
                    run_id=publication_run_id,
                    status=ConfirmationStatus.NOT_CONFIRMED,
                    disposition="not_confirmed",
                    error=None,
                    artifacts=artifact_paths,
                )
                runtime = current_runtime()
                if runtime is not None and staging_token is not None:
                    runtime.unregister(staging_token)
                staging_token = None
                staging = None
                return ProofBundleResult(
                    status=ConfirmationStatus.NOT_CONFIRMED,
                    output_root=published_root,
                    search_run=run,
                    problem_sha256=search_execution.prepared.problem_sha256,
                    events_path=published["events"],
                    qubo_path=published.get("qubo"),
                    result_path=result_path,
                    run_id=publication_run_id,
                )
            evaluated = next(
                item for item in run.evaluations if item.candidate == run.violation
            )
            prefix = evaluated.evaluation.metadata.get("violation_prefix_length")
            if type(prefix) is not int or not 1 <= prefix <= len(run.violation.steps):
                raise ValueError("search violation omitted an exact executed prefix")
            search_qualification = evaluated.evaluation.metadata.get("qualification")
            if not isinstance(search_qualification, Mapping) or not isinstance(
                search_qualification.get("invariant_id"), str
            ):
                raise ValueError("search violation omitted its selected invariant")
            selected_invariant_id = search_qualification["invariant_id"]
            seed_candidate = Candidate(run.violation.steps[:prefix])

            with LocalAnvil() as fresh_anvil:
                fresh_evaluator = ScenarioEvaluator(manifest, bundle, fresh_anvil)
                fresh = fresh_evaluator.evaluate(seed_candidate)
            if not _admissible_violation(
                fresh, manifest.confirmation.kind, selected_invariant_id
            ):
                raise ValueError(
                    "fresh search-prefix evaluation did not violate policy"
                )

            minimization = minimize(
                seed_candidate,
                lambda: _FreshEvaluator(manifest, bundle),
                manifest,
            )
            if not _admissible_violation(
                minimization.final_evaluation,
                manifest.confirmation.kind,
                selected_invariant_id,
            ):
                raise ValueError("minimization did not preserve confirmation policy")

            generated_at = datetime.now(UTC)
            with LocalAnvil() as final_anvil:
                final_evaluator = ScenarioEvaluator(manifest, bundle, final_anvil)
                final_evaluation = final_evaluator.evaluate(minimization.candidate)
                if not _admissible_violation(
                    final_evaluation,
                    manifest.confirmation.kind,
                    selected_invariant_id,
                ):
                    raise ValueError("final fresh evaluation did not violate policy")
                provisional_data = _certificate_data(
                    manifest=manifest,
                    manifest_path=manifest_file,
                    workspace_root=root,
                    output_root=staging,
                    bundle=bundle,
                    run=run,
                    generated_at=generated_at,
                    minimization=minimization,
                    final_evaluation=final_evaluation,
                    evaluator=final_evaluator,
                    anvil=final_anvil,
                    poc_sha256="0" * 64,
                )
                provisional = create_certificate(**provisional_data)
                source = foundry_poc_source(provisional, manifest, workspace_root=root)
                certificate_data = _certificate_data(
                    manifest=manifest,
                    manifest_path=manifest_file,
                    workspace_root=root,
                    output_root=staging,
                    bundle=bundle,
                    run=run,
                    generated_at=generated_at,
                    minimization=minimization,
                    final_evaluation=final_evaluation,
                    evaluator=final_evaluator,
                    anvil=final_anvil,
                    poc_sha256=_digest(source),
                )
                draft = create_certificate(**certificate_data)

            poc_path = generate_foundry_poc(
                draft, manifest, staging, workspace_root=root
            )
            certificate_path = write_certificate(draft, staging / "certificate.json")
            proof_events = list(evidence_events)

            def record(kind: str, details: Mapping[str, object]) -> None:
                prior = proof_events[-1].timestamp if proof_events else generated_at
                now = max(datetime.now(UTC), prior)
                proof_events.append(
                    EvidenceEvent(
                        run_id=run.run_id,
                        sequence=len(proof_events) + 1,
                        timestamp=now,
                        kind=kind,
                        details=details,
                    )
                )

            record(
                "minimization",
                {
                    "original_steps": minimization.original_step_count,
                    "minimized_steps": minimization.minimized_step_count,
                    "evaluation_count": minimization.evaluation_count,
                    "transaction_count": minimization.transaction_count,
                },
            )
            record(
                "poc_generation",
                {"path": draft.poc.path, "sha256": draft.poc.sha256},
            )
            verification = cold_verify(certificate_path, repeats=3, workspace_root=root)
            record(
                "cold_replay",
                {
                    "repeats": len(verification.records),
                    "successful": sum(
                        record.success for record in verification.records
                    ),
                    "status": verification.confirmation_status.value,
                },
            )
            record(
                "confirmation",
                {"status": verification.confirmation_status.value},
            )
            evidence_events = tuple(proof_events)
            events_path = write_events(evidence_events, staging / "events.jsonl")
            markdown_path = write_markdown(
                verification.certificate, staging / "certificate.md"
            )
            artifact_paths = {
                "certificate": certificate_path,
                "markdown": markdown_path,
                "poc": poc_path,
                "events": events_path,
            }
            if qubo_path is not None:
                artifact_paths["qubo"] = qubo_path
            published_root, result_path, published = _publish_run(
                output_base=output_base,
                staging=staging,
                run_id=publication_run_id,
                status=verification.confirmation_status,
                disposition=(
                    "confirmed"
                    if verification.confirmation_status is ConfirmationStatus.CONFIRMED
                    else "not_confirmed"
                ),
                error=(
                    None
                    if verification.confirmation_status is ConfirmationStatus.CONFIRMED
                    else "cold replay did not satisfy confirmation gates"
                ),
                artifacts=artifact_paths,
            )
            runtime = current_runtime()
            if runtime is not None and staging_token is not None:
                runtime.unregister(staging_token)
            staging_token = None
            staging = None
            return ProofBundleResult(
                status=verification.confirmation_status,
                output_root=published_root,
                search_run=run,
                problem_sha256=search_execution.prepared.problem_sha256,
                certificate_path=published["certificate"],
                markdown_path=published["markdown"],
                poc_path=published["poc"],
                events_path=published["events"],
                qubo_path=published.get("qubo"),
                certificate_sha256=verification.certificate.certificate_sha256,
                minimized_steps=minimization.minimized_step_count,
                result_path=result_path,
                run_id=publication_run_id,
                error=(
                    None
                    if verification.confirmation_status is ConfirmationStatus.CONFIRMED
                    else "cold replay did not satisfy confirmation gates"
                ),
            )
    except Exception as error:  # normalize a failed proof gate, never a safe verdict
        normalized_error = f"{type(error).__name__}: {error}"
        if staging is not None:
            try:
                remove_private_directory(staging)
            except Exception as cleanup_error:
                normalized_error += (
                    f"; cleanup {type(cleanup_error).__name__}: {cleanup_error}"
                )
            staging = None
            runtime = current_runtime()
            if runtime is not None and staging_token is not None:
                runtime.unregister(staging_token)
            staging_token = None
        failure_staging: Path | None = None
        failure_staging_token: int | None = None
        try:
            failure_staging, failure_staging_token = _new_staging_directory(
                output_base, publication_run_id
            )
            published_root, result_path, _ = _publish_run(
                output_base=output_base,
                staging=failure_staging,
                run_id=publication_run_id,
                status=ConfirmationStatus.NOT_CONFIRMED,
                disposition="failed",
                error=normalized_error,
                artifacts={},
            )
            runtime = current_runtime()
            if runtime is not None and failure_staging_token is not None:
                runtime.unregister(failure_staging_token)
            failure_staging_token = None
        except Exception as publication_error:
            if failure_staging is not None:
                with suppress(Exception):
                    remove_private_directory(failure_staging)
            runtime = current_runtime()
            if runtime is not None and failure_staging_token is not None:
                runtime.unregister(failure_staging_token)
            return ProofBundleResult(
                status=ConfirmationStatus.NOT_CONFIRMED,
                output_root=output_base,
                search_run=(
                    search_execution.search_run
                    if search_execution is not None
                    else None
                ),
                problem_sha256=(
                    search_execution.prepared.problem_sha256
                    if search_execution is not None
                    else None
                ),
                minimized_steps=(
                    minimization.minimized_step_count
                    if minimization is not None
                    else None
                ),
                run_id=publication_run_id,
                error=(
                    f"{normalized_error}; publication "
                    f"{type(publication_error).__name__}: {publication_error}"
                ),
            )
        return ProofBundleResult(
            status=ConfirmationStatus.NOT_CONFIRMED,
            output_root=published_root,
            search_run=(
                search_execution.search_run if search_execution is not None else None
            ),
            problem_sha256=(
                search_execution.prepared.problem_sha256
                if search_execution is not None
                else None
            ),
            minimized_steps=(
                minimization.minimized_step_count if minimization is not None else None
            ),
            result_path=result_path,
            run_id=publication_run_id,
            error=normalized_error,
        )


def prove_violation(
    manifest_path: Path,
    *,
    strategy: SearchStrategy,
    seed: int,
    output: Path,
    workspace_root: Path,
    limits: SearchLimits | None = None,
) -> ProofBundleResult:
    """Execute one proof inside the process/temp cancellation boundary."""

    with ExecutionRuntime.activate():
        return _prove_violation_active(
            manifest_path,
            strategy=strategy,
            seed=seed,
            output=output,
            workspace_root=workspace_root,
            limits=limits,
        )


__all__ = [
    "PreparedSearch",
    "ProofBundleResult",
    "ProofRunArtifact",
    "ProofRunResult",
    "SearchExecution",
    "monotonic_events_to_evidence",
    "prepare_search",
    "prove_violation",
    "run_search",
]
