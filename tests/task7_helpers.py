from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path

from eth_utils.abi import collapse_if_tuple

from qprover.artifacts import ArtifactBundle
from qprover.certificate import (
    REPLAY_INVOCATION_TEMPLATE,
    ArtifactEvidence,
    AssumptionEvidence,
    AssuranceEvidence,
    BeforeAfterEvidence,
    BuildEvidence,
    ChainEvidence,
    FundingEvidence,
    GasEvidence,
    ImpactEvidence,
    InvariantEvidence,
    MinimizationEvidence,
    PoCEvidence,
    ReplayEvidence,
    SourceEvidence,
    StateEvidence,
    TargetEvidence,
    ToolchainEvidence,
    TransactionEvidence,
    create_certificate,
)
from qprover.minimizer import MinimizationResult
from qprover.models import ConfirmationStatus, TargetManifest

ROOT = Path(__file__).parents[1].resolve()
ZERO_HASH = "0" * 64
ACTOR_ADDRESSES = {
    0: "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266",
    1: "0x70997970c51812dc3a010c7d01b50e0d17dc79c8",
}


def digest(data: bytes | str) -> str:
    return hashlib.sha256(data.encode() if isinstance(data, str) else data).hexdigest()


def state_evidence(values: dict[str, int | bool]) -> StateEvidence:
    return StateEvidence(
        values=values,
        state_sha256=digest(json.dumps(values, sort_keys=True, separators=(",", ":"))),
    )


def make_executed_certificate(
    *,
    manifest: TargetManifest,
    manifest_path: Path,
    bundle: ArtifactBundle,
    minimization: MinimizationResult,
    output_root: Path,
    poc_sha256: str = ZERO_HASH,
    workspace_root: Path = ROOT,
):
    evaluation = minimization.final_evaluation
    metadata = evaluation.metadata
    initial = dict(metadata["initial_observations"])
    current = dict(metadata["current_observations"])
    step_records = metadata["steps"]
    transactions = []
    for step, record in zip(minimization.candidate.steps, step_records, strict=True):
        trace_payload = json.dumps(
            {
                "trace_struct_log_count": record["trace_struct_log_count"],
                "call_trace_count": record["call_trace_count"],
                "trace_failed": record["trace_failed"],
                "return_data": record["return_data"],
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        transactions.append(
            TransactionEvidence(
                index=record["index"],
                action_id=step.action_id,
                target_id=step.target_id,
                signature=step.signature,
                sender_slot=step.sender_slot,
                args=step.args,
                value_wei=step.value_wei,
                calldata_sha256=record["calldata_hash"],
                transaction_sha256=record["transaction_hash"][2:],
                expected_success=record["receipt_status"] == 1,
                receipt_status=record["receipt_status"],
                gas_used=record["gas_used"],
                return_data=record["return_data"],
                revert_data=record["revert_data"],
                trace_sha256=digest(trace_payload),
                observation_state_sha256=record["observation_state_hash"],
            )
        )
    invariant_record = next(
        record for record in metadata["invariants"] if record["value"] is False
    )
    invariant = next(
        item
        for item in manifest.invariants
        if item.id == invariant_record["invariant_id"]
    )
    impact = metadata["impact"]
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
    poc_path = output_root / "poc" / f"QProverReplay_{manifest.target.id}.t.sol"
    gas_values = tuple(item.gas_used for item in transactions)
    return create_certificate(
        run_id=f"task7-{manifest.target.id}",
        generated_at=datetime(2026, 9, 14, 0, 0, tzinfo=UTC),
        confirmation_status=ConfirmationStatus.NOT_CONFIRMED,
        source_kind="executed",
        final_evaluation_outcome=evaluation.outcome,
        target=TargetEvidence(
            id=manifest.target.id,
            workspace_root=".",
            project_root=manifest.target.project_root.resolve()
            .relative_to(workspace_root.resolve())
            .as_posix(),
            revision="66e337d",
            revision_proven=False,
            manifest_path=manifest_path.resolve()
            .relative_to(workspace_root.resolve())
            .as_posix(),
            manifest_sha256=bundle.manifest_sha256,
            source_sha256=bundle.source_sha256,
            sources=sources,
        ),
        artifacts=artifacts,
        build=BuildEvidence(
            command=bundle.build_command,
            manifest_sha256=bundle.manifest_sha256,
            source_sha256=bundle.source_sha256,
            build_info_sha256=bundle.build_info_sha256,
        ),
        toolchain=ToolchainEvidence(
            qprover_version="0.1.0",
            forge_version=bundle.tool_version,
            compiler_version=bundle.compiler_version,
            evm_version=bundle.evm_version,
        ),
        chain=ChainEvidence(
            kind="local",
            chain_id=31337,
            genesis_timestamp=1700000000,
            base_fee_wei=0,
            gas_price_wei=0,
            external_rpc=False,
        ),
        funding=tuple(
            FundingEvidence(
                actor_id=actor.id,
                slot=actor.slot,
                address=ACTOR_ADDRESSES[actor.slot],
                balance_wei=actor.balance_wei,
            )
            for actor in manifest.actors
        ),
        assumptions=(
            AssumptionEvidence(
                id="educational-fixture",
                description="Repository-local educational regression fixture.",
            ),
        ),
        initial_state=StateEvidence(
            values=initial,
            state_sha256=digest(
                json.dumps(initial, sort_keys=True, separators=(",", ":"))
            ),
        ),
        transactions=tuple(transactions),
        before_after=BeforeAfterEvidence(
            before=StateEvidence(
                values=initial,
                state_sha256=digest(
                    json.dumps(initial, sort_keys=True, separators=(",", ":"))
                ),
            ),
            after=StateEvidence(
                values=current, state_sha256=evaluation.state_fingerprint
            ),
        ),
        initial_invariants=tuple(
            InvariantEvidence(
                id=item.id,
                expression=item.expression,
                description=item.description,
                foundry_assertion=item.foundry_assertion,
                evaluated=True,
                value=True,
                reason=None,
            )
            for item in manifest.invariants
        ),
        invariant=InvariantEvidence(
            id=invariant.id,
            expression=invariant.expression,
            description=invariant.description,
            foundry_assertion=invariant.foundry_assertion,
            evaluated=True,
            value=False,
            reason=invariant_record["reason"],
        ),
        impact=ImpactEvidence(
            applicability="economic",
            attacker_observation=manifest.impact.attacker_asset_observation,
            protocol_observation=manifest.impact.protocol_asset_observation,
            attacker_delta=impact["attacker_delta"],
            protocol_delta=impact["protocol_delta"],
            unit=impact["unit"],
            admissible=impact["admissible"],
            executed=True,
        ),
        gas=GasEvidence(total_gas_used=sum(gas_values), per_transaction=gas_values),
        minimization=MinimizationEvidence(
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
        poc=PoCEvidence(
            path=poc_path.relative_to(output_root).as_posix(),
            sha256=poc_sha256,
            manifest_sha256=bundle.manifest_sha256,
            source_sha256=bundle.source_sha256,
            artifact_sha256=artifacts[0].artifact_sha256,
            test_name="test_qprover_replay",
        ),
        replay_invocation_template=REPLAY_INVOCATION_TEMPLATE,
        replay=ReplayEvidence(
            local_only=True, required_repeats=3, recipe=None, records=()
        ),
        assurance=AssuranceEvidence(
            replay_proven_scope=(
                "manifest/source/build/artifact identities; local chain and actor "
                "funding; "
                "transaction execution, receipts, gas, traces, intermediate and final "
                "observations; invariant and impact; single-delete local minimality; "
                "three private staged offline Foundry executions of exactly one named "
                "passing test with stable structured results"
            ),
            historical_search_metadata_scope=(
                "revision label; assumptions; run identifier and timestamp; search and "
                "minimization counters and attempted-operator history"
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
    )
