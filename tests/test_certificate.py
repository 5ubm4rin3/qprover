from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path

import jsonschema
import pytest
from pydantic import ValidationError

from qprover.certificate import (
    ArtifactEvidence,
    AssumptionEvidence,
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
    ProofCertificate,
    ReplayEvidence,
    ReplayRecord,
    SourceEvidence,
    StateEvidence,
    TargetEvidence,
    ToolchainEvidence,
    TransactionEvidence,
    create_certificate,
    render_markdown,
    write_certificate,
    write_events,
)
from qprover.models import ConfirmationStatus, Outcome

H0 = "0" * 64
H1 = "1" * 64
H2 = "2" * 64
H3 = "3" * 64


def _state_hash(values: dict[str, int]) -> str:
    payload = json.dumps(values, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(payload).hexdigest()


def _base(tmp_path: Path) -> dict[str, object]:
    root = tmp_path.resolve()
    return {
        "run_id": "run-7",
        "generated_at": datetime(2026, 9, 14, 1, 2, 3, tzinfo=UTC),
        "source_kind": "executed",
        "final_evaluation_outcome": Outcome.VIOLATION,
        "target": TargetEvidence(
            id="scenario_access_control_a",
            workspace_root=root,
            project_root=root / "foundry",
            revision="66e337d",
            manifest_path=root / "manifest.json",
            manifest_sha256=H0,
            source_sha256=H1,
            sources=(SourceEvidence(path="src/Pair.sol", sha256=H2),),
        ),
        "artifacts": (
            ArtifactEvidence(
                compilation_target="src/Pair.sol:AccessControlA",
                artifact_path="out/Pair.sol/AccessControlA.json",
                artifact_sha256=H2,
                bytecode_sha256=H3,
                build_info_id="build-1",
                build_info_sha256=H1,
            ),
        ),
        "build": BuildEvidence(
            command=("forge", "build", "--offline"),
            manifest_sha256=H0,
            source_sha256=H1,
            build_info_sha256=H1,
        ),
        "toolchain": ToolchainEvidence(
            qprover_version="0.1.0",
            forge_version="1.4.0",
            compiler_version="0.8.34",
            evm_version="prague",
        ),
        "chain": ChainEvidence(
            kind="local",
            chain_id=31337,
            genesis_timestamp=1700000000,
            base_fee_wei=0,
            gas_price_wei=0,
            external_rpc=False,
        ),
        "funding": (
            FundingEvidence(actor_id="attacker", slot=1, balance_wei=100 * 10**18),
        ),
        "assumptions": (
            AssumptionEvidence(id="fixture", description="Educational local fixture."),
        ),
        "initial_state": StateEvidence(
            values={"protocol_assets": 10**19, "attacker_assets": 10**20},
            state_sha256=_state_hash(
                {"protocol_assets": 10**19, "attacker_assets": 10**20}
            ),
        ),
        "transactions": (
            TransactionEvidence(
                index=1,
                action_id="step_alpha",
                target_id="scenario",
                signature="claimRole()",
                sender_slot=1,
                args=(),
                value_wei=0,
                calldata_sha256=H0,
                transaction_sha256=H1,
                expected_success=True,
                receipt_status=1,
                gas_used=42000,
                return_data="0x",
                revert_data=None,
                trace_sha256=H2,
                observation_state_sha256=_state_hash(
                    {"protocol_assets": 0, "attacker_assets": 11 * 10**19}
                ),
            ),
        ),
        "before_after": BeforeAfterEvidence(
            before=StateEvidence(
                values={"protocol_assets": 10**19, "attacker_assets": 10**20},
                state_sha256=_state_hash(
                    {"protocol_assets": 10**19, "attacker_assets": 10**20}
                ),
            ),
            after=StateEvidence(
                values={"protocol_assets": 0, "attacker_assets": 11 * 10**19},
                state_sha256=_state_hash(
                    {"protocol_assets": 0, "attacker_assets": 11 * 10**19}
                ),
            ),
        ),
        "invariant": InvariantEvidence(
            id="assets_preserved",
            expression="protocol_assets >= initial_protocol_assets",
            description="Assets stay present.",
            foundry_assertion="assertGe(target.protocolAssets(), initialAssets);",
            evaluated=True,
            value=False,
            reason=None,
        ),
        "impact": ImpactEvidence(
            attacker_observation="attacker_assets",
            protocol_observation="protocol_assets",
            attacker_delta=10**19,
            protocol_delta=-(10**19),
            unit="wei",
            admissible=True,
            executed=True,
        ),
        "gas": GasEvidence(total_gas_used=42000, per_transaction=(42000,)),
        "minimization": MinimizationEvidence(
            original_steps=3,
            minimized_steps=1,
            evaluation_count=7,
            uncached_candidate_count=7,
            candidate_attempt_count=8,
            unique_candidate_count=6,
            cache_hits=1,
            transaction_count=12,
            attempted_operators=(
                "ddmin-contiguous-chunks",
                "single-delete-fixed-point",
            ),
            locally_minimal=True,
            minimality_claim="Locally minimal under the listed operators.",
            final_outcome=Outcome.VIOLATION,
        ),
        "poc": PoCEvidence(
            path="poc/QProverReplay_run_7.t.sol",
            sha256=H3,
            manifest_sha256=H0,
            source_sha256=H1,
            artifact_sha256=H2,
            test_name="test_qprover_replay",
        ),
        "replay_command": "qprover replay certificate.json",
    }


def _confirmed(tmp_path: Path):
    base = _base(tmp_path)
    provisional = create_certificate(
        confirmation_status=ConfirmationStatus.NOT_CONFIRMED,
        replay=ReplayEvidence(local_only=True, required_repeats=3, records=()),
        **base,
    )
    records = tuple(
        ReplayRecord(
            index=index,
            success=True,
            command=("forge", "test", "--offline"),
            exit_code=0,
            stdout_sha256=str(index) * 64,
            stderr_sha256=H0,
            duration_seconds=0.25,
            certificate_identity_sha256=provisional.certificate_identity_sha256,
            poc_sha256=H3,
            manifest_sha256=H0,
            source_sha256=H1,
            artifact_sha256=H2,
        )
        for index in range(1, 4)
    )
    return create_certificate(
        confirmation_status=ConfirmationStatus.CONFIRMED,
        replay=ReplayEvidence(local_only=True, required_repeats=3, records=records),
        **base,
    )


def test_complete_confirmed_certificate_validates_with_pydantic_and_schema(
    tmp_path: Path,
) -> None:
    certificate = _confirmed(tmp_path)
    data = json.loads(certificate.canonical_json())

    assert certificate.confirmation_status is ConfirmationStatus.CONFIRMED
    assert certificate.generated_at.isoformat() == "2026-09-14T01:02:03+00:00"
    assert certificate.certificate_sha256 == certificate.compute_hash()
    assert certificate.certificate_identity_sha256 == certificate.compute_identity()
    assert certificate.model_validate(data) == certificate
    schema = json.loads(Path("schemas/certificate.schema.json").read_text())
    jsonschema.Draft202012Validator.check_schema(schema)
    jsonschema.validate(data, schema)


def test_certificate_is_deeply_immutable_and_writes_atomically(tmp_path: Path) -> None:
    certificate = _confirmed(tmp_path)
    with pytest.raises(TypeError):
        certificate.initial_state.values["protocol_assets"] = 1  # type: ignore[index]
    destination = tmp_path / "result" / "certificate.json"
    write_certificate(certificate, destination)
    assert json.loads(destination.read_text()) == json.loads(
        certificate.canonical_json()
    )
    assert not tuple(destination.parent.glob("*.tmp"))


def test_zero_hashes_cannot_bypass_certificate_integrity(tmp_path: Path) -> None:
    data = _confirmed(tmp_path).model_dump(mode="json")
    data["certificate_identity_sha256"] = H0
    data["certificate_sha256"] = H0
    with pytest.raises(ValidationError, match="hash mismatch"):
        ProofCertificate.model_validate(data)


@pytest.mark.parametrize(
    "mutation",
    [
        {"source_kind": "static_lead"},
        {"final_evaluation_outcome": Outcome.PASS},
        {
            "impact": ImpactEvidence(
                attacker_observation="attacker_assets",
                protocol_observation="protocol_assets",
                attacker_delta=10**19,
                protocol_delta=-(10**19),
                unit="wei",
                admissible=True,
                executed=False,
            )
        },
    ],
)
def test_confirmation_rejects_unexecuted_or_incomplete_evidence(
    tmp_path: Path, mutation: dict[str, object]
) -> None:
    valid = _confirmed(tmp_path).model_dump(mode="python")
    valid.update(mutation)
    valid.pop("certificate_sha256")
    valid.pop("certificate_identity_sha256")
    with pytest.raises(ValidationError, match="CONFIRMED"):
        create_certificate(**valid)


def test_confirmation_rejects_replay_count_failure_and_identity_mismatch(
    tmp_path: Path,
) -> None:
    certificate = _confirmed(tmp_path)
    base = certificate.model_dump(mode="python")
    records = list(certificate.replay.records)
    variants = [
        records[:2],
        [records[0], records[1].model_copy(update={"success": False}), records[2]],
        [records[0].model_copy(update={"poc_sha256": H0}), *records[1:]],
        [
            records[0].model_copy(update={"certificate_identity_sha256": H0}),
            *records[1:],
        ],
    ]
    for replay_records in variants:
        kwargs = {
            key: value
            for key, value in base.items()
            if key
            not in {"certificate_sha256", "certificate_identity_sha256", "replay"}
        }
        with pytest.raises(ValidationError, match="CONFIRMED"):
            create_certificate(
                replay=ReplayEvidence(
                    local_only=True, required_repeats=3, records=tuple(replay_records)
                ),
                **kwargs,
            )


def test_markdown_uses_only_validated_json_values(tmp_path: Path) -> None:
    certificate = _confirmed(tmp_path)
    markdown = render_markdown(certificate)
    assert "10,000,000,000,000,000,000" in markdown
    assert "42,000" in markdown
    assert "CONFIRMED" in markdown
    with pytest.raises(ValidationError):
        render_markdown({**certificate.model_dump(), "unknown": "injected"})


def test_event_record_is_strict_immutable_schema_valid_and_atomic(
    tmp_path: Path,
) -> None:
    event = EvidenceEvent(
        run_id="run-7",
        sequence=1,
        timestamp=datetime(2026, 9, 14, tzinfo=UTC),
        kind="minimization",
        details={"operator": "single-delete-fixed-point", "accepted": True},
    )
    with pytest.raises(TypeError):
        event.details["accepted"] = False  # type: ignore[index]
    schema = json.loads(Path("schemas/event.schema.json").read_text())
    serialized = event.model_dump(mode="json")
    jsonschema.validate(serialized, schema)
    destination = write_events((event,), tmp_path / "events.jsonl")
    assert json.loads(destination.read_text()) == serialized
