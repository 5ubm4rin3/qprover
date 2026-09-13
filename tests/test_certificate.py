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
    ProofCertificate,
    ReplayEvidence,
    ReplayRecord,
    SourceEvidence,
    StateEvidence,
    TargetEvidence,
    ToolchainEvidence,
    TransactionEvidence,
    _seal_certificate,
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
    return {
        "run_id": "run-7",
        "generated_at": datetime(2026, 9, 14, 1, 2, 3, tzinfo=UTC),
        "source_kind": "executed",
        "final_evaluation_outcome": Outcome.VIOLATION,
        "target": TargetEvidence(
            id="scenario_access_control_a",
            workspace_root=".",
            project_root="benchmarks/foundry",
            revision="66e337d",
            revision_proven=False,
            manifest_path="benchmarks/manifest.json",
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
                constructor_types=(),
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
            FundingEvidence(
                actor_id="attacker",
                slot=1,
                address="0x70997970c51812dc3a010c7d01b50e0d17dc79c8",
                balance_wei=100 * 10**18,
            ),
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
        "assurance": AssuranceEvidence(
            replay_proven_scope=(
                "manifest/source/build/artifact identities; local chain and actor "
                "funding; "
                "transaction execution, receipts, gas, traces, intermediate and final "
                "observations; invariant and impact; single-delete local minimality; "
                "three stable offline Foundry replays"
            ),
            historical_search_metadata_scope=(
                "revision label; assumptions; run identifier and timestamp; search and "
                "minimization counters and attempted-operator history"
            ),
            cryptographic_attestation=False,
        ),
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
            command=(
                "forge",
                "test",
                "--offline",
                "--root",
                "benchmarks/foundry",
                "--match-path",
                f"test/.qprover_replay_{'a' * 32}.t.sol",
                "--match-test",
                "test_qprover_replay",
                "--out",
                f".qprover-cold/replay-{index}/out",
                "--cache-path",
                f".qprover-cold/replay-{index}/cache",
            ),
            exit_code=0,
            stdout_sha256=H0,
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
    return _seal_certificate(provisional, records)


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
    with pytest.raises(ValidationError, match="hash mismatch"):
        ProofCertificate.model_validate(data, context={"allow_unsealed": True})


def test_public_creation_rejects_confirmation_and_replay_forgery(
    tmp_path: Path,
) -> None:
    """Only cold verification may transition a draft to CONFIRMED."""

    base = _base(tmp_path)
    with pytest.raises(ValueError, match="draft.*NOT_CONFIRMED"):
        create_certificate(
            confirmation_status=ConfirmationStatus.CONFIRMED,
            replay=ReplayEvidence(local_only=True, required_repeats=3, records=()),
            **base,
        )

    wrong_command = dict(base)
    wrong_command["replay_command"] = "forge test --offline"
    with pytest.raises(ValidationError, match="replay_command"):
        create_certificate(**wrong_command)

    draft = create_certificate(
        confirmation_status=ConfirmationStatus.NOT_CONFIRMED,
        replay=ReplayEvidence(local_only=True, required_repeats=3, records=()),
        **base,
    )
    forged = ReplayEvidence(
        local_only=True,
        required_repeats=3,
        records=(
            ReplayRecord(
                index=1,
                success=True,
                command=(
                    "forge",
                    "test",
                    "--offline",
                    "--root",
                    "benchmarks/foundry",
                    "--match-path",
                    f"test/.qprover_replay_{'a' * 32}.t.sol",
                    "--match-test",
                    "test_qprover_replay",
                    "--out",
                    ".qprover-cold/replay-1/out",
                    "--cache-path",
                    ".qprover-cold/replay-1/cache",
                ),
                exit_code=0,
                stdout_sha256=H0,
                stderr_sha256=H0,
                duration_seconds=0.1,
                certificate_identity_sha256=draft.certificate_identity_sha256,
                poc_sha256=H3,
                manifest_sha256=H0,
                source_sha256=H1,
                artifact_sha256=H2,
            ),
        ),
    )
    with pytest.raises(ValueError, match="draft.*empty replay"):
        create_certificate(
            confirmation_status=ConfirmationStatus.NOT_CONFIRMED,
            replay=forged,
            **base,
        )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("workspace_root", "/tmp/qprover"),
        ("project_root", "../foundry"),
        ("manifest_path", "benchmarks/../../manifest.json"),
    ],
)
def test_certificate_target_paths_are_portable_and_cannot_traverse(
    tmp_path: Path, field: str, value: str
) -> None:
    """Target paths must remain meaningful after moving a clean workspace."""

    target = {
        "id": "scenario_access_control_a",
        "workspace_root": ".",
        "project_root": "benchmarks/foundry",
        "revision": "66e337d",
        "revision_proven": False,
        "manifest_path": "benchmarks/scenario_access_control_a.json",
        "manifest_sha256": H0,
        "source_sha256": H1,
        "sources": ({"path": "src/Pair.sol", "sha256": H2},),
    }
    target[field] = value

    with pytest.raises(
        ValidationError, match="portable|relative|traversal|Input should"
    ):
        TargetEvidence.model_validate(target)


def test_certificate_revision_is_explicitly_unverified() -> None:
    target = {
        "id": "scenario_access_control_a",
        "workspace_root": ".",
        "project_root": "benchmarks/foundry",
        "revision": "caller-supplied-label",
        "revision_proven": True,
        "manifest_path": "benchmarks/scenario_access_control_a.json",
        "manifest_sha256": H0,
        "source_sha256": H1,
        "sources": ({"path": "src/Pair.sol", "sha256": H2},),
    }

    with pytest.raises(ValidationError, match="revision_proven"):
        TargetEvidence.model_validate(target)


@pytest.mark.parametrize(
    "command",
    [
        ("forge", "test", "--offline"),
        (
            "forge",
            "test",
            "--offline",
            "--root",
            "/tmp/project",
            "--match-path",
            "test/forged.t.sol",
            "--match-test",
            "not_the_replay",
            "--out",
            "/tmp/run/out",
            "--cache-path",
            "/tmp/run/cache",
        ),
    ],
)
def test_replay_record_rejects_forged_command_shape(command: tuple[str, ...]) -> None:
    """Replay records accept only QProver's exact isolated Forge invocation."""

    with pytest.raises(ValidationError, match="exact replay command"):
        ReplayRecord(
            index=1,
            success=True,
            command=command,
            exit_code=0,
            stdout_sha256=H0,
            stderr_sha256=H0,
            duration_seconds=0.1,
            certificate_identity_sha256=H0,
            poc_sha256=H0,
            manifest_sha256=H0,
            source_sha256=H0,
            artifact_sha256=H0,
        )


def test_assurance_explicitly_separates_replay_proof_from_history() -> None:
    assurance = AssuranceEvidence(
        replay_proven_scope=(
            "manifest/source/build/artifact identities; local chain and actor funding; "
            "transaction execution, receipts, gas, traces, intermediate and final "
            "observations; invariant and impact; single-delete local minimality; "
            "three stable offline Foundry replays"
        ),
        historical_search_metadata_scope=(
            "revision label; assumptions; run identifier and timestamp; search and "
            "minimization counters and attempted-operator history"
        ),
        cryptographic_attestation=False,
    )

    assert "transaction execution" in assurance.replay_proven_scope
    assert "revision" in assurance.historical_search_metadata_scope
    assert assurance.cryptographic_attestation is False


def test_json_schema_rejects_structural_replay_command_forgery(
    tmp_path: Path,
) -> None:
    schema = json.loads(Path("schemas/certificate.schema.json").read_text())
    data = json.loads(_confirmed(tmp_path).canonical_json())
    data["replay"]["records"][0]["command"] = ["forge", "test", "--offline"]

    assert "semantic" in schema["$comment"].lower()
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(data, schema)


def test_confirmation_binds_replay_root_to_certificate_target(tmp_path: Path) -> None:
    draft = create_certificate(**_base(tmp_path))
    records = tuple(
        item.model_copy(
            update={
                "command": (
                    *item.command[:4],
                    "another/project",
                    *item.command[5:],
                ),
                "certificate_identity_sha256": (draft.certificate_identity_sha256),
            }
        )
        for item in _confirmed(tmp_path).replay.records
    )

    with pytest.raises(ValidationError, match="isolated replay commands"):
        _seal_certificate(draft, records)


def test_json_schema_rejects_claimed_confirmation_with_failed_replay(
    tmp_path: Path,
) -> None:
    schema = json.loads(Path("schemas/certificate.schema.json").read_text())
    data = json.loads(_confirmed(tmp_path).canonical_json())
    data["replay"]["records"][0]["success"] = False
    data["replay"]["records"][0]["exit_code"] = 1

    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(data, schema)


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
    for field in (
        "certificate_sha256",
        "certificate_identity_sha256",
        "confirmation_status",
        "replay",
    ):
        valid.pop(field)
    draft = create_certificate(**valid)
    records = tuple(
        item.model_copy(
            update={"certificate_identity_sha256": draft.certificate_identity_sha256}
        )
        for item in _confirmed(tmp_path).replay.records
    )
    with pytest.raises(ValidationError, match="CONFIRMED"):
        _seal_certificate(draft, records)


def test_confirmation_rejects_replay_count_failure_and_identity_mismatch(
    tmp_path: Path,
) -> None:
    certificate = _confirmed(tmp_path)
    base = certificate.model_dump(mode="python")
    records = list(certificate.replay.records)
    variants = [
        records[:2],
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
            not in {
                "certificate_sha256",
                "certificate_identity_sha256",
                "confirmation_status",
                "replay",
            }
        }
        draft = create_certificate(**kwargs)
        rebound = tuple(
            item.model_copy(
                update={
                    "certificate_identity_sha256": (
                        H0
                        if item.certificate_identity_sha256 == H0
                        else draft.certificate_identity_sha256
                    )
                }
            )
            for item in replay_records
        )
        with pytest.raises((ValidationError, ValueError), match="CONFIRMED|three"):
            _seal_certificate(draft, rebound)

    kwargs = {
        key: value
        for key, value in base.items()
        if key
        not in {
            "certificate_sha256",
            "certificate_identity_sha256",
            "confirmation_status",
            "replay",
        }
    }
    draft = create_certificate(**kwargs)
    failed = tuple(
        item.model_copy(
            update={
                "success": False,
                "exit_code": 1,
                "certificate_identity_sha256": draft.certificate_identity_sha256,
            }
        )
        if item.index == 2
        else item.model_copy(
            update={"certificate_identity_sha256": draft.certificate_identity_sha256}
        )
        for item in records
    )
    assert (
        _seal_certificate(draft, failed).confirmation_status
        is ConfirmationStatus.NOT_CONFIRMED
    )


def test_markdown_uses_only_validated_json_values(tmp_path: Path) -> None:
    certificate = _confirmed(tmp_path)
    markdown = render_markdown(certificate)
    assert "10,000,000,000,000,000,000" in markdown
    assert "42,000" in markdown
    assert "CONFIRMED" in markdown
    assert "Unverified revision label" in markdown
    assert "Historical-only metadata" in markdown
    assert "Cryptographic attestation: no" in markdown
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
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(
            {**serialized, "timestamp": "2026-09-14T09:00:00+09:00"}, schema
        )
    destination = write_events((event,), tmp_path / "events.jsonl")
    assert json.loads(destination.read_text()) == serialized
