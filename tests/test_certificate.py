from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path

import jsonschema
import pytest
from pydantic import ValidationError

from qprover.certificate import (
    REPLAY_ARGV_TEMPLATE,
    REPLAY_INVOCATION_TEMPLATE,
    REPLAY_MATERIALIZATION,
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
    ReplayRecipe,
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
    write_markdown,
)
from qprover.models import ConfirmationStatus, Outcome
from qprover.safeio import SafeOutputError

H0 = "0" * 64
H1 = "1" * 64
H2 = "2" * 64
H3 = "3" * 64


def test_invariant_only_impact_is_explicitly_not_applicable() -> None:
    evidence = ImpactEvidence(
        applicability="not_applicable",
        attacker_observation=None,
        protocol_observation=None,
        attacker_delta=None,
        protocol_delta=None,
        unit=None,
        admissible=False,
        executed=False,
    )

    assert evidence.applicability == "not_applicable"
    assert evidence.attacker_delta is None


@pytest.mark.parametrize(
    "mutation",
    [
        {"attacker_observation": "attacker_assets"},
        {"protocol_observation": "protocol_assets"},
        {"attacker_delta": 0},
        {"protocol_delta": 0},
        {"unit": "wei"},
        {"admissible": True},
        {"executed": True},
    ],
)
def test_not_applicable_impact_rejects_every_economic_claim(
    mutation: dict[str, object],
) -> None:
    data = {
        "applicability": "not_applicable",
        "attacker_observation": None,
        "protocol_observation": None,
        "attacker_delta": None,
        "protocol_delta": None,
        "unit": None,
        "admissible": False,
        "executed": False,
    }
    data.update(mutation)
    with pytest.raises(ValidationError, match="not-applicable"):
        ImpactEvidence(**data)


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
        "initial_invariants": (
            InvariantEvidence(
                id="assets_preserved",
                expression="protocol_assets >= initial_protocol_assets",
                description="Assets stay present.",
                foundry_assertion="assertGe(target.protocolAssets(), initialAssets);",
                evaluated=True,
                value=True,
                reason=None,
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
            applicability="economic",
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
            minimality_claim=(
                "Replay-verified local minimum under one-step deletion only."
            ),
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
        "replay_invocation_template": REPLAY_INVOCATION_TEMPLATE,
        "assurance": AssuranceEvidence(
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
    }


def _confirmed(tmp_path: Path):
    base = _base(tmp_path)
    provisional = create_certificate(
        confirmation_status=ConfirmationStatus.NOT_CONFIRMED,
        replay=ReplayEvidence(
            local_only=True, required_repeats=3, recipe=None, records=()
        ),
        **base,
    )
    recipe = ReplayRecipe(
        workspace_cwd=".",
        source_project="benchmarks/foundry",
        source_poc="poc/QProverReplay_run_7.t.sol",
        foundry_config="foundry.toml",
        foundry_config_sha256=H0,
        source_sha256=H1,
        poc_sha256=H3,
        staged_project="{private_project}",
        execution_cwd="{private_project}",
        staged_poc="test/QProverReplay.t.sol",
        materialization=REPLAY_MATERIALIZATION,
        argv_template=REPLAY_ARGV_TEMPLATE,
        staging_tree_sha256=H2,
    )
    records = tuple(
        ReplayRecord(
            index=index,
            success=True,
            exit_code=0,
            stdout_sha256=H0,
            stderr_sha256=H0,
            structured_result_sha256=H0,
            duration_seconds=0.25,
            recipe_sha256=recipe.compute_hash(),
            execution_argv_sha256=str(index) * 64,
            execution_cwd_sha256=str(index + 3) * 64,
            staging_tree_sha256=H2,
            staging_unchanged=True,
            suite_count=1,
            test_count=1,
            executed_suite="test/QProverReplay.t.sol:QProverReplayTest",
            executed_test="test_qprover_replay()",
            executed_status="Success",
            certificate_identity_sha256=provisional.certificate_identity_sha256,
            poc_sha256=H3,
            manifest_sha256=H0,
            source_sha256=H1,
            artifact_sha256=H2,
        )
        for index in range(1, 4)
    )
    return _seal_certificate(provisional, recipe, records)


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


@pytest.mark.parametrize("field", ["schema_version", "confirmation_policy"])
def test_raw_certificate_requires_explicit_version_and_confirmation_policy(
    tmp_path: Path, field: str
) -> None:
    data = json.loads(_confirmed(tmp_path).canonical_json())
    data.pop(field)
    schema = json.loads(Path("schemas/certificate.schema.json").read_text())

    with pytest.raises(ValidationError, match=field):
        ProofCertificate.model_validate(data)
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(data, schema)


@pytest.mark.parametrize("kind", ["certificate", "markdown", "events"])
@pytest.mark.parametrize("link_kind", ["symlink", "hardlink"])
def test_artifact_writers_reject_linked_targets(
    tmp_path: Path, kind: str, link_kind: str
) -> None:
    certificate = create_certificate(**_base(tmp_path))
    victim = tmp_path / "victim"
    victim.write_text("untouched")
    destination = tmp_path / f"{kind}.out"
    if link_kind == "symlink":
        destination.symlink_to(victim)
    else:
        destination.hardlink_to(victim)

    with pytest.raises(SafeOutputError):
        if kind == "certificate":
            write_certificate(certificate, destination)
        elif kind == "markdown":
            write_markdown(certificate, destination)
        else:
            write_events(
                (
                    EvidenceEvent(
                        run_id="run-7",
                        sequence=1,
                        timestamp=datetime(2026, 9, 14, tzinfo=UTC),
                        kind="confirmation",
                        details={"status": "NOT_CONFIRMED"},
                    ),
                ),
                destination,
            )
    assert victim.read_text() == "untouched"


def test_artifact_writer_rejects_parent_symlink_and_path_traversal(
    tmp_path: Path,
) -> None:
    certificate = create_certificate(**_base(tmp_path))
    outside = tmp_path / "outside"
    outside.mkdir()
    linked = tmp_path / "linked"
    linked.symlink_to(outside, target_is_directory=True)

    with pytest.raises(SafeOutputError):
        write_certificate(certificate, linked / "certificate.json")
    with pytest.raises(SafeOutputError, match="traversal"):
        write_markdown(certificate, tmp_path / "safe" / ".." / "escaped.md")


def test_artifact_writer_atomically_replaces_one_regular_unlinked_target(
    tmp_path: Path,
) -> None:
    certificate = create_certificate(**_base(tmp_path))
    destination = tmp_path / "certificate.json"
    destination.write_text("old")

    write_certificate(certificate, destination)

    assert ProofCertificate.model_validate_json(destination.read_text()) == certificate


def test_economic_impact_requires_executed_accounting_in_model_and_schema(
    tmp_path: Path,
) -> None:
    data = json.loads(_confirmed(tmp_path).canonical_json())
    data["impact"]["executed"] = False
    schema = json.loads(Path("schemas/certificate.schema.json").read_text())

    with pytest.raises(ValidationError, match="executed"):
        ImpactEvidence.model_validate(data["impact"])
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(data, schema)


@pytest.mark.parametrize(
    "field",
    [
        "applicability",
        "attacker_observation",
        "protocol_observation",
        "attacker_delta",
        "protocol_delta",
        "unit",
    ],
)
def test_raw_impact_omissions_fail_in_model_and_schema(
    tmp_path: Path, field: str
) -> None:
    data = json.loads(_confirmed(tmp_path).canonical_json())
    data["impact"].pop(field)
    schema = json.loads(Path("schemas/certificate.schema.json").read_text())

    with pytest.raises(ValidationError, match=field):
        ImpactEvidence.model_validate(data["impact"])
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(data, schema)


@pytest.mark.parametrize(
    "mutation",
    [
        {"id": "other"},
        {"expression": "true"},
        {"description": "tampered"},
        {"foundry_assertion": "assert(true);"},
        {"evaluated": False},
        {"value": False},
    ],
)
def test_certificate_rejects_tampered_initial_invariant(
    tmp_path: Path, mutation: dict[str, object]
) -> None:
    data = _base(tmp_path)
    initial = data["initial_invariants"][0]
    data["initial_invariants"] = (initial.model_copy(update=mutation),)

    with pytest.raises(ValidationError, match="baseline-true"):
        create_certificate(**data)


def test_certificate_rejects_duplicate_initial_invariant(tmp_path: Path) -> None:
    data = _base(tmp_path)
    initial = data["initial_invariants"][0]
    data["initial_invariants"] = (initial, initial)

    with pytest.raises(ValidationError, match="baseline-true"):
        create_certificate(**data)


def test_certificate_rejects_pre_policy_schema_version(tmp_path: Path) -> None:
    data = _confirmed(tmp_path).model_dump(mode="json")
    data["schema_version"] = "1.0"

    with pytest.raises(ValidationError, match="schema_version"):
        ProofCertificate.model_validate(data)


def test_certificate_labels_replay_invocation_as_an_unresolved_template(
    tmp_path: Path,
) -> None:
    data = _base(tmp_path)
    certificate = create_certificate(**data)

    serialized = certificate.model_dump(mode="json")
    assert serialized["replay_invocation_template"] == REPLAY_INVOCATION_TEMPLATE
    assert "replay_command" not in serialized
    assert "not executable" in certificate.assurance.invocation_template_scope
    assert "trusted" in certificate.assurance.trusted_local_execution_boundary

    legacy = dict(data)
    legacy["replay_command"] = legacy.pop("replay_invocation_template")
    with pytest.raises(ValidationError, match="replay_invocation_template"):
        create_certificate(**legacy)

    schema = json.loads(Path("schemas/certificate.schema.json").read_text())
    serialized["replay_command"] = serialized.pop("replay_invocation_template")
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(serialized, schema)


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
            replay=ReplayEvidence(
                local_only=True, required_repeats=3, recipe=None, records=()
            ),
            **base,
        )

    wrong_template = dict(base)
    wrong_template["replay_invocation_template"] = "forge test --offline"
    with pytest.raises(ValidationError, match="replay_invocation_template"):
        create_certificate(**wrong_template)

    draft = create_certificate(
        confirmation_status=ConfirmationStatus.NOT_CONFIRMED,
        replay=ReplayEvidence(
            local_only=True, required_repeats=3, recipe=None, records=()
        ),
        **base,
    )
    confirmed = _confirmed(tmp_path)
    assert confirmed.replay.recipe is not None
    forged = ReplayEvidence(
        local_only=True,
        required_repeats=3,
        recipe=confirmed.replay.recipe,
        records=(
            confirmed.replay.records[0].model_copy(
                update={
                    "certificate_identity_sha256": (draft.certificate_identity_sha256)
                }
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


def test_replay_recipe_rejects_forged_argv_template() -> None:
    with pytest.raises(ValidationError, match="argv template"):
        ReplayRecipe(
            workspace_cwd=".",
            source_project="benchmarks/foundry",
            source_poc="poc/QProverReplay.t.sol",
            foundry_config="foundry.toml",
            foundry_config_sha256=H0,
            source_sha256=H1,
            poc_sha256=H2,
            staged_project="{private_project}",
            execution_cwd="{private_project}",
            staged_poc="test/QProverReplay.t.sol",
            materialization=REPLAY_MATERIALIZATION,
            argv_template=("forge", "test", "--offline"),
            staging_tree_sha256=H3,
        )


def test_assurance_explicitly_separates_replay_proof_from_history() -> None:
    assurance = AssuranceEvidence(
        replay_proven_scope=(
            "manifest/source/build/artifact identities; local chain and actor funding; "
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
            "replay_invocation_template contains unresolved placeholders and is not "
            "executable until resolved by a conforming QProver CLI"
        ),
        trusted_local_execution_boundary=(
            "Forge, Solc, and Anvil executables are trusted local tool boundaries; the "
            "privileged local host is trusted; no cryptographic attestation protects "
            "against a compromised executable or privileged host"
        ),
        cryptographic_attestation=False,
    )

    assert "transaction execution" in assurance.replay_proven_scope
    assert "revision" in assurance.historical_search_metadata_scope
    assert "not executable" in assurance.invocation_template_scope
    assert "Forge, Solc, and Anvil" in assurance.trusted_local_execution_boundary
    assert assurance.cryptographic_attestation is False


@pytest.mark.parametrize(
    "claim",
    (
        "Exhaustive under every attempted operator.",
        "Every possible reduction was proven.",
        "Globally minimal exploit.",
    ),
)
def test_minimization_claim_cannot_overstate_replay_proof(claim: str) -> None:
    base = _base(Path("."))["minimization"]
    assert isinstance(base, MinimizationEvidence)

    with pytest.raises(ValidationError, match="minimality_claim"):
        MinimizationEvidence.model_validate(
            {**base.model_dump(mode="python"), "minimality_claim": claim}
        )


def test_json_schema_rejects_structural_replay_invocation_forgery(
    tmp_path: Path,
) -> None:
    schema = json.loads(Path("schemas/certificate.schema.json").read_text())
    data = json.loads(_confirmed(tmp_path).canonical_json())
    data["replay"]["recipe"]["argv_template"] = [
        "forge",
        "test",
        "--offline",
    ]

    assert "semantic" in schema["$comment"].lower()
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(data, schema)


def test_json_schema_requires_recipe_exactly_when_replay_records_exist(
    tmp_path: Path,
) -> None:
    schema = json.loads(Path("schemas/certificate.schema.json").read_text())
    confirmed = json.loads(_confirmed(tmp_path).canonical_json())
    confirmed["replay"]["recipe"] = None
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(confirmed, schema)

    draft = json.loads(create_certificate(**_base(tmp_path)).canonical_json())
    draft["replay"]["recipe"] = json.loads(
        _confirmed(tmp_path).replay.recipe.model_dump_json()
    )
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(draft, schema)


def test_confirmation_binds_replay_recipe_to_certificate_target(tmp_path: Path) -> None:
    draft = create_certificate(**_base(tmp_path))
    confirmed = _confirmed(tmp_path)
    assert confirmed.replay.recipe is not None
    recipe = confirmed.replay.recipe.model_copy(
        update={"source_project": "another/project"}
    )
    records = tuple(
        item.model_copy(
            update={
                "recipe_sha256": recipe.compute_hash(),
                "certificate_identity_sha256": (draft.certificate_identity_sha256),
            }
        )
        for item in confirmed.replay.records
    )

    with pytest.raises(ValidationError, match="recipe identity"):
        _seal_certificate(draft, recipe, records)


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
    confirmed = _confirmed(tmp_path)
    assert confirmed.replay.recipe is not None
    records = tuple(
        item.model_copy(
            update={"certificate_identity_sha256": draft.certificate_identity_sha256}
        )
        for item in confirmed.replay.records
    )
    with pytest.raises(ValidationError, match="CONFIRMED"):
        _seal_certificate(draft, confirmed.replay.recipe, records)


def test_confirmation_rejects_replay_count_failure_and_identity_mismatch(
    tmp_path: Path,
) -> None:
    certificate = _confirmed(tmp_path)
    assert certificate.replay.recipe is not None
    recipe = certificate.replay.recipe
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
            _seal_certificate(draft, recipe, rebound)

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
        _seal_certificate(draft, recipe, failed).confirmation_status
        is ConfirmationStatus.NOT_CONFIRMED
    )


def test_markdown_uses_only_validated_json_values(tmp_path: Path) -> None:
    certificate = _confirmed(tmp_path)
    markdown = render_markdown(certificate)
    assert "10,000,000,000,000,000,000" in markdown
    assert "42,000" in markdown
    assert "CONFIRMED" in markdown
    assert "Unverified revision label" in markdown
    assert (
        "Replay invocation template (unresolved; not directly executable)" in markdown
    )
    assert "Historical-only metadata" in markdown
    assert "Trusted local execution boundary" in markdown
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
