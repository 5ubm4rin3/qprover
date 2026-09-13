from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest

from qprover.artifacts import ArtifactBundle, build_target
from qprover.evaluator import ScenarioEvaluator
from qprover.evm import EVMError, LocalAnvil, TransactionRejected
from qprover.manifest import load_manifest
from qprover.models import (
    ActionSpec,
    ActionStep,
    ActorSpec,
    ArgumentSpec,
    Candidate,
    FiniteDomain,
    ImpactSpec,
    IntegerDomain,
    Outcome,
    TargetManifest,
)
from qprover.search.controller import SearchController

ROOT = Path(__file__).parents[1]


def _manifest(name: str) -> TargetManifest:
    return load_manifest(ROOT / "benchmarks" / f"{name}.json")


def _step(
    manifest: TargetManifest,
    action_id: str,
    *,
    args: tuple[object, ...] = (),
    value_wei: int = 0,
) -> ActionStep:
    action = next(item for item in manifest.actions if item.id == action_id)
    return ActionStep(
        action_id=action.id,
        target_id=action.target_id,
        signature=action.signature,
        sender_slot=action.sender_slots[0],
        args=args,
        value_wei=value_wei,
    )


@pytest.fixture
def access_a() -> Iterator[
    tuple[TargetManifest, ArtifactBundle, LocalAnvil, ScenarioEvaluator]
]:
    manifest = _manifest("scenario_access_control_a")
    with build_target(manifest) as bundle, LocalAnvil() as anvil:
        evaluator = ScenarioEvaluator(manifest, bundle, anvil)
        yield manifest, bundle, anvil, evaluator


def test_evaluator_deploys_exact_bundle_and_captures_baseline(
    access_a: tuple[TargetManifest, ArtifactBundle, LocalAnvil, ScenarioEvaluator],
) -> None:
    manifest, bundle, anvil, evaluator = access_a

    assert not bundle.closed
    assert evaluator.deployments.keys() == {"scenario"}
    assert evaluator.actors[0].lower() == anvil.accounts[0]
    assert evaluator.actors[1].lower() == anvil.accounts[1]
    assert evaluator.initial_observations.values == {
        "protocol_assets": 10 * 10**18,
        "attacker_assets": 100 * 10**18,
    }
    assert evaluator.current_observations == evaluator.initial_observations
    assert len(evaluator.initial_observations.state_hash) == 64
    assert anvil.baseline_snapshot_id is not None
    assert manifest.deployments[0].artifact in evaluator.deployment_artifacts.values()


def test_evaluator_executes_violation_with_canonical_evidence_and_resets(
    access_a: tuple[TargetManifest, ArtifactBundle, LocalAnvil, ScenarioEvaluator],
) -> None:
    manifest, _, _, evaluator = access_a
    candidate = Candidate((_step(manifest, "step_alpha"), _step(manifest, "step_beta")))

    first = evaluator.evaluate(candidate)
    second = evaluator.evaluate(candidate)

    assert first.outcome is Outcome.VIOLATION
    assert first.transaction_count == 2
    assert first.state_fingerprint is not None
    assert first.state_fingerprint == second.state_fingerprint
    assert first.trace_features == second.trace_features
    assert any(item.startswith("opcode:step_alpha:") for item in first.trace_features)
    assert any(item.startswith("call:step_beta:") for item in first.trace_features)
    assert first.metadata["violation_prefix_length"] == 2
    assert first.metadata["impact"] == {
        "attacker_delta": 10 * 10**18,
        "protocol_delta": -(10 * 10**18),
        "unit": "wei",
        "admissible": True,
    }
    steps = first.metadata["steps"]
    assert len(steps) == 2
    assert all(len(step["calldata_hash"]) == 64 for step in steps)
    assert all(len(step["transaction_hash"]) == 66 for step in steps)
    assert all(step["receipt_status"] == 1 for step in steps)
    assert all(step["effective_gas_price"] == 0 for step in steps)
    assert all(step["trace_struct_log_count"] > 0 for step in steps)
    assert all(len(step["observation_state_hash"]) == 64 for step in steps)
    assert all(step["trace_failed"] is False for step in steps)
    assert all(step["return_data"].startswith("0x") for step in steps)
    assert (
        first.metadata["initial_observations"]
        == first.metadata["baseline_observations"]
    )


def test_evaluator_returns_pass_for_successful_nonviolating_prefix(
    access_a: tuple[TargetManifest, ArtifactBundle, LocalAnvil, ScenarioEvaluator],
) -> None:
    manifest, _, _, evaluator = access_a

    result = evaluator.evaluate(Candidate((_step(manifest, "step_alpha"),)))

    assert result.outcome is Outcome.PASS
    assert result.transaction_count == 1
    assert result.metadata["violation_prefix_length"] is None
    assert result.metadata["invariants"][0]["value"] is True


def test_evaluator_stops_at_first_mined_revert_and_counts_it() -> None:
    manifest = _manifest("scenario_access_control_b")
    with build_target(manifest) as bundle, LocalAnvil() as anvil:
        evaluator = ScenarioEvaluator(manifest, bundle, anvil)
        candidate = Candidate(
            (
                _step(manifest, "step_alpha"),
                _step(manifest, "step_beta"),
                _step(manifest, "noise_two", args=(7,)),
            )
        )

        result = evaluator.evaluate(candidate)

    assert result.outcome is Outcome.REVERT
    assert result.transaction_count == 1
    assert len(result.metadata["steps"]) == 1
    assert result.metadata["steps"][0]["receipt_status"] == 0
    assert result.metadata["steps"][0]["observation_state_hash"] is None
    assert result.metadata["steps"][0]["trace_failed"] is True
    assert result.metadata["steps"][0]["revert_data"].startswith("0x")
    assert result.metadata["revert_step"] == 1


def test_evaluator_does_not_call_invariant_failure_a_violation_without_impact() -> None:
    source = _manifest("scenario_access_control_a")
    manifest = source.model_copy(
        update={
            "impact": ImpactSpec(
                attacker_asset_observation="protocol_assets",
                protocol_asset_observation="protocol_assets",
                unit="wei",
            )
        }
    )
    candidate = Candidate((_step(manifest, "step_alpha"), _step(manifest, "step_beta")))

    with build_target(manifest) as bundle, LocalAnvil() as anvil:
        result = ScenarioEvaluator(manifest, bundle, anvil).evaluate(candidate)

    assert result.metadata["invariants"][0]["value"] is False
    assert result.metadata["impact"]["protocol_delta"] < 0
    assert result.metadata["impact"]["attacker_delta"] < 0
    assert result.metadata["impact"]["admissible"] is False
    assert result.outcome is Outcome.INCONCLUSIVE


def test_evaluator_rejects_candidate_outside_manifest_without_execution(
    access_a: tuple[TargetManifest, ArtifactBundle, LocalAnvil, ScenarioEvaluator],
) -> None:
    manifest, _, _, evaluator = access_a
    allowed = _step(manifest, "step_alpha")
    candidate = Candidate(
        (
            ActionStep(
                action_id=allowed.action_id,
                target_id=allowed.target_id,
                signature="drain()",
                sender_slot=allowed.sender_slot,
                args=(),
            ),
        )
    )

    result = evaluator.evaluate(candidate)

    assert result.outcome is Outcome.INCONCLUSIVE
    assert result.transaction_count == 0
    assert result.metadata["category"] == "candidate"


def test_evaluator_enforces_integer_domain_constraints_without_execution() -> None:
    source = _manifest("scenario_access_control_a")
    original = next(action for action in source.actions if action.id == "noise_two")
    constrained = ActionSpec(
        **{
            **original.model_dump(),
            "arguments": (
                ArgumentSpec(
                    name="value",
                    type="uint256",
                    domain=IntegerDomain(
                        kind="integer",
                        minimum=0,
                        maximum=9,
                        constraints=("arg0 % 2 == 1",),
                    ),
                ),
            ),
        }
    )
    manifest = source.model_copy(
        update={
            "actions": tuple(
                constrained if action.id == constrained.id else action
                for action in source.actions
            )
        }
    )
    candidate = Candidate((_step(manifest, "noise_two", args=(8,)),))

    with build_target(manifest) as bundle, LocalAnvil() as anvil:
        result = ScenarioEvaluator(manifest, bundle, anvil).evaluate(candidate)

    assert result.outcome is Outcome.INCONCLUSIVE
    assert result.transaction_count == 0
    assert result.metadata["category"] == "candidate"
    assert "constraint" in result.metadata["reason"]


@pytest.mark.parametrize(
    ("sender_slot", "value_wei"),
    [(True, 0), (1.0, 0), (1, False), (1, 0.0)],
)
def test_evaluator_rejects_coerced_sender_or_value_types(
    access_a: tuple[TargetManifest, ArtifactBundle, LocalAnvil, ScenarioEvaluator],
    sender_slot: object,
    value_wei: object,
) -> None:
    manifest, _, _, evaluator = access_a
    action = next(item for item in manifest.actions if item.id == "step_alpha")
    candidate = Candidate(
        (
            ActionStep(
                action_id=action.id,
                target_id=action.target_id,
                signature=action.signature,
                sender_slot=sender_slot,  # type: ignore[arg-type]
                args=(),
                value_wei=value_wei,  # type: ignore[arg-type]
            ),
        )
    )

    result = evaluator.evaluate(candidate)

    assert result.outcome is Outcome.INCONCLUSIVE
    assert result.transaction_count == 0
    assert "exact" in result.metadata["reason"]


def test_evaluator_rejects_manifest_allowed_value_above_uint256() -> None:
    source = _manifest("scenario_access_control_a")
    original = next(action for action in source.actions if action.id == "noise_one")
    oversized = original.model_copy(
        update={"value_domain": FiniteDomain(kind="finite", values=(1 << 256,))}
    )
    manifest = source.model_copy(
        update={
            "actions": tuple(
                oversized if action.id == oversized.id else action
                for action in source.actions
            )
        }
    )
    candidate = Candidate((_step(manifest, "noise_one", value_wei=1 << 256),))

    with build_target(manifest) as bundle, LocalAnvil() as anvil:
        result = ScenarioEvaluator(manifest, bundle, anvil).evaluate(candidate)

    assert result.outcome is Outcome.INCONCLUSIVE
    assert result.transaction_count == 0
    assert "uint256" in result.metadata["reason"]


def test_evaluator_accepts_exact_max_uint256_value_when_affordable() -> None:
    source = _manifest("scenario_access_control_a")
    maximum = (1 << 256) - 1
    original_action = next(
        action for action in source.actions if action.id == "noise_one"
    )
    max_value_action = original_action.model_copy(
        update={"value_domain": FiniteDomain(kind="finite", values=(maximum,))}
    )
    deployment = source.deployments[0].model_copy(update={"value_wei": 0})
    actors = tuple(
        ActorSpec(id=actor.id, slot=actor.slot, balance_wei=maximum)
        if actor.id == "attacker"
        else actor
        for actor in source.actors
    )
    manifest = source.model_copy(
        update={
            "actors": actors,
            "deployments": (deployment,),
            "actions": tuple(
                max_value_action if action.id == max_value_action.id else action
                for action in source.actions
            ),
        }
    )
    candidate = Candidate((_step(manifest, "noise_one", value_wei=maximum),))

    with build_target(manifest) as bundle, LocalAnvil() as anvil:
        result = ScenarioEvaluator(manifest, bundle, anvil).evaluate(candidate)

    assert result.outcome is Outcome.PASS
    assert result.transaction_count == 1
    assert result.metadata["steps"][0]["effective_gas_price"] == 0


def _zero_balance_attacker(manifest: TargetManifest) -> TargetManifest:
    actors = tuple(
        ActorSpec(id=actor.id, slot=actor.slot, balance_wei=0)
        if actor.id == "attacker"
        else actor
        for actor in manifest.actors
    )
    return manifest.model_copy(update={"actors": actors})


def test_evaluator_rejects_unaffordable_step_before_submission() -> None:
    manifest = _zero_balance_attacker(_manifest("scenario_access_control_a"))
    candidate = Candidate((_step(manifest, "noise_one", value_wei=10**18),))

    with build_target(manifest) as bundle, LocalAnvil() as anvil:
        result = ScenarioEvaluator(manifest, bundle, anvil).evaluate(candidate)

    assert result.outcome is Outcome.INCONCLUSIVE
    assert result.transaction_count == 0
    assert result.metadata["category"] == "candidate"
    assert result.metadata["invalid_step"] == 1
    assert "insufficient" in result.metadata["reason"]


def test_later_unaffordable_step_preserves_actual_prior_transaction_count() -> None:
    manifest = _zero_balance_attacker(_manifest("scenario_access_control_a"))
    candidate = Candidate(
        (
            _step(manifest, "noise_two", args=(7,)),
            _step(manifest, "noise_one", value_wei=10**18),
        )
    )

    with build_target(manifest) as bundle, LocalAnvil() as anvil:
        result = ScenarioEvaluator(manifest, bundle, anvil).evaluate(candidate)

    assert result.outcome is Outcome.INCONCLUSIVE
    assert result.transaction_count == 1
    assert len(result.metadata["steps"]) == 1
    assert result.metadata["invalid_step"] == 2


def test_later_invalid_scalar_type_preserves_actual_prior_transaction_count(
    access_a: tuple[TargetManifest, ArtifactBundle, LocalAnvil, ScenarioEvaluator],
) -> None:
    manifest, _, _, evaluator = access_a
    candidate = Candidate(
        (
            _step(manifest, "noise_two", args=(7,)),
            ActionStep(
                action_id="step_alpha",
                target_id="scenario",
                signature="claimRole()",
                sender_slot=1,
                args=(),
                value_wei=False,  # type: ignore[arg-type]
            ),
        )
    )

    result = evaluator.evaluate(candidate)

    assert result.outcome is Outcome.INCONCLUSIVE
    assert result.transaction_count == 1
    assert len(result.metadata["steps"]) == 1
    assert result.metadata["invalid_step"] == 2


def test_deterministic_transaction_rejection_is_candidate_inconclusive(
    access_a: tuple[TargetManifest, ArtifactBundle, LocalAnvil, ScenarioEvaluator],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifest, _, anvil, evaluator = access_a
    monkeypatch.setattr(
        anvil,
        "send_transaction",
        lambda transaction: (_ for _ in ()).throw(
            TransactionRejected("deterministic rejection")
        ),
    )

    result = evaluator.evaluate(Candidate((_step(manifest, "step_alpha"),)))

    assert result.outcome is Outcome.INCONCLUSIVE
    assert result.transaction_count == 0
    assert result.metadata["category"] == "candidate"


def test_malformed_receipt_becomes_infrastructure_evaluation(
    access_a: tuple[TargetManifest, ArtifactBundle, LocalAnvil, ScenarioEvaluator],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifest, _, anvil, evaluator = access_a
    monkeypatch.setattr(
        anvil, "wait_for_receipt", lambda transaction_hash: {"status": []}
    )

    result = evaluator.evaluate(Candidate((_step(manifest, "step_alpha"),)))

    assert result.outcome is Outcome.INFRA_ERROR
    assert result.transaction_count == 1
    assert result.metadata["category"] == "receipt"


def test_malformed_trace_becomes_infrastructure_evaluation(
    access_a: tuple[TargetManifest, ArtifactBundle, LocalAnvil, ScenarioEvaluator],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifest, _, anvil, evaluator = access_a
    original_request = anvil._request

    def malformed_trace(method: str, params=None):
        if method == "debug_traceTransaction":
            return {"failed": False, "returnValue": "0x", "structLogs": "bad"}
        return original_request(method, params)

    monkeypatch.setattr(anvil, "_request", malformed_trace)

    result = evaluator.evaluate(Candidate((_step(manifest, "step_alpha"),)))

    assert result.outcome is Outcome.INFRA_ERROR
    assert result.transaction_count == 1
    assert result.metadata["category"] == "trace"


def test_malformed_observation_rpc_becomes_infrastructure_evaluation(
    access_a: tuple[TargetManifest, ArtifactBundle, LocalAnvil, ScenarioEvaluator],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifest, _, anvil, evaluator = access_a
    monkeypatch.setattr(
        anvil,
        "call",
        lambda transaction: (_ for _ in ()).throw(EVMError("malformed call result")),
    )

    result = evaluator.evaluate(Candidate((_step(manifest, "noise_two", args=(7,)),)))

    assert result.outcome is Outcome.INFRA_ERROR
    assert result.transaction_count == 1
    assert result.metadata["category"] == "observation-rpc"


def test_abi_invalid_allowed_value_is_rejected_before_submission() -> None:
    source = _manifest("scenario_access_control_a")
    original = next(action for action in source.actions if action.id == "noise_two")
    invalid_argument = ArgumentSpec(
        name="value",
        type="uint256",
        domain=FiniteDomain(kind="finite", values=("not-an-integer",)),
    )
    invalid_action = original.model_copy(update={"arguments": (invalid_argument,)})
    manifest = source.model_copy(
        update={
            "actions": tuple(
                invalid_action if action.id == invalid_action.id else action
                for action in source.actions
            )
        }
    )
    candidate = Candidate((_step(manifest, "noise_two", args=("not-an-integer",)),))

    with build_target(manifest) as bundle, LocalAnvil() as anvil:
        result = ScenarioEvaluator(manifest, bundle, anvil).evaluate(candidate)

    assert result.outcome is Outcome.INCONCLUSIVE
    assert result.transaction_count == 0
    assert "ABI" in result.metadata["reason"]


def test_controller_continues_after_unaffordable_candidate() -> None:
    manifest = _zero_balance_attacker(_manifest("scenario_access_control_a"))
    candidates = [
        Candidate((_step(manifest, "noise_one", value_wei=10**18),)),
        Candidate((_step(manifest, "step_alpha"), _step(manifest, "step_beta"))),
    ]

    class Strategy:
        def __init__(self) -> None:
            self.results = []

        def propose(self, remaining_transactions: int):
            del remaining_transactions
            return candidates.pop(0) if candidates else None

        def observe(self, candidate: Candidate, result) -> None:
            del candidate
            self.results.append(result)

    with build_target(manifest) as bundle, LocalAnvil() as anvil:
        evaluator = ScenarioEvaluator(manifest, bundle, anvil)
        run = SearchController(run_id_factory=lambda: "candidate-continuation").run(
            Strategy(), evaluator, manifest.limits
        )

    assert [item.evaluation.outcome for item in run.evaluations] == [
        Outcome.INCONCLUSIVE,
        Outcome.VIOLATION,
    ]
    assert run.evm_transactions == 2
