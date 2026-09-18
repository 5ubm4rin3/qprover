from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

import qprover.search.controller as controller_module
import qprover.trust404_runner as runner
from qprover.models import ActionStep, Candidate
from qprover.trust404 import Track04Action, Track04SearchModel, Track04Variant
from qprover.trust404_harness import VerificationResult


def _model_with_two_concrete_variants() -> Track04SearchModel:
    action = Track04Action(
        id="call:alpha(uint256)",
        kind="call",
        signature="alpha(uint256)",
        function_id="function:Demo:alpha(uint256)",
        param_types=("uint256",),
        payable=False,
        utility=1.0,
        storage_reads=(),
        storage_writes=(),
        provenance=("Demo.sol", "0:1:0"),
    )
    variants = (
        Track04Variant(
            action_id=action.id,
            signature=action.signature,
            args=(1,),
            value_wei=0,
        ),
        Track04Variant(
            action_id=action.id,
            signature=action.signature,
            args=(2,),
            value_wei=0,
        ),
    )
    return Track04SearchModel(
        actions=(action,),
        variants=variants,
        utilities={action.id: action.utility},
        transitions={},
        max_sequence_length=1,
        analysis=SimpleNamespace(),
    )


def test_one_search_evaluation_executes_exactly_one_concrete_candidate(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    model = _model_with_two_concrete_variants()
    ledger = runner._AttemptLedger(lines=[], codes={})
    verifier_calls: list[str] = []

    class FakeController:
        def __init__(self, *, candidate_validator) -> None:
            self.candidate_validator = candidate_validator

        def run(self, strategy, evaluator, limits, *, problem, seed):
            del strategy, limits, problem, seed
            skeleton = Candidate(
                (
                    ActionStep(
                        action_id="call:alpha(uint256)",
                        target_id="target",
                        signature="alpha(uint256)",
                        sender_slot=0,
                        args=(1,),
                        value_wei=0,
                    ),
                )
            )
            evaluation = evaluator.evaluate(skeleton)
            assert evaluation is not None
            return SimpleNamespace(violation=None)

    monkeypatch.setattr(controller_module, "SearchController", FakeController)
    monkeypatch.setattr(runner, "_make_qubo_strategy", lambda: object())

    def verifier(
        _harness_dir,
        _target_path,
        _invariants_path,
        code,
        _manifest,
        **_kwargs,
    ) -> VerificationResult:
        verifier_calls.append(code)
        return VerificationResult(False, "", "not_proven")

    found = runner._run_search(
        model=model,
        target_path=tmp_path / "Target.sol",
        invariants_path=tmp_path / "Invariants.sol",
        manifest=SimpleNamespace(),
        harness_dir=tmp_path,
        seed=7,
        attempt_budget=2,
        deadline=100.0,
        ledger=ledger,
        verifier=verifier,
        clock=lambda: 0.0,
    )

    assert found is False
    assert len(verifier_calls) == 1
    assert ledger.attempts == 1
