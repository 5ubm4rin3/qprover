from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

import qprover.search.controller as controller_module
import qprover.trust404_runner as runner
from qprover.models import ActionStep, Candidate, Outcome
from qprover.trust404 import Track04Action, Track04SearchModel, Track04Variant

TARGET = "0x00000000000000000000000000000000000000a1"


def _model() -> Track04SearchModel:
    action = Track04Action(
        id="call:alpha()",
        kind="call",
        signature="alpha()",
        function_id="function:Demo:alpha()",
        param_types=(),
        payable=False,
        utility=1.0,
        storage_reads=(),
        storage_writes=(),
        provenance=("Demo.sol", "0:1:0"),
    )
    return Track04SearchModel(
        actions=(action,),
        variants=(
            Track04Variant(
                action_id=action.id,
                signature=action.signature,
                args=(),
                value_wei=0,
            ),
        ),
        utilities={action.id: 1.0},
        transitions={},
        max_sequence_length=1,
        analysis=SimpleNamespace(),
    )


def test_run_search_uses_persistent_runtime_instead_of_organizer_verifier(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ledger = runner._AttemptLedger(lines=[], codes={})
    runtime_calls: list[tuple[object, ...]] = []

    class FakeRuntime:
        target_address = TARGET

        def execute(self, calls):
            runtime_calls.append(tuple(calls))
            return SimpleNamespace(
                all_hold=False,
                violated_predicate="solvent",
                transaction_hashes=("0x" + "11" * 32,),
            )

    class FakeController:
        def __init__(self, *, candidate_validator) -> None:
            self.candidate_validator = candidate_validator

        def run(self, strategy, evaluator, limits, *, problem, seed):
            del strategy, limits, problem, seed
            skeleton = Candidate(
                (
                    ActionStep(
                        action_id="call:alpha()",
                        target_id="target",
                        signature="alpha()",
                        sender_slot=0,
                        args=(),
                        value_wei=0,
                    ),
                )
            )
            evaluation = evaluator.evaluate(skeleton)
            return SimpleNamespace(
                violation=skeleton if evaluation.outcome is Outcome.VIOLATION else None
            )

    monkeypatch.setattr(controller_module, "SearchController", FakeController)
    monkeypatch.setattr(runner, "_make_qubo_strategy", lambda: object())

    def forbidden_verifier(*_args, **_kwargs):
        raise AssertionError("search must not invoke organizer verifier")

    found = runner._run_search(
        model=_model(),
        target_path=tmp_path / "Target.sol",
        invariants_path=tmp_path / "Invariants.sol",
        manifest=SimpleNamespace(),
        harness_dir=tmp_path,
        seed=7,
        attempt_budget=1,
        deadline=100.0,
        ledger=ledger,
        verifier=forbidden_verifier,
        clock=lambda: 0.0,
        runtime=FakeRuntime(),
    )

    assert found is True
    assert ledger.attempts == 1
    assert ledger.winner_code is not None
    assert len(runtime_calls) == 1
    assert len(runtime_calls[0]) == 1
    call = runtime_calls[0][0]
    assert call.target == TARGET
    assert call.value_wei == 0
    assert call.calldata.startswith("0x")


def test_run_search_executes_semantic_hypothesis_before_portfolio(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ledger = runner._AttemptLedger(lines=[], codes={})

    class FakeRuntime:
        target_address = TARGET

        def execute(self, calls):
            assert len(calls) == 1
            return SimpleNamespace(
                all_hold=False,
                violated_predicate="solvent",
                transaction_hashes=("0x" + "11" * 32,),
            )

    class ForbiddenController:
        def __init__(self, **_kwargs) -> None:
            raise AssertionError("semantic violation must stop before portfolio search")

    monkeypatch.setattr(
        controller_module,
        "SearchController",
        ForbiddenController,
    )
    monkeypatch.setattr(
        runner,
        "_semantic_hypotheses",
        lambda _model, _runtime: (("call:alpha()",),),
    )

    found = runner._run_search(
        model=_model(),
        target_path=tmp_path / "Target.sol",
        invariants_path=tmp_path / "Invariants.sol",
        manifest=SimpleNamespace(),
        harness_dir=tmp_path,
        seed=7,
        attempt_budget=2,
        deadline=100.0,
        ledger=ledger,
        verifier=lambda *_args, **_kwargs: None,
        clock=lambda: 0.0,
        runtime=FakeRuntime(),
    )

    assert found is True
    assert ledger.attempts == 1
    assert "strategy=semantic" in ledger.lines[0]


def test_semantic_prepass_preserves_an_attempt_for_portfolio(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ledger = runner._AttemptLedger(lines=[], codes={})
    portfolio_budgets: list[int] = []

    class FakeRuntime:
        target_address = TARGET

        def execute(self, calls):
            assert len(calls) == 1
            return SimpleNamespace(
                all_hold=True,
                violated_predicate="",
                transaction_hashes=("0x" + "11" * 32,),
            )

    class FakeController:
        def __init__(self, **_kwargs) -> None:
            pass

        def run(self, strategy, evaluator, limits, *, problem, seed):
            del strategy, problem, seed
            portfolio_budgets.append(limits.candidate_budget)
            skeleton = Candidate(
                (
                    ActionStep(
                        action_id="call:alpha()",
                        target_id="target",
                        signature="alpha()",
                        sender_slot=0,
                        args=(),
                        value_wei=0,
                    ),
                )
            )
            evaluator.evaluate(skeleton)
            return SimpleNamespace(violation=None)

    monkeypatch.setattr(controller_module, "SearchController", FakeController)
    monkeypatch.setattr(
        runner,
        "_semantic_hypotheses",
        lambda _model, _runtime: (
            ("call:alpha()",),
            ("call:alpha()",),
        ),
    )

    found = runner._run_search(
        model=_model(),
        target_path=tmp_path / "Target.sol",
        invariants_path=tmp_path / "Invariants.sol",
        manifest=SimpleNamespace(),
        harness_dir=tmp_path,
        seed=7,
        attempt_budget=2,
        deadline=100.0,
        ledger=ledger,
        verifier=lambda *_args, **_kwargs: None,
        clock=lambda: 0.0,
        runtime=FakeRuntime(),
    )

    assert found is False
    assert portfolio_budgets == [1]
    assert ledger.attempts == 2
    assert "strategy=semantic" in ledger.lines[0]
    assert "strategy=portfolio" in ledger.lines[1]
