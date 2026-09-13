from __future__ import annotations

from collections import Counter
from pathlib import Path

import pytest

from qprover.manifest import load_manifest
from qprover.minimizer import MinimizationError, minimize
from qprover.models import ActionStep, Candidate, Outcome
from qprover.search.base import Evaluation


class PredicateEvaluator:
    def __init__(self) -> None:
        self.calls: Counter[str] = Counter()

    def evaluate(self, candidate: Candidate) -> Evaluation:
        self.calls[candidate.canonical_id] += 1
        actions = tuple(step.action_id for step in candidate.steps)
        violating = "prepare" in actions and "trigger" in actions
        admissible = violating and actions.index("prepare") < actions.index("trigger")
        return Evaluation(
            outcome=Outcome.VIOLATION if admissible else Outcome.PASS,
            transaction_count=len(candidate.steps),
            metadata={"impact": {"admissible": admissible}},
        )


def _step(action: str, sender: int = 2, arg: int = 9, value: int = 7) -> ActionStep:
    return ActionStep(action, "scenario", f"{action}(uint256)", sender, (arg,), value)


def test_minimizer_executes_each_unique_reduction_and_final_candidate() -> None:
    evaluator = PredicateEvaluator()
    candidate = Candidate(
        (
            _step("noise_a"),
            _step("prepare"),
            _step("noise_b"),
            _step("trigger", sender=1),
            _step("noise_c"),
        )
    )
    domains = {
        action: {
            "sender_slots": (1, 2),
            "arguments": ((0, 1, 9),),
            "values": (0, 1, 7),
        }
        for action in ("noise_a", "prepare", "noise_b", "trigger", "noise_c")
    }

    result = minimize(candidate, evaluator, domains)

    assert tuple(step.action_id for step in result.candidate.steps) == (
        "prepare",
        "trigger",
    )
    assert all(step.sender_slot == 1 for step in result.candidate.steps)
    assert all(
        step.args == (0,) and step.value_wei == 0 for step in result.candidate.steps
    )
    assert result.final_evaluation.outcome is Outcome.VIOLATION
    assert result.final_evaluation.metadata["impact"]["admissible"] is True
    assert result.evaluation_count == sum(evaluator.calls.values())
    assert result.uncached_candidate_count == result.evaluation_count
    assert result.transaction_count == sum(
        attempt.transaction_count for attempt in result.attempts if not attempt.cached
    )
    assert evaluator.calls[result.candidate.canonical_id] >= 2
    assert result.locally_minimal is True
    assert result.attempted_operators == (
        "ddmin-contiguous-chunks",
        "single-delete-fixed-point",
        "actor-normalization",
        "argument-simplification",
        "value-simplification",
        "final-fresh-evaluation",
    )
    assert "global" not in result.minimality_claim.lower()


def test_minimizer_rejects_nonviolating_or_inadmissible_seed() -> None:
    evaluator = PredicateEvaluator()
    domains = {
        "noise_a": {
            "sender_slots": (1,),
            "arguments": ((9,),),
            "values": (7,),
        }
    }
    with pytest.raises(MinimizationError, match="admissible executed violation"):
        minimize(Candidate((_step("noise_a"),)), evaluator, domains)


def test_minimizer_uses_only_manifest_allowed_slots_and_values() -> None:
    manifest = load_manifest(Path("benchmarks/scenario_reentrancy_a.json"))
    candidate = Candidate(
        (
            ActionStep(
                "step_alpha", "scenario", "prime(uint256)", 1, (10**18,), 10**18
            ),
            ActionStep("step_beta", "scenario", "attack()", 1, (), 0),
        )
    )

    class ReentryPredicate:
        def evaluate(self, proposed: Candidate) -> Evaluation:
            valid = proposed == candidate
            return Evaluation(
                outcome=Outcome.VIOLATION if valid else Outcome.INCONCLUSIVE,
                transaction_count=len(proposed.steps) if valid else 0,
                metadata={"impact": {"admissible": valid}},
            )

    result = minimize(candidate, ReentryPredicate(), manifest)
    assert result.candidate == candidate


def test_evaluator_factory_closes_every_uncached_lifecycle() -> None:
    lifecycle = Counter()

    class ManagedEvaluator(PredicateEvaluator):
        def __enter__(self):
            lifecycle["entered"] += 1
            return self

        def __exit__(self, *exc_info: object) -> None:
            lifecycle["closed"] += 1

    candidate = Candidate((_step("prepare"), _step("trigger", sender=1)))
    domains = {
        action: {
            "sender_slots": (1, 2),
            "arguments": ((0, 9),),
            "values": (0, 7),
        }
        for action in ("prepare", "trigger")
    }

    result = minimize(candidate, ManagedEvaluator, domains)

    assert lifecycle == {
        "entered": result.evaluation_count,
        "closed": result.evaluation_count,
    }
