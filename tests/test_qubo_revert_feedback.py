from __future__ import annotations

from collections import Counter

from qprover.models import ActionStep, Candidate, Outcome
from qprover.parameters import ActionVariant
from qprover.search.annealing import SimulatedAnnealingBackend
from qprover.search.base import Evaluation
from qprover.search.bqm import SearchProblem
from qprover.search.qubo import QuboStrategy


def test_qubo_revert_feedback_penalizes_only_failed_prefix_action() -> None:
    actions = ("a", "b", "c")
    variants = tuple(
        ActionVariant(
            action_id=action,
            target_id="target",
            signature=f"{action}()",
            sender_slot=0,
            args=(),
            value_wei=0,
            max_repetitions=1,
            argument_provenance=(),
            value_provenance=("test",),
        )
        for action in actions
    )
    problem = SearchProblem(
        actions=actions,
        max_sequence_length=3,
        repetition_limits={action: 1 for action in actions},
        variants=variants,
    )
    strategy = QuboStrategy(backend=SimulatedAnnealingBackend(), reads=1)
    strategy.initialize(problem, seed=7)
    candidate = Candidate(
        tuple(
            ActionStep(action, "target", f"{action}()", 0, (), 0)
            for action in actions
        )
    )

    strategy.observe(
        candidate,
        Evaluation(
            outcome=Outcome.REVERT,
            transaction_count=2,
            metadata={"note": "revert_step=1"},
        ),
    )

    assert strategy._revert_counts == Counter({"b": 1})
