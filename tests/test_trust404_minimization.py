from __future__ import annotations

from qprover.minimizer import minimize_track04_candidate
from qprover.trust404_values import ValueCandidate, ValueStep


def _candidate(actions: tuple[str, ...]) -> ValueCandidate:
    return ValueCandidate(
        tuple(
            ValueStep(
                action_id=action,
                target_instance_id="instance:root",
                signature=f"{action}()",
                args=(),
                value_wei=0,
            )
            for action in actions
        )
    )


def test_track04_minimizer_deletes_redundant_middle_action() -> None:
    seed = _candidate(("prepare", "noise", "break"))

    def violates(candidate: object) -> bool:
        actions = tuple(step.action_id for step in candidate.steps)
        return "prepare" in actions and "break" in actions

    result = minimize_track04_candidate(seed, violates, max_evaluations=32)

    assert tuple(step.action_id for step in result.candidate.steps) == (
        "prepare",
        "break",
    )
    assert result.minimized_step_count == 2
