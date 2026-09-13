from __future__ import annotations

import os
from pathlib import Path

from qprover.analysis import analyze
from qprover.artifacts import build_target
from qprover.evaluator import ScenarioEvaluator
from qprover.evm import LocalAnvil
from qprover.graph import build_program_graph
from qprover.hypotheses import generate_hypotheses
from qprover.manifest import load_manifest
from qprover.models import ActionStep, Candidate, ConfirmationStatus, Outcome
from qprover.parameters import expand_action_variants
from qprover.search.base import candidate_is_valid
from qprover.search.bqm import SearchProblem
from qprover.search.controller import SearchController
from qprover.search.risk import RiskGuidedStrategy

ROOT = Path(__file__).parents[2]


def _process_exists(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    return True


def _known_candidate(
    manifest, actions: tuple[tuple[str, tuple, int], ...]
) -> Candidate:
    steps = []
    for action_id, args, value in actions:
        action = next(item for item in manifest.actions if item.id == action_id)
        steps.append(
            ActionStep(
                action_id=action.id,
                target_id=action.target_id,
                signature=action.signature,
                sender_slot=action.sender_slots[0],
                args=args,
                value_wei=value,
            )
        )
    return Candidate(tuple(steps))


def _access_problem(manifest, report, graph, hypotheses) -> SearchProblem:
    variants = expand_action_variants(manifest, report)
    utilities = {action.id: 0.0 for action in manifest.actions}
    transitions: dict[tuple[str, str], float] = {}
    for hypothesis in hypotheses:
        for action_id, function_id in zip(
            hypothesis.action_ids, hypothesis.function_ids, strict=True
        ):
            utilities[action_id] = max(
                utilities[action_id], graph.action_utility(function_id)
            )
        for actions, functions in zip(
            zip(hypothesis.action_ids, hypothesis.action_ids[1:], strict=False),
            zip(hypothesis.function_ids, hypothesis.function_ids[1:], strict=False),
            strict=True,
        ):
            transitions[actions] = max(
                transitions.get(actions, 0.0),
                graph.transition_benefit(*functions),
            )
    return SearchProblem(
        actions=tuple(action.id for action in manifest.actions),
        max_sequence_length=manifest.limits.max_sequence_length,
        utilities=utilities,
        transitions=transitions,
        variants=variants,
        hypothesis_sequences=tuple(item.action_ids for item in hypotheses),
    )


def test_graph_risk_search_executes_access_control_violation_and_twin() -> None:
    vulnerable = load_manifest(ROOT / "benchmarks/scenario_access_control_a.json")
    with build_target(vulnerable) as bundle:
        report = analyze(bundle)
        graph = build_program_graph(report)
        hypotheses = generate_hypotheses(graph, vulnerable)
        problem = _access_problem(vulnerable, report, graph, hypotheses)
        strategy = RiskGuidedStrategy(beam_width=8)
        strategy.initialize(problem, seed=11)
        anvil = LocalAnvil()
        with anvil:
            pid_a = anvil.process_id
            evaluator = ScenarioEvaluator(vulnerable, bundle, anvil)
            controller = SearchController(
                run_id_factory=lambda: "access-control-local",
                candidate_validator=lambda candidate: candidate_is_valid(
                    problem, candidate
                ),
            )
            limits = vulnerable.limits.model_copy(
                update={"transaction_budget": 6, "candidate_budget": 3}
            )
            run = controller.run(strategy, evaluator, limits)
        evidence_a = bundle.evidence_root

    assert pid_a is not None and not _process_exists(pid_a)
    assert not evidence_a.exists()
    assert run.confirmation_status is ConfirmationStatus.CANDIDATE_VIOLATION
    assert run.violation is not None and len(run.violation.steps) >= 2
    assert tuple(step.action_id for step in run.violation.steps[:2]) == (
        "step_alpha",
        "step_beta",
    )
    assert run.evaluations[-1].evaluation.outcome is Outcome.VIOLATION
    assert run.evaluations[-1].evaluation.transaction_count == len(run.violation.steps)

    sound = load_manifest(ROOT / "benchmarks/scenario_access_control_b.json")
    with build_target(sound) as bundle, LocalAnvil() as anvil:
        pid_b = anvil.process_id
        control = ScenarioEvaluator(sound, bundle, anvil).evaluate(run.violation)
        evidence_b = bundle.evidence_root

    assert pid_b is not None and not _process_exists(pid_b)
    assert not evidence_b.exists()
    assert control.outcome is not Outcome.VIOLATION
    assert control.transaction_count == 1


def test_known_reentrancy_pair_executes_dynamic_callback_regression() -> None:
    outcomes = {}
    trace_counts = {}
    pids = []
    evidence_paths = []
    for variant in "ab":
        manifest = load_manifest(
            ROOT / f"benchmarks/scenario_reentrancy_{variant}.json"
        )
        candidate = _known_candidate(
            manifest,
            (
                ("step_alpha", (10**18,), 10**18),
                ("step_beta", (), 0),
            ),
        )
        with build_target(manifest) as bundle, LocalAnvil() as anvil:
            pids.append(anvil.process_id)
            result = ScenarioEvaluator(manifest, bundle, anvil).evaluate(candidate)
            evidence_paths.append(bundle.evidence_root)
        outcomes[variant] = result
        trace_counts[variant] = sum(
            step["call_trace_count"] for step in result.metadata["steps"]
        )

    assert outcomes["a"].outcome is Outcome.VIOLATION
    assert outcomes["a"].transaction_count == 2
    assert outcomes["a"].metadata["impact"]["attacker_delta"] == 2 * 10**18
    assert outcomes["b"].outcome is Outcome.REVERT
    assert outcomes["b"].transaction_count == 2
    assert trace_counts["a"] >= 5
    assert all(pid is not None and not _process_exists(pid) for pid in pids)
    assert all(not path.exists() for path in evidence_paths)
