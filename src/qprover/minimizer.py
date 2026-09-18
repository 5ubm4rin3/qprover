"""Deterministic execution-backed local counterexample minimization."""

from __future__ import annotations

import math
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, replace
from typing import Literal, Protocol

from qprover.models import ActionSpec, Candidate, Outcome, TargetManifest
from qprover.search.base import CandidateEvaluator, Evaluation


class MinimizationError(RuntimeError):
    """A seed or final candidate did not retain its declared violation policy."""


class EvaluatorFactory(Protocol):
    def __call__(self) -> CandidateEvaluator: ...


@dataclass(frozen=True, slots=True)
class MinimizationAttempt:
    operator: str
    candidate_id: str
    step_count: int
    outcome: Outcome
    admissible: bool
    accepted: bool
    cached: bool
    transaction_count: int


@dataclass(frozen=True, slots=True)
class MinimizationResult:
    candidate: Candidate
    final_evaluation: Evaluation
    original_step_count: int
    minimized_step_count: int
    attempts: tuple[MinimizationAttempt, ...]
    evaluation_count: int
    uncached_candidate_count: int
    candidate_attempt_count: int
    unique_candidate_count: int
    cache_hits: int
    transaction_count: int
    attempted_operators: tuple[str, ...]
    locally_minimal: bool
    minimality_claim: Literal[
        "Replay-verified local minimum under one-step deletion only."
    ]


def _qualification_identity(evaluation: Evaluation) -> tuple[str, str] | None:
    qualification = evaluation.metadata.get("qualification")
    if (
        evaluation.outcome is not Outcome.VIOLATION
        or not isinstance(qualification, Mapping)
        or qualification.get("qualified") is not True
        or qualification.get("policy")
        not in {"invariant_and_economic_impact", "invariant_violation"}
        or not isinstance(qualification.get("invariant_id"), str)
    ):
        return None
    return qualification["policy"], qualification["invariant_id"]


def _is_violation(
    evaluation: Evaluation, expected: tuple[str, str] | None = None
) -> bool:
    identity = _qualification_identity(evaluation)
    return identity is not None and (expected is None or identity == expected)


def _evaluate_fresh(
    evaluator: CandidateEvaluator | EvaluatorFactory, candidate: Candidate
) -> Evaluation:
    if not isinstance(evaluator, type) and hasattr(evaluator, "evaluate"):
        return evaluator.evaluate(candidate)  # type: ignore[union-attr]
    if not callable(evaluator):
        raise TypeError("evaluator must provide evaluate() or be a factory")
    produced = evaluator()
    if hasattr(produced, "__enter__") and hasattr(produced, "__exit__"):
        with produced as active:  # type: ignore[attr-defined]
            return active.evaluate(candidate)
    try:
        return produced.evaluate(candidate)
    finally:
        close = getattr(produced, "close", None)
        if callable(close):
            close()


def _domain_record(domains: Mapping[str, object], action_id: str) -> object:
    try:
        return domains[action_id]
    except KeyError as error:
        raise MinimizationError(
            f"missing minimization domain for {action_id}"
        ) from error


def _slots(record: object) -> tuple[int, ...]:
    values = (
        record.sender_slots
        if isinstance(record, ActionSpec)
        else record.get("sender_slots", ())
        if isinstance(record, Mapping)
        else ()
    )
    return tuple(value for value in values if type(value) is int)


def _argument_values(record: object, index: int, current: object) -> tuple[object, ...]:
    if isinstance(record, ActionSpec):
        domain = record.arguments[index].domain
        if domain.kind == "finite":
            values: Sequence[object] = domain.values
        else:
            values = tuple(
                value
                for value in (0, 1, domain.minimum, domain.maximum)
                if domain.minimum <= value <= domain.maximum
            )
    elif isinstance(record, Mapping):
        arguments = record.get("arguments", ())
        values = arguments[index] if index < len(arguments) else ()
    else:
        values = ()
    return _simpler_values(values, current)


def _call_values(record: object, current: int) -> tuple[int, ...]:
    if isinstance(record, ActionSpec):
        values: Sequence[object] = record.value_domain.values
    elif isinstance(record, Mapping):
        values = record.get("values", ())
    else:
        values = ()
    return tuple(
        value for value in _simpler_values(values, current) if type(value) is int
    )


def _complexity(value: object) -> tuple[int, int, str]:
    if type(value) is bool:
        return (0 if value is False else 1, 1, repr(value))
    if type(value) is int:
        magnitude = abs(value)
        encoded = max(1, math.ceil(magnitude.bit_length() / 8))
        return (0 if value == 0 else 1 if value == 1 else 2, encoded, str(value))
    if isinstance(value, str):
        return (0 if not value else 2, len(value.encode()), value)
    return (3, len(repr(value)), repr(value))


def _simpler_values(values: Sequence[object], current: object) -> tuple[object, ...]:
    distinct: list[object] = []
    for value in values:
        if type(value) is type(current) and value == current:
            continue
        if any(type(value) is type(prior) and value == prior for prior in distinct):
            continue
        if _complexity(value) < _complexity(current):
            distinct.append(value)
    return tuple(sorted(distinct, key=_complexity))


def minimize(
    candidate: Candidate,
    evaluator: CandidateEvaluator | EvaluatorFactory,
    domains: Mapping[str, object] | TargetManifest,
) -> MinimizationResult:
    """Minimize one executed violation under explicit local operators.

    Cached proposals are never credited as new execution evidence. The seed and
    final result are always evaluated afresh, and evaluator factories are
    entered/closed once per uncached evaluation.
    """

    if not isinstance(candidate, Candidate) or not candidate.steps:
        raise MinimizationError("seed must be a nonempty candidate")
    domain_map: Mapping[str, object] = (
        {action.id: action for action in domains.actions}
        if isinstance(domains, TargetManifest)
        else domains
    )
    attempts: list[MinimizationAttempt] = []
    cache: dict[str, Evaluation] = {}
    evaluation_count = 0
    transaction_count = 0
    cache_hits = 0
    last_evaluation: Evaluation | None = None
    expected_qualification: tuple[str, str] | None = None

    def probe(proposed: Candidate, operator: str, *, fresh: bool = False) -> bool:
        nonlocal evaluation_count, transaction_count, cache_hits
        nonlocal last_evaluation, expected_qualification
        cached = not fresh and proposed.canonical_id in cache
        if cached:
            evaluation = cache[proposed.canonical_id]
            cache_hits += 1
            counted_transactions = 0
        else:
            evaluation = _evaluate_fresh(evaluator, proposed)
            evaluation_count += 1
            transaction_count += evaluation.transaction_count
            counted_transactions = evaluation.transaction_count
            if not fresh:
                cache[proposed.canonical_id] = evaluation
        last_evaluation = evaluation
        accepted = _is_violation(evaluation, expected_qualification)
        if accepted and expected_qualification is None:
            expected_qualification = _qualification_identity(evaluation)
        attempts.append(
            MinimizationAttempt(
                operator=operator,
                candidate_id=proposed.canonical_id,
                step_count=len(proposed.steps),
                outcome=evaluation.outcome,
                admissible=accepted,
                accepted=accepted,
                cached=cached,
                transaction_count=counted_transactions,
            )
        )
        return accepted

    if not probe(candidate, "initial-fresh-evaluation", fresh=True):
        raise MinimizationError("seed is not a qualified executed violation")
    current = candidate

    # Deterministic contiguous-chunk ddmin.
    granularity = 2
    while len(current.steps) >= 2:
        chunk_size = math.ceil(len(current.steps) / granularity)
        reduced = False
        for start in range(0, len(current.steps), chunk_size):
            proposed_steps = current.steps[:start] + current.steps[start + chunk_size :]
            if not proposed_steps:
                continue
            proposed = Candidate(proposed_steps)
            if probe(proposed, "ddmin-contiguous-chunks"):
                current = proposed
                granularity = max(2, granularity - 1)
                reduced = True
                break
        if reduced:
            continue
        if granularity >= len(current.steps):
            break
        granularity = min(len(current.steps), granularity * 2)

    # One-at-a-time deletion to a fixed point.
    changed = True
    while changed and len(current.steps) > 1:
        changed = False
        for index in range(len(current.steps)):
            proposed = Candidate(current.steps[:index] + current.steps[index + 1 :])
            if probe(proposed, "single-delete-fixed-point"):
                current = proposed
                changed = True
                break

    # Normalize actors only when this strictly reduces the number of actor slots.
    changed = True
    while changed:
        changed = False
        current_slots = {step.sender_slot for step in current.steps}
        for index, step in enumerate(current.steps):
            record = _domain_record(domain_map, step.action_id)
            choices = tuple(
                sorted(
                    (slot for slot in _slots(record) if slot != step.sender_slot),
                    key=lambda slot: (slot not in current_slots, slot),
                )
            )
            for slot in choices:
                steps = list(current.steps)
                steps[index] = replace(step, sender_slot=slot)
                proposed = Candidate(tuple(steps))
                proposed_slot_count = len({item.sender_slot for item in proposed.steps})
                if proposed_slot_count >= len(current_slots):
                    continue
                if probe(proposed, "actor-normalization"):
                    current = proposed
                    changed = True
                    break
            if changed:
                break

    for operator in ("argument-simplification", "value-simplification"):
        changed = True
        while changed:
            changed = False
            for index, step in enumerate(current.steps):
                record = _domain_record(domain_map, step.action_id)
                if operator == "argument-simplification":
                    proposals = []
                    for argument_index, value in enumerate(step.args):
                        for simpler in _argument_values(record, argument_index, value):
                            args = list(step.args)
                            args[argument_index] = simpler
                            proposals.append(replace(step, args=tuple(args)))
                else:
                    proposals = [
                        replace(step, value_wei=value)
                        for value in _call_values(record, step.value_wei)
                    ]
                for replacement in proposals:
                    steps = list(current.steps)
                    steps[index] = replacement
                    proposed = Candidate(tuple(steps))
                    if probe(proposed, operator):
                        current = proposed
                        changed = True
                        break
                if changed:
                    break

    # Changes in one dimension can unlock another. Exhaustively revisit every
    # declared operator until no one-step local reduction survives execution.
    while True:
        accepted_reduction = False
        for chunk_size in range(len(current.steps) - 1, 0, -1):
            operator = (
                "single-delete-fixed-point"
                if chunk_size == 1
                else "ddmin-contiguous-chunks"
            )
            for start in range(0, len(current.steps) - chunk_size + 1):
                proposed_steps = (
                    current.steps[:start] + current.steps[start + chunk_size :]
                )
                if not proposed_steps:
                    continue
                proposed = Candidate(proposed_steps)
                if probe(proposed, operator):
                    current = proposed
                    accepted_reduction = True
                    break
            if accepted_reduction:
                break
        if accepted_reduction:
            continue

        current_slots = {step.sender_slot for step in current.steps}
        for index, step in enumerate(current.steps):
            record = _domain_record(domain_map, step.action_id)
            for slot in sorted(_slots(record)):
                if slot == step.sender_slot:
                    continue
                steps = list(current.steps)
                steps[index] = replace(step, sender_slot=slot)
                proposed = Candidate(tuple(steps))
                if len({item.sender_slot for item in proposed.steps}) >= len(
                    current_slots
                ):
                    continue
                if probe(proposed, "actor-normalization"):
                    current = proposed
                    accepted_reduction = True
                    break
            if accepted_reduction:
                break
        if accepted_reduction:
            continue

        for index, step in enumerate(current.steps):
            record = _domain_record(domain_map, step.action_id)
            for argument_index, value in enumerate(step.args):
                for simpler in _argument_values(record, argument_index, value):
                    args = list(step.args)
                    args[argument_index] = simpler
                    steps = list(current.steps)
                    steps[index] = replace(step, args=tuple(args))
                    proposed = Candidate(tuple(steps))
                    if probe(proposed, "argument-simplification"):
                        current = proposed
                        accepted_reduction = True
                        break
                if accepted_reduction:
                    break
            if accepted_reduction:
                break
        if accepted_reduction:
            continue

        for index, step in enumerate(current.steps):
            record = _domain_record(domain_map, step.action_id)
            for value in _call_values(record, step.value_wei):
                steps = list(current.steps)
                steps[index] = replace(step, value_wei=value)
                proposed = Candidate(tuple(steps))
                if probe(proposed, "value-simplification"):
                    current = proposed
                    accepted_reduction = True
                    break
            if accepted_reduction:
                break
        if not accepted_reduction:
            break

    if not probe(current, "final-fresh-evaluation", fresh=True):
        raise MinimizationError("final fresh evaluation lost the qualified violation")
    if last_evaluation is None:  # pragma: no cover - guarded by the successful probe
        raise AssertionError("final evaluation was not retained")
    final_evaluation = last_evaluation

    operators = (
        "ddmin-contiguous-chunks",
        "single-delete-fixed-point",
        "actor-normalization",
        "argument-simplification",
        "value-simplification",
        "final-fresh-evaluation",
    )
    return MinimizationResult(
        candidate=current,
        final_evaluation=final_evaluation,
        original_step_count=len(candidate.steps),
        minimized_step_count=len(current.steps),
        attempts=tuple(attempts),
        evaluation_count=evaluation_count,
        uncached_candidate_count=evaluation_count,
        candidate_attempt_count=len(attempts),
        unique_candidate_count=len({attempt.candidate_id for attempt in attempts}),
        cache_hits=cache_hits,
        transaction_count=transaction_count,
        attempted_operators=operators,
        locally_minimal=True,
        minimality_claim=(
            "Replay-verified local minimum under one-step deletion only."
        ),
    )



@dataclass(frozen=True, slots=True)
class Track04MinimizationResult:
    candidate: object
    original_step_count: int
    minimized_step_count: int
    evaluation_count: int
    attempted_candidates: tuple[str, ...]


def minimize_track04_candidate(
    candidate: object,
    violates: Callable[[object], bool],
    *,
    max_evaluations: int = 64,
) -> Track04MinimizationResult:
    """Execution-back a generic Track04 witness down to a local trace minimum."""

    if type(max_evaluations) is not int or max_evaluations <= 0:
        raise ValueError("max_evaluations must be positive")
    steps = tuple(getattr(candidate, "steps", ()))
    if not steps:
        raise MinimizationError("Track04 seed must contain at least one step")
    candidate_type = type(candidate)
    evaluations = 0
    attempted: list[str] = []

    def rebuild(proposed_steps: tuple[object, ...]) -> object:
        return candidate_type(proposed_steps)

    def probe(proposed: object) -> bool:
        nonlocal evaluations
        if evaluations >= max_evaluations:
            return False
        evaluations += 1
        attempted.append(str(getattr(proposed, "canonical_id", repr(proposed))))
        try:
            return bool(violates(proposed))
        except Exception:
            return False

    if not probe(candidate):
        raise MinimizationError("Track04 seed no longer violates the invariant")
    current = candidate

    # Prefer the earliest violating prefix.
    for length in range(1, len(steps)):
        proposed = rebuild(steps[:length])
        if probe(proposed):
            current = proposed
            break

    # Deterministic contiguous-chunk deletion.
    granularity = 2
    while len(getattr(current, "steps")) > 1 and evaluations < max_evaluations:
        current_steps = tuple(getattr(current, "steps"))
        chunk = math.ceil(len(current_steps) / granularity)
        changed = False
        for start in range(0, len(current_steps), chunk):
            proposed_steps = current_steps[:start] + current_steps[start + chunk :]
            if not proposed_steps:
                continue
            proposed = rebuild(proposed_steps)
            if probe(proposed):
                current = proposed
                granularity = max(2, granularity - 1)
                changed = True
                break
        if changed:
            continue
        if granularity >= len(current_steps):
            break
        granularity = min(len(current_steps), granularity * 2)

    # One-step deletion fixed point.
    changed = True
    while changed and len(getattr(current, "steps")) > 1:
        if evaluations >= max_evaluations:
            break
        changed = False
        current_steps = tuple(getattr(current, "steps"))
        for index in range(len(current_steps)):
            proposed = rebuild(
                current_steps[:index] + current_steps[index + 1 :]
            )
            if probe(proposed):
                current = proposed
                changed = True
                break

    if evaluations < max_evaluations and not probe(current):
        raise MinimizationError("Track04 final minimized witness lost the violation")
    return Track04MinimizationResult(
        candidate=current,
        original_step_count=len(steps),
        minimized_step_count=len(tuple(getattr(current, "steps"))),
        evaluation_count=evaluations,
        attempted_candidates=tuple(attempted),
    )
