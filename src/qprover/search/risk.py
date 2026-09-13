"""Deterministic graph/risk-guided beam-prefix strategy."""

from __future__ import annotations

from collections import Counter

from qprover.models import Candidate, Outcome
from qprover.search.base import (
    Evaluation,
    StrategyStats,
    candidate_is_valid,
    require_strategy_problem,
    step_from_variant,
)
from qprover.search.bqm import SearchProblem

_RANKING_INPUTS = (
    "dynamic_novelty",
    "hypothesis_relevance",
    "length_cost",
    "revert_penalty",
    "static_utility",
    "transition_benefit",
)


class RiskGuidedStrategy:
    name = "risk"

    def __init__(self, *, beam_width: int = 32) -> None:
        if type(beam_width) is not int or beam_width <= 0:
            raise ValueError("beam_width must be an exact positive integer")
        self._beam_width = beam_width
        self._initialized = False

    def initialize(self, problem: SearchProblem, seed: int) -> None:
        require_strategy_problem(problem, seed)
        self._problem = problem
        self._seed = seed
        self._proposed: set[str] = set()
        self._revert_counts: Counter[str] = Counter()
        self._novel_actions: Counter[str] = Counter()
        self._observations = 0
        self._candidates = self._build_ranked_candidates()
        self._initialized = True

    def _hypothesis_score(self, actions: tuple[str, ...]) -> float:
        score = 0.0
        for hypothesis in self._problem.hypothesis_sequences:
            common = 0
            for actual, expected in zip(actions, hypothesis, strict=False):
                if actual != expected:
                    break
                common += 1
            if actions == hypothesis:
                candidate = 5.0
            elif common == len(hypothesis) and len(actions) > len(hypothesis):
                candidate = max(0.0, 4.0 - (len(actions) - len(hypothesis)))
            else:
                candidate = 2.0 * common / len(hypothesis)
            score = max(score, candidate)
        return score

    def _score(self, candidate: Candidate) -> float:
        actions = tuple(step.action_id for step in candidate.steps)
        utility = sum(self._problem.utilities[action] for action in actions)
        transitions = sum(
            self._problem.transitions.get(pair, 0.0)
            for pair in zip(actions, actions[1:], strict=False)
        )
        hypothesis = self._hypothesis_score(actions)
        novelty = sum(1.0 / (1 + self._novel_actions[action]) for action in actions)
        revert = sum(self._revert_counts[action] for action in actions)
        length = self._problem.length_weight * len(actions)
        return utility + transitions + hypothesis + 0.1 * novelty - revert - length

    def _build_ranked_candidates(self) -> tuple[Candidate, ...]:
        variants = tuple(
            sorted(self._problem.variants, key=lambda item: item.canonical_id)
        )
        frontier = tuple(Candidate((step_from_variant(item),)) for item in variants)
        all_prefixes: dict[str, Candidate] = {}
        for _ in range(self._problem.max_sequence_length):
            valid = {
                candidate.canonical_id: candidate
                for candidate in frontier
                if candidate_is_valid(self._problem, candidate)
            }
            ranked = sorted(
                valid.values(), key=lambda item: (-self._score(item), item.canonical_id)
            )
            beam = tuple(ranked[: self._beam_width])
            all_prefixes.update((item.canonical_id, item) for item in beam)
            frontier = tuple(
                Candidate((*prefix.steps, step_from_variant(variant)))
                for prefix in beam
                for variant in variants
            )
        return tuple(
            sorted(
                all_prefixes.values(),
                key=lambda item: (-self._score(item), item.canonical_id),
            )
        )

    def propose(self, remaining_transactions: int) -> Candidate | None:
        if not self._initialized:
            raise RuntimeError("strategy is not initialized")
        if type(remaining_transactions) is not int or remaining_transactions <= 0:
            return None
        ranked = sorted(
            self._candidates,
            key=lambda item: (-self._score(item), item.canonical_id),
        )
        for candidate in ranked:
            if (
                len(candidate.steps) <= remaining_transactions
                and candidate.canonical_id not in self._proposed
            ):
                self._proposed.add(candidate.canonical_id)
                return candidate
        return None

    def observe(self, candidate: Candidate, result: Evaluation) -> None:
        if not self._initialized:
            raise RuntimeError("strategy is not initialized")
        self._observations += 1
        actions = tuple(step.action_id for step in candidate.steps)
        if result.outcome is Outcome.REVERT:
            self._revert_counts.update(actions)
        if result.trace_features or result.state_fingerprint is not None:
            self._novel_actions.update(set(actions))

    @property
    def stats(self) -> StrategyStats:
        return StrategyStats(
            name=self.name,
            counters={
                "observations": self._observations,
                "proposals": len(self._proposed),
                "reverts": sum(self._revert_counts.values()),
            },
            metadata={
                "beam_width": self._beam_width,
                "ranking_inputs": _RANKING_INPUTS,
            },
        )
