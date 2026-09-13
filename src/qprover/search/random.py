"""Seeded uniform transaction-sequence baseline."""

from __future__ import annotations

import random
from collections import Counter

from qprover.models import Candidate
from qprover.search.base import (
    Evaluation,
    StrategyStats,
    require_strategy_problem,
    step_from_variant,
    variants_by_action,
)
from qprover.search.bqm import SearchProblem


class RandomStrategy:
    name = "random"

    def __init__(self, *, proposal_attempts: int = 256) -> None:
        if type(proposal_attempts) is not int or proposal_attempts <= 0:
            raise ValueError("proposal_attempts must be an exact positive integer")
        self._proposal_attempts = proposal_attempts
        self._initialized = False

    def initialize(self, problem: SearchProblem, seed: int) -> None:
        require_strategy_problem(problem, seed)
        self._problem = problem
        self._rng = random.Random(seed)
        self._by_action = variants_by_action(problem)
        self._proposed: set[str] = set()
        self._observations = 0
        self._duplicate_draws = 0
        self._initialized = True

    def _draw(self, maximum_length: int) -> Candidate:
        length = self._rng.randint(1, maximum_length)
        counts: Counter[str] = Counter()
        steps = []
        for _ in range(length):
            allowed_actions = [
                action
                for action in self._problem.actions
                if counts[action] < self._problem.repetition_limits[action]
            ]
            action = self._rng.choice(allowed_actions)
            variant = self._rng.choice(self._by_action[action])
            steps.append(step_from_variant(variant))
            counts[action] += 1
        return Candidate(tuple(steps))

    def propose(self, remaining_transactions: int) -> Candidate | None:
        if not self._initialized:
            raise RuntimeError("strategy is not initialized")
        if type(remaining_transactions) is not int or remaining_transactions <= 0:
            return None
        maximum = min(
            remaining_transactions,
            self._problem.max_sequence_length,
            sum(self._problem.repetition_limits.values()),
        )
        for _ in range(self._proposal_attempts):
            candidate = self._draw(maximum)
            if candidate.canonical_id not in self._proposed:
                self._proposed.add(candidate.canonical_id)
                return candidate
            self._duplicate_draws += 1
        return None

    def observe(self, candidate: Candidate, result: Evaluation) -> None:
        del candidate, result
        if not self._initialized:
            raise RuntimeError("strategy is not initialized")
        self._observations += 1

    @property
    def stats(self) -> StrategyStats:
        return StrategyStats(
            name=self.name,
            counters={
                "duplicate_draws": self._duplicate_draws,
                "observations": self._observations,
                "proposals": len(self._proposed),
            },
        )
