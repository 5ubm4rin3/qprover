"""Coverage and observation-state novelty guided corpus mutation."""

from __future__ import annotations

import random
from collections import Counter

from qprover.models import Candidate, Outcome
from qprover.search.base import (
    Evaluation,
    StrategyStats,
    candidate_is_valid,
    require_strategy_problem,
    step_from_variant,
    variants_by_action,
)
from qprover.search.bqm import SearchProblem

_MUTATIONS = ("append", "argument", "delete", "replace", "splice")


class CoverageGuidedStrategy:
    name = "coverage"

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
        self._variants = tuple(
            sorted(problem.variants, key=lambda item: item.canonical_id)
        )
        self._proposed: set[str] = set()
        self._corpus: dict[str, Candidate] = {}
        self._features: set[str] = set()
        self._states: set[str] = set()
        self._mutation_order = list(_MUTATIONS)
        self._rng.shuffle(self._mutation_order)
        self._mutation_index = 0
        self._mutation_attempts = Counter({name: 0 for name in _MUTATIONS})
        self._novel_observations = 0
        self._observations = 0
        self._reverts = 0
        self._initialized = True

    def _random_candidate(self, maximum: int) -> Candidate:
        length = self._rng.randint(1, maximum)
        counts: Counter[str] = Counter()
        steps = []
        for _ in range(length):
            actions = [
                action
                for action in self._problem.actions
                if counts[action] < self._problem.repetition_limits[action]
            ]
            action = self._rng.choice(actions)
            variant = self._rng.choice(self._by_action[action])
            steps.append(step_from_variant(variant))
            counts[action] += 1
        return Candidate(tuple(steps))

    def _next_mutation(self) -> str:
        name = self._mutation_order[self._mutation_index % len(self._mutation_order)]
        self._mutation_index += 1
        self._mutation_attempts[name] += 1
        return name

    def _mutate(self, maximum: int) -> Candidate | None:
        corpus = tuple(self._corpus[key] for key in sorted(self._corpus))
        base = self._rng.choice(corpus)
        mutation = self._next_mutation()
        steps = list(base.steps[:maximum])
        if mutation == "append":
            if len(steps) >= maximum:
                return None
            steps.append(step_from_variant(self._rng.choice(self._variants)))
        elif mutation == "delete":
            if len(steps) <= 1:
                return None
            del steps[self._rng.randrange(len(steps))]
        elif mutation == "replace":
            position = self._rng.randrange(len(steps))
            replacements = [
                step_from_variant(item)
                for item in self._variants
                if step_from_variant(item) != steps[position]
            ]
            if not replacements:
                return None
            steps[position] = self._rng.choice(replacements)
        elif mutation == "argument":
            position = self._rng.randrange(len(steps))
            replacements = [
                step_from_variant(item)
                for item in self._by_action[steps[position].action_id]
                if step_from_variant(item) != steps[position]
            ]
            if not replacements:
                return None
            steps[position] = self._rng.choice(replacements)
        else:
            other = self._rng.choice(corpus)
            first_cut = self._rng.randrange(1, len(steps) + 1)
            second_cut = self._rng.randrange(len(other.steps))
            steps = (steps[:first_cut] + list(other.steps[second_cut:]))[:maximum]
        candidate = Candidate(tuple(steps))
        return candidate if candidate_is_valid(self._problem, candidate) else None

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
            candidate = (
                self._mutate(maximum)
                if self._corpus
                else self._random_candidate(maximum)
            )
            if candidate is None or candidate.canonical_id in self._proposed:
                continue
            self._proposed.add(candidate.canonical_id)
            return candidate
        return None

    def observe(self, candidate: Candidate, result: Evaluation) -> None:
        if not self._initialized:
            raise RuntimeError("strategy is not initialized")
        self._observations += 1
        if result.outcome is Outcome.REVERT:
            self._reverts += 1
        new_features = result.trace_features - self._features
        new_state = (
            result.state_fingerprint is not None
            and result.state_fingerprint not in self._states
        )
        if new_features or new_state:
            self._features.update(result.trace_features)
            if result.state_fingerprint is not None:
                self._states.add(result.state_fingerprint)
            self._corpus[candidate.canonical_id] = candidate
            self._novel_observations += 1

    @property
    def stats(self) -> StrategyStats:
        return StrategyStats(
            name=self.name,
            counters={
                "corpus_size": len(self._corpus),
                "novel_observations": self._novel_observations,
                "observations": self._observations,
                "proposals": len(self._proposed),
                "reverts": self._reverts,
            },
            metadata={
                "mutation_attempts": dict(sorted(self._mutation_attempts.items()))
            },
        )
