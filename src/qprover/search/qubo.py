"""BQM-backed transaction-sequence proposals with feasibility auditing."""

from __future__ import annotations

import itertools
from collections import Counter
from typing import Protocol

from qprover.models import Candidate, Outcome
from qprover.search.annealing import SimulatedAnnealingBackend
from qprover.search.base import (
    Evaluation,
    StrategyStats,
    candidate_is_valid,
    require_strategy_problem,
    step_from_variant,
)
from qprover.search.bqm import (
    BinaryQuadraticModel,
    SampleSet,
    SearchFeedback,
    SearchProblem,
    SequenceBQMBuilder,
)


class BQMBackend(Protocol):
    def sample(self, bqm: BinaryQuadraticModel, **options: object) -> SampleSet: ...


class QuboStrategy:
    """Decode BQM samples, resample sparsity, then prove small-space exhaustion.

    Exact fallback is deliberately disabled when the raw native sequence bound
    exceeds ``max_exact_fallback_sequences``. In that case ``None`` follows only
    bounded solver attempts and ``exhaustion_proven`` remains false.
    """

    name = "qubo"

    def __init__(
        self,
        *,
        backend: BQMBackend,
        reads: int = 64,
        transition_enabled: bool = True,
        feedback_batch_size: int = 8,
        resample_attempts: int = 3,
        max_exact_fallback_sequences: int = 4096,
    ) -> None:
        if type(reads) is not int or reads <= 0:
            raise ValueError("reads must be an exact positive integer")
        if type(feedback_batch_size) is not int or feedback_batch_size <= 0:
            raise ValueError("feedback_batch_size must be an exact positive integer")
        if type(resample_attempts) is not int or resample_attempts < 0:
            raise ValueError("resample_attempts must be a nonnegative exact integer")
        if (
            type(max_exact_fallback_sequences) is not int
            or max_exact_fallback_sequences < 0
        ):
            raise ValueError(
                "max_exact_fallback_sequences must be a nonnegative exact integer"
            )
        self._backend = backend
        self._reads = reads
        self._transition_enabled = transition_enabled
        self._feedback_batch_size = feedback_batch_size
        self._resample_limit = resample_attempts
        self._max_exact_fallback_sequences = max_exact_fallback_sequences
        self._initialized = False

    def initialize(self, problem: SearchProblem, seed: int) -> None:
        require_strategy_problem(problem, seed)
        self._problem = problem
        self._seed = seed
        self._variants = tuple(
            sorted(problem.variants, key=lambda item: item.canonical_id)
        )
        self._tokens = tuple(f"variant:{item.canonical_id}" for item in self._variants)
        self._variant_by_token = dict(zip(self._tokens, self._variants, strict=True))
        self._proposed: set[str] = set()
        self._revert_counts: Counter[str] = Counter()
        self._successful_transitions: Counter[tuple[str, str]] = Counter()
        self._observations = 0
        self._feedback_since_build = 0
        self._builds = 0
        self._decoded_feasible = 0
        self._decoded_infeasible = 0
        self._solver_metadata: dict[str, object] = {}
        self._ranked: tuple[tuple[float, Candidate], ...] = ()
        self._last_bqm: BinaryQuadraticModel | None = None
        self._resample_attempts = 0
        self._exact_fallbacks = 0
        self._fallback_space_bound = 0
        self._exhaustion_proven = False
        self._initialized = True

    def _optimization_problem(self) -> SearchProblem:
        utilities = {
            token: self._problem.utilities[variant.action_id]
            for token, variant in self._variant_by_token.items()
        }
        transitions = {}
        if self._transition_enabled:
            transitions = {
                (first_token, second_token): self._problem.transitions.get(
                    (first.action_id, second.action_id), 0.0
                )
                + 0.05
                * self._successful_transitions[(first.action_id, second.action_id)]
                for first_token, first in self._variant_by_token.items()
                for second_token, second in self._variant_by_token.items()
            }
        repetitions = {
            token: self._problem.repetition_limits[variant.action_id]
            for token, variant in self._variant_by_token.items()
        }
        discounts = self._problem.discounts
        return SearchProblem(
            actions=self._tokens,
            max_sequence_length=self._problem.max_sequence_length,
            utilities=utilities,
            transitions=transitions,
            repetition_limits=repetitions,
            discounts=discounts,
            utility_weight=self._problem.utility_weight,
            transition_weight=self._problem.transition_weight,
            revert_weight=self._problem.revert_weight,
            length_weight=self._problem.length_weight,
        )

    def _sample(self, bqm: BinaryQuadraticModel) -> SampleSet:
        if isinstance(self._backend, SimulatedAnnealingBackend):
            return self._backend.sample(
                bqm,
                seed=self._seed + self._builds,
                reads=self._reads,
            )
        return self._backend.sample(bqm, reads=self._reads)

    def _rebuild(self) -> None:
        optimization = self._optimization_problem()
        penalties = {
            token: float(self._revert_counts[variant.action_id])
            for token, variant in self._variant_by_token.items()
        }
        bqm = SequenceBQMBuilder().build(
            optimization,
            SearchFeedback(revert_penalties=penalties),
        )
        samples = self._sample(bqm)
        self._last_bqm = bqm
        ranked: dict[str, tuple[float, Candidate]] = {}
        feasible = 0
        infeasible = 0
        for sample in samples.samples:
            decoded = sample.decoded
            if not decoded.feasibility.feasible or not decoded.sequence:
                infeasible += 1
                continue
            candidate = Candidate(
                tuple(
                    step_from_variant(self._variant_by_token[token])
                    for token in decoded.sequence
                )
            )
            if not candidate_is_valid(self._problem, candidate):
                infeasible += 1
                continue
            feasible += 1
            previous = ranked.get(candidate.canonical_id)
            item = (sample.energy, candidate)
            if previous is None or item[0] < previous[0]:
                ranked[candidate.canonical_id] = item
        self._ranked = tuple(
            sorted(
                ranked.values(),
                key=lambda item: (item[0], len(item[1].steps), item[1].canonical_id),
            )
        )
        self._decoded_feasible += feasible
        self._decoded_infeasible += infeasible
        self._solver_metadata = dict(samples.metadata)
        self._builds += 1
        self._feedback_since_build = 0

    def _next_unseen(self, remaining_transactions: int) -> Candidate | None:
        for _, candidate in self._ranked:
            if (
                len(candidate.steps) <= remaining_transactions
                and candidate.canonical_id not in self._proposed
            ):
                return candidate
        return None

    def _exact_fallback(
        self,
        remaining_transactions: int,
    ) -> tuple[Candidate | None, bool]:
        horizon = min(remaining_transactions, self._problem.max_sequence_length)
        sequence_bound = 0
        sequences_at_length = 1
        for _ in range(horizon):
            sequences_at_length *= len(self._tokens)
            sequence_bound += sequences_at_length
            if sequence_bound > self._max_exact_fallback_sequences:
                self._fallback_space_bound = sequence_bound
                return None, False
        self._fallback_space_bound = sequence_bound
        self._exact_fallbacks += 1
        if self._last_bqm is None:
            raise AssertionError("exact fallback requires a built BQM")
        candidates: dict[str, tuple[float, Candidate]] = {}
        for length in range(1, horizon + 1):
            for sequence in itertools.product(self._tokens, repeat=length):
                candidate = Candidate(
                    tuple(
                        step_from_variant(self._variant_by_token[token])
                        for token in sequence
                    )
                )
                if candidate.canonical_id in self._proposed or not candidate_is_valid(
                    self._problem, candidate
                ):
                    continue
                energy = self._last_bqm.energy(self._last_bqm.encode(sequence))
                candidates[candidate.canonical_id] = (energy, candidate)
        if not candidates:
            return None, True
        _, candidate = min(
            candidates.values(),
            key=lambda item: (item[0], len(item[1].steps), item[1].canonical_id),
        )
        return candidate, False

    def propose(self, remaining_transactions: int) -> Candidate | None:
        if not self._initialized:
            raise RuntimeError("strategy is not initialized")
        if type(remaining_transactions) is not int or remaining_transactions <= 0:
            return None
        if not self._ranked or self._feedback_since_build >= self._feedback_batch_size:
            self._rebuild()
        candidate = self._next_unseen(remaining_transactions)
        if candidate is not None:
            self._proposed.add(candidate.canonical_id)
            self._exhaustion_proven = False
            return candidate
        for _ in range(self._resample_limit):
            self._resample_attempts += 1
            self._rebuild()
            candidate = self._next_unseen(remaining_transactions)
            if candidate is not None:
                self._proposed.add(candidate.canonical_id)
                self._exhaustion_proven = False
                return candidate
        candidate, exhausted = self._exact_fallback(remaining_transactions)
        self._exhaustion_proven = exhausted
        if candidate is not None:
            self._proposed.add(candidate.canonical_id)
        return candidate

    def observe(self, candidate: Candidate, result: Evaluation) -> None:
        if not self._initialized:
            raise RuntimeError("strategy is not initialized")
        self._observations += 1
        self._feedback_since_build += 1
        actions = tuple(step.action_id for step in candidate.steps)
        if result.outcome is Outcome.REVERT:
            self._revert_counts.update(actions)
        elif result.outcome in {Outcome.PASS, Outcome.VIOLATION}:
            self._successful_transitions.update(zip(actions, actions[1:], strict=False))

    @property
    def stats(self) -> StrategyStats:
        return StrategyStats(
            name=self.name,
            counters={
                "bqm_builds": self._builds,
                "observations": self._observations,
                "proposals": len(self._proposed),
            },
            metadata={
                "decoded_feasible": self._decoded_feasible,
                "decoded_infeasible": self._decoded_infeasible,
                "exact_fallbacks": self._exact_fallbacks,
                "exhaustion_proven": self._exhaustion_proven,
                "fallback_space_bound": self._fallback_space_bound,
                "max_exact_fallback_sequences": self._max_exact_fallback_sequences,
                "repair_count": 0,
                "resample_attempts": self._resample_attempts,
                "solver": dict(self._solver_metadata),
                "solver_calls": self._builds,
                "transition_enabled": self._transition_enabled,
            },
        )
