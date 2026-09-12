"""Small-instance exact reference solvers for binary and native sequence spaces."""

from __future__ import annotations

import itertools
import time
from collections import Counter
from dataclasses import dataclass

from qprover.search.bqm import (
    BinaryQuadraticModel,
    SampleSet,
    SearchProblem,
    sample_from_bits,
)


class SolverError(ValueError):
    """Raised when a solver cannot safely handle the requested model."""


@dataclass(frozen=True, slots=True)
class ExactConfig:
    reads: int = 1

    def __post_init__(self) -> None:
        if self.reads <= 0:
            raise ValueError("reads must be positive")


class ExactBackend:
    def __init__(self, *, max_bits: int = 20) -> None:
        if max_bits <= 0:
            raise ValueError("max_bits must be positive")
        self.max_bits = max_bits

    def sample(
        self,
        bqm: BinaryQuadraticModel,
        config: ExactConfig | None = None,
        *,
        reads: int | None = None,
    ) -> SampleSet:
        if config is not None:
            if reads is not None:
                raise ValueError("reads cannot be supplied twice")
            reads = config.reads
        requested = reads if reads is not None else 1
        if requested <= 0:
            raise ValueError("reads must be positive")
        bits = len(bqm.variables)
        if bits > self.max_bits:
            raise SolverError(
                f"BQM has {bits} bits, exceeding exact max_bits={self.max_bits}"
            )
        started = time.perf_counter()
        samples = [
            sample_from_bits(bqm, value)
            for value in itertools.product((0, 1), repeat=bits)
        ]
        samples.sort(key=lambda item: (item.energy, item.bits))
        elapsed = time.perf_counter() - started
        return SampleSet(
            tuple(samples[: min(requested, len(samples))]),
            {
                "backend": "exact-bit-enumeration",
                "logical_bits": bits,
                "max_bits": self.max_bits,
                "optimality_proven": True,
                "reads_requested": requested,
                "states_evaluated": 1 << bits,
                "wall_seconds": elapsed,
            },
        )


def exact_feasible_sequences(
    problem: SearchProblem,
    bqm: BinaryQuadraticModel,
) -> SampleSet:
    """Independently enumerate native feasible sequences, then encode for scoring."""

    if problem != bqm.problem:
        raise SolverError("feasible oracle problem does not match the BQM")
    started = time.perf_counter()
    sequences: list[tuple[str, ...]] = [()]
    for length in range(1, problem.max_sequence_length + 1):
        for sequence in itertools.product(problem.actions, repeat=length):
            counts = Counter(sequence)
            if all(
                counts[action] <= problem.repetition_limits[action]
                for action in problem.actions
            ):
                sequences.append(sequence)
    samples = [sample_from_bits(bqm, bqm.encode(sequence)) for sequence in sequences]
    samples.sort(key=lambda item: (item.energy, item.bits))
    elapsed = time.perf_counter() - started
    return SampleSet(
        tuple(samples),
        {
            "backend": "exact-feasible-sequences",
            "logical_bits": len(bqm.variables),
            "optimality_proven": True,
            "states_evaluated": len(sequences),
            "wall_seconds": elapsed,
        },
    )
