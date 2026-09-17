"""Inspectably seeded simulated annealing for canonical binary models."""

from __future__ import annotations

import math
import random
import time
from dataclasses import dataclass

from qprover.search.bqm import BinaryQuadraticModel, SampleSet, sample_from_bits


@dataclass(frozen=True, slots=True)
class AnnealingConfig:
    seed: int = 0
    reads: int = 32
    sweeps: int = 200
    temperature_start: float = 10.0
    temperature_end: float = 0.01

    def __post_init__(self) -> None:
        if type(self.seed) is not int:
            raise ValueError("seed must be an exact integer")
        if type(self.reads) is not int or self.reads <= 0:
            raise ValueError("reads must be an exact positive integer")
        if type(self.sweeps) is not int or self.sweeps <= 0:
            raise ValueError("sweeps must be an exact positive integer")
        if type(self.temperature_start) not in (int, float) or type(
            self.temperature_end
        ) not in (int, float):
            raise ValueError("temperatures must be finite positive int or float values")
        try:
            temperature_start = float(self.temperature_start)
            temperature_end = float(self.temperature_end)
        except OverflowError as error:
            raise ValueError("temperatures must be finite and positive") from error
        if (
            not math.isfinite(temperature_start)
            or not math.isfinite(temperature_end)
            or temperature_start <= 0
            or temperature_end <= 0
        ):
            raise ValueError("temperatures must be finite and positive")
        if temperature_end > temperature_start:
            raise ValueError("temperature_end cannot exceed temperature_start")
        object.__setattr__(self, "temperature_start", temperature_start)
        object.__setattr__(self, "temperature_end", temperature_end)


def _flip_delta(bqm: BinaryQuadraticModel, bits: list[int], index: int) -> float:
    terms = [bqm.linear.get(index, 0.0)]
    for neighbor, coefficient in bqm.quadratic_adjacency[index]:
        if neighbor == index:
            terms.append(coefficient)
        else:
            terms.append(coefficient * bits[neighbor])
    try:
        field = math.fsum(terms)
    except OverflowError as error:
        raise ValueError("non-finite annealing flip energy") from error
    delta = (1 - 2 * bits[index]) * field
    if not math.isfinite(delta):
        raise ValueError("non-finite annealing flip energy")
    return delta


class SimulatedAnnealingBackend:
    def sample(
        self,
        bqm: BinaryQuadraticModel,
        config: AnnealingConfig | None = None,
        **overrides: object,
    ) -> SampleSet:
        if config is not None and overrides:
            raise ValueError("annealing configuration cannot be supplied twice")
        if config is None:
            config = AnnealingConfig(**overrides)
        started = time.perf_counter()
        generator = random.Random(config.seed)
        variable_order = list(range(len(bqm.variables)))
        samples = []
        if config.sweeps == 1:
            temperatures = (config.temperature_start,)
        else:
            start_log = math.log(config.temperature_start)
            end_log = math.log(config.temperature_end)
            interior = tuple(
                math.exp(
                    start_log + (end_log - start_log) * sweep / (config.sweeps - 1)
                )
                for sweep in range(1, config.sweeps - 1)
            )
            temperatures = (
                config.temperature_start,
                *interior,
                config.temperature_end,
            )
        for _ in range(config.reads):
            bits = [generator.randrange(2) for _ in bqm.variables]
            for temperature in temperatures:
                generator.shuffle(variable_order)
                for index in variable_order:
                    delta = _flip_delta(bqm, bits, index)
                    if delta <= 0 or generator.random() < math.exp(
                        -delta / temperature
                    ):
                        bits[index] ^= 1
            samples.append(sample_from_bits(bqm, bits))
        samples.sort(key=lambda item: (item.energy, item.bits))
        elapsed = time.perf_counter() - started
        return SampleSet(
            tuple(samples),
            {
                "backend": "simulated-annealing",
                "logical_bits": len(bqm.variables),
                "reads": config.reads,
                "seed": config.seed,
                "start_policy": "random-binary",
                "sweeps": config.sweeps,
                "temperature_end": config.temperature_end,
                "temperature_schedule": "geometric-log-space",
                "temperature_start": config.temperature_start,
                "update_order": "random-permutation",
                "wall_seconds": elapsed,
            },
        )
