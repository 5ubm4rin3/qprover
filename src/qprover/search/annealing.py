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
        if self.reads <= 0:
            raise ValueError("reads must be positive")
        if self.sweeps <= 0:
            raise ValueError("sweeps must be positive")
        if (
            not math.isfinite(self.temperature_start)
            or not math.isfinite(self.temperature_end)
            or self.temperature_start <= 0
            or self.temperature_end <= 0
        ):
            raise ValueError("temperatures must be finite and positive")
        if self.temperature_end > self.temperature_start:
            raise ValueError("temperature_end cannot exceed temperature_start")


def _flip_delta(bqm: BinaryQuadraticModel, bits: list[int], index: int) -> float:
    field = bqm.linear.get(index, 0.0)
    for (first, second), coefficient in bqm.quadratic.items():
        if first == second == index:
            field += coefficient
        elif first == index:
            field += coefficient * bits[second]
        elif second == index:
            field += coefficient * bits[first]
    return (1 - 2 * bits[index]) * field


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
            ratio = (config.temperature_end / config.temperature_start) ** (
                1 / (config.sweeps - 1)
            )
            temperatures = tuple(
                config.temperature_start * ratio**sweep
                for sweep in range(config.sweeps)
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
                "temperature_schedule": "geometric",
                "temperature_start": config.temperature_start,
                "update_order": "random-permutation",
                "wall_seconds": elapsed,
            },
        )
