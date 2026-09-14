from __future__ import annotations

import json

import pytest

from qprover.models import Outcome
from qprover.parameters import ActionVariant
from qprover.search.annealing import SimulatedAnnealingBackend
from qprover.search.base import Evaluation
from qprover.search.bqm import SampleSet, SearchProblem, sample_from_bits
from qprover.search.qubo import QuboStrategy


def _variant(action: str, value: int) -> ActionVariant:
    return ActionVariant(
        action_id=action,
        target_id="scenario",
        signature=f"{action}(uint256)",
        sender_slot=1,
        args=(value,),
        value_wei=0,
        max_repetitions=1,
        argument_provenance=(("explicit",),),
        value_provenance=("explicit",),
    )


class RecordingBackend:
    def __init__(self) -> None:
        self.models = []

    def sample(self, bqm, **options):
        self.models.append(bqm)
        sequence = (bqm.problem.actions[0],)
        return SampleSet(
            (sample_from_bits(bqm, bqm.encode(sequence)),),
            {
                "backend": "recording",
                "reads": options["reads"],
                "sweeps": 5,
                "wall_seconds": 0.25,
                "logical_bits": len(bqm.variables),
            },
        )


def test_qubo_groups_variant_tokens_and_accumulates_all_build_evidence() -> None:
    variants = (_variant("prime", 1), _variant("prime", 2), _variant("attack", 0))
    problem = SearchProblem(
        actions=("prime", "attack"),
        max_sequence_length=2,
        utilities={"prime": 0.2, "attack": 0.9},
        transitions={("prime", "attack"): 0.8},
        repetition_limits={"prime": 1, "attack": 1},
        variants=variants,
    )
    backend = RecordingBackend()
    strategy = QuboStrategy(
        backend=backend,
        reads=3,
        feedback_batch_size=1,
        resample_attempts=0,
        max_exact_fallback_sequences=0,
    )
    strategy.initialize(problem, seed=11)

    first = strategy.propose(2)
    assert first is not None
    strategy.observe(first, Evaluation(Outcome.PASS, 1))
    strategy.propose(2)

    assert len(backend.models) == 2
    for model in backend.models:
        prime_tokens = tuple(
            token
            for token in model.problem.actions
            if model.problem.repetition_groups[token] == "prime"
        )
        assert len(prime_tokens) == 2
        illegal = list(model.encode((prime_tokens[0],)))
        illegal[model.index(1, "__STOP__")] = 0
        illegal[model.index(1, prime_tokens[1])] = 1
        assert not model.decode(illegal).feasibility.feasible
        assert model.decode(illegal).feasibility.repetition_violations == ("prime",)

    evidence = strategy.evidence
    assert evidence["problem_sha256"] == problem.sha256
    assert {
        key: value
        for key, value in evidence["solver_totals"].items()
        if key != "compute_wall_seconds"
    } == {
        "calls": 2,
        "reads": 6,
        "sweeps": 10,
        "wall_seconds": 0.5,
        "decoded_feasible": 2,
        "decoded_infeasible": 0,
    }
    assert evidence["solver_totals"]["compute_wall_seconds"] >= 0.5
    assert len(evidence["builds"]) == 2
    assert all(item["model_sha256"] for item in evidence["builds"])
    assert all(item["requested_seed"] in {11, 12} for item in evidence["builds"])
    assert all(item["seed_supported"] is False for item in evidence["builds"])
    assert all(item["effective_seed"] is None for item in evidence["builds"])
    json.dumps(evidence, allow_nan=False)


@pytest.mark.parametrize(
    "metadata",
    [
        {
            "backend": "malicious",
            "logical_bits": 4,
            "reads": 1,
            "wall_seconds": float("nan"),
        },
        {
            "backend": "malicious",
            "logical_bits": 4,
            "reads": True,
            "wall_seconds": 0.1,
        },
        {
            "backend": "malicious",
            "logical_bits": 4,
            "reads": 1,
            "wall_seconds": 0.1,
            "unknown": 7,
        },
        {
            "backend": "malicious",
            "logical_bits": 5,
            "reads": 1,
            "wall_seconds": 0.1,
        },
        {
            "backend": "malicious",
            "logical_bits": 4,
            "reads": 1,
            "wall_seconds": 0.1,
            "seed": 99,
        },
    ],
)
def test_qubo_rejects_malformed_or_fabricated_backend_evidence(metadata) -> None:
    class MaliciousBackend:
        def sample(self, bqm, **options):
            del options
            return SampleSet(
                (sample_from_bits(bqm, bqm.encode((bqm.problem.actions[0],))),),
                metadata,
            )

    strategy = QuboStrategy(backend=MaliciousBackend(), reads=1)
    strategy.initialize(
        SearchProblem(
            actions=("prime",),
            max_sequence_length=2,
            variants=(_variant("prime", 1),),
        ),
        seed=11,
    )

    with pytest.raises(ValueError, match="backend metadata"):
        strategy.propose(2)


def test_qubo_records_simulated_annealing_seed_as_effective() -> None:
    strategy = QuboStrategy(
        backend=SimulatedAnnealingBackend(), reads=2, resample_attempts=0
    )
    strategy.initialize(
        SearchProblem(
            actions=("prime",),
            max_sequence_length=1,
            variants=(_variant("prime", 1),),
        ),
        seed=23,
    )

    assert strategy.propose(1) is not None
    build = strategy.evidence["builds"][0]
    assert build["requested_seed"] == 23
    assert build["seed_supported"] is True
    assert build["effective_seed"] == 23


def test_qubo_records_exact_fallback_compute_separately() -> None:
    strategy = QuboStrategy(
        backend=RecordingBackend(),
        reads=1,
        resample_attempts=0,
        max_exact_fallback_sequences=10,
    )
    strategy.initialize(
        SearchProblem(
            actions=("prime",),
            max_sequence_length=1,
            variants=(_variant("prime", 1),),
        ),
        seed=5,
    )

    first = strategy.propose(1)
    assert first is not None
    assert strategy.propose(1) is None

    evidence = strategy.evidence
    assert evidence["fallback"]["calls"] == 1
    assert evidence["fallback"]["wall_seconds"] >= 0
    assert evidence["fallback"]["records"][0]["enumerated_count"] == 1
    assert (
        evidence["solver_totals"]["compute_wall_seconds"]
        >= evidence["solver_totals"]["wall_seconds"]
    )


def test_qubo_evidence_snapshot_cannot_mutate_accumulated_builds() -> None:
    strategy = QuboStrategy(backend=RecordingBackend(), reads=1)
    strategy.initialize(
        SearchProblem(
            actions=("prime",),
            max_sequence_length=1,
            variants=(_variant("prime", 1),),
        ),
        seed=5,
    )
    assert strategy.propose(1) is not None
    first = strategy.evidence
    first["builds"][0]["requested_seed"] = 999

    assert strategy.evidence["builds"][0]["requested_seed"] == 5
