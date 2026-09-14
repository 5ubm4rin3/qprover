from __future__ import annotations

from qprover.models import Outcome
from qprover.parameters import ActionVariant
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
    assert evidence["solver_totals"] == {
        "calls": 2,
        "reads": 6,
        "sweeps": 10,
        "wall_seconds": 0.5,
        "decoded_feasible": 2,
        "decoded_infeasible": 0,
    }
    assert len(evidence["builds"]) == 2
    assert all(item["model_sha256"] for item in evidence["builds"])
