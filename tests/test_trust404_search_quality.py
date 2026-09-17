from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

from qprover.search.bqm import SearchFeedback, SequenceBQMBuilder
from qprover.trust404 import (
    ADDRESS_REF_PREFIX,
    SELF_ADDRESS,
    Track04Action,
    Track04Manifest,
    Track04SearchModel,
    Track04Variant,
    _abi_values,
    render_candidate,
)
from qprover.trust404_runner import _skeleton_problem


def _manifest(tmp_path: Path) -> Track04Manifest:
    path = tmp_path / "manifest.json"
    path.write_text(
        json.dumps(
            {
                "schema": "trust404.track04.manifest/0.1",
                "target": {
                    "name": "Demo",
                    "src": "Demo.sol",
                    "solc": "0.8.24",
                    "evm_version": "cancun",
                },
                "deploy": {
                    "mode": "local",
                    "constructor_args": [],
                    "value_wei": "0",
                },
                "determinism": {
                    "block_number": 1,
                    "block_timestamp": 2,
                    "seed": 42,
                },
                "invariants": {
                    "contract": "Invariants.sol",
                    "predicates": ["healthy"],
                },
                "budget": {"timeout_sec": 300, "max_attempts": 5},
            }
        ),
        encoding="utf-8",
    )
    return Track04Manifest.load(path)


def _model() -> Track04SearchModel:
    actions = (
        Track04Action(
            id="call:a()",
            kind="call",
            signature="a()",
            function_id="a",
            param_types=(),
            payable=False,
            utility=0.8,
            storage_reads=(),
            storage_writes=("x",),
            provenance=("Demo.sol", "0:1:0"),
        ),
        Track04Action(
            id="call:b()",
            kind="call",
            signature="b()",
            function_id="b",
            param_types=(),
            payable=False,
            utility=0.8,
            storage_reads=("x",),
            storage_writes=("y",),
            provenance=("Demo.sol", "1:1:0"),
        ),
        Track04Action(
            id="call:c()",
            kind="call",
            signature="c()",
            function_id="c",
            param_types=(),
            payable=False,
            utility=0.6,
            storage_reads=(),
            storage_writes=("z",),
            provenance=("Demo.sol", "2:1:0"),
        ),
    )
    variants = tuple(
        Track04Variant(action.id, action.signature, (), 0) for action in actions
    )
    return Track04SearchModel(
        actions=actions,
        variants=variants,
        utilities={action.id: action.utility for action in actions},
        transitions={(actions[0].id, actions[1].id): 0.8},
        max_sequence_length=6,
        analysis=SimpleNamespace(),
    )


def test_address_domain_keeps_attacker_self_before_reachable_contract_refs(
    tmp_path: Path,
) -> None:
    refs = (
        ADDRESS_REF_PREFIX + "pool()",
        ADDRESS_REF_PREFIX + "borrowToken()",
        ADDRESS_REF_PREFIX + "collateralToken()",
    )

    values = _abi_values("address", _manifest(tmp_path), address_refs=refs)

    assert values[0] == SELF_ADDRESS
    assert set(refs).issubset(values)


def test_action_skeleton_objective_does_not_reward_unrelated_tail() -> None:
    problem = _skeleton_problem(_model())
    bqm = SequenceBQMBuilder().build(problem, SearchFeedback.empty())

    useful = bqm.energy(bqm.encode(("call:a()", "call:b()")))
    padded = bqm.energy(bqm.encode(("call:a()", "call:b()", "call:c()")))

    assert useful < padded


def test_renderer_marks_step_for_stable_revert_feedback() -> None:
    from qprover.models import ActionStep, Candidate

    model = _model()
    candidate = Candidate(
        (
            ActionStep("call:a()", "target", "a()", 0, (), 0),
            ActionStep("call:b()", "target", "b()", 0, (), 0),
        )
    )

    code = render_candidate(model, candidate)

    assert "error QProverFailure(uint256 step);" in code
    assert "_qproverStep = 0;" in code
    assert "_qproverStep = 1;" in code
    assert "revert QProverFailure(_qproverStep);" in code
