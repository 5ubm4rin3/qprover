from __future__ import annotations

from qprover.trust404_property import PropertyAnalysis, PropertyFact
from qprover.trust404_resources import build_property_slices


def _analysis(predicate: str, function_id: str) -> PropertyAnalysis:
    return PropertyAnalysis(
        invariants_source_name="Invariants.sol",
        contract_name="Invariants",
        facts=(
            PropertyFact(
                predicate_name=predicate,
                function_id=function_id,
                target_parameter_index=0,
                target_balance_read=True,
                target_calls=(),
                constants=(10**18,),
                comparison_hints=(("target.balance", ">=", "1000000000000000000"),),
                source_span="0:1:0",
                bound_from_check_all=True,
                known=True,
            ),
        ),
    )


def test_property_slice_survives_semantic_rename() -> None:
    first = build_property_slices(
        _analysis("alpha", "function:alpha"),
        root_target_identity="root",
    )
    second = build_property_slices(
        _analysis("renamed", "function:renamed"),
        root_target_identity="root",
    )

    assert len(first) == len(second) == 1
    assert tuple(resource.kind for resource in first[0].resources) == tuple(
        resource.kind for resource in second[0].resources
    )
    assert first[0].direction_hint == second[0].direction_hint == "decrease"


def test_irrelevant_property_metadata_does_not_change_resource_kind() -> None:
    baseline = build_property_slices(
        _analysis("alpha", "function:alpha"),
        root_target_identity="root",
    )[0]
    renamed = _analysis("wrapper_name", "function:wrapper")
    mutated = PropertyAnalysis(
        invariants_source_name=renamed.invariants_source_name,
        contract_name=renamed.contract_name,
        facts=renamed.facts
        + (
            PropertyFact(
                predicate_name="irrelevant",
                function_id="function:irrelevant",
                target_parameter_index=None,
                target_balance_read=False,
                target_calls=(),
                constants=(),
                comparison_hints=(),
                source_span="1:1:0",
                bound_from_check_all=False,
                known=False,
            ),
        ),
    )
    relevant = build_property_slices(
        mutated,
        root_target_identity="root",
    )[0]

    assert tuple(resource.kind for resource in relevant.resources) == tuple(
        resource.kind for resource in baseline.resources
    )
