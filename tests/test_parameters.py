from __future__ import annotations

from types import SimpleNamespace

import pytest

from qprover.models import ArgumentSpec, TargetManifest
from qprover.parameters import (
    ParameterError,
    expand_action_variants,
    expand_argument_values,
    solve_integer_domain,
)


def _manifest(tmp_path, *, max_variants: int = 32) -> TargetManifest:
    source = tmp_path / "Target.sol"
    source.write_text(
        "contract Target { function act(uint8 amount, bool enabled) external { "
        "require(amount != 17); } }",
        encoding="utf-8",
    )
    return TargetManifest.model_validate(
        {
            "schema_version": "1.0",
            "target": {
                "id": "target",
                "project_root": str(tmp_path),
                "solidity_version": "0.8.34",
                "evm_version": "prague",
                "source_files": [str(source)],
            },
            "actors": [
                {"id": "deployer", "slot": 0, "balance_wei": 10**18},
                {"id": "attacker", "slot": 2, "balance_wei": 10**18},
            ],
            "deployments": [
                {
                    "id": "target",
                    "artifact": "Target.sol:Target",
                    "constructor_args": [],
                    "sender_slot": 0,
                    "value_wei": 0,
                }
            ],
            "actions": [
                {
                    "id": "act",
                    "target_id": "target",
                    "signature": "act(uint8,bool)",
                    "mutability": "nonpayable",
                    "sender_slots": [2, 0],
                    "arguments": [
                        {
                            "name": "amount",
                            "type": "uint8",
                            "domain": {
                                "kind": "integer",
                                "minimum": 3,
                                "maximum": 20,
                            },
                        },
                        {
                            "name": "enabled",
                            "type": "bool",
                            "domain": {
                                "kind": "finite",
                                "values": [True, False, True],
                            },
                        },
                    ],
                    "value_domain": {"kind": "finite", "values": [0]},
                    "max_repetitions": 2,
                }
            ],
            "observations": [
                {
                    "id": "protocol_assets",
                    "kind": "native_balance",
                    "actor_id": "deployer",
                },
                {
                    "id": "attacker_assets",
                    "kind": "native_balance",
                    "actor_id": "attacker",
                },
            ],
            "invariants": [
                {
                    "id": "preserved",
                    "expression": "protocol_assets >= initial_protocol_assets",
                    "description": "preserved",
                    "foundry_assertion": "assert(true);",
                }
            ],
            "impact": {
                "attacker_asset_observation": "attacker_assets",
                "protocol_asset_observation": "protocol_assets",
                "unit": "wei",
            },
            "limits": {
                "max_sequence_length": 2,
                "max_variants": max_variants,
                "transaction_budget": 10,
                "candidate_budget": 10,
                "wall_seconds": 10,
            },
        }
    )


def test_integer_expansion_has_stable_boundary_power_constant_order() -> None:
    argument = ArgumentSpec.model_validate(
        {
            "name": "amount",
            "type": "uint8",
            "domain": {
                "kind": "integer",
                "minimum": 3,
                "maximum": 20,
            },
        }
    )

    values = expand_argument_values(argument, source_constants=(17, 7), cap=20)

    assert tuple(item.value for item in values) == (3, 20, 4, 19, 8, 16, 7, 17)
    assert tuple(item.provenance for item in values) == (
        ("boundary",),
        ("boundary",),
        ("boundary",),
        ("boundary",),
        ("boundary",),
        ("boundary",),
        ("constant",),
        ("constant",),
    )


def test_full_abi_integer_range_includes_type_extrema() -> None:
    unsigned = ArgumentSpec.model_validate(
        {
            "name": "u",
            "type": "uint8",
            "domain": {"kind": "integer", "minimum": 0, "maximum": 255},
        }
    )
    signed = ArgumentSpec.model_validate(
        {
            "name": "i",
            "type": "int8",
            "domain": {"kind": "integer", "minimum": -128, "maximum": 127},
        }
    )

    assert {item.value for item in expand_argument_values(unsigned)} >= {0, 1, 255}
    assert {item.value for item in expand_argument_values(signed)} >= {-128, 127}


def test_finite_values_deduplicate_without_reordering() -> None:
    argument = ArgumentSpec.model_validate(
        {
            "name": "amount",
            "type": "uint256",
            "domain": {"kind": "finite", "values": [3, 1, 3, 2]},
        }
    )

    values = expand_argument_values(argument)

    assert tuple(item.value for item in values) == (3, 1, 2)
    assert all(item.provenance == ("explicit",) for item in values)


@pytest.mark.parametrize(
    ("abi_type", "value"),
    [
        ("address", "0x1234"),
        ("bytes2", "0x01"),
        ("bytes", "0x0"),
        ("bool", 1),
        ("uint8", 256),
        ("int8", -129),
    ],
)
def test_finite_domain_rejects_values_not_encodable_by_abi(
    abi_type: str, value: object
) -> None:
    argument = ArgumentSpec.model_validate(
        {
            "name": "value",
            "type": abi_type,
            "domain": {"kind": "finite", "values": [value]},
        }
    )

    with pytest.raises(ParameterError, match="ABI"):
        expand_argument_values(argument)


@pytest.mark.parametrize(
    ("abi_type", "value"),
    [
        ("address", "0x0000000000000000000000000000000000000001"),
        ("bytes2", "0x0102"),
        ("bytes", "0x"),
        ("bool", False),
        ("string", "hello"),
    ],
)
def test_finite_domain_accepts_valid_scalar_abi_values(
    abi_type: str, value: object
) -> None:
    argument = ArgumentSpec.model_validate(
        {
            "name": "value",
            "type": abi_type,
            "domain": {"kind": "finite", "values": [value]},
        }
    )

    assert expand_argument_values(argument)[0].value == value


def test_z3_domain_solves_modular_constraint_deterministically() -> None:
    expected = ((1039,), (2036,), (3033,), (4030,))

    first = solve_integer_domain(
        names=("arg0",),
        constraints=("arg0 > 1000", "arg0 % 997 == 42"),
        bounds={"arg0": (0, 5000)},
        max_models=4,
    )
    second = solve_integer_domain(
        names=("arg0",),
        constraints=("arg0 > 1000", "arg0 % 997 == 42"),
        bounds={"arg0": (0, 5000)},
        max_models=4,
    )

    assert first == expected
    assert second == expected


def test_z3_domain_solves_two_variables_and_named_constants() -> None:
    values = solve_integer_domain(
        names=("arg0", "arg1"),
        constraints=("arg0 + arg1 == target", "arg0 < arg1", "arg0 & 1 == 1"),
        bounds={"arg0": (0, 5), "arg1": (0, 5)},
        constants={"target": 6},
        max_models=4,
    )

    assert values == ((1, 5),)


@pytest.mark.parametrize(
    "constraint",
    ["f(arg0)", "arg0.real == 1", "arg0[0] == 1", "unknown == 1"],
)
def test_z3_domain_rejects_non_whitelisted_or_unknown_syntax(
    constraint: str,
) -> None:
    with pytest.raises(ParameterError):
        solve_integer_domain(
            names=("arg0",),
            constraints=(constraint,),
            bounds={"arg0": (0, 5)},
            max_models=1,
        )


@pytest.mark.parametrize("constraint", ["arg0 / 2 == 1", "~arg0 == -2"])
def test_z3_domain_matches_invariant_operator_whitelist(constraint: str) -> None:
    with pytest.raises(ParameterError, match="unsupported"):
        solve_integer_domain(
            names=("arg0",),
            constraints=(constraint,),
            bounds={"arg0": (0, 5)},
            max_models=2,
        )


def test_z3_floor_division_and_modulus_match_python_for_negative_divisors() -> None:
    division = solve_integer_domain(
        names=("arg0",),
        constraints=("arg0 // -2 == -3",),
        bounds={"arg0": (-5, 5)},
        max_models=10,
    )
    modulus = solve_integer_domain(
        names=("arg0",),
        constraints=("arg0 % -2 == -1",),
        bounds={"arg0": (1, 3)},
        max_models=10,
    )

    assert division == ((5,),)
    assert modulus == ((1,), (3,))


@pytest.mark.parametrize(
    "constraint",
    ["arg0 // (arg0 - 1) == 1", "arg0 % (arg0 - 1) == 0"],
)
def test_z3_domains_exclude_undefined_zero_divisors(constraint: str) -> None:
    values = solve_integer_domain(
        names=("arg0",),
        constraints=(constraint,),
        bounds={"arg0": (1, 1)},
        max_models=2,
    )

    assert values == ()


def test_z3_shift_has_exact_non_overflowing_semantics() -> None:
    values = solve_integer_domain(
        names=("arg0",),
        constraints=("arg0 << 10 == 1024",),
        bounds={"arg0": (1, 1)},
        max_models=1,
    )

    assert values == ((1,),)


@pytest.mark.parametrize("constraint", ["1 << arg0 == 2", "1 << 4097 > 0"])
def test_z3_shift_requires_bounded_literal_rhs(constraint: str) -> None:
    with pytest.raises(ParameterError, match="shift"):
        solve_integer_domain(
            names=("arg0",),
            constraints=(constraint,),
            bounds={"arg0": (0, 1)},
            max_models=2,
        )


def test_z3_exponent_bound_matches_invariant_evaluator() -> None:
    values = solve_integer_domain(
        names=("arg0",),
        constraints=("arg0 ** 9 == 512",),
        bounds={"arg0": (0, 3)},
        max_models=2,
    )

    assert values == ((2,),)


def test_z3_bounded_variable_exponent_matches_invariant_evaluator() -> None:
    values = solve_integer_domain(
        names=("arg0", "arg1"),
        constraints=("arg0 ** arg1 == 8",),
        bounds={"arg0": (2, 2), "arg1": (3, 3)},
        max_models=2,
    )

    assert values == ((2, 3),)


def test_z3_bitwise_operations_match_python_for_negative_values() -> None:
    values = solve_integer_domain(
        names=("arg0",),
        constraints=("arg0 & 1 == 1", "arg0 ^ 2 == -3"),
        bounds={"arg0": (-3, -1)},
        max_models=4,
    )

    assert values == ((-1,),)


@pytest.mark.parametrize("bad_limit", [True, 1.0])
def test_parameter_public_limits_reject_silent_integer_coercion(bad_limit) -> None:
    argument = ArgumentSpec.model_validate(
        {
            "name": "amount",
            "type": "uint8",
            "domain": {"kind": "integer", "minimum": 0, "maximum": 2},
        }
    )
    with pytest.raises(ParameterError, match="cap"):
        expand_argument_values(argument, cap=bad_limit)
    with pytest.raises(ParameterError, match="max_models"):
        solve_integer_domain(
            names=("arg0",),
            constraints=("arg0 >= 0",),
            bounds={"arg0": (0, 2)},
            max_models=bad_limit,
        )


@pytest.mark.parametrize("abi_type", ["bytes0", "bytes33"])
def test_fixed_bytes_width_must_be_between_one_and_thirty_two(
    abi_type: str,
) -> None:
    size = int(abi_type.removeprefix("bytes"))
    argument = ArgumentSpec.model_validate(
        {
            "name": "blob",
            "type": abi_type,
            "domain": {"kind": "finite", "values": ["0x" + "00" * size]},
        }
    )

    with pytest.raises(ParameterError, match="unsupported ABI"):
        expand_argument_values(argument)


def test_action_value_candidates_must_fit_uint256(tmp_path) -> None:
    raw = _manifest(tmp_path).model_dump(mode="python")
    raw["actions"][0]["mutability"] = "payable"
    raw["actions"][0]["value_domain"]["values"] = (2**256,)
    manifest = TargetManifest.model_validate(raw)

    with pytest.raises(ParameterError, match="uint256"):
        expand_action_variants(manifest, SimpleNamespace(contracts=()))


def test_action_expansion_is_capped_cartesian_and_retains_provenance(
    tmp_path,
) -> None:
    manifest = _manifest(tmp_path, max_variants=3)
    report = SimpleNamespace(contracts=())

    variants = expand_action_variants(manifest, report)

    assert len(variants) == 3
    assert tuple(
        (item.sender_slot, item.args, item.value_wei) for item in variants
    ) == (
        (0, (3, True), 0),
        (0, (3, False), 0),
        (0, (20, True), 0),
    )
    assert variants[0].argument_provenance == (("boundary",), ("explicit",))
    assert variants[0].value_provenance == ("explicit",)
    assert len({item.canonical_id for item in variants}) == 3


def test_source_constants_are_scoped_into_integer_variants(tmp_path) -> None:
    manifest = _manifest(tmp_path)

    variants = expand_action_variants(manifest, SimpleNamespace(contracts=()))

    assert any(item.args[0] == 17 for item in variants)
    sourced = next(item for item in variants if item.args[0] == 17)
    assert sourced.argument_provenance[0] == ("constant",)


def test_action_expansion_preserves_correlated_z3_models(tmp_path) -> None:
    raw = _manifest(tmp_path).model_dump(mode="python")
    raw["actions"][0]["signature"] = "act(uint8,uint8)"
    raw["actions"][0]["sender_slots"] = (0,)
    raw["actions"][0]["arguments"] = (
        {
            "name": "left",
            "type": "uint8",
            "domain": {
                "kind": "integer",
                "minimum": 0,
                "maximum": 3,
                "constraints": ("arg0 + arg1 == 3",),
            },
        },
        {
            "name": "right",
            "type": "uint8",
            "domain": {
                "kind": "integer",
                "minimum": 0,
                "maximum": 3,
            },
        },
    )
    manifest = TargetManifest.model_validate(raw)

    variants = expand_action_variants(manifest, SimpleNamespace(contracts=()))

    assert {item.args for item in variants} == {(0, 3), (1, 2), (2, 1), (3, 0)}
    assert all(
        "z3" in provenance
        for variant in variants
        for provenance in variant.argument_provenance
    )
