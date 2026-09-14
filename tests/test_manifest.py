import json
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from qprover.manifest import ManifestError, load_manifest
from qprover.models import (
    ActionStep,
    Candidate,
    DeploymentSpec,
    ObservationSnapshot,
    TargetManifest,
)


def minimal_manifest(tmp_path: Path) -> dict[str, Any]:
    project_root = tmp_path / "fixture"
    source_dir = project_root / "src"
    source_dir.mkdir(parents=True)
    (source_dir / "Vault.sol").write_text(
        "contract Vault { function deposit(uint256) external {} }",
        encoding="utf-8",
    )
    return {
        "schema_version": "1.0",
        "target": {
            "id": "fixture",
            "project_root": "fixture",
            "solidity_version": "0.8.34",
            "evm_version": "prague",
            "source_files": ["src/Vault.sol"],
        },
        "actors": [
            {"id": "deployer", "slot": 0, "balance_wei": 10**20},
            {"id": "attacker", "slot": 1, "balance_wei": 10**18},
        ],
        "deployments": [
            {
                "id": "vault",
                "artifact": "src/Vault.sol:Vault",
                "constructor_args": [],
                "sender_slot": 0,
                "value_wei": 0,
            }
        ],
        "actions": [
            {
                "id": "deposit",
                "target_id": "vault",
                "signature": "deposit(uint256)",
                "mutability": "payable",
                "sender_slots": [1],
                "arguments": [
                    {
                        "name": "amount",
                        "type": "uint256",
                        "domain": {
                            "kind": "integer",
                            "minimum": 0,
                            "maximum": 100,
                        },
                    }
                ],
                "value_domain": {"kind": "finite", "values": [0, 1]},
                "max_repetitions": 2,
            }
        ],
        "observations": [
            {
                "id": "protocol_assets",
                "kind": "call",
                "target_id": "vault",
                "signature": "protocolAssets()",
                "args": [],
            },
            {
                "id": "attacker_assets",
                "kind": "native_balance",
                "actor_id": "attacker",
            },
        ],
        "invariants": [
            {
                "id": "assets_preserved",
                "expression": "protocol_assets >= initial_protocol_assets",
                "description": "Protocol assets must not decrease",
                "foundry_assertion": (
                    "assertGe(target.protocolAssets(), initialAssets);"
                ),
            }
        ],
        "impact": {
            "attacker_asset_observation": "attacker_assets",
            "protocol_asset_observation": "protocol_assets",
            "unit": "wei",
        },
        "limits": {
            "max_sequence_length": 3,
            "max_variants": 32,
            "transaction_budget": 100,
            "candidate_budget": 50,
            "wall_seconds": 30,
        },
    }


def write_json(path: Path, raw: dict[str, Any]) -> Path:
    path.write_text(json.dumps(raw), encoding="utf-8")
    return path


def test_manifest_loads_exact_values_and_canonical_paths(tmp_path: Path) -> None:
    path = write_json(tmp_path / "target.json", minimal_manifest(tmp_path))

    manifest = load_manifest(path)

    assert isinstance(manifest, TargetManifest)
    assert manifest.schema_version == "1.0"
    assert manifest.target.id == "fixture"
    assert manifest.target.project_root == (tmp_path / "fixture").resolve()
    assert manifest.target.source_files == (
        (tmp_path / "fixture" / "src" / "Vault.sol").resolve(),
    )
    assert manifest.actions[0].arguments[0].domain.minimum == 0
    assert manifest.actions[0].arguments[0].domain.maximum == 100
    assert manifest.actions[0].value_domain.values == (0, 1)
    assert manifest.limits.transaction_budget == 100


def test_manifest_records_are_immutable(tmp_path: Path) -> None:
    manifest = load_manifest(
        write_json(tmp_path / "target.json", minimal_manifest(tmp_path))
    )

    with pytest.raises(ValidationError, match="frozen_instance"):
        manifest.target.id = "changed"  # type: ignore[misc]


def test_candidate_id_is_stable_and_sensitive_to_steps() -> None:
    first = Candidate(
        steps=(ActionStep("deposit", "vault", "deposit(uint256)", 1, (1,)),)
    )
    same = Candidate(
        steps=(ActionStep("deposit", "vault", "deposit(uint256)", 1, (1,)),)
    )
    different = Candidate(
        steps=(ActionStep("deposit", "vault", "deposit(uint256)", 1, (2,)),)
    )

    assert first.canonical_id == same.canonical_id
    assert first.canonical_id != different.canonical_id
    assert len(first.canonical_id) == 64


def test_action_step_deeply_freezes_argument_aliases() -> None:
    nested = [2, 3]
    step = ActionStep("deposit", "vault", "deposit(uint256[])", 1, (nested,))
    before = Candidate(steps=(step,)).canonical_id

    nested.append(4)

    assert step.args == ((2, 3),)
    assert Candidate(steps=(step,)).canonical_id == before


def test_action_step_rejects_mapping_arguments() -> None:
    with pytest.raises(TypeError, match="mapping"):
        ActionStep("deposit", "vault", "deposit(uint256)", 1, ({"value": 1},))


def test_candidate_copies_and_freezes_steps_alias() -> None:
    step = ActionStep("deposit", "vault", "deposit(uint256)", 1, (1,))
    steps = [step]
    candidate = Candidate(steps=steps)  # type: ignore[arg-type]
    before = candidate.canonical_id

    steps.append(ActionStep("deposit", "vault", "deposit(uint256)", 1, (2,)))

    assert candidate.steps == (step,)
    assert candidate.canonical_id == before


def test_observation_snapshot_copies_and_freezes_values() -> None:
    source = {"protocol_assets": 10}
    snapshot = ObservationSnapshot(values=source, state_hash="a" * 64)

    source["protocol_assets"] = 0

    assert snapshot.values["protocol_assets"] == 10
    with pytest.raises(TypeError):
        snapshot.values["protocol_assets"] = 1  # type: ignore[index]


def test_deployment_spec_deeply_freezes_constructor_arguments() -> None:
    nested = [1, 2]
    reference = {"deployment": "vault"}
    deployment = DeploymentSpec(
        id="child",
        artifact="src/Child.sol:Child",
        constructor_args=(nested, reference),
        sender_slot=0,
        value_wei=0,
    )

    nested.append(3)
    reference["deployment"] = "changed"

    assert deployment.constructor_args[0] == (1, 2)
    assert deployment.constructor_args[1]["deployment"] == "vault"
    with pytest.raises(TypeError):
        deployment.constructor_args[1]["deployment"] = "changed"  # type: ignore[index]
    assert deployment.model_dump(mode="json")["constructor_args"] == [
        [1, 2],
        {"deployment": "vault"},
    ]


@pytest.mark.parametrize("field", ["rpc_url", "unexpected"])
def test_manifest_rejects_external_rpc_and_unknown_fields(
    tmp_path: Path, field: str
) -> None:
    raw = minimal_manifest(tmp_path)
    raw[field] = "https://example.invalid"
    path = write_json(tmp_path / "target.json", raw)

    with pytest.raises(ManifestError):
        load_manifest(path)


def test_manifest_rejects_path_escape(tmp_path: Path) -> None:
    raw = minimal_manifest(tmp_path)
    raw["target"]["project_root"] = "../outside"

    with pytest.raises(ManifestError, match="outside manifest directory"):
        load_manifest(write_json(tmp_path / "target.json", raw))


def test_manifest_rejects_source_path_escape(tmp_path: Path) -> None:
    raw = minimal_manifest(tmp_path)
    raw["target"]["source_files"] = ["../Outside.sol"]

    with pytest.raises(ManifestError, match="outside project root"):
        load_manifest(write_json(tmp_path / "target.json", raw))


def test_manifest_rejects_action_argument_without_domain(tmp_path: Path) -> None:
    raw = minimal_manifest(tmp_path)
    del raw["actions"][0]["arguments"][0]["domain"]

    with pytest.raises(ManifestError):
        load_manifest(write_json(tmp_path / "target.json", raw))


def test_manifest_rejects_non_state_changing_action(tmp_path: Path) -> None:
    raw = minimal_manifest(tmp_path)
    raw["actions"][0]["mutability"] = "view"

    with pytest.raises(ManifestError):
        load_manifest(write_json(tmp_path / "target.json", raw))


@pytest.mark.parametrize(
    "collection",
    ["actors", "deployments", "actions", "observations", "invariants"],
)
def test_manifest_rejects_duplicate_symbolic_ids(
    tmp_path: Path, collection: str
) -> None:
    raw = minimal_manifest(tmp_path)
    raw[collection].append(raw[collection][0].copy())

    with pytest.raises(ManifestError, match="duplicate symbolic id"):
        load_manifest(write_json(tmp_path / "target.json", raw))


@pytest.mark.parametrize(
    "signature",
    [
        "deposit(uint)",
        "deposit(address, uint256)",
        "deposit",
        "deposit(banana)",
        "deposit(uint257)",
        "deposit(uint256[)",
        "deposit(fixed)",
    ],
)
def test_manifest_rejects_noncanonical_abi_signature(
    tmp_path: Path, signature: str
) -> None:
    raw = minimal_manifest(tmp_path)
    raw["actions"][0]["signature"] = signature

    with pytest.raises(ManifestError, match="canonical ABI signature"):
        load_manifest(write_json(tmp_path / "target.json", raw))


def test_manifest_rejects_declared_argument_type_mismatch(tmp_path: Path) -> None:
    raw = minimal_manifest(tmp_path)
    raw["actions"][0]["signature"] = "deposit(address)"

    with pytest.raises(ManifestError, match="declared argument types"):
        load_manifest(write_json(tmp_path / "target.json", raw))


def test_manifest_rejects_invalid_declared_argument_type(tmp_path: Path) -> None:
    raw = minimal_manifest(tmp_path)
    raw["actions"][0]["arguments"][0]["type"] = "banana"

    with pytest.raises(ManifestError, match="canonical ABI type"):
        load_manifest(write_json(tmp_path / "target.json", raw))


def test_manifest_rejects_observation_call_arity_mismatch(tmp_path: Path) -> None:
    raw = minimal_manifest(tmp_path)
    raw["observations"][0]["signature"] = "protocolAssets(uint256)"

    with pytest.raises(ManifestError, match="observation call arity"):
        load_manifest(write_json(tmp_path / "target.json", raw))


def test_manifest_accepts_canonical_tuple_and_array_types(tmp_path: Path) -> None:
    raw = minimal_manifest(tmp_path)
    raw["actions"][0]["signature"] = "deposit((address,uint256)[],bytes32[2])"
    raw["actions"][0]["arguments"] = [
        {
            "name": "entries",
            "type": "(address,uint256)[]",
            "domain": {"kind": "finite", "values": ["fixture"]},
        },
        {
            "name": "proof",
            "type": "bytes32[2]",
            "domain": {"kind": "finite", "values": ["fixture"]},
        },
    ]

    manifest = load_manifest(write_json(tmp_path / "target.json", raw))

    assert tuple(argument.type for argument in manifest.actions[0].arguments) == (
        "(address,uint256)[]",
        "bytes32[2]",
    )


def test_manifest_rejects_no_invariants(tmp_path: Path) -> None:
    raw = minimal_manifest(tmp_path)
    raw["invariants"] = []

    with pytest.raises(ManifestError):
        load_manifest(write_json(tmp_path / "target.json", raw))


def test_manifest_rejects_observation_id_that_is_not_expression_identifier(
    tmp_path: Path,
) -> None:
    raw = minimal_manifest(tmp_path)
    raw["observations"][0]["id"] = "protocol-assets"
    raw["invariants"][0]["expression"] = "attacker_assets >= initial_attacker_assets"
    raw["impact"]["protocol_asset_observation"] = "protocol-assets"

    with pytest.raises(ManifestError):
        load_manifest(write_json(tmp_path / "target.json", raw))


def test_manifest_rejects_reserved_initial_observation_id(tmp_path: Path) -> None:
    raw = minimal_manifest(tmp_path)
    raw["observations"][0]["id"] = "initial_protocol_assets"
    raw["invariants"][0]["expression"] = (
        "initial_protocol_assets >= initial_initial_protocol_assets"
    )
    raw["impact"]["protocol_asset_observation"] = "initial_protocol_assets"

    with pytest.raises(ManifestError, match="initial_"):
        load_manifest(write_json(tmp_path / "target.json", raw))


def test_manifest_rejects_current_and_initial_observation_name_collision(
    tmp_path: Path,
) -> None:
    raw = minimal_manifest(tmp_path)
    initial_alias = raw["observations"][0].copy()
    initial_alias["id"] = "initial_protocol_assets"
    raw["observations"].append(initial_alias)

    with pytest.raises(ManifestError, match="initial_"):
        load_manifest(write_json(tmp_path / "target.json", raw))


@pytest.mark.parametrize(
    "observation_id",
    ["and", "class", "True", "False", "None"],
)
def test_manifest_rejects_observation_id_that_is_not_expression_addressable(
    tmp_path: Path, observation_id: str
) -> None:
    raw = minimal_manifest(tmp_path)
    raw["observations"][0]["id"] = observation_id
    raw["impact"]["protocol_asset_observation"] = observation_id
    if observation_id in {"True", "False", "None"}:
        raw["invariants"][0]["expression"] = (
            f"{observation_id} == initial_{observation_id}"
        )
    else:
        raw["invariants"][0]["expression"] = (
            "attacker_assets >= initial_attacker_assets"
        )

    with pytest.raises(ManifestError, match="expression identifier"):
        load_manifest(write_json(tmp_path / "target.json", raw))


def test_manifest_accepts_expression_addressable_observation_id(tmp_path: Path) -> None:
    raw = minimal_manifest(tmp_path)
    raw["observations"][0]["id"] = "protocol_total_2"
    raw["impact"]["protocol_asset_observation"] = "protocol_total_2"
    raw["invariants"][0]["expression"] = "protocol_total_2 >= initial_protocol_total_2"

    manifest = load_manifest(write_json(tmp_path / "target.json", raw))

    assert manifest.observations[0].id == "protocol_total_2"


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("max_sequence_length", 0),
        ("max_variants", -1),
        ("transaction_budget", 0),
        ("candidate_budget", 0),
        ("wall_seconds", 0),
    ],
)
def test_manifest_rejects_nonpositive_limits(
    tmp_path: Path, field: str, value: int
) -> None:
    raw = minimal_manifest(tmp_path)
    raw["limits"][field] = value

    with pytest.raises(ManifestError):
        load_manifest(write_json(tmp_path / "target.json", raw))


@pytest.mark.parametrize(
    ("collection", "field", "value"),
    [
        ("actors", "slot", False),
        ("actors", "balance_wei", "100"),
        ("deployments", "sender_slot", 0.0),
        ("deployments", "value_wei", True),
        ("actions", "max_repetitions", "2"),
    ],
)
def test_manifest_rejects_coercible_values_for_integer_fields(
    tmp_path: Path, collection: str, field: str, value: object
) -> None:
    raw = minimal_manifest(tmp_path)
    raw[collection][0][field] = value

    with pytest.raises(ManifestError):
        load_manifest(write_json(tmp_path / "target.json", raw))


@pytest.mark.parametrize(
    ("field", "value"),
    [("minimum", "0"), ("maximum", False), ("include_boundaries", 1)],
)
def test_manifest_rejects_coercible_integer_domain_scalars(
    tmp_path: Path, field: str, value: object
) -> None:
    raw = minimal_manifest(tmp_path)
    raw["actions"][0]["arguments"][0]["domain"][field] = value

    with pytest.raises(ManifestError):
        load_manifest(write_json(tmp_path / "target.json", raw))


@pytest.mark.parametrize(
    ("field", "value"),
    [("transaction_budget", 100.0), ("wall_seconds", "30")],
)
def test_manifest_rejects_coercible_search_limit_scalars(
    tmp_path: Path, field: str, value: object
) -> None:
    raw = minimal_manifest(tmp_path)
    raw["limits"][field] = value

    with pytest.raises(ManifestError):
        load_manifest(write_json(tmp_path / "target.json", raw))


@pytest.mark.parametrize("value", [False, 1.0, "1"])
def test_manifest_rejects_non_integer_call_values(
    tmp_path: Path, value: object
) -> None:
    raw = minimal_manifest(tmp_path)
    raw["actions"][0]["value_domain"]["values"] = [value]

    with pytest.raises(ManifestError):
        load_manifest(write_json(tmp_path / "target.json", raw))


def test_manifest_rejects_unknown_symbolic_references(tmp_path: Path) -> None:
    raw = minimal_manifest(tmp_path)
    raw["actions"][0]["target_id"] = "missing"

    with pytest.raises(ManifestError, match="unknown deployment"):
        load_manifest(write_json(tmp_path / "target.json", raw))


def test_published_schema_matches_model_schema() -> None:
    published = json.loads(
        Path("schemas/target-manifest.schema.json").read_text(encoding="utf-8")
    )

    assert published == TargetManifest.model_json_schema()
    assert published["additionalProperties"] is False
    assert set(published["required"]) == {
        "schema_version",
        "target",
        "actors",
        "deployments",
        "actions",
        "observations",
        "invariants",
        "limits",
    }
    assert len(published["allOf"]) == 2


def test_manifest_confirmation_policy_is_explicit_and_backward_compatible(
    tmp_path: Path,
) -> None:
    raw = minimal_manifest(tmp_path)
    economic = load_manifest(write_json(tmp_path / "economic.json", raw))
    raw = json.loads(json.dumps(raw))
    raw["confirmation"] = {"kind": "invariant_violation"}
    raw.pop("impact")
    invariant_only = load_manifest(write_json(tmp_path / "invariant.json", raw))

    assert economic.confirmation.kind == "invariant_and_economic_impact"
    assert invariant_only.confirmation.kind == "invariant_violation"
