"""Structural guardrails for the label-neutral educational benchmark suite."""

from __future__ import annotations

import json
from pathlib import Path

from qprover.analysis import analyze
from qprover.artifacts import build_target
from qprover.graph import build_program_graph
from qprover.hypotheses import generate_hypotheses
from qprover.manifest import load_manifest
from qprover.models import TargetManifest
from qprover.parameters import expand_action_variants

ROOT = Path(__file__).resolve().parents[1]
BENCHMARKS = ROOT / "benchmarks"
MANIFESTS = BENCHMARKS
FORBIDDEN = ("vulnerable", "sound", "safe", "fixed", "exploit")
FAMILIES = (
    "access_control",
    "reentrancy",
    "side_entrance",
    "oracle",
    "governance",
    "signature_replay",
)


def _manifest_paths() -> tuple[Path, ...]:
    return tuple(sorted(MANIFESTS.glob("scenario_*.json")))


def _normalized_actions(manifest: TargetManifest) -> tuple[object, ...]:
    actions = manifest.actions
    return tuple(
        (
            action.id,
            action.signature,
            action.mutability,
            action.sender_slots,
            tuple(
                (
                    argument.name,
                    argument.type,
                    argument.domain.model_dump(mode="json"),
                )
                for argument in action.arguments
            ),
            action.value_domain.model_dump(mode="json"),
            action.max_repetitions,
        )
        for action in actions
    )


def test_suite_contains_exactly_twelve_label_neutral_manifests() -> None:
    paths = _manifest_paths()

    assert len(paths) == 12
    manifests = tuple(load_manifest(path) for path in paths)
    target_ids = {manifest.target.id for manifest in manifests}
    assert len(target_ids) == 12
    assert {path.stem.rsplit("_", 1)[0] for path in paths} == {
        f"scenario_{family}" for family in FAMILIES
    }
    for path, manifest in zip(paths, manifests, strict=True):
        public_text = " ".join(
            (
                path.name,
                manifest.target.id,
                *(invariant.description for invariant in manifest.invariants),
            )
        ).lower()
        assert not any(term in public_text for term in FORBIDDEN)
        assert manifest.target.id == path.stem
        assert len(manifest.actions) >= 4


def test_twins_have_identical_public_search_contracts() -> None:
    for family in FAMILIES:
        first = load_manifest(MANIFESTS / f"scenario_{family}_a.json")
        second = load_manifest(MANIFESTS / f"scenario_{family}_b.json")

        assert _normalized_actions(first) == _normalized_actions(second)
        assert first.actors == second.actors
        assert first.actions == second.actions
        assert tuple(
            observation.model_dump(mode="json") for observation in first.observations
        ) == tuple(
            observation.model_dump(mode="json") for observation in second.observations
        )
        assert first.limits == second.limits
        assert first.invariants == second.invariants
        assert first.impact == second.impact


def test_attacker_impact_is_the_authoritative_eoa_native_balance() -> None:
    for path in _manifest_paths():
        manifest = load_manifest(path)
        attacker_observation = next(
            observation
            for observation in manifest.observations
            if observation.id == "attacker_assets"
        )

        assert attacker_observation.id == "attacker_assets"
        assert attacker_observation.kind == "native_balance"
        assert attacker_observation.actor_id == "attacker"
        assert attacker_observation.target_id is None
        assert attacker_observation.signature is None
        assert manifest.impact.attacker_asset_observation == "attacker_assets"


def test_oracle_pair_requires_the_same_exact_collateral() -> None:
    for variant in "ab":
        manifest = load_manifest(MANIFESTS / f"scenario_oracle_{variant}.json")
        borrow = next(action for action in manifest.actions if action.id == "step_beta")

        assert borrow.value_domain.model_dump(mode="json") == {
            "kind": "finite",
            "values": [10**18],
        }


def test_labels_and_known_sequences_are_scorer_only() -> None:
    labels_path = BENCHMARKS / "labels.json"
    labels = json.loads(labels_path.read_text(encoding="utf-8"))

    assert set(labels) == {
        f"scenario_{family}_{variant}" for family in FAMILIES for variant in "ab"
    }
    assert {entry["expected"] for entry in labels.values()} == {"positive", "negative"}
    assert all("witness" in entry for entry in labels.values())
    for path in _manifest_paths():
        raw = path.read_text(encoding="utf-8").lower()
        assert "witness" not in raw
        assert "expected" not in raw
        assert "positive" not in raw
        assert "negative" not in raw


def test_every_benchmark_manifest_has_a_production_analysis_closure() -> None:
    expected_hypotheses = {
        "access_control": ("authorization-writer-to-guarded-value-sink",),
        "governance": ("authorization-writer-to-guarded-value-sink",),
        "oracle": ("public-value-sink-with-weak-or-unknown-guard",),
        "side_entrance": ("public-value-sink-with-weak-or-unknown-guard",),
        "signature_replay": ("public-value-sink-with-weak-or-unknown-guard",),
    }
    built_targets: list[str] = []
    for path in _manifest_paths():
        manifest = load_manifest(path)
        with build_target(manifest) as bundle:
            built_targets.append(manifest.target.id)
            assert bundle.closed is False
            assert all(not source.startswith("test/") for source in bundle.source_names)
            assert all("labels" not in source for source in bundle.source_names)
            assert set(bundle.source_names) == {
                manifest.deployments[0].artifact.rsplit(":", 1)[0],
                "src/IQProverScenario.sol",
            }
            report = analyze(bundle)
            graph = build_program_graph(report)
            assert graph.nodes
            assert expand_action_variants(manifest, report)
            hypotheses = generate_hypotheses(graph, manifest)
            family = manifest.target.id.removeprefix("scenario_").rsplit("_", 1)[0]
            if family == "reentrancy":
                # The current static lead rules do not model the dynamically created
                # callback actor, so the executable reentrancy pair intentionally has
                # no static hypothesis. Ground-truth Foundry witnesses cover it.
                assert hypotheses == ()
            else:
                assert tuple(hypothesis.kind for hypothesis in hypotheses) == (
                    expected_hypotheses[family]
                )
        assert bundle.closed is True

    assert built_targets == [path.stem for path in _manifest_paths()]
    assert len(built_targets) == 12
