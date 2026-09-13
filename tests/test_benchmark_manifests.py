"""Structural guardrails for the label-neutral educational benchmark suite."""

from __future__ import annotations

import json
from pathlib import Path

from qprover.manifest import load_manifest
from qprover.models import TargetManifest

ROOT = Path(__file__).resolve().parents[1]
BENCHMARKS = ROOT / "benchmarks"
MANIFESTS = BENCHMARKS / "manifests"
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
    return tuple(sorted(MANIFESTS.glob("*.json")))


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
        assert tuple(
            observation.model_dump(mode="json") for observation in first.observations
        ) == tuple(
            observation.model_dump(mode="json") for observation in second.observations
        )
        assert first.limits == second.limits
        assert first.invariants == second.invariants
        assert first.impact == second.impact


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
