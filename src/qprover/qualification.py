"""One manifest-bound predicate for executable violation qualification."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class ViolationQualification:
    qualified: bool
    policy: str
    invariant_id: str | None
    reason: str

    def to_dict(self) -> dict[str, object]:
        return {
            "qualified": self.qualified,
            "policy": self.policy,
            "invariant_id": self.invariant_id,
            "reason": self.reason,
        }


def qualify_violation(
    *,
    policy: str,
    invariant_ids: Sequence[str],
    baseline: Sequence[Mapping[str, object]],
    current: Sequence[Mapping[str, object]],
    impact: Mapping[str, object],
) -> ViolationQualification:
    """Require baseline-true to final-false for one manifest-ordered invariant."""

    if policy not in {
        "invariant_and_economic_impact",
        "invariant_violation",
    }:
        return ViolationQualification(False, policy, None, "unsupported policy")
    baseline_by_id = {
        item.get("invariant_id"): item
        for item in baseline
        if isinstance(item.get("invariant_id"), str)
    }
    current_by_id = {
        item.get("invariant_id"): item
        for item in current
        if isinstance(item.get("invariant_id"), str)
    }
    if (
        len(baseline) != len(invariant_ids)
        or len(current) != len(invariant_ids)
        or len(baseline_by_id) != len(invariant_ids)
        or len(current_by_id) != len(invariant_ids)
        or set(baseline_by_id) != set(invariant_ids)
        or set(current_by_id) != set(invariant_ids)
    ):
        return ViolationQualification(False, policy, None, "invariant set mismatch")
    for invariant_id in invariant_ids:
        record = baseline_by_id[invariant_id]
        if record.get("status") != "evaluated" or record.get("value") is not True:
            return ViolationQualification(
                False, policy, None, f"baseline invariant is not true: {invariant_id}"
            )
    selected = next(
        (
            invariant_id
            for invariant_id in invariant_ids
            if current_by_id[invariant_id].get("status") == "evaluated"
            and current_by_id[invariant_id].get("value") is False
        ),
        None,
    )
    if selected is None:
        return ViolationQualification(False, policy, None, "no true-to-false invariant")
    if (
        policy == "invariant_and_economic_impact"
        and impact.get("admissible") is not True
    ):
        return ViolationQualification(
            False, policy, selected, "economic impact is not admissible"
        )
    return ViolationQualification(True, policy, selected, "policy satisfied")


__all__ = ["ViolationQualification", "qualify_violation"]
