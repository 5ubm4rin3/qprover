"""Deterministic benchmark summaries and conservative statistics."""

from __future__ import annotations

import hashlib
import json
import math
from collections import defaultdict
from collections.abc import Sequence
from pathlib import Path

from qprover.benchmark import (
    BenchmarkConfig,
    BenchmarkMatrix,
    BenchmarkRun,
    BenchmarkScore,
    BenchmarkSuite,
    expected_run_keys,
)
from qprover.safeio import safe_atomic_write


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _canonical(value: object) -> str:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )


def _semantic_rows_sha(rows: Sequence[BenchmarkRun | BenchmarkScore]) -> str:
    ordered = sorted(rows, key=lambda item: item.run_key)
    payload = "".join(
        _canonical(item.model_dump(mode="json")) + "\n" for item in ordered
    )
    return hashlib.sha256(payload.encode()).hexdigest()


def _binomial_cdf(k: int, n: int, probability: float) -> float:
    from math import comb

    return math.fsum(
        comb(n, i) * probability**i * (1.0 - probability) ** (n - i)
        for i in range(k + 1)
    )


def _binomial_upper_tail(k: int, n: int, probability: float) -> float:
    from math import comb

    return math.fsum(
        comb(n, i) * probability**i * (1.0 - probability) ** (n - i)
        for i in range(k, n + 1)
    )


def _bisect_increasing(function, target: float) -> float:
    low = 0.0
    high = 1.0
    for _ in range(80):
        middle = (low + high) / 2.0
        if function(middle) < target:
            low = middle
        else:
            high = middle
    return (low + high) / 2.0


def _bisect_decreasing(function, target: float) -> float:
    low = 0.0
    high = 1.0
    for _ in range(80):
        middle = (low + high) / 2.0
        if function(middle) > target:
            low = middle
        else:
            high = middle
    return (low + high) / 2.0


def clopper_pearson(
    successes: int,
    total: int,
    alpha: float = 0.05,
) -> tuple[float, float]:
    """Return a two-sided exact Clopper-Pearson binomial interval."""

    if (
        type(successes) is not int
        or type(total) is not int
        or total <= 0
        or not 0 <= successes <= total
    ):
        raise ValueError(
            "successes/total must be exact integers with 0 <= successes <= total"
        )
    if type(alpha) is not float or not 0.0 < alpha < 1.0:
        raise ValueError("alpha must be a float strictly between zero and one")

    lower = 0.0
    if successes > 0:
        lower = _bisect_increasing(
            lambda probability: _binomial_upper_tail(
                successes,
                total,
                probability,
            ),
            alpha / 2.0,
        )

    upper = 1.0
    if successes < total:
        upper = _bisect_decreasing(
            lambda probability: _binomial_cdf(
                successes,
                total,
                probability,
            ),
            alpha / 2.0,
        )
    return lower, upper


def _rate(successes: int, total: int) -> dict[str, object]:
    if total == 0:
        return {
            "successes": 0,
            "total": 0,
            "rate": None,
            "ci95": None,
        }
    low, high = clopper_pearson(successes, total)
    return {
        "successes": successes,
        "total": total,
        "rate": successes / total,
        "ci95": [low, high],
    }


def _restricted_mean_time(
    observations: Sequence[tuple[float, bool]],
    horizon: float,
) -> float:
    """Kaplan-Meier restricted mean time to first accepted search hit."""

    if not observations:
        raise ValueError("restricted mean requires at least one observation")
    if type(horizon) is not float or not math.isfinite(horizon) or horizon < 0:
        raise ValueError("restricted mean horizon must be finite and nonnegative")
    normalized: list[tuple[float, bool]] = []
    for duration, event in observations:
        if (
            type(duration) is not float
            or not math.isfinite(duration)
            or duration < 0
            or type(event) is not bool
        ):
            raise ValueError(
                "restricted mean observations must be finite durations/events"
            )
        normalized.append((duration, event))
    if max(duration for duration, _ in normalized) < horizon:
        raise ValueError("restricted mean horizon exceeds observed follow-up")

    risk = len(normalized)
    survival = 1.0
    area = 0.0
    previous = 0.0
    by_time: dict[float, list[bool]] = defaultdict(list)
    for duration, event in normalized:
        by_time[duration].append(event)
    for duration in sorted(by_time):
        if duration > horizon:
            break
        area += survival * (duration - previous)
        events = sum(by_time[duration])
        censored = len(by_time[duration]) - events
        if events:
            survival *= 1.0 - events / risk
        risk -= events + censored
        previous = duration
        if duration == horizon:
            return area
    if previous < horizon:
        area += survival * (horizon - previous)
    return area


def _known_sum(rows: Sequence[BenchmarkRun], field: str) -> dict[str, int]:
    values = [getattr(row, field) for row in rows]
    known = [value for value in values if value is not None]
    return {
        "known_total": sum(known),
        "known_cells": len(known),
        "unknown_cells": len(values) - len(known),
    }


def _strategy_solver_totals(rows: Sequence[BenchmarkRun]) -> dict[str, object]:
    calls = reads = sweeps = 0
    fallback_calls = 0
    max_bits = 0
    max_couplers = 0
    seconds = 0.0
    fallback_seconds = 0.0
    unavailable = 0
    for row in rows:
        evidence = row.strategy_evidence
        if evidence.kind == "qubo":
            calls += evidence.solver_calls
            reads += evidence.reads
            sweeps += evidence.sweeps
            seconds += evidence.solver_seconds
            fallback_calls += evidence.fallback_calls
            fallback_seconds += evidence.fallback_seconds
            max_bits = max(max_bits, evidence.max_logical_bits)
            max_couplers = max(max_couplers, evidence.max_couplers)
        elif evidence.kind == "qubo_unavailable":
            unavailable += 1
    return {
        "calls": calls,
        "reads": reads,
        "sweeps": sweeps,
        "seconds": seconds,
        "fallback_calls": fallback_calls,
        "fallback_seconds": fallback_seconds,
        "max_logical_bits": max_bits,
        "max_couplers": max_couplers,
        "unavailable_cells": unavailable,
    }


def _fixture_balanced_macro(
    by_strategy: dict[str, list[BenchmarkRun]],
    score_by_key: dict[str, BenchmarkScore],
) -> dict[str, dict[str, float | None]]:
    result: dict[str, dict[str, float | None]] = {}
    for strategy, rows in sorted(by_strategy.items()):
        by_target: dict[str, list[BenchmarkRun]] = defaultdict(list)
        for row in rows:
            by_target[row.public_target_id].append(row)

        target_correct: list[float] = []
        target_confirmed: list[float] = []
        for target_rows in by_target.values():
            scores = [score_by_key[row.run_key] for row in target_rows]
            target_correct.append(sum(score.correct for score in scores) / len(scores))
            target_confirmed.append(
                sum(row.confirmation_status.value == "CONFIRMED" for row in target_rows)
                / len(target_rows)
            )
        result[strategy] = {
            "target_correct_rate_mean": (
                math.fsum(target_correct) / len(target_correct)
                if target_correct
                else None
            ),
            "target_confirmed_rate_mean": (
                math.fsum(target_confirmed) / len(target_confirmed)
                if target_confirmed
                else None
            ),
        }
    return result


def build_completeness_report(
    *,
    matrix: BenchmarkMatrix,
    suite: BenchmarkSuite,
    config: BenchmarkConfig,
    runs: Sequence[BenchmarkRun],
) -> dict[str, object]:
    """Build a label-free deterministic report for an incomplete matrix."""

    expected = set(expected_run_keys(matrix, suite, config))
    by_key = {row.run_key: row for row in runs}
    if len(by_key) != len(runs):
        raise ValueError("completeness report contains duplicate run keys")
    unknown = set(by_key) - expected
    if unknown:
        raise ValueError("completeness report contains unexpected run keys")
    incomplete_rows = sorted(row.run_key for row in runs if row.state == "incomplete")
    missing = sorted(expected - set(by_key))
    terminal = sum(row.state in {"completed", "failed"} for row in runs)
    return {
        "schema_version": "1.0",
        "kind": "label_free_completeness",
        "matrix_id": matrix.matrix_id,
        "complete": not missing and not incomplete_rows and terminal == len(expected),
        "expected_cells": len(expected),
        "recorded_cells": len(runs),
        "terminal_cells": terminal,
        "missing_run_keys": missing,
        "incomplete_run_keys": incomplete_rows,
        "runs_semantic_sha256": _semantic_rows_sha(runs),
        "labels_accessed": False,
    }


def write_completeness_report(
    report: dict[str, object],
    json_path: Path,
    markdown_path: Path,
) -> tuple[Path, Path]:
    if report.get("kind") != "label_free_completeness":
        raise ValueError("not a label-free completeness report")
    payload = json.dumps(report, sort_keys=True, indent=2, allow_nan=False) + "\n"
    safe_atomic_write(json_path, payload)
    lines = [
        "# QProver Benchmark Completeness",
        "",
        f"Matrix: `{report['matrix_id']}`",
        "",
        "This report is label-free; scorer labels were not opened.",
        "",
        f"Recorded: {report['recorded_cells']}/{report['expected_cells']}",
        f"Terminal: {report['terminal_cells']}/{report['expected_cells']}",
        f"Complete: {str(report['complete']).lower()}",
        "",
    ]
    safe_atomic_write(markdown_path, "\n".join(lines))
    return json_path, markdown_path


def _reproduction_argument(path: Path) -> str:
    """Return a stable workspace-relative benchmark path when possible."""

    resolved = path.resolve()
    parts = resolved.parts
    benchmark_positions = [
        index for index, part in enumerate(parts) if part == "benchmarks"
    ]
    if benchmark_positions:
        return "/".join(parts[benchmark_positions[-1] :])
    return resolved.as_posix()


def build_report(
    *,
    matrix: BenchmarkMatrix,
    runs: Sequence[BenchmarkRun],
    scores: Sequence[BenchmarkScore],
    suite_path: Path,
    config_path: Path,
    runs_path: Path,
    scores_path: Path,
    labels_path: Path,
) -> dict[str, object]:
    """Build a byte-order-independent report from validated benchmark rows."""

    del runs_path, scores_path
    score_by_key = {score.run_key: score for score in scores}
    if set(score_by_key) != {row.run_key for row in runs}:
        raise ValueError("report inputs do not describe the same benchmark cells")

    by_strategy: dict[str, list[BenchmarkRun]] = defaultdict(list)
    by_target: dict[str, list[BenchmarkRun]] = defaultdict(list)
    for row in runs:
        by_strategy[row.strategy].append(row)
        by_target[row.public_target_id].append(row)

    followup_maxima = []
    for rows in by_strategy.values():
        observed = [
            row.timings.search_seconds
            for row in rows
            if row.state == "completed" and row.timings.search_seconds is not None
        ]
        if observed:
            followup_maxima.append(max(observed))
    common_horizon = min(followup_maxima) if followup_maxima else None

    strategies: dict[str, object] = {}
    for name, unsorted_rows in sorted(by_strategy.items()):
        rows = sorted(unsorted_rows, key=lambda row: row.run_key)
        scored = [score_by_key[row.run_key] for row in rows]
        positives = [
            (row, score)
            for row, score in zip(rows, scored, strict=True)
            if score.expected == "positive"
        ]
        negatives = [
            (row, score)
            for row, score in zip(rows, scored, strict=True)
            if score.expected == "negative"
        ]
        executed = sum(row.executed_violation is True for row in rows)
        accepted_hits = sum(row.search_hit is True for row in rows)
        confirmed = sum(row.confirmation_status.value == "CONFIRMED" for row in rows)
        false_confirmed = sum(score.false_confirmed for _, score in negatives)
        cold = sum(
            row.confirmation_status.value == "CONFIRMED" and row.cold_replays == 3
            for row in rows
        )
        proof_attempts = sum(row.proof_attempted is True for row in rows)
        failures = sum(row.state == "failed" for row in rows)
        incomplete = sum(row.state == "incomplete" for row in rows)
        censored = [
            row
            for row in rows
            if row.state == "completed" and row.hit_observation == "censored"
        ]
        success_times = [
            row.timings.search_seconds
            for row in rows
            if row.search_hit is True and row.timings.search_seconds is not None
        ]
        time_observations = [
            (row.timings.search_seconds, row.search_hit is True)
            for row in rows
            if row.state == "completed" and row.timings.search_seconds is not None
        ]
        strategies[name] = {
            "scheduled": len(rows),
            "completed": sum(row.state == "completed" for row in rows),
            "failures": failures,
            "incomplete": incomplete,
            "executed_violation": _rate(executed, len(rows)),
            "accepted_search_hit": _rate(accepted_hits, len(rows)),
            "proof_attempted": _rate(proof_attempts, len(rows)),
            "confirmed": _rate(confirmed, len(rows)),
            "positive_confirmed": _rate(
                sum(
                    row.confirmation_status.value == "CONFIRMED" for row, _ in positives
                ),
                len(positives),
            ),
            "negative_false_confirmed": _rate(
                false_confirmed,
                len(negatives),
            ),
            "cold_replay_confirmed": _rate(cold, len(rows)),
            "censored_misses": len(censored),
            "search_time_success_conditional_mean": (
                math.fsum(success_times) / len(success_times) if success_times else None
            ),
            "search_time_common_horizon_seconds": common_horizon,
            "search_time_rmst_common_horizon": (
                _restricted_mean_time(time_observations, common_horizon)
                if time_observations and common_horizon is not None
                else None
            ),
            "totals": {
                "candidates": _known_sum(rows, "candidates_evaluated"),
                "duplicate_proposals": _known_sum(rows, "duplicate_proposals"),
                "unique_trace_features": _known_sum(rows, "unique_trace_features"),
                "search_transactions": _known_sum(
                    rows,
                    "search_transactions",
                ),
                "minimized_steps": _known_sum(rows, "minimized_steps"),
                "reverts": sum(row.outcome_counts.get("REVERT", 0) for row in rows),
                "solver": _strategy_solver_totals(rows),
            },
        }

    targets: dict[str, object] = {}
    for target, unsorted_rows in sorted(by_target.items()):
        rows = sorted(unsorted_rows, key=lambda row: row.run_key)
        scored = [score_by_key[row.run_key] for row in rows]
        targets[target] = {
            "scheduled": len(rows),
            "correct": _rate(
                sum(score.correct for score in scored),
                len(scored),
            ),
            "confirmed": _rate(
                sum(row.confirmation_status.value == "CONFIRMED" for row in rows),
                len(rows),
            ),
            "failures": sum(row.state == "failed" for row in rows),
        }

    families: dict[
        tuple[str, str, int],
        dict[str, BenchmarkScore],
    ] = defaultdict(dict)
    for score in scores:
        families[(score.family, score.strategy, score.seed)][score.pair] = score
    pair_counts: dict[str, list[int]] = defaultdict(lambda: [0, 0])
    for (_, strategy, _), pair in families.items():
        if "a" not in pair or "b" not in pair:
            continue
        pair_counts[strategy][1] += 1
        if pair["a"].correct and pair["b"].correct:
            pair_counts[strategy][0] += 1
    pair_correct = {
        name: _rate(values[0], values[1])
        for name, values in sorted(pair_counts.items())
    }

    strategy_family_counts: dict[
        tuple[str, str],
        dict[str, int],
    ] = defaultdict(
        lambda: {
            "positive_total": 0,
            "positive_confirmed": 0,
            "negative_total": 0,
            "negative_false_confirmed": 0,
        }
    )
    for score in scores:
        counts = strategy_family_counts[(score.strategy, score.family)]
        if score.expected == "positive":
            counts["positive_total"] += 1
            counts["positive_confirmed"] += int(score.predicted == "positive")
        else:
            counts["negative_total"] += 1
            counts["negative_false_confirmed"] += int(score.predicted == "positive")

    strategy_family: dict[str, dict[str, object]] = defaultdict(dict)
    for (strategy, family), counts in sorted(strategy_family_counts.items()):
        strategy_family[strategy][family] = {
            "positive_confirmed": _rate(
                counts["positive_confirmed"],
                counts["positive_total"],
            ),
            "negative_false_confirmed": _rate(
                counts["negative_false_confirmed"],
                counts["negative_total"],
            ),
        }

    matrix_payload = _canonical(matrix.model_dump(mode="json")) + "\n"
    return {
        "schema_version": "1.0",
        "matrix_id": matrix.matrix_id,
        "hashes": {
            "suite_file": _sha(suite_path),
            "suite_semantic": matrix.suite_sha256,
            "config_file": _sha(config_path),
            "config_semantic": matrix.config_sha256,
            "matrix": hashlib.sha256(matrix_payload.encode()).hexdigest(),
            "runs_semantic": _semantic_rows_sha(runs),
            "scores_semantic": _semantic_rows_sha(scores),
            "labels": _sha(labels_path),
        },
        "toolchain": matrix.toolchain.model_dump(mode="json"),
        "strategies": strategies,
        "targets": targets,
        "fixture_balanced_macro": _fixture_balanced_macro(
            by_strategy,
            score_by_key,
        ),
        "family_pair_correct": pair_correct,
        "strategy_family": strategy_family,
        "methodology": {
            "seed_semantics": (
                "Deterministic policies must agree across repeated ignored "
                "seeds; stochastic seeds are nested within fixture families."
            ),
            "censoring": (
                "Budget stops and unproven solver exhaustion are "
                "right-censored at actual observed spend; infrastructure and "
                "nondeterminism failures remain separately visible."
            ),
            "limits": (
                "MicroBench is a small, synthetic, public, white-box paired "
                "suite. Related twins are not independent. Optimization "
                "weights must not be tuned on reported evaluation cells. "
                "Results establish neither broad real-world exploit discovery "
                "nor quantum advantage."
            ),
        },
        "reproduce": (
            f"uv run qprover benchmark --suite {_reproduction_argument(suite_path)} "
            f"--config {_reproduction_argument(config_path)} --workspace . "
            "--out <output> && "
            "uv run qprover report --input <output> "
            f"--suite {_reproduction_argument(suite_path)} "
            f"--config {_reproduction_argument(config_path)} "
            f"--labels {_reproduction_argument(labels_path)}"
        ),
    }


def write_report(
    report: dict[str, object],
    json_path: Path,
    markdown_path: Path,
) -> tuple[Path, Path]:
    json_payload = (
        json.dumps(
            report,
            sort_keys=True,
            indent=2,
            allow_nan=False,
        )
        + "\n"
    )
    safe_atomic_write(json_path, json_payload)

    methodology = report["methodology"]
    strategies = report["strategies"]
    if not isinstance(methodology, dict) or not isinstance(strategies, dict):
        raise ValueError("report has invalid summary structure")
    lines = [
        "# QProver MicroBench Report",
        "",
        f"Matrix: `{report['matrix_id']}`",
        "",
        str(methodology["limits"]),
        "",
        "## Strategy summary",
        "",
        ("| Strategy | Scheduled | Confirmed | False-confirmed | Censored |"),
        "|---|---:|---:|---:|---:|",
    ]
    for name, raw in sorted(strategies.items()):
        if not isinstance(raw, dict):
            raise ValueError("strategy report entry must be an object")
        confirmed = raw["confirmed"]
        false_confirmed = raw["negative_false_confirmed"]
        if not isinstance(confirmed, dict) or not isinstance(
            false_confirmed,
            dict,
        ):
            raise ValueError("strategy rate entry must be an object")
        lines.append(
            f"| {name} | {raw['scheduled']} | "
            f"{confirmed['successes']}/{confirmed['total']} | "
            f"{false_confirmed['successes']}/{false_confirmed['total']} | "
            f"{raw['censored_misses']} |"
        )
    family_summary = report.get("strategy_family", {})
    if not isinstance(family_summary, dict):
        raise ValueError("strategy-family report entry must be an object")

    lines.extend(
        [
            "",
            "## Strategy × family",
            "",
            "| Strategy | Family | Positive confirmed | Negative false-confirmed |",
            "|---|---|---:|---:|",
        ]
    )
    for strategy, families in sorted(family_summary.items()):
        if not isinstance(families, dict):
            raise ValueError("strategy-family entry must be an object")
        for family, raw in sorted(families.items()):
            if not isinstance(raw, dict):
                raise ValueError("strategy-family rate entry must be an object")
            positive = raw["positive_confirmed"]
            negative = raw["negative_false_confirmed"]
            if not isinstance(positive, dict) or not isinstance(negative, dict):
                raise ValueError("strategy-family rate must be an object")
            lines.append(
                f"| {strategy} | {family} | "
                f"{positive['successes']}/{positive['total']} | "
                f"{negative['successes']}/{negative['total']} |"
            )

    lines.extend(
        [
            "",
            "## Reproduction",
            "",
            f"`{report['reproduce']}`",
            "",
        ]
    )
    safe_atomic_write(markdown_path, "\n".join(lines))
    return json_path, markdown_path
