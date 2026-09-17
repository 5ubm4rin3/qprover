"""Official TRUST404 Track 04 CLI execution loop for QProver v2."""

from __future__ import annotations

import argparse
import math
import os
import re
import sys
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from qprover.trust404 import (
    EXIT_ERROR,
    EXIT_FOUND,
    EXIT_NOT_FOUND,
    ManifestContractError,
    Track04Manifest,
    Track04SearchModel,
    build_search_model,
    render_candidate,
)
from qprover.trust404_harness import VerificationResult, verify_exploit

_NOOP_EXPLOIT = """// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

contract Exploit {
    function run(address) external payable {}
}
"""


@dataclass(slots=True)
class _AttemptLedger:
    lines: list[str]
    codes: dict[str, str]
    last_code: str = _NOOP_EXPLOIT
    winner_code: str | None = None
    attempts: int = 0
    fatal_error: bool = False


def _make_qubo_strategy():
    from qprover.search.annealing import AnnealingConfig, SimulatedAnnealingBackend
    from qprover.search.qubo import QuboStrategy

    class _Track04AnnealingBackend(SimulatedAnnealingBackend):
        def sample(self, bqm, config=None, **overrides):
            if config is not None:
                return super().sample(bqm, config=config)
            return super().sample(
                bqm,
                config=AnnealingConfig(
                    seed=int(overrides.get("seed", 0)),
                    reads=int(overrides.get("reads", 8)),
                    sweeps=64,
                ),
            )

    return QuboStrategy(
        backend=_Track04AnnealingBackend(),
        reads=8,
        feedback_batch_size=1,
        resample_attempts=1,
        max_exact_fallback_sequences=0,
    )


def _default_harness_dir() -> Path:
    configured = os.environ.get("TRUST404_HARNESS_DIR")
    if configured:
        return Path(configured).resolve()
    return Path(__file__).resolve().parents[2] / "trust404" / "harness"


def _write_outputs(out_dir: Path, ledger: _AttemptLedger) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    code = ledger.winner_code or ledger.last_code
    (out_dir / "Exploit.sol").write_text(code, encoding="utf-8")
    log = "\n".join(ledger.lines)
    (out_dir / "attempts.log").write_text(log + ("\n" if log else ""), encoding="utf-8")


def _safe_note(note: str) -> str:
    compact = " ".join(note.split())
    return compact[:240].replace("\t", " ")


def _revert_transaction_count(note: str, candidate_length: int) -> int:
    if type(candidate_length) is not int or candidate_length <= 0:
        raise ValueError("candidate_length must be a positive integer")
    match = re.fullmatch(r"revert_step=(\d+)", note)
    if match is None:
        return candidate_length
    step = int(match.group(1))
    if step >= candidate_length:
        return candidate_length
    return step + 1


def _deterministic_note(verification: VerificationResult) -> str:
    if verification.category == "forge_error":
        if re.fullmatch(r"revert_step=\d+", verification.note):
            return verification.note
        return "forge_error"
    if verification.category == "timeout":
        return "timeout"
    return _safe_note(verification.note)


def _variant_rank(variant) -> tuple[object, ...]:
    dynamic = sum(
        isinstance(argument, str) and argument.startswith("__QPROVER_")
        for argument in variant.args
    )
    self_refs = sum(argument == "__QPROVER_SELF__" for argument in variant.args)
    nonzero_integers = sum(
        type(argument) is int and argument != 0 for argument in variant.args
    )
    funded = int(variant.value_wei > 0)
    return (
        -dynamic,
        -self_refs,
        -funded,
        -nonzero_integers,
        repr(variant.args),
        variant.value_wei,
    )


def _variants_by_action(model: Track04SearchModel) -> dict[str, tuple[object, ...]]:
    grouped: dict[str, list[object]] = {action.id: [] for action in model.actions}
    for variant in model.variants:
        grouped[variant.action_id].append(variant)
    return {
        action_id: tuple(sorted(items, key=_variant_rank))
        for action_id, items in grouped.items()
    }


def _skeleton_problem(model: Track04SearchModel):
    """Build an action-level QUBO problem; parameters are completed later."""

    from qprover.parameters import ActionVariant
    from qprover.search.bqm import SearchProblem

    grouped = _variants_by_action(model)
    representatives = []
    for action in model.actions:
        choices = grouped[action.id]
        if not choices:
            raise ValueError(f"action has no Track04 variants: {action.id}")
        variant = choices[0]
        representatives.append(
            ActionVariant(
                action_id=variant.action_id,
                target_id="target",
                signature=variant.signature,
                sender_slot=0,
                args=variant.args,
                value_wei=variant.value_wei,
                max_repetitions=variant.max_repetitions,
                argument_provenance=tuple(("track04-skeleton",) for _ in variant.args),
                value_provenance=("track04-skeleton",),
            )
        )
    repetition_limits = {action.id: 2 for action in model.actions}
    discounts = tuple(1.0 / (index + 1) for index in range(model.max_sequence_length))
    return SearchProblem(
        actions=tuple(action.id for action in model.actions),
        max_sequence_length=model.max_sequence_length,
        utilities=model.utilities,
        transitions=model.transitions,
        repetition_limits=repetition_limits,
        discounts=discounts,
        variants=tuple(representatives),
        hypothesis_sequences=(),
        length_weight=0.30,
    )


def _concrete_candidates(model: Track04SearchModel, skeleton, limit: int):
    """Complete one action skeleton with a bounded deterministic parameter frontier."""

    from qprover.models import ActionStep, Candidate

    if type(limit) is not int or limit <= 0:
        return ()
    grouped = _variants_by_action(model)
    domains = tuple(grouped[step.action_id] for step in skeleton.steps)
    if any(not domain for domain in domains):
        return ()

    candidates: list[Candidate] = []
    seen: set[str] = set()

    def add(selected: tuple[object, ...]) -> bool:
        candidate = Candidate(
            tuple(
                ActionStep(
                    action_id=variant.action_id,
                    target_id="target",
                    signature=variant.signature,
                    sender_slot=0,
                    args=variant.args,
                    value_wei=variant.value_wei,
                )
                for variant in selected
            )
        )
        if candidate.canonical_id in seen:
            return False
        seen.add(candidate.canonical_id)
        candidates.append(candidate)
        return len(candidates) >= limit

    baseline = tuple(domain[0] for domain in domains)
    if add(baseline):
        return tuple(candidates)

    max_rank = max(len(domain) for domain in domains)
    for rank in range(1, max_rank):
        selected = tuple(domain[min(rank, len(domain) - 1)] for domain in domains)
        if add(selected):
            return tuple(candidates)

    for index, domain in enumerate(domains):
        for variant in domain[1:]:
            selected = list(baseline)
            selected[index] = variant
            if add(tuple(selected)):
                return tuple(candidates)
    return tuple(candidates)


def _record_attempt(
    ledger: _AttemptLedger,
    candidate,
    verification: VerificationResult,
) -> None:
    result_name = {
        "proven": "PROVEN",
        "not_proven": "NOT_PROVEN",
        "forge_error": "REVERT",
        "timeout": "TIMEOUT",
        "infrastructure": "ERROR",
        "unsupported_deploy": "ERROR",
    }.get(verification.category, verification.category.upper())
    actions = ",".join(step.action_id for step in candidate.steps)
    ledger.lines.append(
        "\t".join(
            (
                f"attempt={ledger.attempts}",
                "stage=search",
                "strategy=qubo",
                f"result={result_name}",
                f"violated={verification.violated_predicate}",
                f"candidate={candidate.canonical_id}",
                f"actions={actions}",
                f"note={_deterministic_note(verification)}",
            )
        )
    )


def _run_search(
    *,
    model: Track04SearchModel,
    target_path: Path,
    invariants_path: Path,
    manifest: Track04Manifest,
    harness_dir: Path,
    seed: int,
    attempt_budget: int,
    deadline: float,
    ledger: _AttemptLedger,
    verifier: Callable[..., VerificationResult],
    clock: Callable[[], float],
) -> bool:
    from qprover.models import Outcome, SearchLimits
    from qprover.search.base import Evaluation, candidate_is_valid
    from qprover.search.controller import SearchController

    problem = _skeleton_problem(model)
    strategy = _make_qubo_strategy()

    class Evaluator:
        def evaluate(self, skeleton):
            remaining_attempts = attempt_budget - ledger.attempts
            remaining_wall = deadline - clock()
            if remaining_attempts <= 0 or remaining_wall <= 0:
                return Evaluation(
                    outcome=Outcome.INCONCLUSIVE,
                    transaction_count=0,
                    metadata={"note": "budget"},
                )

            quota = min(2, remaining_attempts)
            candidates = _concrete_candidates(model, skeleton, quota)
            saw_pass = False
            saw_revert = False
            saw_timeout = False
            last_note = ""
            revert_count = len(skeleton.steps)
            for candidate in candidates:
                remaining_wall = deadline - clock()
                if remaining_wall <= 0 or ledger.attempts >= attempt_budget:
                    saw_timeout = True
                    break
                code = render_candidate(model, candidate)
                ledger.last_code = code
                ledger.codes[candidate.canonical_id] = code
                verification = verifier(
                    harness_dir,
                    target_path,
                    invariants_path,
                    code,
                    manifest,
                    timeout_seconds=max(1, math.ceil(remaining_wall)),
                )
                ledger.attempts += 1
                _record_attempt(ledger, candidate, verification)
                last_note = verification.note
                if verification.category in {
                    "infrastructure",
                    "unsupported_deploy",
                }:
                    ledger.fatal_error = True
                    return Evaluation(
                        outcome=Outcome.INFRA_ERROR,
                        transaction_count=0,
                        metadata={"note": verification.note},
                    )
                if verification.proven:
                    ledger.winner_code = code
                    return Evaluation(
                        outcome=Outcome.VIOLATION,
                        transaction_count=len(skeleton.steps),
                        metadata={
                            "violated_predicate": verification.violated_predicate
                        },
                    )
                if verification.category == "not_proven":
                    saw_pass = True
                elif verification.category == "forge_error":
                    saw_revert = True
                    revert_count = _revert_transaction_count(
                        verification.note, len(skeleton.steps)
                    )
                elif verification.category == "timeout":
                    saw_timeout = True

            if saw_pass:
                return Evaluation(
                    outcome=Outcome.PASS,
                    transaction_count=len(skeleton.steps),
                    metadata={"note": last_note},
                )
            if saw_revert:
                return Evaluation(
                    outcome=Outcome.REVERT,
                    transaction_count=revert_count,
                    metadata={"note": last_note},
                )
            if saw_timeout:
                return Evaluation(
                    outcome=Outcome.INCONCLUSIVE,
                    transaction_count=0,
                    metadata={"note": "timeout"},
                )
            return Evaluation(
                outcome=Outcome.INCONCLUSIVE,
                transaction_count=0,
                metadata={"note": "no-concrete-candidate"},
            )

    remaining_wall = math.floor(deadline - clock())
    if remaining_wall <= 0 or attempt_budget <= 0:
        return False
    limits = SearchLimits(
        max_sequence_length=problem.max_sequence_length,
        max_variants=max(1, len(problem.variants)),
        transaction_budget=max(1, attempt_budget * problem.max_sequence_length),
        candidate_budget=attempt_budget,
        wall_seconds=max(1, remaining_wall),
    )
    controller = SearchController(
        candidate_validator=lambda candidate: candidate_is_valid(problem, candidate)
    )
    run = controller.run(
        strategy,
        Evaluator(),
        limits,
        problem=problem,
        seed=seed,
    )
    return run.violation is not None and ledger.winner_code is not None


def run_track04(
    contract_path: Path | str,
    invariants_path: Path | str,
    manifest_path: Path | str,
    out_dir: Path | str,
    *,
    timeout_seconds: int,
    seed: int,
    max_attempts: int,
    harness_dir: Path | str | None = None,
    verifier: Callable[..., VerificationResult] = verify_exploit,
    clock: Callable[[], float] = time.monotonic,
) -> int:
    if type(timeout_seconds) is not int or timeout_seconds <= 0:
        raise ValueError("timeout_seconds must be a positive integer")
    if type(seed) is not int:
        raise ValueError("seed must be an integer")
    if type(max_attempts) is not int or max_attempts <= 0:
        raise ValueError("max_attempts must be a positive integer")

    deadline = clock() + timeout_seconds
    contract = Path(contract_path).resolve()
    invariants = Path(invariants_path).resolve()
    output = Path(out_dir).resolve()
    if not contract.is_file():
        raise FileNotFoundError(f"contract not found: {contract}")
    if not invariants.is_file():
        raise FileNotFoundError(f"invariants not found: {invariants}")
    manifest = Track04Manifest.load(manifest_path)

    remaining_analysis = math.ceil(deadline - clock())
    if remaining_analysis <= 0:
        ledger = _AttemptLedger(lines=[], codes={})
        _write_outputs(output, ledger)
        return EXIT_NOT_FOUND
    previous_analysis_timeout = os.environ.get("QPROVER_ANALYSIS_TIMEOUT")
    os.environ["QPROVER_ANALYSIS_TIMEOUT"] = str(remaining_analysis)
    try:
        model = build_search_model(contract, invariants, manifest)
    finally:
        if previous_analysis_timeout is None:
            os.environ.pop("QPROVER_ANALYSIS_TIMEOUT", None)
        else:
            os.environ["QPROVER_ANALYSIS_TIMEOUT"] = previous_analysis_timeout

    ledger = _AttemptLedger(lines=[], codes={})
    if not model.actions or deadline - clock() <= 0:
        _write_outputs(output, ledger)
        return EXIT_NOT_FOUND

    hdir = (
        Path(harness_dir).resolve()
        if harness_dir is not None
        else _default_harness_dir()
    )
    if _run_search(
        model=model,
        target_path=contract,
        invariants_path=invariants,
        manifest=manifest,
        harness_dir=hdir,
        seed=seed,
        attempt_budget=max_attempts,
        deadline=deadline,
        ledger=ledger,
        verifier=verifier,
        clock=clock,
    ):
        _write_outputs(output, ledger)
        return EXIT_FOUND
    _write_outputs(output, ledger)
    return EXIT_ERROR if ledger.fatal_error else EXIT_NOT_FOUND


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="qprover-trust404")
    parser.add_argument("--contract", required=True)
    parser.add_argument("--invariants", required=True)
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--timeout", type=int, required=True)
    parser.add_argument("--seed", type=int, required=True)
    parser.add_argument("--max-attempts", type=int, required=True, dest="max_attempts")
    return parser


def main(argv: list[str] | None = None) -> int:
    try:
        args = _parser().parse_args(argv)
        return run_track04(
            args.contract,
            args.invariants,
            args.manifest,
            args.out,
            timeout_seconds=args.timeout,
            seed=args.seed,
            max_attempts=args.max_attempts,
        )
    except (ManifestContractError, OSError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        return EXIT_ERROR
    except Exception as error:  # fail-closed CLI boundary
        print(f"error: internal {type(error).__name__}: {error}", file=sys.stderr)
        return EXIT_ERROR


if __name__ == "__main__":
    raise SystemExit(main())
