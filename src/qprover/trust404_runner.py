"""Official TRUST404 Track 04 CLI execution loop for QProver v2."""

from __future__ import annotations

import argparse
import math
import os
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
    to_qprover_problem,
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


def _deterministic_note(verification: VerificationResult) -> str:
    if verification.category == "forge_error":
        return "forge_error"
    if verification.category == "timeout":
        return "timeout"
    return _safe_note(verification.note)


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

    problem = to_qprover_problem(model)
    strategy = _make_qubo_strategy()

    class Evaluator:
        def evaluate(self, candidate):
            code = render_candidate(model, candidate)
            ledger.last_code = code
            ledger.codes[candidate.canonical_id] = code
            remaining_wall = deadline - clock()
            if remaining_wall <= 0:
                return Evaluation(
                    outcome=Outcome.INCONCLUSIVE,
                    transaction_count=0,
                    metadata={"note": "timeout"},
                )
            verification = verifier(
                harness_dir,
                target_path,
                invariants_path,
                code,
                manifest,
                timeout_seconds=max(1, math.ceil(remaining_wall)),
            )
            ledger.attempts += 1
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
            if verification.category in {"infrastructure", "unsupported_deploy"}:
                ledger.fatal_error = True
            if verification.proven:
                ledger.winner_code = code
                return Evaluation(
                    outcome=Outcome.VIOLATION,
                    transaction_count=len(candidate.steps),
                    metadata={"violated_predicate": verification.violated_predicate},
                )
            if verification.category == "not_proven":
                return Evaluation(
                    outcome=Outcome.PASS,
                    transaction_count=len(candidate.steps),
                    metadata={"note": verification.note},
                )
            if verification.category == "forge_error":
                return Evaluation(
                    outcome=Outcome.REVERT,
                    transaction_count=max(1, len(candidate.steps)),
                    metadata={"note": verification.note},
                )
            if verification.category == "timeout":
                return Evaluation(
                    outcome=Outcome.INCONCLUSIVE,
                    transaction_count=0,
                    metadata={"note": verification.note},
                )
            return Evaluation(
                outcome=Outcome.INFRA_ERROR,
                transaction_count=0,
                metadata={"note": verification.note},
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

    contract = Path(contract_path).resolve()
    invariants = Path(invariants_path).resolve()
    output = Path(out_dir).resolve()
    if not contract.is_file():
        raise FileNotFoundError(f"contract not found: {contract}")
    if not invariants.is_file():
        raise FileNotFoundError(f"invariants not found: {invariants}")
    manifest = Track04Manifest.load(manifest_path)
    model = build_search_model(contract, invariants, manifest)
    ledger = _AttemptLedger(lines=[], codes={})
    if not model.actions:
        _write_outputs(output, ledger)
        return EXIT_NOT_FOUND

    hdir = (
        Path(harness_dir).resolve()
        if harness_dir is not None
        else _default_harness_dir()
    )
    deadline = clock() + timeout_seconds
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
