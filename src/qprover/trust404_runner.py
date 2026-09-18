"""Official TRUST404 Track 04 CLI execution loop for QProver v2."""

from __future__ import annotations

import argparse
import json
import math
import os
import re
import sys
import time
from collections.abc import Callable
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace

from qprover.evm import LocalAnvil
from qprover.minimizer import MinimizationError, minimize_track04_candidate
from qprover.trust404 import (
    ADDRESS_REF_PREFIX,
    EXIT_ERROR,
    EXIT_FOUND,
    EXIT_NOT_FOUND,
    OTHER_ADDRESS,
    SELF_ADDRESS,
    TARGET_ADDRESS,
    UINT_REF_PREFIX,
    ManifestContractError,
    Track04Manifest,
    Track04SearchModel,
    build_search_model,
    render_candidate,
)
from qprover.trust404_frontier import PortfolioStrategy, SearchState, StateFrontier
from qprover.trust404_harness import VerificationResult, verify_exploit
from qprover.trust404_runtime import (
    RuntimeCall,
    RuntimeCandidateRevert,
    deploy_runtime_from_artifacts,
)
from qprover.trust404_values import (
    Add,
    Const,
    ContractAddress,
    Max,
    Min,
    PreviousReturn,
    ReadUint,
    Scale,
    SelfAddress,
    Sub,
    TargetAddress,
    complete_parameters,
)

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
    winner_candidate: object | None = None
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


def _make_portfolio_strategy(seed: int, *, include_qubo: bool = True):
    from qprover.search.coverage import CoverageGuidedStrategy
    from qprover.search.risk import RiskGuidedStrategy

    planners = {
        "best_first": RiskGuidedStrategy(beam_width=24),
        "coverage": CoverageGuidedStrategy(proposal_attempts=96),
    }
    if include_qubo:
        planners["qubo"] = _make_qubo_strategy()
    return PortfolioStrategy(planners, seed=seed)


def _default_harness_dir() -> Path:
    configured = os.environ.get("TRUST404_HARNESS_DIR")
    if configured:
        return Path(configured).resolve()
    return Path(__file__).resolve().parents[2] / "trust404" / "harness"


def _search_attacker_bytecode(harness_dir: Path) -> str:
    preferred = harness_dir / "out" / "SearchAttacker.sol" / "SearchAttacker.json"
    candidates = (
        (preferred,)
        if preferred.is_file()
        else tuple(sorted(harness_dir.glob("out/**/SearchAttacker.json")))
    )
    if len(candidates) != 1:
        raise ValueError("SearchAttacker artifact is missing or ambiguous")
    try:
        raw = json.loads(candidates[0].read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError("SearchAttacker artifact is invalid") from error
    bytecode_record = raw.get("bytecode") if isinstance(raw, dict) else None
    bytecode = (
        bytecode_record.get("object") if isinstance(bytecode_record, dict) else None
    )
    if not isinstance(bytecode, str) or not bytecode:
        raise ValueError("SearchAttacker artifact lacks deployment bytecode")
    return bytecode if bytecode.startswith("0x") else "0x" + bytecode


@contextmanager
def _default_runtime_factory(
    *,
    model: Track04SearchModel,
    target_path: Path,
    invariants_path: Path,
    manifest: Track04Manifest,
    harness_dir: Path,
    deadline: float,
    clock: Callable[[], float],
):
    del target_path, invariants_path
    if deadline - clock() <= 0:
        raise ValueError("runtime deadline expired before Anvil startup")

    manager = LocalAnvil()
    if hasattr(manager, "configure_block_context"):
        manager.configure_block_context(
            manifest.block_number,
            manifest.block_timestamp,
        )

    with manager as anvil:
        anvil.set_block_context(manifest.block_number, manifest.block_timestamp)
        runtime = deploy_runtime_from_artifacts(
            anvil,
            analysis=model.analysis,
            manifest=manifest,
            search_attacker_bytecode=_search_attacker_bytecode(harness_dir),
            attacker_funding_wei=10 * 10**18,
            observation_sources=model.runtime_uint_sources,
        )
        yield runtime


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
    if verification.category in {"forge_error", "runtime_revert"}:
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


def _search_horizons(model: Track04SearchModel) -> tuple[int, ...]:
    """Return deterministic shortest-first horizons with full-length fallback."""

    return tuple(range(1, model.max_sequence_length + 1))


def _instance_id_for_path(path: tuple[str, ...]) -> str:
    if not path:
        return "instance:root"
    return "instance:path:" + "|".join(path)


def _skeleton_problem(
    model: Track04SearchModel,
    *,
    horizon: int | None = None,
):
    """Build an action-level QUBO problem; parameters are completed later."""

    from qprover.parameters import ActionVariant
    from qprover.search.bqm import SearchProblem

    active_horizon = model.max_sequence_length if horizon is None else horizon
    if (
        type(active_horizon) is not int
        or active_horizon <= 0
        or active_horizon > model.max_sequence_length
    ):
        raise ValueError("horizon must be within the Track04 search model")

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
                target_id=_instance_id_for_path(action.target_path),
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
    discounts = tuple(1.0 / (index + 1) for index in range(active_horizon))
    return SearchProblem(
        actions=tuple(action.id for action in model.actions),
        max_sequence_length=active_horizon,
        utilities=model.utilities,
        transitions=model.transitions,
        repetition_limits=repetition_limits,
        discounts=discounts,
        variants=tuple(representatives),
        hypothesis_sequences=(),
        length_weight=0.30,
    )


def _concrete_candidates(
    model: Track04SearchModel,
    skeleton,
    limit: int,
    *,
    state: object | None = None,
):
    """Complete one skeleton with contextual expressions or legacy bounded values."""

    from qprover.models import ActionStep, Candidate

    if type(limit) is not int or limit <= 0:
        return ()
    if state is not None:
        contextual = complete_parameters(skeleton, state, model, limit)
        if contextual:
            return contextual
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


def _runtime_instance_address(runtime: object, instance_id: str) -> str:
    resolver = getattr(runtime, "instance_address", None)
    if callable(resolver):
        return resolver(instance_id)
    if instance_id in {"instance:root", "root", "target"}:
        target = getattr(runtime, "target_address", None)
        if isinstance(target, str):
            return target
    raise ValueError(f"runtime cannot resolve contract instance {instance_id!r}")


def _resolve_value_expr(value: object, runtime: object) -> object:
    if isinstance(value, Const):
        return value.value
    if isinstance(value, SelfAddress):
        return runtime.attacker_address
    if isinstance(value, TargetAddress):
        return runtime.target_address
    if isinstance(value, ContractAddress):
        return _runtime_instance_address(runtime, value.instance_id)
    if isinstance(value, ReadUint):
        arguments = tuple(_resolve_value_expr(item, runtime) for item in value.args)
        return runtime.read_uint(value.instance_id, value.signature, arguments)
    if isinstance(value, Scale):
        resolved = int(_resolve_value_expr(value.value, runtime))
        if resolved == 0 or value.numerator == 0:
            return 0
        maximum = (1 << 256) - 1
        if resolved > maximum // value.numerator:
            return maximum
        return (resolved * value.numerator) // value.denominator
    if isinstance(value, Add):
        return int(_resolve_value_expr(value.left, runtime)) + int(
            _resolve_value_expr(value.right, runtime)
        )
    if isinstance(value, Sub):
        left = int(_resolve_value_expr(value.left, runtime))
        right = int(_resolve_value_expr(value.right, runtime))
        if right > left:
            raise ValueError("contextual subtraction would underflow")
        return left - right
    if isinstance(value, Min):
        return min(
            int(_resolve_value_expr(value.left, runtime)),
            int(_resolve_value_expr(value.right, runtime)),
        )
    if isinstance(value, Max):
        return max(
            int(_resolve_value_expr(value.left, runtime)),
            int(_resolve_value_expr(value.right, runtime)),
        )
    if isinstance(value, PreviousReturn):
        raise ValueError("PreviousReturn is unavailable without a runtime observation")
    return value


def _signature_types(signature: str) -> tuple[str, ...]:
    opening = signature.find("(")
    if opening < 0 or not signature.endswith(")"):
        raise ValueError("invalid ABI signature")
    encoded = signature[opening + 1 : -1]
    if not encoded:
        return ()
    return tuple(part.strip() for part in encoded.split(","))


def _runtime_argument(value: object, abi_type: str, runtime: object) -> object:
    """Resolve one contextual or legacy ABI argument."""

    from web3 import Web3

    value = _resolve_value_expr(value, runtime)
    if abi_type == "address":
        if value == SELF_ADDRESS:
            value = runtime.attacker_address
        elif value == TARGET_ADDRESS:
            value = runtime.target_address
        elif value == OTHER_ADDRESS:
            value = "0x000000000000000000000000000000000000bEEF"
        elif isinstance(value, str) and value.startswith(ADDRESS_REF_PREFIX):
            raise ValueError("dynamic address reference requires contextual ValueExpr")
        if not isinstance(value, str):
            raise ValueError("runtime address argument must resolve to a string")
        return Web3.to_checksum_address(value)

    if isinstance(value, str) and value.startswith(UINT_REF_PREFIX):
        raise ValueError("dynamic uint reference requires contextual ValueExpr")
    if (
        abi_type.startswith("bytes")
        and isinstance(value, str)
        and value.startswith("0x")
    ):
        return bytes.fromhex(value[2:])
    return value


def _runtime_calls(model: Track04SearchModel, candidate, runtime: object):
    from web3 import Web3

    actions = {action.id: action for action in model.actions}
    calls: list[RuntimeCall] = []

    def encode_call(
        target_instance_id: str,
        signature: str,
        args: tuple[object, ...],
        value_wei: int,
    ) -> RuntimeCall:
        abi_types = _signature_types(signature)
        if len(args) != len(abi_types):
            raise ValueError("runtime argument count does not match action ABI")
        concrete = tuple(
            _runtime_argument(value, abi_type, runtime)
            for value, abi_type in zip(args, abi_types, strict=True)
        )
        selector = bytes(Web3.keccak(text=signature)[:4])
        encoded = Web3().codec.encode(list(abi_types), list(concrete))
        return RuntimeCall(
            target=_runtime_instance_address(runtime, target_instance_id),
            value_wei=value_wei,
            calldata="0x" + (selector + encoded).hex(),
        )

    for step in candidate.steps:
        action = actions[step.action_id]
        target_instance_id = getattr(
            step,
            "target_instance_id",
            _instance_id_for_path(action.target_path),
        )
        primary = encode_call(
            target_instance_id,
            action.signature,
            tuple(step.args),
            int(step.value_wei),
        )
        callback = getattr(step, "callback_program", None)
        if callback is not None:
            nested = tuple(
                encode_call(
                    instruction.target.instance_id
                    if isinstance(instruction.target, ContractAddress)
                    else "instance:root",
                    instruction.signature,
                    instruction.args,
                    int(_resolve_value_expr(instruction.value, runtime)),
                )
                for instruction in callback.instructions
            )
            primary = RuntimeCall(
                target=primary.target,
                value_wei=primary.value_wei,
                calldata=primary.calldata,
                callback_program=nested,
                callback_depth_budget=callback.depth_budget,
            )
        calls.append(primary)
    return tuple(calls)


def _record_attempt(
    ledger: _AttemptLedger,
    candidate,
    verification: VerificationResult,
) -> None:
    result_name = {
        "proven": "PROVEN",
        "not_proven": "NOT_PROVEN",
        "forge_error": "REVERT",
        "runtime_revert": "REVERT",
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
                "strategy=portfolio",
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
    runtime: object | None = None,
) -> bool:
    from qprover.models import Outcome, SearchLimits
    from qprover.search.base import Evaluation, candidate_is_valid
    from qprover.search.controller import SearchController

    frontier = StateFrontier()

    def record_state(candidate: object, runtime_result: object) -> None:
        fingerprint = getattr(runtime_result, "state_fingerprint", None)
        if not isinstance(fingerprint, str) or not fingerprint:
            return
        features = frozenset(getattr(runtime_result, "trace_features", ()))
        frontier.add(
            SearchState(
                state_id=f"state:{fingerprint}",
                fingerprint=fingerprint,
                trace_action_ids=tuple(
                    str(getattr(step, "action_id", ""))
                    for step in getattr(candidate, "steps", ())
                ),
                property_observations=(
                    ("all_hold", bool(getattr(runtime_result, "all_hold", True))),
                    (
                        "violated_predicate",
                        str(getattr(runtime_result, "violated_predicate", "")),
                    ),
                ),
                runtime_instances=tuple(getattr(runtime, "instances", ()))
                if runtime is not None
                else (),
                novelty=float(len(features)),
            )
        )

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

            contextual_state = (
                SimpleNamespace(
                    runtime_uint_sources=model.runtime_uint_sources,
                    previous_returns=(),
                    runtime_instances=tuple(
                        getattr(runtime, "instances", ())
                    ),
                )
                if runtime is not None
                else None
            )
            candidates = _concrete_candidates(
                model,
                skeleton,
                1,
                state=contextual_state,
            )
            if not candidates:
                return Evaluation(
                    outcome=Outcome.INCONCLUSIVE,
                    transaction_count=0,
                    metadata={"note": "no-concrete-candidate"},
                )

            candidate = candidates[0]
            remaining_wall = deadline - clock()
            if remaining_wall <= 0 or ledger.attempts >= attempt_budget:
                return Evaluation(
                    outcome=Outcome.INCONCLUSIVE,
                    transaction_count=0,
                    metadata={"note": "budget"},
                )

            code = render_candidate(model, candidate)
            ledger.last_code = code
            ledger.codes[candidate.canonical_id] = code

            if runtime is None:
                verification = verifier(
                    harness_dir,
                    target_path,
                    invariants_path,
                    code,
                    manifest,
                    timeout_seconds=max(1, math.ceil(remaining_wall)),
                )
            else:
                try:
                    runtime_result = runtime.execute(
                        _runtime_calls(model, candidate, runtime)
                    )
                except RuntimeCandidateRevert as error:
                    ledger.attempts += 1
                    verification = VerificationResult(
                        False,
                        "",
                        "runtime_revert",
                        f"revert_step={error.step}",
                    )
                    _record_attempt(ledger, candidate, verification)
                    return Evaluation(
                        outcome=Outcome.REVERT,
                        transaction_count=error.step + 1,
                        metadata={
                            "revert_step": error.step,
                            "revert_selector": error.revert_selector or "",
                            "raw_revert_hash": error.raw_revert_hash or "",
                        },
                    )
                except ValueError as error:
                    return Evaluation(
                        outcome=Outcome.INCONCLUSIVE,
                        transaction_count=0,
                        metadata={"note": str(error)},
                    )
                verification = VerificationResult(
                    proven=not runtime_result.all_hold,
                    violated_predicate=runtime_result.violated_predicate,
                    category=(
                        "proven" if not runtime_result.all_hold else "not_proven"
                    ),
                    note="persistent_runtime",
                )

            ledger.attempts += 1
            _record_attempt(ledger, candidate, verification)
            if runtime is not None:
                record_state(candidate, runtime_result)

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
                ledger.winner_candidate = candidate
                return Evaluation(
                    outcome=Outcome.VIOLATION,
                    transaction_count=len(candidate.steps),
                    trace_features=frozenset(
                        getattr(runtime_result, "trace_features", ())
                    )
                    if runtime is not None
                    else frozenset(),
                    state_fingerprint=(
                        getattr(runtime_result, "state_fingerprint", None)
                        if runtime is not None
                        else None
                    ),
                    metadata={"violated_predicate": verification.violated_predicate},
                )
            if verification.category == "not_proven":
                return Evaluation(
                    outcome=Outcome.PASS,
                    transaction_count=len(candidate.steps),
                    trace_features=frozenset(
                        getattr(runtime_result, "trace_features", ())
                    )
                    if runtime is not None
                    else frozenset(),
                    state_fingerprint=(
                        getattr(runtime_result, "state_fingerprint", None)
                        if runtime is not None
                        else None
                    ),
                    metadata={"note": verification.note},
                )
            if verification.category == "forge_error":
                return Evaluation(
                    outcome=Outcome.REVERT,
                    transaction_count=_revert_transaction_count(
                        verification.note,
                        len(candidate.steps),
                    ),
                    metadata={"note": verification.note},
                )
            if verification.category == "timeout":
                return Evaluation(
                    outcome=Outcome.INCONCLUSIVE,
                    transaction_count=0,
                    metadata={"note": "timeout"},
                )
            return Evaluation(
                outcome=Outcome.INCONCLUSIVE,
                transaction_count=0,
                metadata={"note": verification.note},
            )

    if attempt_budget <= 0:
        return False

    for horizon in _search_horizons(model):
        remaining_attempts = attempt_budget - ledger.attempts
        remaining_wall = math.floor(deadline - clock())
        if remaining_attempts <= 0 or remaining_wall <= 0:
            break

        problem = _skeleton_problem(model, horizon=horizon)
        strategy = _make_portfolio_strategy(
            seed + horizon,
            include_qubo=horizon <= 4,
        )
        limits = SearchLimits(
            max_sequence_length=problem.max_sequence_length,
            max_variants=max(1, len(problem.variants)),
            transaction_budget=max(
                1,
                remaining_attempts * problem.max_sequence_length,
            ),
            candidate_budget=remaining_attempts,
            wall_seconds=max(1, remaining_wall),
        )
        controller = SearchController(
            candidate_validator=lambda candidate, problem=problem: candidate_is_valid(
                problem, candidate
            )
        )
        run = controller.run(
            strategy,
            Evaluator(),
            limits,
            problem=problem,
            seed=seed,
        )
        if run.violation is not None and ledger.winner_code is not None:
            return True

    return False


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
    runtime_factory: Callable[..., object] | None = None,
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
    if runtime_factory is None:
        found = _run_search(
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
        )
        if found:
            _write_outputs(output, ledger)
            return EXIT_FOUND
    else:
        runtime_context = runtime_factory(
            model=model,
            target_path=contract,
            invariants_path=invariants,
            manifest=manifest,
            harness_dir=hdir,
            deadline=deadline,
            clock=clock,
        )
        with runtime_context as runtime:
            found = _run_search(
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
                runtime=runtime,
            )
            if found and ledger.winner_candidate is not None and deadline - clock() > 0:
                def still_violates(proposed: object) -> bool:
                    if deadline - clock() <= 0:
                        return False
                    try:
                        result = runtime.execute(
                            _runtime_calls(model, proposed, runtime)
                        )
                    except RuntimeCandidateRevert:
                        return False
                    return not result.all_hold

                try:
                    minimized = minimize_track04_candidate(
                        ledger.winner_candidate,
                        still_violates,
                        max_evaluations=max(1, min(32, max_attempts * 4)),
                    )
                except MinimizationError:
                    pass
                else:
                    ledger.winner_candidate = minimized.candidate
                    ledger.winner_code = render_candidate(
                        model,
                        minimized.candidate,
                    )
        if found and ledger.winner_code is not None:
            remaining_wall = deadline - clock()
            if remaining_wall > 0:
                final_proof = verifier(
                    hdir,
                    contract,
                    invariants,
                    ledger.winner_code,
                    manifest,
                    timeout_seconds=max(1, math.ceil(remaining_wall)),
                )
                if final_proof.category in {
                    "infrastructure",
                    "unsupported_deploy",
                }:
                    ledger.fatal_error = True
                elif final_proof.proven:
                    _write_outputs(output, ledger)
                    return EXIT_FOUND
            ledger.winner_code = None

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
            runtime_factory=_default_runtime_factory,
        )
    except (ManifestContractError, OSError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        return EXIT_ERROR
    except Exception as error:  # fail-closed CLI boundary
        print(f"error: internal {type(error).__name__}: {error}", file=sys.stderr)
        return EXIT_ERROR


if __name__ == "__main__":
    raise SystemExit(main())
