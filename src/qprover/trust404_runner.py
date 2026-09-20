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
    proven_predicate: str = ""
    minimized: bool = False
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


def _result_payload(ledger: _AttemptLedger) -> dict[str, object]:
    proven = ledger.winner_code is not None and bool(ledger.proven_predicate)
    status = "PROVEN" if proven else "ERROR" if ledger.fatal_error else "NOT_FOUND"
    steps = tuple(getattr(ledger.winner_candidate, "steps", ())) if proven else ()
    exploit_path = [
        {"step": index, "action": str(getattr(step, "action_id", ""))}
        for index, step in enumerate(steps)
    ]
    if proven:
        sequence = " -> ".join(item["action"] for item in exploit_path)
        sequence_label = (
            "minimized exploit sequence" if ledger.minimized else "exploit sequence"
        )
        explanation = (
            f"Organizer Harness execution reproduced invariant "
            f"{ledger.proven_predicate!r} after the {sequence_label}"
            + (f": {sequence}." if sequence else ".")
        )
    elif ledger.fatal_error:
        explanation = (
            "No exploit was reported because the organizer proof boundary "
            "encountered an infrastructure or unsupported-deployment error."
        )
    else:
        explanation = (
            "No candidate reproduced an invariant violation within the configured "
            "time and attempt budgets."
        )
    return {
        "status": status,
        "violated_invariant": ledger.proven_predicate if proven else None,
        "exploit_path": exploit_path,
        "explanation": explanation,
        "proof": {
            "organizer_harness_reproduced": proven,
            "minimized_candidate": proven and ledger.minimized,
        },
        "attempts": ledger.attempts,
    }


def _write_outputs(out_dir: Path, ledger: _AttemptLedger) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    proven = ledger.winner_code is not None and bool(ledger.proven_predicate)
    code = ledger.winner_code if proven else _NOOP_EXPLOIT
    (out_dir / "Exploit.sol").write_text(code, encoding="utf-8")
    log = "\n".join(ledger.lines)
    (out_dir / "attempts.log").write_text(log + ("\n" if log else ""), encoding="utf-8")
    result = json.dumps(
        _result_payload(ledger),
        sort_keys=True,
        indent=2,
        ensure_ascii=False,
    )
    (out_dir / "result.json").write_text(result + "\n", encoding="utf-8")


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
                max_repetitions=3,
                argument_provenance=tuple(("track04-skeleton",) for _ in variant.args),
                value_provenance=("track04-skeleton",),
            )
        )
    repetition_limits = {action.id: 3 for action in model.actions}
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


def _semantic_hypotheses(
    model: Track04SearchModel,
    runtime: object,
) -> tuple[tuple[str, ...], ...]:
    """Derive executable prerequisite chains from compiler facts and aliases.

    These are deterministic search seeds, not proof. Runtime execution and the
    fresh organizer replay remain the only paths to ``PROVEN``.
    """

    actions = {action.id: action for action in model.actions}
    report = getattr(model.analysis, "report", None)
    functions = {
        function.canonical_id: function
        for contract in getattr(report, "contracts", ())
        for function in getattr(contract, "functions", ())
    }
    contracts = {
        str(contract.name): contract
        for contract in getattr(report, "contracts", ())
        if isinstance(getattr(contract, "name", None), str)
    }
    storage_by_declaration = {
        int(storage.declaration_id): storage
        for contract in contracts.values()
        for storage in getattr(contract, "storage", ())
        if type(getattr(storage, "declaration_id", None)) is int
    }
    storage_by_contract_name = {
        (str(contract.name), str(storage.name)): storage
        for contract in contracts.values()
        for storage in getattr(contract, "storage", ())
    }
    storage_by_id = {
        str(storage.canonical_id): storage
        for contract in contracts.values()
        for storage in getattr(contract, "storage", ())
    }
    root_contract = contracts.get(str(getattr(model.analysis, "contract_name", "")))
    root_signatures = {
        str(function.signature)
        for function in getattr(root_contract, "functions", ())
        if isinstance(getattr(function, "signature", None), str)
    }
    address_cache: dict[tuple[str, ...], str | None] = {}

    def address(path: tuple[str, ...]) -> str | None:
        if path not in address_cache:
            try:
                resolved = _runtime_instance_address(
                    runtime,
                    _instance_id_for_path(path),
                )
            except (KeyError, ValueError):
                resolved = None
            address_cache[path] = (
                resolved.lower() if isinstance(resolved, str) else None
            )
        return address_cache[path]

    def fact(action: object) -> object | None:
        return functions.get(str(getattr(action, "function_id", "")))

    def receiver_path(
        base_path: tuple[str, ...], call: object
    ) -> tuple[str, ...] | None:
        declaration = getattr(call, "receiver_declaration", None)
        name = getattr(call, "receiver_name", None)
        if (
            type(declaration) is not int
            or declaration not in storage_by_declaration
            or not isinstance(name, str)
            or not name
        ):
            return None
        return (*base_path, f"{name}()")

    def receiver_contract_name(call: object) -> str | None:
        type_name = getattr(call, "receiver_type", None)
        if not isinstance(type_name, str):
            return None
        match = re.match(r"^(?:contract|interface)\s+([A-Za-z_]\w*)", type_name)
        return match.group(1) if match is not None else None

    effect_cache: dict[
        str,
        tuple[
            frozenset[tuple[str, str]],
            frozenset[tuple[str, str]],
            tuple[tuple[str, object], ...],
            tuple[tuple[str, object], ...],
        ],
    ] = {}

    def action_effects(action: object):
        cached = effect_cache.get(str(action.id))
        if cached is not None:
            return cached

        def collect(
            function: object,
            path: tuple[str, ...],
            active: frozenset[tuple[str, tuple[str, ...]]],
        ) -> tuple[
            set[tuple[str, str]],
            set[tuple[str, str]],
            list[tuple[str, object]],
            list[tuple[str, object]],
        ]:
            function_id = str(getattr(function, "canonical_id", ""))
            marker = (function_id, path)
            if marker in active:
                return set(), set(), [], []
            instance = address(path)
            if instance is None:
                return set(), set(), [], []
            reads = {
                (instance, str(storage_id))
                for storage_id in getattr(function, "storage_reads", ())
            }
            writes = {
                (instance, str(storage_id))
                for storage_id in getattr(function, "storage_writes", ())
            }
            guards = [
                (instance, guard) for guard in getattr(function, "storage_guards", ())
            ]
            assignments = [
                (instance, assignment)
                for assignment in getattr(function, "storage_assignments", ())
            ]
            next_active = active | frozenset({marker})
            for call in getattr(function, "calls", ()):
                kind = str(getattr(call, "kind", ""))
                callee = functions.get(str(getattr(call, "callee_id", "")))
                if kind == "internal" and callee is not None:
                    nested = collect(callee, path, next_active)
                else:
                    nested_path = receiver_path(path, call)
                    if nested_path is None:
                        continue
                    nested_address = address(nested_path)
                    if nested_address is None:
                        continue
                    if callee is not None:
                        nested = collect(callee, nested_path, next_active)
                    else:
                        contract_name = receiver_contract_name(call)
                        storage = storage_by_contract_name.get(
                            (str(contract_name), str(getattr(call, "member_name", "")))
                        )
                        if storage is None:
                            continue
                        nested = (
                            {(nested_address, str(storage.canonical_id))},
                            set(),
                            [],
                            [],
                        )
                reads.update(nested[0])
                writes.update(nested[1])
                guards.extend(nested[2])
                assignments.extend(nested[3])
            return reads, writes, guards, assignments

        function = fact(action)
        if function is None:
            result = (frozenset(), frozenset(), (), ())
        else:
            reads, writes, guards, assignments = collect(
                function,
                tuple(getattr(action, "target_path", ())),
                frozenset(),
            )
            result = (
                frozenset(reads),
                frozenset(writes),
                tuple(guards),
                tuple(assignments),
            )
        effect_cache[str(action.id)] = result
        return result

    def action_key(action: object) -> tuple[str, str | None]:
        return (
            str(getattr(action, "function_id", "")),
            address(tuple(getattr(action, "target_path", ()))),
        )

    def dependency_chain(
        action: object,
        active: frozenset[tuple[str, str | None]] = frozenset(),
        *,
        alternative_index: int | None = None,
        choice_counter: list[int] | None = None,
    ) -> tuple[str, ...]:
        if choice_counter is None:
            choice_counter = [0]
        current_key = action_key(action)
        if current_key in active:
            return ()
        next_active = active | frozenset({current_key})
        reads, _, _, _ = action_effects(action)
        function = fact(action)
        action_address = address(tuple(getattr(action, "target_path", ())))
        if function is not None and action_address is not None:
            contextual_storage = {
                str(getattr(expression, "source_id", ""))
                for expression in getattr(function, "parameter_expressions", ())
                if getattr(expression, "source_kind", None) == "storage"
            }
            contextual_storage.update(
                str(getattr(guard, "storage_id", ""))
                for guard in getattr(function, "storage_guards", ())
            )
            has_low_level_call = any(
                getattr(call, "kind", None) == "low_level"
                for call in getattr(function, "calls", ())
            )
            local_writes = {
                (action_address, str(storage_id))
                for storage_id in getattr(function, "storage_writes", ())
                if str(storage_id) not in contextual_storage
                and not (
                    has_low_level_call
                    and str(
                        getattr(storage_by_id.get(str(storage_id)), "type_name", "")
                    ).startswith("mapping")
                )
            }
            reads = reads - local_writes
        prerequisite_candidates: dict[str, object] = {}
        covered_locations: set[tuple[str, str]] = set()
        for location in sorted(reads):
            if location in covered_locations:
                continue
            ranked: list[tuple[object, ...]] = []
            for candidate in actions.values():
                if action_key(candidate) in next_active:
                    continue
                candidate_function = fact(candidate)
                if candidate_function is None:
                    continue
                fixed_role_guard = any(
                    not str(
                        getattr(storage_by_id.get(str(storage_id)), "type_name", "")
                    ).startswith("mapping")
                    for storage_id in getattr(candidate_function, "role_guards", ())
                )
                if fixed_role_guard:
                    continue
                candidate_reads, candidate_writes, _, _ = action_effects(candidate)
                if location not in candidate_writes:
                    continue
                candidate_calls_root = any(
                    str(getattr(call, "callee_signature", "")) in root_signatures
                    for call in getattr(candidate_function, "calls", ())
                )
                effect_instances = {
                    instance for instance, _ in candidate_reads | candidate_writes
                }
                if (
                    tuple(getattr(candidate, "target_path", ()))
                    and not candidate_calls_root
                    and location in candidate_reads
                    and len(effect_instances) == 1
                    and bool(tuple(getattr(candidate_function, "calls", ())))
                ):
                    continue
                ranked.append(
                    (
                        len(tuple(getattr(candidate, "target_path", ()))),
                        -float(getattr(candidate, "utility", 0.0)),
                        len(candidate_reads),
                        str(candidate.id),
                        candidate,
                    )
                )
            if ranked:
                ordered_candidates = sorted(ranked)
                candidate_index = 0
                if len(ordered_candidates) > 1:
                    current_choice = choice_counter[0]
                    choice_counter[0] += 1
                    if current_choice == alternative_index:
                        candidate_index = 1
                selected = ordered_candidates[candidate_index][-1]
                prerequisite_candidates[str(selected.id)] = selected
                covered_locations.update(action_effects(selected)[1])

        ordered = sorted(
            prerequisite_candidates.values(),
            key=lambda candidate: (
                int("address" in tuple(getattr(candidate, "param_types", ()))),
                len(action_effects(candidate)[0]),
                str(candidate.id),
            ),
        )
        chain: list[str] = []
        for predecessor in ordered:
            chain.extend(
                dependency_chain(
                    predecessor,
                    next_active,
                    alternative_index=alternative_index,
                    choice_counter=choice_counter,
                )
            )
        if action.id not in chain:
            chain.append(action.id)
        deduplicated: list[str] = []
        seen_keys: set[tuple[str, str | None]] = set()
        for action_id in chain:
            key = action_key(actions[action_id])
            if key in seen_keys:
                continue
            seen_keys.add(key)
            deduplicated.append(action_id)
        return tuple(deduplicated)

    def satisfies(operator: str, value: int, constant: int) -> bool:
        return {
            "==": value == constant,
            "!=": value != constant,
            "<": value < constant,
            "<=": value <= constant,
            ">": value > constant,
            ">=": value >= constant,
        }.get(operator, False)

    def guard_chain(
        action: object,
        active: frozenset[str] = frozenset(),
    ) -> tuple[str, ...]:
        if action.id in active:
            return ()
        function = fact(action)
        if function is None:
            return (action.id,)
        next_active = active | frozenset({action.id})
        chain: list[str] = []
        action_address = address(tuple(getattr(action, "target_path", ())))
        for guard in getattr(function, "storage_guards", ()):
            candidates: list[tuple[object, ...]] = []
            for candidate in actions.values():
                if candidate.id in next_active:
                    continue
                candidate_function = fact(candidate)
                if candidate_function is None:
                    continue
                candidate_address = address(
                    tuple(getattr(candidate, "target_path", ()))
                )
                if action_address is None or candidate_address != action_address:
                    continue
                matching = tuple(
                    assignment
                    for assignment in getattr(
                        candidate_function, "storage_assignments", ()
                    )
                    if getattr(assignment, "storage_id", None)
                    == getattr(guard, "storage_id", None)
                    and type(getattr(assignment, "constant", None)) is int
                    and type(getattr(guard, "constant", None)) is int
                    and satisfies(
                        str(getattr(guard, "operator", "")),
                        int(assignment.constant),
                        int(guard.constant),
                    )
                )
                if not matching:
                    continue
                candidates.append(
                    (
                        len(getattr(candidate_function, "storage_guards", ())),
                        -len(matching),
                        -float(getattr(candidate, "utility", 0.0)),
                        str(candidate.id),
                        candidate,
                    )
                )
            if candidates:
                predecessor = min(candidates)[-1]
                chain.extend(guard_chain(predecessor, next_active))
        if action.id not in chain:
            chain.append(action.id)
        return tuple(chain)

    hypotheses: set[tuple[str, ...]] = set()
    property_calls = {
        str(member)
        for property_fact in getattr(
            getattr(model.analysis, "property_analysis", None), "facts", ()
        )
        for member in getattr(property_fact, "target_calls", ())
    }
    property_storage = {
        str(storage.canonical_id)
        for storage in getattr(root_contract, "storage", ())
        if str(getattr(storage, "name", "")) in property_calls
    }
    root_address = address(())
    property_direct = {
        str(action.id)
        for action in actions.values()
        if not tuple(getattr(action, "target_path", ()))
        and root_address is not None
        and any(
            instance == root_address and storage_id in property_storage
            for instance, storage_id in action_effects(action)[1]
        )
    }
    hypotheses.update((action_id,) for action_id in property_direct)

    def order_authorization_writers(sequence: tuple[str, ...]) -> tuple[str, ...]:
        ordered = list(sequence)
        for action_id in sequence:
            producer = actions[action_id]
            if "address" not in tuple(getattr(producer, "param_types", ())):
                continue
            writes = action_effects(producer)[1]
            if not writes:
                continue
            consumers = [
                consumer_id
                for consumer_id in ordered
                if consumer_id != action_id
                and writes.intersection(action_effects(actions[consumer_id])[0])
            ]
            if not consumers:
                continue
            consumer_id = min(
                consumers,
                key=lambda item: (
                    len(tuple(getattr(actions[item], "target_path", ()))),
                    ordered.index(item),
                ),
            )
            ordered.remove(action_id)
            ordered.insert(ordered.index(consumer_id), action_id)
        return tuple(ordered)

    def add_hypothesis(sequence: tuple[str, ...], endpoint: object) -> None:
        sequence = order_authorization_writers(sequence)
        candidates = [sequence]
        if len(sequence) == model.max_sequence_length + 1:
            for index, action_id in enumerate(sequence[:-1]):
                writes = action_effects(actions[action_id])[1]
                covered = frozenset().union(
                    *(
                        action_effects(actions[other_id])[1]
                        for other_index, other_id in enumerate(sequence)
                        if other_index != index
                    )
                )
                if writes and writes.issubset(covered):
                    candidates.append((*sequence[:index], *sequence[index + 1 :]))
        for candidate in candidates:
            if 1 < len(candidate) <= model.max_sequence_length:
                hypotheses.add(candidate)
        reads, writes, _, _ = action_effects(endpoint)
        if not reads.intersection(writes):
            return
        if bool(getattr(endpoint, "payable", False)):
            return
        endpoint_function = fact(endpoint)
        calls_root = any(
            str(getattr(call, "callee_signature", "")) in root_signatures
            for call in getattr(endpoint_function, "calls", ())
        )
        if tuple(getattr(endpoint, "target_path", ())) and not calls_root:
            return
        if any(
            str(getattr(call, "kind", "")) == "low_level"
            or (
                str(getattr(call, "kind", "")) == "external"
                and (
                    (callee := functions.get(str(getattr(call, "callee_id", ""))))
                    is None
                    or bool(tuple(getattr(callee, "storage_writes", ())))
                )
            )
            for call in getattr(endpoint_function, "calls", ())
        ):
            return
        guarded_storage = {
            str(getattr(guard, "storage_id", ""))
            for guard in getattr(endpoint_function, "storage_guards", ())
            if type(getattr(guard, "constant", None)) is int
        }
        assigned_storage = {
            str(getattr(assignment, "storage_id", ""))
            for assignment in getattr(endpoint_function, "storage_assignments", ())
            if type(getattr(assignment, "constant", None)) is int
        }
        if guarded_storage.intersection(assigned_storage):
            return
        for additional_repetitions in (1, 2):
            repeated = (*sequence, *((str(endpoint.id),) * additional_repetitions))
            if len(repeated) <= model.max_sequence_length:
                hypotheses.add(repeated)

    for endpoint in actions.values():
        guarded = tuple(dict.fromkeys(guard_chain(endpoint)))
        add_hypothesis(guarded, endpoint)
        dependent_variants = {dependency_chain(endpoint)}
        dependent_variants.update(
            dependency_chain(endpoint, alternative_index=index) for index in range(32)
        )
        for dependent in sorted(dependent_variants):
            add_hypothesis(dependent, endpoint)
            combined = tuple(
                dict.fromkeys((*dependent[:-1], *guarded[:-1], str(endpoint.id)))
            )
            add_hypothesis(combined, endpoint)

    def rank(sequence: tuple[str, ...]) -> tuple[object, ...]:
        first = actions[sequence[0]]
        endpoint = actions[sequence[-1]]
        endpoint_function = fact(endpoint)
        calls_root = any(
            str(getattr(call, "callee_signature", "")) in root_signatures
            for call in getattr(endpoint_function, "calls", ())
        )
        dependency_inversions = sum(
            bool(
                action_effects(actions[sequence[later]])[1].intersection(
                    action_effects(actions[sequence[earlier]])[0]
                )
            )
            for earlier in range(len(sequence))
            for later in range(earlier + 1, len(sequence))
        )
        return (
            int(str(endpoint.id) not in property_direct),
            int(bool(endpoint.target_path) and not calls_root),
            -len(sequence),
            int(bool(first.target_path)),
            len(first.param_types),
            dependency_inversions,
            -sum(bool(actions[action_id].callback_enabled) for action_id in sequence),
            -endpoint.utility,
            sequence,
        )

    return tuple(sorted(hypotheses, key=rank))


def _hypothesis_skeleton(
    model: Track04SearchModel,
    sequence: tuple[str, ...],
) -> object:
    from qprover.models import ActionStep, Candidate

    actions = {action.id: action for action in model.actions}
    grouped = _variants_by_action(model)
    steps = []
    for action_id in sequence:
        action = actions[action_id]
        variant = grouped[action_id][0]
        steps.append(
            ActionStep(
                action_id=action_id,
                target_id=_instance_id_for_path(action.target_path),
                signature=variant.signature,
                sender_slot=0,
                args=variant.args,
                value_wei=variant.value_wei,
            )
        )
    return Candidate(tuple(steps))


def _semantic_value_hints(
    model: Track04SearchModel,
    skeleton: object,
) -> tuple[
    dict[tuple[int, int], int],
    dict[int, int],
    dict[tuple[int, int], TargetAddress],
]:
    """Derive bounded numeric hints from compiler comparisons along one trace."""

    report = getattr(model.analysis, "report", None)
    functions = {
        str(function.canonical_id): function
        for contract in getattr(report, "contracts", ())
        for function in getattr(contract, "functions", ())
    }
    root = next(
        (
            contract
            for contract in getattr(report, "contracts", ())
            if getattr(contract, "source_name", None)
            == getattr(model.analysis, "source_name", None)
            and getattr(contract, "name", None)
            == getattr(model.analysis, "contract_name", None)
        ),
        None,
    )
    root_by_signature = {
        str(function.signature): function for function in getattr(root, "functions", ())
    }
    actions = {action.id: action for action in model.actions}

    def constants(action: object) -> tuple[int, ...]:
        function = functions.get(str(getattr(action, "function_id", "")))
        if function is None:
            return ()
        values = {
            value
            for value in getattr(function, "comparison_constants", ())
            if type(value) is int and 0 < value <= 10 * 10**18
        }
        for call in getattr(function, "calls", ()):
            callee = functions.get(str(getattr(call, "callee_id", "")))
            if callee is not None:
                values.update(
                    value
                    for value in getattr(callee, "comparison_constants", ())
                    if type(value) is int and 0 < value <= 10 * 10**18
                )
            root_callee = root_by_signature.get(
                str(getattr(call, "callee_signature", ""))
            )
            if root_callee is not None:
                values.update(
                    value
                    for value in getattr(root_callee, "comparison_constants", ())
                    if type(value) is int and 0 < value <= 10 * 10**18
                )
        return tuple(sorted(values))

    steps = tuple(getattr(skeleton, "steps", ()))
    by_step = tuple(constants(actions[step.action_id]) for step in steps)
    parameter_hints: dict[tuple[int, int], int] = {}
    value_hints: dict[int, int] = {}
    address_hints: dict[tuple[int, int], TargetAddress] = {}
    for index, step in enumerate(steps):
        action = actions[step.action_id]
        function = functions.get(str(action.function_id))
        calls_root = any(
            str(getattr(call, "callee_signature", "")) in root_by_signature
            for call in getattr(function, "calls", ())
        )
        if calls_root:
            for parameter_index, abi_type in enumerate(action.param_types):
                if abi_type == "address":
                    address_hints[(index, parameter_index)] = TargetAddress()
        if action.payable:
            payable_candidates = {value for later in by_step[index:] for value in later}
            if payable_candidates:
                value_hints[index] = max(payable_candidates)
        candidates = by_step[index]
        if not candidates:
            candidates = next((item for item in by_step[index + 1 :] if item), ())
        if not candidates:
            continue
        hint = max(candidates)
        for parameter_index, abi_type in enumerate(action.param_types):
            if abi_type.startswith(("uint", "int")):
                parameter_hints[(index, parameter_index)] = hint
    return parameter_hints, value_hints, address_hints


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


def _runtime_call(
    model: Track04SearchModel, step: object, runtime: object
) -> RuntimeCall:
    from web3 import Web3

    actions = {action.id: action for action in model.actions}

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
    return primary


def _runtime_call_builders(model: Track04SearchModel, candidate: object):
    return tuple(
        lambda runtime, step=step: _runtime_call(model, step, runtime)
        for step in candidate.steps
    )


def _runtime_calls(model: Track04SearchModel, candidate, runtime: object):
    return tuple(
        builder(runtime) for builder in _runtime_call_builders(model, candidate)
    )


def _record_final_proof(
    ledger: _AttemptLedger,
    verification: VerificationResult,
) -> None:
    result = (
        "PROVEN"
        if verification.proven
        else "ERROR"
        if verification.category
        in {"forge_error", "infrastructure", "unsupported_deploy"}
        else "NOT_PROVEN"
    )
    ledger.lines.append(
        "\t".join(
            (
                f"attempt={ledger.attempts}",
                "stage=final-proof",
                "strategy=organizer",
                f"result={result}",
                f"violated={verification.violated_predicate}",
                f"note={_deterministic_note(verification)}",
            )
        )
    )
    if verification.proven:
        ledger.proven_predicate = verification.violated_predicate


def _record_attempt(
    ledger: _AttemptLedger,
    candidate,
    verification: VerificationResult,
    *,
    strategy: str = "portfolio",
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
                f"strategy={strategy}",
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
    active_strategy = "portfolio"

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

            semantic_hints = (
                _semantic_value_hints(model, skeleton)
                if active_strategy == "semantic"
                else ({}, {}, {})
            )
            contextual_state = (
                SimpleNamespace(
                    runtime_uint_sources=model.runtime_uint_sources,
                    previous_returns=(),
                    runtime_instances=tuple(getattr(runtime, "instances", ())),
                    parameter_hints=semantic_hints[0],
                    value_hints=semantic_hints[1],
                    address_hints=semantic_hints[2],
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
                    lazy_execute = getattr(runtime, "execute_lazy", None)
                    if callable(lazy_execute):
                        runtime_result = lazy_execute(
                            _runtime_call_builders(model, candidate)
                        )
                    else:
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
                    _record_attempt(
                        ledger,
                        candidate,
                        verification,
                        strategy=active_strategy,
                    )
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
            _record_attempt(
                ledger,
                candidate,
                verification,
                strategy=active_strategy,
            )
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
                if runtime is None:
                    ledger.proven_predicate = verification.violated_predicate
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

    if runtime is not None:
        active_strategy = "semantic"
        semantic_problem = _skeleton_problem(model)
        semantic_attempts = 0
        semantic_limit = min(3, max(0, attempt_budget - ledger.attempts - 1))
        for sequence in _semantic_hypotheses(model, runtime):
            if semantic_attempts >= semantic_limit or deadline - clock() <= 0:
                break
            skeleton = _hypothesis_skeleton(model, sequence)
            if not candidate_is_valid(semantic_problem, skeleton):
                continue
            evaluation = Evaluator().evaluate(skeleton)
            semantic_attempts += 1
            if (
                evaluation.outcome is Outcome.VIOLATION
                and ledger.winner_code is not None
            ):
                return True
            if evaluation.outcome is Outcome.INFRA_ERROR:
                return False

    active_strategy = "portfolio"

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
    _write_outputs(
        output,
        _AttemptLedger(lines=[], codes={}, fatal_error=True),
    )
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
                        lazy_execute = getattr(runtime, "execute_lazy", None)
                        if callable(lazy_execute):
                            result = lazy_execute(
                                _runtime_call_builders(model, proposed)
                            )
                        else:
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
                    ledger.minimized = True
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
                _record_final_proof(ledger, final_proof)
                if final_proof.category in {
                    "forge_error",
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
