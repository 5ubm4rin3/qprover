"""Official TRUST404 Track 04 adapter with macro-free generic search."""

from __future__ import annotations

import itertools
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

from qprover.analysis import FunctionFacts
from qprover.trust404_analysis import Track04Analysis, compile_track04_target

OFFICIAL_SCHEMA = "trust404.track04.manifest/0.1"
SELF_ADDRESS = "__QPROVER_SELF__"
OTHER_ADDRESS = "__QPROVER_OTHER__"
TARGET_ADDRESS = "__QPROVER_TARGET__"
EXIT_FOUND = 0
EXIT_NOT_FOUND = 1
EXIT_ERROR = 2


class ManifestContractError(ValueError):
    """Organizer manifest violates the Track 04 v0.1 contract."""


def _mapping(value: object, label: str) -> Mapping[str, object]:
    if not isinstance(value, dict):
        raise ManifestContractError(f"{label} must be an object")
    if any(type(key) is not str for key in value):
        raise ManifestContractError(f"{label} keys must be strings")
    return value


def _string(value: object, label: str, *, allow_empty: bool = False) -> str:
    if type(value) is not str or (not allow_empty and not value):
        raise ManifestContractError(f"{label} must be a nonempty string")
    return value


def _positive_int(value: object, label: str) -> int:
    if type(value) is not int or value <= 0:
        raise ManifestContractError(f"{label} must be a positive integer")
    return value


def _nonnegative_int(value: object, label: str) -> int:
    if type(value) is not int or value < 0:
        raise ManifestContractError(f"{label} must be a nonnegative integer")
    return value


@dataclass(frozen=True, slots=True)
class Track04Manifest:
    schema: str
    target_name: str
    target_src: str
    solc: str
    evm_version: str
    deploy_mode: str
    constructor_args: tuple[object, ...]
    deploy_value_wei: int
    setup: str | None
    block_number: int
    block_timestamp: int
    manifest_seed: int
    invariants_contract: str
    predicates: tuple[str, ...]
    timeout_sec: int
    max_attempts: int
    path: Path

    @classmethod
    def load(cls, path: Path | str) -> Track04Manifest:
        manifest_path = Path(path).resolve()
        try:
            raw = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            raise ManifestContractError(f"manifest parse failed: {error}") from error
        root = _mapping(raw, "manifest")
        schema = _string(root.get("schema"), "schema")
        if schema != OFFICIAL_SCHEMA:
            raise ManifestContractError(
                f"unsupported schema {schema!r}; expected {OFFICIAL_SCHEMA!r}"
            )
        target = _mapping(root.get("target"), "target")
        deploy = _mapping(root.get("deploy"), "deploy")
        determinism = _mapping(root.get("determinism"), "determinism")
        invariants = _mapping(root.get("invariants"), "invariants")
        budget = _mapping(root.get("budget"), "budget")
        deploy_mode = _string(deploy.get("mode"), "deploy.mode")
        if deploy_mode != "local":
            raise ManifestContractError("deploy.mode must be 'local' for Track 04")
        constructor_args_raw = deploy.get("constructor_args")
        if not isinstance(constructor_args_raw, list):
            raise ManifestContractError("deploy.constructor_args must be an array")
        value_text = _string(deploy.get("value_wei"), "deploy.value_wei")
        if not value_text.isdecimal():
            raise ManifestContractError("deploy.value_wei must be a decimal string")
        deploy_value_wei = int(value_text)
        if deploy_value_wei >= 1 << 256:
            raise ManifestContractError("deploy.value_wei exceeds uint256")
        predicates_raw = invariants.get("predicates")
        if not isinstance(predicates_raw, list) or not predicates_raw:
            raise ManifestContractError(
                "invariants.predicates must be a nonempty array"
            )
        if any(type(item) is not str or not item for item in predicates_raw):
            raise ManifestContractError(
                "invariants.predicates must contain nonempty strings"
            )
        if len(set(predicates_raw)) != len(predicates_raw):
            raise ManifestContractError(
                "invariants.predicates must not contain duplicates"
            )
        setup_raw = deploy.get("setup")
        setup = None if setup_raw is None else _string(setup_raw, "deploy.setup")
        return cls(
            schema=schema,
            target_name=_string(target.get("name"), "target.name"),
            target_src=_string(target.get("src"), "target.src"),
            solc=_string(target.get("solc"), "target.solc"),
            evm_version=_string(target.get("evm_version"), "target.evm_version"),
            deploy_mode=deploy_mode,
            constructor_args=tuple(constructor_args_raw),
            deploy_value_wei=deploy_value_wei,
            setup=setup,
            block_number=_nonnegative_int(
                determinism.get("block_number"), "determinism.block_number"
            ),
            block_timestamp=_nonnegative_int(
                determinism.get("block_timestamp"), "determinism.block_timestamp"
            ),
            manifest_seed=_nonnegative_int(determinism.get("seed"), "determinism.seed"),
            invariants_contract=_string(
                invariants.get("contract"), "invariants.contract"
            ),
            predicates=tuple(predicates_raw),
            timeout_sec=_positive_int(budget.get("timeout_sec"), "budget.timeout_sec"),
            max_attempts=_positive_int(
                budget.get("max_attempts"), "budget.max_attempts"
            ),
            path=manifest_path,
        )


@dataclass(frozen=True, slots=True)
class Track04Action:
    id: str
    kind: str
    signature: str
    function_id: str
    param_types: tuple[str, ...]
    payable: bool
    utility: float
    storage_reads: tuple[str, ...]
    storage_writes: tuple[str, ...]
    provenance: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class Track04Variant:
    action_id: str
    signature: str
    args: tuple[object, ...]
    value_wei: int
    max_repetitions: int = 2


@dataclass(frozen=True, slots=True)
class Track04SearchModel:
    actions: tuple[Track04Action, ...]
    variants: tuple[Track04Variant, ...]
    utilities: Mapping[str, float]
    transitions: Mapping[tuple[str, str], float]
    max_sequence_length: int
    analysis: Track04Analysis


def _abi_values(abi_type: str, manifest: Track04Manifest) -> tuple[object, ...]:
    if re.fullmatch(r"uint(?:[0-9]+)?", abi_type):
        width_text = abi_type[4:]
        width = int(width_text) if width_text else 256
        maximum = (1 << width) - 1
        values = [0, 1, 10**6, 10**18]
        if manifest.deploy_value_wei:
            values.extend(
                [
                    manifest.deploy_value_wei // 2,
                    manifest.deploy_value_wei,
                ]
            )
        values.append(maximum)
        return tuple(dict.fromkeys(value for value in values if 0 <= value <= maximum))
    if re.fullmatch(r"int(?:[0-9]+)?", abi_type):
        width_text = abi_type[3:]
        width = int(width_text) if width_text else 256
        minimum = -(1 << (width - 1))
        maximum = (1 << (width - 1)) - 1
        return (0, 1, -1, minimum, maximum)
    if abi_type == "address":
        return (SELF_ADDRESS, OTHER_ADDRESS, TARGET_ADDRESS)
    if abi_type == "bool":
        return (False, True)
    if abi_type == "bytes32":
        return ("0x" + "00" * 32, "0x" + "ff" * 32)
    if abi_type == "bytes":
        return ("0x",)
    if abi_type == "string":
        return ("",)
    return ()


def _variants(
    action_id: str,
    signature: str,
    param_types: tuple[str, ...],
    payable: bool,
    manifest: Track04Manifest,
    *,
    cap: int = 24,
) -> tuple[Track04Variant, ...]:
    domains = [_abi_values(param_type, manifest) for param_type in param_types]
    if any(not domain for domain in domains):
        return ()
    products = itertools.product(*domains) if domains else ((),)
    values = (0, 10**18) if payable else (0,)
    result: list[Track04Variant] = []
    for args in products:
        for value in values:
            result.append(
                Track04Variant(
                    action_id=action_id,
                    signature=signature,
                    args=tuple(args),
                    value_wei=value,
                )
            )
            if len(result) >= cap:
                return tuple(result)
    return tuple(result)


def _function_utility(function: FunctionFacts) -> float:
    """Label-neutral relevance prior based only on semantic compiler facts."""

    score = 0.10
    if function.transitive_storage_writes:
        score += 0.30
    if function.transitive_storage_reads:
        score += 0.10
    if function.calls:
        score += 0.10
    if function.value_flows:
        score += 0.20
    if function.external_call_before_write:
        score += 0.10
    return round(min(1.0, score), 6)


def build_search_model(
    contract_path: Path | str,
    invariants_path: Path | str,
    manifest: Track04Manifest,
) -> Track04SearchModel:
    """Build a macro-free generic action model from compiler-backed facts."""

    invariants = Path(invariants_path).resolve()
    if not invariants.is_file():
        raise FileNotFoundError(f"invariants not found: {invariants}")
    analysis = compile_track04_target(
        contract_path,
        target_name=manifest.target_name,
        target_src=manifest.target_src,
        solc_version=manifest.solc,
        evm_version=manifest.evm_version,
    )
    contract = analysis.report.contract(analysis.source_name, analysis.contract_name)
    functions = tuple(
        function
        for function in contract.functions
        if function.visibility in {"public", "external"}
        and function.state_mutability not in {"view", "pure"}
        and function.function_selector is not None
    )
    actions: list[Track04Action] = []
    variants: list[Track04Variant] = []
    function_by_action: dict[str, FunctionFacts] = {}
    utilities: dict[str, float] = {}
    for function in functions:
        action_id = f"call:{function.signature}"
        utility = _function_utility(function)
        action_variants = _variants(
            action_id,
            function.signature,
            function.parameters,
            function.state_mutability == "payable",
            manifest,
        )
        if not action_variants:
            continue
        action = Track04Action(
            id=action_id,
            kind="call",
            signature=function.signature,
            function_id=function.canonical_id,
            param_types=function.parameters,
            payable=function.state_mutability == "payable",
            utility=utility,
            storage_reads=function.transitive_storage_reads,
            storage_writes=function.transitive_storage_writes,
            provenance=(function.source_name, function.source_span),
        )
        actions.append(action)
        variants.extend(action_variants)
        function_by_action[action_id] = function
        utilities[action_id] = utility

    transitions: dict[tuple[str, str], float] = {}
    for first in actions:
        first_function = function_by_action[first.id]
        first_writes = set(first_function.transitive_storage_writes)
        for second in actions:
            if first.id == second.id:
                continue
            second_function = function_by_action[second.id]
            dependency = first_writes.intersection(
                set(second_function.transitive_storage_reads)
                | set(second_function.transitive_storage_writes)
            )
            if not dependency:
                continue
            benefit = 0.45 + 0.25 * second.utility
            transitions[(first.id, second.id)] = round(min(1.0, benefit), 6)

    return Track04SearchModel(
        actions=tuple(sorted(actions, key=lambda item: item.id)),
        variants=tuple(
            sorted(
                variants,
                key=lambda item: (item.action_id, repr(item.args), item.value_wei),
            )
        ),
        utilities={key: utilities[key] for key in sorted(utilities)},
        transitions={key: transitions[key] for key in sorted(transitions)},
        max_sequence_length=4,
        analysis=analysis,
    )


def _solidity_literal(value: object) -> str:
    if value == SELF_ADDRESS:
        return "address(this)"
    if value == OTHER_ADDRESS:
        return "address(0x000000000000000000000000000000000000bEEF)"
    if value == TARGET_ADDRESS:
        return "target"
    if type(value) is bool:
        return "true" if value else "false"
    if type(value) is int:
        return str(value)
    if isinstance(value, str) and re.fullmatch(r"0x[0-9a-fA-F]*", value):
        return f'hex"{value[2:]}"'
    if isinstance(value, str):
        escaped = value.replace("\\", "\\\\").replace('"', '\\"')
        return f'"{escaped}"'
    raise ValueError(f"unsupported Solidity literal: {value!r}")


def _encode_signature(signature: str, args: Sequence[object]) -> str:
    rendered = ", ".join(_solidity_literal(value) for value in args)
    if rendered:
        return f'abi.encodeWithSignature("{signature}", {rendered})'
    return f'abi.encodeWithSignature("{signature}")'


def render_candidate(model: Track04SearchModel, candidate: object) -> str:
    """Lower a generic action sequence into the official standalone Exploit.sol."""

    steps = tuple(getattr(candidate, "steps", ()))
    if not steps:
        raise ValueError("candidate must contain at least one step")
    actions = {action.id: action for action in model.actions}
    lines: list[str] = []
    for step in steps:
        action = actions.get(step.action_id)
        if action is None:
            raise ValueError(f"unknown action {step.action_id!r}")
        lines.append(
            f"_mustCall(target, {int(step.value_wei)}, "
            + _encode_signature(action.signature, tuple(step.args))
            + ");"
        )
    body = "\n".join(f"        {line}" for line in lines)
    return f"""// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

contract Exploit {{
    function run(address target) external payable {{
{body}
    }}

    function _mustCall(address target, uint256 value, bytes memory data) private {{
        (bool ok,) = target.call{{value: value}}(data);
        require(ok, "qprover-call");
    }}

    receive() external payable {{}}
}}
"""


def to_qprover_problem(model: Track04SearchModel):
    """Convert Track 04 compiler facts into QProver's generic SearchProblem."""

    from qprover.parameters import ActionVariant
    from qprover.search.bqm import SearchProblem

    variants = tuple(
        ActionVariant(
            action_id=variant.action_id,
            target_id="target",
            signature=variant.signature,
            sender_slot=0,
            args=variant.args,
            value_wei=variant.value_wei,
            max_repetitions=variant.max_repetitions,
            argument_provenance=tuple(("track04-abi-domain",) for _ in variant.args),
            value_provenance=("track04-abi-domain",),
        )
        for variant in model.variants
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
        variants=variants,
        hypothesis_sequences=(),
        length_weight=0.15,
    )
