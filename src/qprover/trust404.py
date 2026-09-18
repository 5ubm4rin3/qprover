"""Official TRUST404 Track 04 adapter with macro-free generic search."""

from __future__ import annotations

import itertools
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from qprover.trust404_analysis import Track04Analysis, compile_track04_target
from qprover.trust404_resources import (
    build_property_slices,
    score_function_relevance,
)

OFFICIAL_SCHEMA = "trust404.track04.manifest/0.1"
SELF_ADDRESS = "__QPROVER_SELF__"
OTHER_ADDRESS = "__QPROVER_OTHER__"
TARGET_ADDRESS = "__QPROVER_TARGET__"
ADDRESS_REF_PREFIX = "__QPROVER_ADDRESS_REF__:"
UINT_REF_PREFIX = "__QPROVER_UINT_REF__:"
EXIT_FOUND = 0
EXIT_NOT_FOUND = 1
EXIT_ERROR = 2

_CONTRACT_TYPE = re.compile(r"^(?:contract|interface)\s+([A-Za-z_]\w*)")
_UINT_TYPE = re.compile(r"uint(?:[0-9]+)?$")
_MAPPING_ADDRESS_UINT = re.compile(
    r"mapping\s*\(\s*address\s*=>\s*(uint(?:[0-9]+)?)\s*\)$"
)
_RUNTIME_SCALES = ((1, 1), (9, 10), (1, 2), (2, 1))


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
    target_path: tuple[str, ...] = ()
    callback_enabled: bool = False


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
    runtime_uint_sources: tuple[object, ...] = ()
    source_constants: tuple[int, ...] = ()


@dataclass(frozen=True, slots=True)
class _RuntimeUintSource:
    target_path: tuple[str, ...]
    signature: str
    argument_mode: str
    reads: tuple[str, ...]

    @property
    def identity(self) -> tuple[tuple[str, ...], str, str]:
        return self.target_path, self.signature, self.argument_mode

    @property
    def instance_id(self) -> str:
        if not self.target_path:
            return "instance:root"
        return "instance:path:" + "|".join(self.target_path)


def _address_ref(path: tuple[str, ...]) -> str:
    return ADDRESS_REF_PREFIX + "|".join(path)


def _decode_address_ref(value: str) -> tuple[str, ...]:
    if not value.startswith(ADDRESS_REF_PREFIX):
        raise ValueError("not a QProver address reference")
    encoded = value[len(ADDRESS_REF_PREFIX) :]
    path = tuple(item for item in encoded.split("|") if item)
    if not path:
        raise ValueError("address reference path must be nonempty")
    return path


def _uint_ref(source: _RuntimeUintSource, numerator: int, denominator: int) -> str:
    path = "/".join(source.target_path) if source.target_path else "~"
    return UINT_REF_PREFIX + "|".join(
        (
            path,
            source.signature,
            source.argument_mode,
            str(numerator),
            str(denominator),
        )
    )


def _decode_uint_ref(
    value: str,
) -> tuple[tuple[str, ...], str, str, int, int]:
    if not value.startswith(UINT_REF_PREFIX):
        raise ValueError("not a QProver uint reference")
    parts = value[len(UINT_REF_PREFIX) :].split("|")
    if len(parts) != 5:
        raise ValueError("invalid uint reference")
    path_text, signature, mode, numerator_text, denominator_text = parts
    path = () if path_text == "~" else tuple(path_text.split("/"))
    if mode not in {"none", "self"}:
        raise ValueError("unsupported uint source argument mode")
    try:
        numerator = int(numerator_text)
        denominator = int(denominator_text)
    except ValueError as error:
        raise ValueError("invalid uint reference scale") from error
    if numerator < 0 or denominator <= 0:
        raise ValueError("invalid uint reference scale")
    return path, signature, mode, numerator, denominator


def _abi_values(
    abi_type: str,
    manifest: Track04Manifest,
    *,
    address_refs: tuple[str, ...] = (),
    uint_refs: tuple[str, ...] = (),
) -> tuple[object, ...]:
    if re.fullmatch(r"uint(?:[0-9]+)?", abi_type):
        width_text = abi_type[4:]
        width = int(width_text) if width_text else 256
        maximum = (1 << width) - 1
        values: list[object] = [maximum, *uint_refs, 10**18]
        if manifest.deploy_value_wei:
            values.extend(
                [
                    manifest.deploy_value_wei,
                    manifest.deploy_value_wei // 2,
                ]
            )
        values.extend((10**6, 1, 0))
        return tuple(dict.fromkeys(values))
    if re.fullmatch(r"int(?:[0-9]+)?", abi_type):
        width_text = abi_type[3:]
        width = int(width_text) if width_text else 256
        minimum = -(1 << (width - 1))
        maximum = (1 << (width - 1)) - 1
        return (0, 1, -1, minimum, maximum)
    if abi_type == "address":
        return tuple(
            dict.fromkeys(
                (
                    SELF_ADDRESS,
                    TARGET_ADDRESS,
                    *address_refs,
                    OTHER_ADDRESS,
                )
            )
        )
    if abi_type == "bool":
        return (False, True)
    if abi_type == "bytes32":
        return ("0x" + "00" * 32, "0x" + "ff" * 32)
    if abi_type == "bytes":
        return ("0x",)
    if abi_type == "string":
        return ("",)
    return ()


def _anchor_values(domain: tuple[object, ...]) -> tuple[object, ...]:
    if len(domain) <= 3:
        return domain
    return tuple(dict.fromkeys((domain[0], domain[1], domain[-1])))


def _bounded_products(
    domains: Sequence[tuple[object, ...]], cap: int
) -> tuple[tuple[object, ...], ...]:
    if not domains:
        return ((),)
    if len(domains) == 1:
        return tuple((value,) for value in domains[0][:cap])
    result: list[tuple[object, ...]] = []
    seen: set[str] = set()

    def append(values: tuple[object, ...]) -> bool:
        key = repr(values)
        if key in seen:
            return False
        seen.add(key)
        result.append(values)
        return len(result) >= cap

    anchors = tuple(_anchor_values(domain) for domain in domains)
    for values in itertools.product(*anchors):
        if append(tuple(values)):
            return tuple(result)
    baseline = tuple(domain[0] for domain in domains)
    for index, domain in enumerate(domains):
        for value in domain:
            values = list(baseline)
            values[index] = value
            if append(tuple(values)):
                return tuple(result)
    for values in itertools.product(*domains):
        if append(tuple(values)):
            return tuple(result)
    return tuple(result)


def _variants(
    action_id: str,
    signature: str,
    param_types: tuple[str, ...],
    payable: bool,
    manifest: Track04Manifest,
    *,
    address_refs: tuple[str, ...] = (),
    uint_refs: tuple[str, ...] = (),
    cap: int = 24,
) -> tuple[Track04Variant, ...]:
    domains = [
        _abi_values(
            param_type,
            manifest,
            address_refs=address_refs,
            uint_refs=uint_refs,
        )
        for param_type in param_types
    ]
    if any(not domain for domain in domains):
        return ()
    argument_products = _bounded_products(tuple(domains), cap)
    values = (0, 10**18) if payable else (0,)
    result: list[Track04Variant] = []
    for args in argument_products:
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


def _function_utility(function: Any, *, callback_enabled: bool = False) -> float:
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
    if callback_enabled:
        score += 0.10
    return round(min(1.0, score), 6)


def _callback_capable(function: Any) -> bool:
    """Require generic evidence of a native low-level value callback path."""

    if not bool(getattr(function, "external_call_before_write", False)):
        return False
    calls = tuple(getattr(function, "calls", ()))
    flows = tuple(getattr(function, "value_flows", ()))
    has_typed_facts = any(
        getattr(call, "kind", None) is not None for call in calls
    ) or any(getattr(flow, "asset", None) is not None for flow in flows)
    if not has_typed_facts:
        return True
    low_level = any(getattr(call, "kind", None) == "low_level" for call in calls)
    native_out = any(
        getattr(flow, "asset", None) == "native"
        and getattr(flow, "direction", None) == "out"
        for flow in flows
    )
    return low_level and native_out


def _contract_identity(contract: Any) -> tuple[str, str]:
    return str(contract.source_name), str(contract.name)


def _resolve_contract_type(report: Any, current: Any, type_name: str) -> Any | None:
    try:
        return report.contract(current.source_name, type_name)
    except KeyError:
        try:
            return report.contract(type_name)
        except KeyError:
            return None


def _reachable_contracts(
    analysis: Track04Analysis, *, max_depth: int = 3
) -> tuple[tuple[tuple[str, ...], Any], ...]:
    root = analysis.report.contract(analysis.source_name, analysis.contract_name)
    queue: list[tuple[tuple[str, ...], Any, frozenset[tuple[str, str]]]] = [
        ((), root, frozenset({_contract_identity(root)}))
    ]
    result: list[tuple[tuple[str, ...], Any]] = []
    index = 0
    while index < len(queue):
        path, contract, ancestry = queue[index]
        index += 1
        result.append((path, contract))
        if len(path) >= max_depth:
            continue
        abi_signatures = set(getattr(contract, "abi_signatures", ()))
        for storage in sorted(
            getattr(contract, "storage", ()), key=lambda item: str(item.name)
        ):
            match = _CONTRACT_TYPE.match(str(storage.type_name))
            if match is None:
                continue
            getter = f"{storage.name}()"
            if getter not in abi_signatures:
                continue
            reached = _resolve_contract_type(analysis.report, contract, match.group(1))
            if reached is None:
                continue
            identity = _contract_identity(reached)
            if identity in ancestry:
                continue
            queue.append(
                (
                    (*path, getter),
                    reached,
                    ancestry | frozenset({identity}),
                )
            )
    return tuple(result)


def _function_effects(
    report: Any,
) -> Mapping[str, tuple[frozenset[str], frozenset[str]]]:
    functions = {
        function.canonical_id: function
        for contract in report.contracts
        for function in contract.functions
    }
    memo: dict[str, tuple[frozenset[str], frozenset[str]]] = {}

    def visit(
        function_id: str, active: frozenset[str]
    ) -> tuple[frozenset[str], frozenset[str]]:
        if function_id in memo:
            return memo[function_id]
        function = functions[function_id]
        reads = set(function.transitive_storage_reads)
        writes = set(function.transitive_storage_writes)
        if function_id in active:
            return frozenset(reads), frozenset(writes)
        next_active = active | frozenset({function_id})
        for call in function.calls:
            callee_id = getattr(call, "callee_id", None)
            if callee_id not in functions or callee_id in next_active:
                continue
            nested_reads, nested_writes = visit(callee_id, next_active)
            reads.update(nested_reads)
            writes.update(nested_writes)
        result = frozenset(reads), frozenset(writes)
        memo[function_id] = result
        return result

    for function_id in sorted(functions):
        visit(function_id, frozenset())
    return memo


def _runtime_uint_sources(
    reachable: Sequence[tuple[tuple[str, ...], Any]],
    effects: Mapping[str, tuple[frozenset[str], frozenset[str]]],
) -> tuple[_RuntimeUintSource, ...]:
    sources: dict[tuple[tuple[str, ...], str, str], _RuntimeUintSource] = {}
    for target_path, contract in reachable:
        for function in getattr(contract, "functions", ()):
            if (
                function.visibility not in {"public", "external"}
                or function.state_mutability not in {"view", "pure"}
                or function.function_selector is None
                or len(getattr(function, "returns", ())) != 1
                or _UINT_TYPE.fullmatch(str(function.returns[0])) is None
            ):
                continue
            parameters = tuple(function.parameters)
            if parameters == ():
                mode = "none"
            elif parameters == ("address",):
                mode = "self"
            else:
                continue
            reads, _ = effects.get(
                function.canonical_id,
                (frozenset(function.transitive_storage_reads), frozenset()),
            )
            source = _RuntimeUintSource(
                target_path=target_path,
                signature=function.signature,
                argument_mode=mode,
                reads=tuple(sorted(reads)),
            )
            sources[source.identity] = source

        abi_signatures = set(getattr(contract, "abi_signatures", ()))
        for storage in getattr(contract, "storage", ()):
            type_name = str(storage.type_name)
            storage_id = getattr(storage, "canonical_id", None)
            reads = (str(storage_id),) if storage_id is not None else ()
            if _UINT_TYPE.fullmatch(type_name):
                signature = f"{storage.name}()"
                if signature in abi_signatures:
                    source = _RuntimeUintSource(
                        target_path=target_path,
                        signature=signature,
                        argument_mode="none",
                        reads=reads,
                    )
                    sources[source.identity] = source
                continue
            if _MAPPING_ADDRESS_UINT.fullmatch(type_name):
                signature = f"{storage.name}(address)"
                if signature in abi_signatures:
                    source = _RuntimeUintSource(
                        target_path=target_path,
                        signature=signature,
                        argument_mode="self",
                        reads=reads,
                    )
                    sources[source.identity] = source
    return tuple(sources[key] for key in sorted(sources))


def _rank_uint_refs(
    sources: Sequence[_RuntimeUintSource],
    *,
    action_reads: frozenset[str],
    action_writes: frozenset[str],
    action_path: tuple[str, ...],
    limit_sources: int = 3,
) -> tuple[str, ...]:
    relevant_state = action_reads | action_writes

    def rank(source: _RuntimeUintSource) -> tuple[int, int, str]:
        overlap = len(set(source.reads) & relevant_state)
        same_target = int(source.target_path == action_path)
        return -overlap, -same_target, _uint_ref(source, 1, 1)

    selected = sorted(sources, key=rank)[:limit_sources]
    return tuple(
        _uint_ref(source, numerator, denominator)
        for source in selected
        for numerator, denominator in _RUNTIME_SCALES
    )


def _action_id(
    target_path: tuple[str, ...], signature: str, *, callback_enabled: bool
) -> str:
    if target_path:
        identifier = f"call:{'/'.join(target_path)}:{signature}"
    else:
        identifier = f"call:{signature}"
    return identifier + ("@callback" if callback_enabled else "")


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
        invariants_path=invariants,
        setup_path=(
            manifest.path.parent / manifest.setup
            if manifest.setup is not None
            else None
        ),
        predicates=manifest.predicates,
    )
    property_analysis = getattr(analysis, "property_analysis", None)
    property_slices = (
        build_property_slices(
            property_analysis,
            root_target_identity="root",
        )
        if property_analysis is not None
        else ()
    )
    reachable = _reachable_contracts(analysis)
    address_refs = tuple(_address_ref(path) for path, _ in reachable if path)
    effects = _function_effects(analysis.report)
    uint_sources = _runtime_uint_sources(reachable, effects)

    actions: list[Track04Action] = []
    variants: list[Track04Variant] = []
    utilities: dict[str, float] = {}

    for target_path, contract in reachable:
        functions = tuple(
            function
            for function in contract.functions
            if function.visibility in {"public", "external"}
            and function.state_mutability not in {"view", "pure"}
            and function.function_selector is not None
        )
        for function in functions:
            reads, writes = effects.get(
                function.canonical_id,
                (
                    frozenset(function.transitive_storage_reads),
                    frozenset(function.transitive_storage_writes),
                ),
            )
            uint_refs = _rank_uint_refs(
                uint_sources,
                action_reads=reads,
                action_writes=writes,
                action_path=target_path,
            )
            modes = (False, True) if _callback_capable(function) else (False,)
            for callback_enabled in modes:
                action_id = _action_id(
                    target_path,
                    function.signature,
                    callback_enabled=callback_enabled,
                )
                base_utility = _function_utility(
                    function,
                    callback_enabled=callback_enabled,
                )
                property_relevance = (
                    score_function_relevance(function, property_slices)
                    if not target_path
                    else 0.0
                )
                utility = round(
                    min(
                        1.0,
                        base_utility + 0.5 * min(1.0, property_relevance),
                    ),
                    6,
                )
                action_variants = _variants(
                    action_id,
                    function.signature,
                    function.parameters,
                    function.state_mutability == "payable",
                    manifest,
                    address_refs=address_refs,
                    uint_refs=uint_refs,
                )
                if not action_variants:
                    continue
                actions.append(
                    Track04Action(
                        id=action_id,
                        kind="call",
                        signature=function.signature,
                        function_id=function.canonical_id,
                        param_types=function.parameters,
                        payable=function.state_mutability == "payable",
                        utility=utility,
                        storage_reads=tuple(sorted(reads)),
                        storage_writes=tuple(sorted(writes)),
                        provenance=(function.source_name, function.source_span),
                        target_path=target_path,
                        callback_enabled=callback_enabled,
                    )
                )
                variants.extend(action_variants)
                utilities[action_id] = utility

    transitions: dict[tuple[str, str], float] = {}
    for first in actions:
        first_writes = set(first.storage_writes)
        for second in actions:
            if first.id == second.id:
                continue
            dependency = first_writes.intersection(
                set(second.storage_reads) | set(second.storage_writes)
            )
            if not dependency:
                continue
            benefit = 0.45 + 0.25 * second.utility
            transitions[(first.id, second.id)] = round(min(1.0, benefit), 6)

    source_constants = {
        constant
        for fact in getattr(property_analysis, "facts", ())
        for constant in getattr(fact, "constants", ())
        if type(constant) is int
    }
    for contract in analysis.report.contracts:
        for function in contract.functions:
            source_constants.update(
                item.constant
                for item in getattr(function, "parameter_constraints", ())
            )

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
        max_sequence_length=6,
        analysis=analysis,
        runtime_uint_sources=tuple(uint_sources),
        source_constants=tuple(sorted(source_constants)),
    )


def _address_expression(root: str, path: tuple[str, ...]) -> str:
    expression = root
    for getter in path:
        expression = f'_readAddress({expression}, abi.encodeWithSignature("{getter}"))'
    return expression


def _uint_expression(value: str) -> str:
    path, signature, mode, numerator, denominator = _decode_uint_ref(value)
    target = _address_expression("target", path)
    if mode == "self":
        data = f'abi.encodeWithSignature("{signature}", address(this))'
    else:
        data = f'abi.encodeWithSignature("{signature}")'
    return f"_scale(_readUint({target}, {data}), {numerator}, {denominator})"


def _solidity_literal(value: object) -> str:
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
    )

    if isinstance(value, Const):
        return _solidity_literal(value.value)
    if isinstance(value, SelfAddress):
        return "address(this)"
    if isinstance(value, TargetAddress):
        return "target"
    if isinstance(value, ContractAddress):
        if value.access_path:
            return _address_expression("target", value.access_path)
        if value.instance_id in {"instance:root", "root", "target"}:
            return "target"
        if value.instance_id.startswith("instance:0x"):
            return f"address({value.instance_id.removeprefix('instance:')})"
        if value.instance_id.startswith("instance:path:"):
            path = tuple(
                item
                for item in value.instance_id.removeprefix("instance:path:").split("|")
                if item
            )
            return _address_expression("target", path)
        raise ValueError(f"unrenderable contract instance: {value.instance_id}")
    if isinstance(value, ReadUint):
        target = _solidity_literal(ContractAddress(value.instance_id))
        data = _encode_signature(value.signature, value.args)
        return f"_readUint({target}, {data})"
    if isinstance(value, Scale):
        rendered = _solidity_literal(value.value)
        return f"_scale({rendered}, {value.numerator}, {value.denominator})"
    if isinstance(value, Add):
        return f"({_solidity_literal(value.left)} + {_solidity_literal(value.right)})"
    if isinstance(value, Sub):
        return f"({_solidity_literal(value.left)} - {_solidity_literal(value.right)})"
    if isinstance(value, Min):
        return f"_min({_solidity_literal(value.left)}, {_solidity_literal(value.right)})"
    if isinstance(value, Max):
        return f"_max({_solidity_literal(value.left)}, {_solidity_literal(value.right)})"
    if isinstance(value, PreviousReturn):
        raise ValueError("PreviousReturn requires a stored temporary during rendering")

    if value == SELF_ADDRESS:
        return "address(this)"
    if value == OTHER_ADDRESS:
        return "address(0x000000000000000000000000000000000000bEEF)"
    if value == TARGET_ADDRESS:
        return "target"
    if isinstance(value, str) and value.startswith(ADDRESS_REF_PREFIX):
        return _address_expression("target", _decode_address_ref(value))
    if isinstance(value, str) and value.startswith(UINT_REF_PREFIX):
        return _uint_expression(value)
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
    callback_needed = False
    for index, step in enumerate(steps):
        action = actions.get(step.action_id)
        if action is None:
            raise ValueError(f"unknown action {step.action_id!r}")
        lines.append(f"_qproverStep = {index};")
        action_target = _address_expression("target", action.target_path)
        call_data = _encode_signature(action.signature, tuple(step.args))
        callback_program = getattr(step, "callback_program", None)
        if callback_program is not None:
            callback_needed = True
            lines.extend(
                (
                    "delete _callbackTargets;",
                    "delete _callbackValues;",
                    "delete _callbackData;",
                    "_callbackCursor = 0;",
                    f"_callbackBudget = {int(callback_program.depth_budget)};",
                )
            )
            for instruction in callback_program.instructions:
                callback_target = _solidity_literal(instruction.target)
                callback_value = _solidity_literal(instruction.value)
                callback_data = _encode_signature(
                    instruction.signature,
                    instruction.args,
                )
                lines.extend(
                    (
                        f"_callbackTargets.push({callback_target});",
                        f"_callbackValues.push({callback_value});",
                        f"_callbackData.push({callback_data});",
                    )
                )
            lines.extend(
                (
                    f"_mustCall({action_target}, {int(step.value_wei)}, {call_data});",
                    "delete _callbackTargets;",
                    "delete _callbackValues;",
                    "delete _callbackData;",
                    "_callbackCursor = 0;",
                    "_callbackBudget = 0;",
                )
            )
        else:
            lines.append(
                f"_mustCall({action_target}, {int(step.value_wei)}, {call_data});"
            )

    common_fields = """
    error QProverFailure(uint256 step);
    uint256 private _qproverStep;
"""
    callback_fields = ""
    receive_block = "\n    receive() external payable {}\n"
    if callback_needed:
        callback_fields = """
    address[] private _callbackTargets;
    uint256[] private _callbackValues;
    bytes[] private _callbackData;
    uint256 private _callbackCursor;
    uint256 private _callbackBudget;
"""
        receive_block = """
    receive() external payable {
        _dispatchCallback();
    }

    fallback() external payable {
        _dispatchCallback();
    }

    function _dispatchCallback() private {
        if (_callbackBudget == 0 || _callbackCursor >= _callbackTargets.length) return;
        uint256 cursor = _callbackCursor;
        _callbackCursor = cursor + 1;
        _callbackBudget -= 1;
        (bool ok,) = _callbackTargets[cursor].call{value: _callbackValues[cursor]}(
            _callbackData[cursor]
        );
        if (!ok) revert QProverFailure(_qproverStep);
    }
"""

    body = "\n".join(f"        {line}" for line in lines)
    return f"""// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

contract Exploit {{{common_fields}{callback_fields}
    function run(address target) external payable {{
{body}
    }}

    function _mustCall(address target, uint256 value, bytes memory data) private {{
        (bool ok,) = target.call{{value: value}}(data);
        if (!ok) revert QProverFailure(_qproverStep);
    }}

    function _readAddress(address target, bytes memory data) private view returns (address value) {{
        (bool ok, bytes memory result) = target.staticcall(data);
        if (!ok || result.length < 32) revert QProverFailure(_qproverStep);
        value = abi.decode(result, (address));
    }}

    function _readUint(address target, bytes memory data) private view returns (uint256 value) {{
        (bool ok, bytes memory result) = target.staticcall(data);
        if (!ok || result.length < 32) revert QProverFailure(_qproverStep);
        value = abi.decode(result, (uint256));
    }}

    function _scale(uint256 value, uint256 numerator, uint256 denominator) private pure returns (uint256) {{
        require(denominator != 0, "qprover-scale");
        if (value == 0 || numerator == 0) return 0;
        if (value > type(uint256).max / numerator) return type(uint256).max;
        return (value * numerator) / denominator;
    }}

    function _min(uint256 left, uint256 right) private pure returns (uint256) {{
        return left < right ? left : right;
    }}

    function _max(uint256 left, uint256 right) private pure returns (uint256) {{
        return left > right ? left : right;
    }}
{receive_block}}}
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
