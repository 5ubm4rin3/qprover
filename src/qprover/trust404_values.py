"""Typed contextual value expressions for TRUST404 Track 04."""

from __future__ import annotations

import hashlib
import itertools
import json
import re
from dataclasses import dataclass

from qprover.parameters import ParameterError, solve_integer_domain


class ValueExpr:
    """Marker base for deterministic Track04 parameter expressions."""


@dataclass(frozen=True, slots=True)
class Const(ValueExpr):
    value: object


@dataclass(frozen=True, slots=True)
class SelfAddress(ValueExpr):
    pass


@dataclass(frozen=True, slots=True)
class TargetAddress(ValueExpr):
    pass


@dataclass(frozen=True, slots=True)
class ContractAddress(ValueExpr):
    instance_id: str
    access_path: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class ReadUint(ValueExpr):
    instance_id: str
    signature: str
    args: tuple[ValueExpr, ...] = ()


@dataclass(frozen=True, slots=True)
class PreviousReturn(ValueExpr):
    step_index: int
    return_index: int


@dataclass(frozen=True, slots=True)
class Scale(ValueExpr):
    value: ValueExpr
    numerator: int
    denominator: int

    def __post_init__(self) -> None:
        if type(self.numerator) is not int or self.numerator < 0:
            raise ValueError("scale numerator must be a nonnegative integer")
        if type(self.denominator) is not int or self.denominator <= 0:
            raise ValueError("scale denominator must be a positive integer")


@dataclass(frozen=True, slots=True)
class Add(ValueExpr):
    left: ValueExpr
    right: ValueExpr


@dataclass(frozen=True, slots=True)
class Sub(ValueExpr):
    left: ValueExpr
    right: ValueExpr


@dataclass(frozen=True, slots=True)
class Min(ValueExpr):
    left: ValueExpr
    right: ValueExpr


@dataclass(frozen=True, slots=True)
class Max(ValueExpr):
    left: ValueExpr
    right: ValueExpr


@dataclass(frozen=True, slots=True)
class CallInstruction:
    target: ContractAddress | TargetAddress
    signature: str
    args: tuple[ValueExpr, ...] = ()
    value: ValueExpr = Const(0)


@dataclass(frozen=True, slots=True)
class CallbackProgram:
    trigger_context: str
    instructions: tuple[CallInstruction, ...]
    depth_budget: int = 1

    def __post_init__(self) -> None:
        if not self.trigger_context:
            raise ValueError("callback trigger context must be nonempty")
        if type(self.depth_budget) is not int or self.depth_budget <= 0:
            raise ValueError("callback depth budget must be positive")


@dataclass(frozen=True, slots=True)
class ValueStep:
    action_id: str
    target_instance_id: str
    signature: str
    args: tuple[ValueExpr, ...]
    value_wei: int
    sender_slot: int = 0
    callback_program: CallbackProgram | None = None

    @property
    def target_id(self) -> str:
        return self.target_instance_id


def _expr_record(value: object) -> object:
    if isinstance(value, Const):
        return {"kind": "const", "value": value.value}
    if isinstance(value, SelfAddress):
        return {"kind": "self"}
    if isinstance(value, TargetAddress):
        return {"kind": "target"}
    if isinstance(value, ContractAddress):
        return {
            "kind": "contract",
            "instance": value.instance_id,
            "path": value.access_path,
        }
    if isinstance(value, ReadUint):
        return {
            "kind": "read_uint",
            "instance": value.instance_id,
            "signature": value.signature,
            "args": tuple(_expr_record(item) for item in value.args),
        }
    if isinstance(value, PreviousReturn):
        return {
            "kind": "previous_return",
            "step": value.step_index,
            "index": value.return_index,
        }
    if isinstance(value, Scale):
        return {
            "kind": "scale",
            "value": _expr_record(value.value),
            "numerator": value.numerator,
            "denominator": value.denominator,
        }
    if isinstance(value, (Add, Sub, Min, Max)):
        return {
            "kind": type(value).__name__.lower(),
            "left": _expr_record(value.left),
            "right": _expr_record(value.right),
        }
    if isinstance(value, CallbackProgram):
        return {
            "kind": "callback",
            "trigger": value.trigger_context,
            "depth": value.depth_budget,
            "instructions": tuple(_expr_record(item) for item in value.instructions),
        }
    if isinstance(value, CallInstruction):
        return {
            "kind": "call",
            "target": _expr_record(value.target),
            "signature": value.signature,
            "args": tuple(_expr_record(item) for item in value.args),
            "value": _expr_record(value.value),
        }
    if value is None or type(value) in (bool, int, str):
        return value
    if isinstance(value, tuple):
        return tuple(_expr_record(item) for item in value)
    return repr(value)


@dataclass(frozen=True, slots=True)
class ValueCandidate:
    steps: tuple[ValueStep, ...]

    @property
    def canonical_id(self) -> str:
        payload = [
            {
                "action_id": step.action_id,
                "target_instance_id": step.target_instance_id,
                "signature": step.signature,
                "args": tuple(_expr_record(item) for item in step.args),
                "value_wei": step.value_wei,
                "callback": _expr_record(step.callback_program),
            }
            for step in self.steps
        ]
        encoded = json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            default=str,
        )
        return hashlib.sha256(encoded.encode()).hexdigest()


_INTEGER = re.compile(r"(u?)int([0-9]*)")


def _integer_bounds(abi_type: str) -> tuple[int, int] | None:
    match = _INTEGER.fullmatch(abi_type)
    if match is None:
        return None
    unsigned, width_text = match.groups()
    width = int(width_text) if width_text else 256
    if width < 8 or width > 256 or width % 8:
        return None
    if unsigned:
        return 0, (1 << width) - 1
    return -(1 << (width - 1)), (1 << (width - 1)) - 1


def _step_target(step: object) -> str:
    value = getattr(step, "target_instance_id", None)
    if isinstance(value, str) and value:
        return value
    target_id = getattr(step, "target_id", None)
    if isinstance(target_id, str) and target_id not in {"target", "root"}:
        return target_id
    return "instance:root"


def _actions(analysis: object) -> dict[str, object]:
    direct = tuple(getattr(analysis, "actions", ()))
    if direct:
        return {str(item.id): item for item in direct}
    model = getattr(analysis, "model", None)
    direct = tuple(getattr(model, "actions", ())) if model is not None else ()
    return {str(item.id): item for item in direct}


def _function_fact(analysis: object, action: object) -> object | None:
    function_id = getattr(action, "function_id", None)
    roots = (
        getattr(analysis, "analysis", None),
        getattr(analysis, "report", None),
        analysis,
    )
    for root in roots:
        report = getattr(root, "report", root)
        for contract in getattr(report, "contracts", ()):
            for function in getattr(contract, "functions", ()):
                if getattr(function, "canonical_id", None) == function_id:
                    return function
    return None


def _constraints(analysis: object, action: object) -> tuple[object, ...]:
    direct = tuple(getattr(analysis, "parameter_constraints", ()))
    function_id = getattr(action, "function_id", None)
    selected = tuple(
        item
        for item in direct
        if getattr(item, "action_id", None) in {None, getattr(action, "id", None)}
        and getattr(item, "function_id", None) in {None, function_id}
    )
    if selected:
        return selected
    function = _function_fact(analysis, action)
    return tuple(getattr(function, "parameter_constraints", ())) if function else ()


def _constraint_models(
    abi_type: str,
    parameter_index: int,
    constraints: tuple[object, ...],
    limit: int,
) -> tuple[Const, ...]:
    bounds = _integer_bounds(abi_type)
    if bounds is None:
        return ()
    relevant = tuple(
        item
        for item in constraints
        if getattr(item, "parameter_index", None) == parameter_index
        and getattr(item, "operator", None) in {"<", "<=", ">", ">=", "==", "!="}
        and type(getattr(item, "constant", None)) is int
    )
    if not relevant:
        return ()
    sources = tuple(f"arg0 {item.operator} {item.constant}" for item in relevant)
    try:
        models = solve_integer_domain(
            names=("arg0",),
            constraints=sources,
            bounds={"arg0": bounds},
            max_models=max(1, min(limit, 4)),
        )
    except ParameterError:
        return ()
    return tuple(Const(model[0]) for model in models)


def _address_domain(
    steps: tuple[object, ...],
    index: int,
    state: object,
) -> tuple[ValueExpr, ...]:
    values: list[ValueExpr] = []

    def add(value: ValueExpr) -> None:
        if value not in values:
            values.append(value)

    if index + 1 < len(steps):
        add(ContractAddress(_step_target(steps[index + 1])))
    for prior in reversed(steps[:index]):
        add(ContractAddress(_step_target(prior)))
    add(SelfAddress())
    add(TargetAddress())

    instances = tuple(getattr(state, "runtime_instances", ()))
    for item in sorted(
        instances,
        key=lambda value: str(getattr(value, "instance_id", value)),
    ):
        identity = getattr(item, "instance_id", item)
        if isinstance(identity, str):
            paths = tuple(getattr(item, "discovery_paths", ()))
            path = paths[0] if paths else ()
            add(ContractAddress(identity, tuple(path)))
    return tuple(values)


def _uint_domain(
    action: object,
    step: object,
    parameter_index: int,
    abi_type: str,
    state: object,
    analysis: object,
    limit: int,
) -> tuple[ValueExpr, ...]:
    reads = set(getattr(action, "storage_reads", ()))
    writes = set(getattr(action, "storage_writes", ()))
    target = _step_target(step)
    sources = tuple(getattr(state, "runtime_uint_sources", ()))

    def rank(source: object) -> tuple[int, int, str, str]:
        overlap = len(set(getattr(source, "reads", ())) & (reads | writes))
        same_target = int(getattr(source, "instance_id", "") == target)
        return (
            -overlap,
            -same_target,
            str(getattr(source, "instance_id", "")),
            str(getattr(source, "signature", "")),
        )

    result: list[ValueExpr] = []

    def add(value: ValueExpr) -> None:
        if value not in result:
            result.append(value)

    for source in sorted(sources, key=rank):
        mode = getattr(source, "argument_mode", "none")
        args: tuple[ValueExpr, ...]
        if mode == "self":
            args = (SelfAddress(),)
        elif mode == "none":
            args = ()
        else:
            continue
        read = ReadUint(
            str(getattr(source, "instance_id", target)),
            str(getattr(source, "signature", "")),
            args,
        )
        if not read.signature:
            continue
        add(read)
        add(Scale(read, 1, 2))
        add(Scale(read, 2, 1))
        if len(result) >= limit:
            return tuple(result[:limit])

    for item in tuple(getattr(state, "previous_returns", ())):
        step_index = getattr(item, "step_index", None)
        return_index = getattr(item, "return_index", None)
        if type(step_index) is int and type(return_index) is int:
            add(PreviousReturn(step_index, return_index))

    for value in _constraint_models(
        abi_type,
        parameter_index,
        _constraints(analysis, action),
        limit,
    ):
        add(value)

    constants = tuple(getattr(analysis, "source_constants", ()))
    for value in sorted({value for value in constants if type(value) is int}):
        add(Const(value))

    bounds = _integer_bounds(abi_type)
    if bounds is not None:
        minimum, maximum = bounds
        for value in (1, 0, maximum, minimum):
            if minimum <= value <= maximum:
                add(Const(value))
    return tuple(result[:limit])


def _fallback_domain(abi_type: str) -> tuple[ValueExpr, ...]:
    if abi_type == "bool":
        return (Const(False), Const(True))
    if abi_type == "bytes":
        return (Const("0x"),)
    if abi_type == "string":
        return (Const(""),)
    match = re.fullmatch(r"bytes([0-9]+)", abi_type)
    if match:
        return (Const("0x" + "00" * int(match.group(1))),)
    return ()


def _parameter_domains(
    steps: tuple[object, ...],
    index: int,
    state: object,
    analysis: object,
    limit: int,
) -> tuple[tuple[ValueExpr, ...], ...]:
    actions = _actions(analysis)
    step = steps[index]
    action = actions.get(str(step.action_id))
    if action is None:
        return ()
    domains: list[tuple[ValueExpr, ...]] = []
    for parameter_index, abi_type in enumerate(
        tuple(getattr(action, "param_types", ()))
    ):
        if abi_type == "address":
            domain = _address_domain(steps, index, state)
        elif _integer_bounds(abi_type) is not None:
            domain = _uint_domain(
                action,
                step,
                parameter_index,
                abi_type,
                state,
                analysis,
                limit,
            )
        else:
            domain = _fallback_domain(abi_type)
        if not domain:
            return ()
        domains.append(domain)
    return tuple(domains)


def _products(
    domains: tuple[tuple[ValueExpr, ...], ...],
    limit: int,
) -> tuple[tuple[ValueExpr, ...], ...]:
    if not domains:
        return ((),)
    baseline = tuple(domain[0] for domain in domains)
    result: list[tuple[ValueExpr, ...]] = [baseline]
    if limit == 1:
        return tuple(result)
    max_rank = max(len(domain) for domain in domains)
    for rank in range(1, max_rank):
        value = tuple(domain[min(rank, len(domain) - 1)] for domain in domains)
        if value not in result:
            result.append(value)
        if len(result) >= limit:
            return tuple(result)
    for values in itertools.product(*domains):
        value = tuple(values)
        if value not in result:
            result.append(value)
        if len(result) >= limit:
            break
    return tuple(result)


def complete_parameters(
    skeleton: object,
    state: object,
    analysis: object,
    limit: int,
) -> tuple[ValueCandidate, ...]:
    """Complete one skeleton with deterministic contextual typed expressions."""

    if type(limit) is not int or limit <= 0:
        return ()
    steps = tuple(getattr(skeleton, "steps", ()))
    if not steps:
        return ()
    per_step = tuple(
        _products(_parameter_domains(steps, index, state, analysis, limit), limit)
        for index in range(len(steps))
    )
    if any(not domain for domain in per_step):
        return ()

    candidates: list[ValueCandidate] = []
    seen: set[str] = set()
    for selected in itertools.product(*per_step):
        mutable_steps = [
            ValueStep(
                action_id=str(step.action_id),
                target_instance_id=_step_target(step),
                signature=str(step.signature),
                args=tuple(args),
                value_wei=int(getattr(step, "value_wei", 0)),
                sender_slot=int(getattr(step, "sender_slot", 0)),
            )
            for step, args in zip(steps, selected, strict=True)
        ]
        actions = _actions(analysis)
        for index in range(len(mutable_steps) - 1):
            current = mutable_steps[index]
            action = actions.get(current.action_id)
            if not bool(getattr(action, "callback_enabled", False)):
                continue
            following = mutable_steps[index + 1]
            program = CallbackProgram(
                trigger_context="receive_or_fallback",
                instructions=(
                    CallInstruction(
                        target=ContractAddress(following.target_instance_id),
                        signature=following.signature,
                        args=following.args,
                        value=Const(following.value_wei),
                    ),
                ),
                depth_budget=1,
            )
            mutable_steps[index] = ValueStep(
                action_id=current.action_id,
                target_instance_id=current.target_instance_id,
                signature=current.signature,
                args=current.args,
                value_wei=current.value_wei,
                sender_slot=current.sender_slot,
                callback_program=program,
            )
        candidate = ValueCandidate(tuple(mutable_steps))
        if candidate.canonical_id in seen:
            continue
        seen.add(candidate.canonical_id)
        candidates.append(candidate)
        if len(candidates) >= limit:
            break
    return tuple(candidates)
