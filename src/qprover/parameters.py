"""Deterministic concrete ABI-parameter expansion and bounded SMT solving."""

from __future__ import annotations

import ast
import hashlib
import itertools
import json
import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

import z3

from qprover.expression import ExpressionError, evaluate_expression
from qprover.models import ActionSpec, ArgumentSpec, IntegerDomain, TargetManifest


class ParameterError(ValueError):
    """Raised when a parameter domain cannot be expanded safely."""


@dataclass(frozen=True, slots=True)
class ConcreteValue:
    value: object
    provenance: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ActionVariant:
    action_id: str
    target_id: str
    signature: str
    sender_slot: int
    args: tuple[object, ...]
    value_wei: int
    max_repetitions: int
    argument_provenance: tuple[tuple[str, ...], ...]
    value_provenance: tuple[str, ...]

    @property
    def canonical_id(self) -> str:
        payload = json.dumps(
            {
                "action_id": self.action_id,
                "args": self.args,
                "sender_slot": self.sender_slot,
                "signature": self.signature,
                "target_id": self.target_id,
                "value_wei": self.value_wei,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        return hashlib.sha256(payload.encode()).hexdigest()


_INTEGER_TYPE = re.compile(r"(u?)int([0-9]+)")
_BYTES_TYPE = re.compile(r"bytes([0-9]+)")
_HEX = re.compile(r"0x[0-9a-fA-F]*")
_NUMBER = re.compile(r"\b(?:0x[0-9a-fA-F_]+|[0-9][0-9_]*)\b")
_MAX_EXPONENT = 256
_MAX_SHIFT = 4096


def _integer_bounds(abi_type: str) -> tuple[int, int] | None:
    match = _INTEGER_TYPE.fullmatch(abi_type)
    if match is None:
        return None
    unsigned, width_text = match.groups()
    width = int(width_text)
    if width < 8 or width > 256 or width % 8:
        return None
    if unsigned:
        return 0, (1 << width) - 1
    return -(1 << (width - 1)), (1 << (width - 1)) - 1


def _validate_abi_value(abi_type: str, value: object) -> None:
    integer_bounds = _integer_bounds(abi_type)
    if integer_bounds is not None:
        minimum, maximum = integer_bounds
        if type(value) is not int or not minimum <= value <= maximum:
            raise ParameterError(f"value {value!r} is not ABI-encodable as {abi_type}")
        return
    if abi_type == "bool":
        if type(value) is not bool:
            raise ParameterError(f"value {value!r} is not ABI-encodable as bool")
        return
    if abi_type == "address":
        if (
            not isinstance(value, str)
            or len(value) != 42
            or _HEX.fullmatch(value) is None
        ):
            raise ParameterError(f"value {value!r} is not ABI-encodable as address")
        return
    if abi_type == "string":
        if not isinstance(value, str):
            raise ParameterError(f"value {value!r} is not ABI-encodable as string")
        return
    if abi_type == "bytes":
        if (
            not isinstance(value, str)
            or _HEX.fullmatch(value) is None
            or (len(value) - 2) % 2
        ):
            raise ParameterError(f"value {value!r} is not ABI-encodable as bytes")
        return
    bytes_match = _BYTES_TYPE.fullmatch(abi_type)
    if bytes_match is not None:
        size = int(bytes_match.group(1))
        if not 1 <= size <= 32:
            raise ParameterError(f"unsupported ABI parameter type: {abi_type}")
        if (
            not isinstance(value, str)
            or _HEX.fullmatch(value) is None
            or len(value) != 2 + size * 2
        ):
            raise ParameterError(f"value {value!r} is not ABI-encodable as {abi_type}")
        return
    raise ParameterError(f"unsupported ABI parameter type: {abi_type}")


def _append_candidate(
    candidates: list[ConcreteValue],
    positions: dict[object, int],
    value: object,
    provenance: str,
) -> None:
    try:
        existing = positions.get(value)
    except TypeError as error:
        raise ParameterError(
            "unhashable ABI parameter values are unsupported"
        ) from error
    if existing is None:
        positions[value] = len(candidates)
        candidates.append(ConcreteValue(value, (provenance,)))
        return
    current = candidates[existing]
    if provenance not in current.provenance:
        candidates[existing] = ConcreteValue(
            current.value, current.provenance + (provenance,)
        )


def expand_argument_values(
    argument: ArgumentSpec,
    *,
    source_constants: Iterable[int] = (),
    cap: int = 64,
) -> tuple[ConcreteValue, ...]:
    """Expand one scalar ABI argument without nondeterministic sampling."""

    if type(cap) is not int or cap <= 0:
        raise ParameterError("parameter value cap must be positive")
    candidates: list[ConcreteValue] = []
    positions: dict[object, int] = {}
    domain = argument.domain
    if domain.kind == "finite":
        for value in domain.values:
            _validate_abi_value(argument.type, value)
            _append_candidate(candidates, positions, value, "explicit")
        return tuple(candidates[:cap])

    type_bounds = _integer_bounds(argument.type)
    if type_bounds is None:
        raise ParameterError(
            f"integer domain requires an integer ABI type, got {argument.type}"
        )
    type_minimum, type_maximum = type_bounds
    if domain.minimum < type_minimum or domain.maximum > type_maximum:
        raise ParameterError(
            f"integer domain is outside ABI bounds for {argument.type}"
        )

    if domain.include_boundaries:
        boundary_values = (
            0,
            1,
            type_minimum,
            type_maximum,
            domain.minimum,
            domain.maximum,
            domain.minimum + 1,
            domain.maximum - 1,
        )
        for value in boundary_values:
            if domain.minimum <= value <= domain.maximum:
                _append_candidate(candidates, positions, value, "boundary")
        power = 1
        while power <= domain.maximum and power <= type_maximum:
            if domain.minimum <= power <= domain.maximum:
                _append_candidate(candidates, positions, power, "boundary")
            power <<= 1

    for value in sorted(set(source_constants)):
        if type(value) is int and domain.minimum <= value <= domain.maximum:
            _append_candidate(candidates, positions, value, "constant")

    if not candidates:
        raise ParameterError(f"integer domain for {argument.name} produced no values")
    return tuple(candidates[:cap])


class _ConstraintTranslator:
    def __init__(
        self,
        variables: Mapping[str, z3.ArithRef],
        constants: Mapping[str, int],
        bounds: Mapping[str, tuple[int, int]],
        trees: Sequence[ast.AST],
    ) -> None:
        self.variables = variables
        self.constants = constants
        self.bounds = bounds
        del trees

    def _interval(self, node: ast.AST) -> tuple[int, int] | None:
        """Enclose integer-coerced values on defined evaluation paths.

        Booleans inhabit [0, 1]; and/or retain the selected operand's range.
        An undefined-only operation may use any enclosure (we use [0, 0]):
        translate() separately tracks whether its value can be evaluated.
        None means a finite enclosure could not be established.
        """
        if isinstance(node, ast.Expression):
            return self._interval(node.body)
        if isinstance(node, ast.Constant) and type(node.value) is bool:
            value = int(node.value)
            return value, value
        if isinstance(node, ast.Constant) and type(node.value) is int:
            return node.value, node.value
        if isinstance(node, ast.Name):
            if node.id in self.bounds:
                return self.bounds[node.id]
            if node.id in self.constants:
                value = self.constants[node.id]
                return value, value
            return None
        if isinstance(node, ast.UnaryOp):
            if isinstance(node.op, ast.Not):
                interval = self._interval(node.operand)
                if interval == (0, 0):
                    return 1, 1
                if interval is not None and not interval[0] <= 0 <= interval[1]:
                    return 0, 0
                return 0, 1
            interval = self._interval(node.operand)
            if interval is None:
                return None
            if isinstance(node.op, ast.UAdd):
                return interval
            if isinstance(node.op, ast.USub):
                return -interval[1], -interval[0]
            return None
        if isinstance(node, ast.Compare):
            return 0, 1
        if isinstance(node, ast.BoolOp):
            selected: list[tuple[int, int]] = []
            for index, child in enumerate(node.values):
                interval = self._interval(child)
                if interval is None:
                    return None
                low, high = interval
                if index == len(node.values) - 1:
                    selected.append(interval)
                    break
                if isinstance(node.op, ast.And):
                    if low <= 0 <= high:
                        selected.append((0, 0))
                    if low == high == 0:
                        break
                else:
                    if low < 0:
                        selected.append((low, min(high, -1)))
                    if high > 0:
                        selected.append((max(low, 1), high))
                    if not low <= 0 <= high:
                        break
            return min(low for low, _ in selected), max(high for _, high in selected)
        if not isinstance(node, ast.BinOp):
            return None
        left = self._interval(node.left)
        right = self._interval(node.right)
        if left is None or right is None:
            return None
        left_low, left_high = left
        right_low, right_high = right
        if isinstance(node.op, ast.Add):
            return left_low + right_low, left_high + right_high
        if isinstance(node.op, ast.Sub):
            return left_low - right_high, left_high - right_low
        if isinstance(node.op, ast.Mult):
            products = (
                left_low * right_low,
                left_low * right_high,
                left_high * right_low,
                left_high * right_high,
            )
            return min(products), max(products)
        if isinstance(node.op, ast.Pow):
            if not 0 <= right_low <= right_high <= _MAX_EXPONENT:
                return None
            # Extremes occur at an endpoint (or zero) of the base interval.
            # Both exponent parities are needed for negative bases; their first
            # and last occurrences bound each monotone integer-power family.
            exponents = {right_low, right_high}
            if right_low < right_high:
                exponents.update((right_low + 1, right_high - 1))
            bases = {left_low, left_high}
            bases.update(
                value for value in (-1, 0, 1) if left_low <= value <= left_high
            )
            values = [base**exponent for base in bases for exponent in exponents]
            return min(values), max(values)
        if isinstance(node.op, (ast.LShift, ast.RShift)):
            if not 0 <= right_low <= right_high <= _MAX_SHIFT:
                return None
            if isinstance(node.op, ast.LShift):
                values = [base << count for base in left for count in right]
            else:
                values = [base >> count for base in left for count in right]
            return min(values), max(values)
        if isinstance(node.op, (ast.FloorDiv, ast.Mod)):
            # Exclude zero from each sign interval. Quotient extrema occur at
            # numerator endpoints and divisor endpoints nearest/farthest zero.
            divisors = {value for value in right if value != 0}
            divisors.update(
                value for value in (-1, 1) if right_low <= value <= right_high
            )
            if not divisors:
                return 0, 0
            if isinstance(node.op, ast.FloorDiv):
                values = [base // divisor for base in left for divisor in divisors]
                return min(values), max(values)
            return min(0, right_low + 1), max(0, right_high - 1)
        if isinstance(node.op, (ast.BitAnd, ast.BitOr, ast.BitXor)):
            if left_low == left_high and right_low == right_high:
                if isinstance(node.op, ast.BitAnd):
                    value = left_low & right_low
                elif isinstance(node.op, ast.BitOr):
                    value = left_low | right_low
                else:
                    value = left_low ^ right_low
                return value, value
            if isinstance(node.op, ast.BitAnd):
                nonnegative_highs = [high for low, high in (left, right) if low >= 0]
                if nonnegative_highs:
                    return 0, min(nonnegative_highs)
            magnitude_bits = max(abs(value).bit_length() for value in (*left, *right))
            maximum = (1 << magnitude_bits) - 1
            if left_low >= 0 and right_low >= 0:
                return 0, maximum
            return -(1 << magnitude_bits), maximum
        return None

    @staticmethod
    def _power(
        base: z3.ArithRef, exponent: z3.ArithRef, low: int, high: int
    ) -> z3.ArithRef:
        """Exact bounded exponentiation, with O(log(high)) shared AST nodes."""
        result = z3.IntVal(1)
        factor = base
        for bit in range(high.bit_length()):
            if low == high:
                if high & (1 << bit):
                    result = result * factor
            else:
                result = z3.If(
                    (exponent / (1 << bit)) % 2 == 1, result * factor, result
                )
            if bit + 1 < high.bit_length():
                factor = factor * factor
        return result

    @staticmethod
    def _shift(
        base: z3.ArithRef, count: z3.ArithRef, low: int, high: int, *, left: bool
    ) -> z3.ArithRef:
        """Compose constant shifts selected by count bits, without overflow.

        Repeated floor divisions by positive powers of two compose exactly,
        including negative numerators. At most 13 stages encode count <= 4096.
        """
        result = base
        for bit in range(high.bit_length()):
            if low == high and not high & (1 << bit):
                continue
            factor = z3.IntVal(1 << (1 << bit))
            shifted = result * factor if left else result / factor
            result = (
                shifted
                if low == high
                else z3.If((count / (1 << bit)) % 2 == 1, shifted, result)
            )
        return result

    def _bitwise(
        self,
        node: ast.BinOp,
        left: z3.ArithRef,
        right: z3.ArithRef,
    ) -> z3.ArithRef:
        left_interval = self._interval(node.left)
        right_interval = self._interval(node.right)
        if left_interval is None or right_interval is None:
            raise ParameterError("bitwise operands require statically bounded integers")
        width = (
            max(
                *(
                    abs(value).bit_length()
                    for value in (*left_interval, *right_interval)
                ),
                1,
            )
            + 1
        )
        if width > 4096:
            raise ParameterError("bitwise constraint width exceeds safe exact limit")
        left_bits = z3.Int2BV(left, width)
        right_bits = z3.Int2BV(right, width)
        if isinstance(node.op, ast.BitAnd):
            result = left_bits & right_bits
        elif isinstance(node.op, ast.BitOr):
            result = left_bits | right_bits
        else:
            result = left_bits ^ right_bits
        return z3.BV2Int(result, is_signed=True)

    @staticmethod
    def _truth(value: z3.ExprRef) -> z3.BoolRef:
        if z3.is_bool(value):
            return value
        if z3.is_arith(value):
            return value != 0
        raise ParameterError("boolean constraint operand must be integer or boolean")

    @staticmethod
    def _integer(value: z3.ExprRef) -> z3.ArithRef:
        if z3.is_arith(value):
            return value
        if z3.is_bool(value):
            return z3.If(value, z3.IntVal(1), z3.IntVal(0))
        raise ParameterError("arithmetic constraint operand must be integer or boolean")

    @classmethod
    def _compatible(
        cls, left: z3.ExprRef, right: z3.ExprRef
    ) -> tuple[z3.ExprRef, z3.ExprRef]:
        if z3.is_bool(left) and z3.is_bool(right):
            return left, right
        return cls._integer(left), cls._integer(right)

    @classmethod
    def _select(
        cls,
        condition: z3.BoolRef,
        when_true: z3.ExprRef,
        when_false: z3.ExprRef,
    ) -> z3.ExprRef:
        when_true, when_false = cls._compatible(when_true, when_false)
        return z3.If(condition, when_true, when_false)

    def translate(self, node: ast.AST) -> tuple[z3.ExprRef, z3.BoolRef]:
        if isinstance(node, ast.Expression):
            return self.translate(node.body)
        if isinstance(node, ast.Constant):
            if type(node.value) is bool:
                return z3.BoolVal(node.value), z3.BoolVal(True)
            if type(node.value) is not int:
                raise ParameterError("constraints allow only integer/boolean constants")
            return z3.IntVal(node.value), z3.BoolVal(True)
        if isinstance(node, ast.Name):
            if node.id in self.variables:
                return self.variables[node.id], z3.BoolVal(True)
            if node.id in self.constants:
                return z3.IntVal(self.constants[node.id]), z3.BoolVal(True)
            raise ParameterError(f"unknown constraint name: {node.id}")
        if isinstance(node, ast.UnaryOp):
            operand, defined = self.translate(node.operand)
            if isinstance(node.op, ast.UAdd):
                return self._integer(operand), defined
            if isinstance(node.op, ast.USub):
                return -self._integer(operand), defined
            if isinstance(node.op, ast.Not):
                return z3.Not(self._truth(operand)), defined
            raise ParameterError("unsupported unary constraint operator")
        if isinstance(node, ast.BinOp):
            left, left_defined = self.translate(node.left)
            right, right_defined = self.translate(node.right)
            defined = z3.And(left_defined, right_defined)
            left, right = self._integer(left), self._integer(right)
            if isinstance(node.op, ast.Add):
                return left + right, defined
            if isinstance(node.op, ast.Sub):
                return left - right, defined
            if isinstance(node.op, ast.Mult):
                return left * right, defined
            if isinstance(node.op, ast.Div):
                raise ParameterError("unsupported binary constraint operator: Div")
            if isinstance(node.op, (ast.FloorDiv, ast.Mod)):
                defined = z3.And(defined, right != 0)
                quotient = z3.If(right > 0, left / right, (-left) / (-right))
                if isinstance(node.op, ast.FloorDiv):
                    return quotient, defined
                return left - quotient * right, defined
            if isinstance(node.op, ast.Pow):
                exponent_interval = self._interval(node.right)
                if exponent_interval is None or not (
                    0 <= exponent_interval[0] <= exponent_interval[1] <= _MAX_EXPONENT
                ):
                    raise ParameterError(
                        f"constraint exponent must be in [0, {_MAX_EXPONENT}]"
                    )
                low, high = exponent_interval
                return self._power(left, right, low, high), defined
            if isinstance(node.op, (ast.LShift, ast.RShift)):
                count_interval = self._interval(node.right)
                if count_interval is None or not (
                    0 <= count_interval[0] <= count_interval[1] <= _MAX_SHIFT
                ):
                    raise ParameterError(
                        f"constraint shift must be in [0, {_MAX_SHIFT}]"
                    )
                return self._shift(
                    left, right, *count_interval, left=isinstance(node.op, ast.LShift)
                ), defined
            if isinstance(node.op, (ast.BitAnd, ast.BitOr, ast.BitXor)):
                return self._bitwise(node, left, right), defined
            raise ParameterError("unsupported binary constraint operator")
        if isinstance(node, ast.BoolOp):
            first_value, first_defined = self.translate(node.values[0])
            result = first_value
            defined = first_defined
            if isinstance(node.op, ast.And):
                for child in node.values[1:]:
                    child_value, child_defined = self.translate(child)
                    truth = self._truth(result)
                    defined = z3.And(
                        defined,
                        z3.Or(z3.Not(truth), child_defined),
                    )
                    result = self._select(truth, child_value, result)
                return result, defined
            if not isinstance(node.op, ast.Or):
                raise ParameterError("unsupported boolean constraint operator")
            for child in node.values[1:]:
                child_value, child_defined = self.translate(child)
                truth = self._truth(result)
                defined = z3.And(defined, z3.Or(truth, child_defined))
                result = self._select(truth, result, child_value)
            return result, defined
        if isinstance(node, ast.Compare):
            left, defined = self.translate(node.left)
            truth = z3.BoolVal(True)
            for operator, comparator in zip(node.ops, node.comparators, strict=True):
                right, right_defined = self.translate(comparator)
                defined = z3.And(defined, z3.Or(z3.Not(truth), right_defined))
                if isinstance(operator, ast.Eq):
                    comparable_left, comparable_right = self._compatible(left, right)
                    comparison = comparable_left == comparable_right
                elif isinstance(operator, ast.NotEq):
                    comparable_left, comparable_right = self._compatible(left, right)
                    comparison = comparable_left != comparable_right
                elif isinstance(operator, ast.Lt):
                    comparable_left, comparable_right = (
                        self._integer(left),
                        self._integer(right),
                    )
                    comparison = comparable_left < comparable_right
                elif isinstance(operator, ast.LtE):
                    comparable_left, comparable_right = (
                        self._integer(left),
                        self._integer(right),
                    )
                    comparison = comparable_left <= comparable_right
                elif isinstance(operator, ast.Gt):
                    comparable_left, comparable_right = (
                        self._integer(left),
                        self._integer(right),
                    )
                    comparison = comparable_left > comparable_right
                elif isinstance(operator, ast.GtE):
                    comparable_left, comparable_right = (
                        self._integer(left),
                        self._integer(right),
                    )
                    comparison = comparable_left >= comparable_right
                else:
                    raise ParameterError("unsupported comparison operator")
                truth = z3.And(truth, comparison)
                left = right
            return truth, defined
        raise ParameterError(f"unsupported constraint syntax: {type(node).__name__}")


def _lexicographic_model(
    solver: z3.Solver,
    names: tuple[str, ...],
    variables: Mapping[str, z3.ArithRef],
    bounds: Mapping[str, tuple[int, int]],
) -> tuple[int, ...] | None:
    if solver.check() != z3.sat:
        return None
    values: list[int] = []
    solver.push()
    try:
        for name in names:
            low, high = bounds[name]
            while low < high:
                middle = (low + high) // 2
                solver.push()
                solver.add(variables[name] <= middle)
                satisfiable = solver.check() == z3.sat
                solver.pop()
                if satisfiable:
                    high = middle
                else:
                    low = middle + 1
            values.append(low)
            solver.add(variables[name] == low)
        if solver.check() != z3.sat:
            raise ParameterError("internal deterministic model selection failure")
        return tuple(values)
    finally:
        solver.pop()


def solve_integer_domain(
    *,
    names: tuple[str, ...],
    constraints: tuple[str, ...],
    bounds: Mapping[str, tuple[int, int]],
    max_models: int,
    constants: Mapping[str, int] | None = None,
) -> tuple[tuple[int, ...], ...]:
    """Enumerate lexicographically stable, explicitly blocked bounded models."""

    if not names or len(set(names)) != len(names):
        raise ParameterError("constraint variable names must be nonempty and unique")
    if type(max_models) is not int or max_models <= 0:
        raise ParameterError("max_models must be positive")
    if set(bounds) != set(names):
        raise ParameterError("every constraint variable must have exactly one bound")
    for name in names:
        minimum, maximum = bounds[name]
        if type(minimum) is not int or type(maximum) is not int or minimum > maximum:
            raise ParameterError(f"invalid bounds for {name}")
    constants = dict(constants or {})
    if set(constants).intersection(names):
        raise ParameterError("constant names cannot shadow variables")
    if not all(type(value) is int for value in constants.values()):
        raise ParameterError("constraint constants must be integers")
    try:
        trees = tuple(ast.parse(source, mode="eval") for source in constraints)
    except SyntaxError as error:
        raise ParameterError("invalid constraint syntax") from error

    variables = {name: z3.Int(name) for name in names}
    translator = _ConstraintTranslator(variables, constants, bounds, trees)
    solver = z3.Solver()
    for name in names:
        minimum, maximum = bounds[name]
        solver.add(variables[name] >= minimum, variables[name] <= maximum)
    for tree in trees:
        expression, defined = translator.translate(tree)
        solver.add(defined, translator._truth(expression))

    models: list[tuple[int, ...]] = []
    while len(models) < max_models:
        values = _lexicographic_model(solver, names, variables, bounds)
        if values is None:
            break
        concrete = dict(constants)
        concrete.update(zip(names, values, strict=True))
        try:
            results = tuple(
                evaluate_expression(source, concrete) for source in constraints
            )
        except ExpressionError as error:
            raise ParameterError(
                "constraint differs from invariant expression semantics"
            ) from error
        if any(
            result.status != "evaluated" or not bool(result.value) for result in results
        ):
            raise ParameterError("SMT model failed concrete semantic revalidation")
        models.append(values)
        solver.add(
            z3.Or(
                *(
                    variables[name] != value
                    for name, value in zip(names, values, strict=True)
                )
            )
        )
    return tuple(models)


def _strip_comments_and_strings(source: str) -> str:
    return re.sub(
        r'//[^\n]*|/\*.*?\*/|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'',
        " ",
        source,
        flags=re.DOTALL,
    )


def _function_source(source: str, signature: str) -> str:
    name = signature.split("(", maxsplit=1)[0]
    match = re.search(rf"\bfunction\s+{re.escape(name)}\s*\(", source)
    if match is None:
        return ""
    opening = source.find("{", match.end())
    if opening < 0:
        return ""
    depth = 0
    for position in range(opening, len(source)):
        if source[position] == "{":
            depth += 1
        elif source[position] == "}":
            depth -= 1
            if depth == 0:
                return source[match.start() : position + 1]
    return ""


def _source_constants(
    manifest: TargetManifest, action: ActionSpec, report: object
) -> tuple[int, ...]:
    deployment = next(
        item for item in manifest.deployments if item.id == action.target_id
    )
    source_name, contract_name = deployment.artifact.rsplit(":", maxsplit=1)
    segment = ""
    contracts = getattr(report, "contracts", ())
    deployed_contract = next(
        (
            item
            for item in contracts
            if item.name == contract_name and item.source_name == source_name
        ),
        None,
    )
    linearization = getattr(deployed_contract, "linearized_base_contracts", ())
    candidates = [
        function
        for contract in contracts
        if contract.name == contract_name or contract.canonical_id in linearization
        for function in contract.functions
        if function.signature == action.signature
    ]
    if len(candidates) == 1:
        function = candidates[0]
        source_path = next(
            (
                path
                for path in manifest.target.source_files
                if path.resolve()
                .relative_to(manifest.target.project_root.resolve())
                .as_posix()
                == function.source_name
            ),
            None,
        )
        if source_path is not None:
            raw = source_path.read_bytes()
            try:
                start_text, length_text, _ = function.source_span.split(":")
                start, length = int(start_text), int(length_text)
                segment = raw[start : start + length].decode("utf-8")
            except (UnicodeDecodeError, ValueError):
                segment = ""
    if not segment:
        path = next(
            (
                item
                for item in manifest.target.source_files
                if item.name == Path(source_name).name
            ),
            None,
        )
        if path is not None:
            try:
                segment = _function_source(
                    path.read_text(encoding="utf-8"), action.signature
                )
            except OSError as error:
                raise ParameterError(f"cannot read source constants: {path}") from error
    cleaned = _strip_comments_and_strings(segment)
    values = {int(token.replace("_", ""), 0) for token in _NUMBER.findall(cleaned)}
    return tuple(sorted(values))


def _z3_argument_products(
    action: ActionSpec,
    expanded: list[tuple[ConcreteValue, ...]],
    *,
    cap: int,
) -> tuple[tuple[ConcreteValue, ...], ...] | None:
    constrained = [
        (index, argument)
        for index, argument in enumerate(action.arguments)
        if isinstance(argument.domain, IntegerDomain) and argument.domain.constraints
    ]
    if not constrained:
        return None
    integer_arguments = [
        (index, argument)
        for index, argument in enumerate(action.arguments)
        if isinstance(argument.domain, IntegerDomain)
    ]
    names = tuple(f"arg{index}" for index, _ in integer_arguments)
    bounds = {
        name: (argument.domain.minimum, argument.domain.maximum)
        for name, (_, argument) in zip(names, integer_arguments, strict=True)
    }
    constraints = tuple(
        expression
        for _, argument in constrained
        for expression in argument.domain.constraints
    )
    models = solve_integer_domain(
        names=names,
        constraints=constraints,
        bounds=bounds,
        max_models=cap,
    )
    if not models:
        raise ParameterError(f"constraints for action {action.id} are unsatisfiable")
    integer_indexes = {index for index, _ in integer_arguments}
    unconstrained_indexes = tuple(
        index for index in range(len(action.arguments)) if index not in integer_indexes
    )
    unconstrained_products = tuple(
        itertools.product(*(expanded[index] for index in unconstrained_indexes))
    ) or ((),)
    products: list[tuple[ConcreteValue, ...]] = []
    for model in models:
        integer_values: dict[int, ConcreteValue] = {}
        for (index, _), value in zip(integer_arguments, model, strict=True):
            existing = {item.value: item for item in expanded[index]}
            previous = existing.get(value)
            provenance = previous.provenance if previous else ()
            if "z3" not in provenance:
                provenance += ("z3",)
            integer_values[index] = ConcreteValue(value, provenance)
        for unconstrained in unconstrained_products:
            free_values = dict(zip(unconstrained_indexes, unconstrained, strict=True))
            products.append(
                tuple(
                    integer_values.get(index, free_values.get(index))
                    for index in range(len(action.arguments))
                )
            )
            if len(products) == cap:
                return tuple(products)
    return tuple(products)


def expand_action_variants(
    manifest: TargetManifest,
    report: object,
) -> tuple[ActionVariant, ...]:
    """Build a globally capped, deterministic Cartesian product of allowed calls."""

    variants: list[ActionVariant] = []
    cap = manifest.limits.max_variants
    for action in manifest.actions:
        constants = _source_constants(manifest, action, report)
        expanded = [
            expand_argument_values(argument, source_constants=constants, cap=cap)
            for argument in action.arguments
        ]
        z3_products = _z3_argument_products(action, expanded, cap=cap)
        value_candidates: list[ConcreteValue] = []
        value_positions: dict[object, int] = {}
        for value in action.value_domain.values:
            _validate_abi_value("uint256", value)
            _append_candidate(value_candidates, value_positions, value, "explicit")
        for sender_slot in sorted(set(action.sender_slots)):
            argument_products = (
                iter(z3_products)
                if z3_products is not None
                else itertools.product(*expanded)
                if expanded
                else iter(((),))
            )
            for arguments in argument_products:
                for call_value in value_candidates:
                    variants.append(
                        ActionVariant(
                            action_id=action.id,
                            target_id=action.target_id,
                            signature=action.signature,
                            sender_slot=sender_slot,
                            args=tuple(item.value for item in arguments),
                            value_wei=call_value.value,
                            max_repetitions=action.max_repetitions,
                            argument_provenance=tuple(
                                item.provenance for item in arguments
                            ),
                            value_provenance=call_value.provenance,
                        )
                    )
                    if len(variants) == cap:
                        return tuple(variants)
    return tuple(variants)
