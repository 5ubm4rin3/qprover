"""Safe evaluator for manifest-supplied integer and boolean invariants."""

from __future__ import annotations

import ast
import operator
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Literal


class ExpressionError(ValueError):
    """Raised for malformed or non-whitelisted invariant syntax."""


@dataclass(frozen=True, slots=True)
class ExpressionResult:
    status: Literal["evaluated", "inconclusive"]
    value: int | bool | None
    reason: str | None = None


class _MissingObservation(Exception):
    def __init__(self, name: str) -> None:
        self.name = name


_BINARY_OPERATORS = {
    ast.Add: operator.add,
    ast.Sub: operator.sub,
    ast.Mult: operator.mul,
    ast.FloorDiv: operator.floordiv,
    ast.Mod: operator.mod,
    ast.BitAnd: operator.and_,
    ast.BitOr: operator.or_,
    ast.BitXor: operator.xor,
    ast.LShift: operator.lshift,
    ast.RShift: operator.rshift,
}
_COMPARISON_OPERATORS = {
    ast.Eq: operator.eq,
    ast.NotEq: operator.ne,
    ast.Lt: operator.lt,
    ast.LtE: operator.le,
    ast.Gt: operator.gt,
    ast.GtE: operator.ge,
}
_MAX_EXPONENT = 256
_MAX_SHIFT = 4096


def _validate_node(node: ast.AST) -> None:
    if isinstance(node, ast.Expression):
        _validate_node(node.body)
        return
    if isinstance(node, ast.Constant):
        if type(node.value) not in (int, bool):
            raise ExpressionError("only integer and boolean constants are allowed")
        return
    if isinstance(node, ast.Name):
        return
    if isinstance(node, ast.UnaryOp):
        if not isinstance(node.op, (ast.Not, ast.UAdd, ast.USub)):
            raise ExpressionError(
                f"unsupported unary operator: {type(node.op).__name__}"
            )
        _validate_node(node.operand)
        return
    if isinstance(node, ast.BoolOp):
        if not isinstance(node.op, (ast.And, ast.Or)):
            raise ExpressionError(
                f"unsupported boolean operator: {type(node.op).__name__}"
            )
        for value in node.values:
            _validate_node(value)
        return
    if isinstance(node, ast.BinOp):
        if not isinstance(node.op, (*_BINARY_OPERATORS, ast.Pow)):
            raise ExpressionError(
                f"unsupported binary operator: {type(node.op).__name__}"
            )
        _validate_node(node.left)
        _validate_node(node.right)
        return
    if isinstance(node, ast.Compare):
        if not all(isinstance(item, tuple(_COMPARISON_OPERATORS)) for item in node.ops):
            raise ExpressionError("unsupported comparison operator")
        _validate_node(node.left)
        for comparator in node.comparators:
            _validate_node(comparator)
        return
    raise ExpressionError(f"unsafe expression node: {type(node).__name__}")


def _evaluate(node: ast.AST, values: Mapping[str, int | bool]) -> int | bool:
    if isinstance(node, ast.Expression):
        return _evaluate(node.body, values)
    if isinstance(node, ast.Constant):
        return node.value
    if isinstance(node, ast.Name):
        try:
            return values[node.id]
        except KeyError as error:
            raise _MissingObservation(node.id) from error
    if isinstance(node, ast.UnaryOp):
        operand = _evaluate(node.operand, values)
        if isinstance(node.op, ast.Not):
            return not operand
        if isinstance(node.op, ast.UAdd):
            return +operand
        return -operand
    if isinstance(node, ast.BoolOp):
        result = _evaluate(node.values[0], values)
        if isinstance(node.op, ast.And):
            for value in node.values[1:]:
                if not result:
                    return result
                result = _evaluate(value, values)
            return result
        for value in node.values[1:]:
            if result:
                return result
            result = _evaluate(value, values)
        return result
    if isinstance(node, ast.BinOp):
        left = _evaluate(node.left, values)
        right = _evaluate(node.right, values)
        if isinstance(node.op, ast.Pow):
            if not isinstance(right, int) or not 0 <= right <= _MAX_EXPONENT:
                raise ExpressionError(
                    f"exponent must be between 0 and {_MAX_EXPONENT}"
                )
            return operator.pow(left, right)
        if (
            isinstance(node.op, (ast.LShift, ast.RShift))
            and not 0 <= right <= _MAX_SHIFT
        ):
            raise ExpressionError(f"shift must be between 0 and {_MAX_SHIFT}")
        operation = _BINARY_OPERATORS[type(node.op)]
        return operation(left, right)
    if isinstance(node, ast.Compare):
        left = _evaluate(node.left, values)
        for comparison, comparator_node in zip(node.ops, node.comparators, strict=True):
            right = _evaluate(comparator_node, values)
            if not _COMPARISON_OPERATORS[type(comparison)](left, right):
                return False
            left = right
        return True
    raise AssertionError(f"validated node was not handled: {type(node).__name__}")


def evaluate_expression(
    expression: str, values: Mapping[str, int | bool]
) -> ExpressionResult:
    """Evaluate a whitelisted invariant without executing Python code."""

    for name, value in values.items():
        if type(value) not in (int, bool):
            raise ExpressionError(f"observation {name!r} must be an int or bool")
    try:
        parsed = ast.parse(expression, mode="eval")
    except SyntaxError as error:
        raise ExpressionError(f"invalid expression syntax: {error.msg}") from error
    _validate_node(parsed)
    try:
        value = _evaluate(parsed, values)
    except _MissingObservation as error:
        return ExpressionResult(
            status="inconclusive",
            value=None,
            reason=f"missing observation: {error.name}",
        )
    except ZeroDivisionError:
        return ExpressionResult(
            status="inconclusive", value=None, reason="division by zero"
        )
    return ExpressionResult(status="evaluated", value=value)
