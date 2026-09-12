import pytest

from qprover.expression import ExpressionError, evaluate_expression


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        ("assets + 3 * shares", 17),
        ("assets // shares", 1),
        ("assets % shares", 1),
        ("2 ** shares", 16),
        ("assets & 6", 4),
        ("assets | 2", 7),
        ("assets ^ 1", 4),
        ("assets << 1", 10),
        ("assets >> 1", 2),
        ("-assets + +shares", -1),
    ],
)
def test_expression_evaluates_integer_arithmetic(
    source: str, expected: int
) -> None:
    result = evaluate_expression(source, {"assets": 5, "shares": 4})

    assert result.status == "evaluated"
    assert result.value == expected
    assert result.reason is None


def test_expression_evaluates_chained_comparisons() -> None:
    result = evaluate_expression("0 < assets <= cap != 0", {"assets": 5, "cap": 5})

    assert result.status == "evaluated"
    assert result.value is True


def test_invariant_violation_is_a_value_not_an_exception() -> None:
    result = evaluate_expression(
        "protocol_assets >= initial_protocol_assets",
        {"protocol_assets": 4, "initial_protocol_assets": 10},
    )

    assert result.status == "evaluated"
    assert result.value is False


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        ("healthy and assets > 0", True),
        ("not healthy or assets == 0", False),
    ],
)
def test_expression_evaluates_boolean_operators(
    source: str, expected: bool
) -> None:
    result = evaluate_expression(source, {"healthy": True, "assets": 2})

    assert result.status == "evaluated"
    assert result.value is expected


def test_missing_observation_is_inconclusive() -> None:
    result = evaluate_expression("assets >= missing", {"assets": 2})

    assert result.status == "inconclusive"
    assert result.value is None
    assert result.reason == "missing observation: missing"


@pytest.mark.parametrize(
    "source",
    [
        "False and missing",
        "True or missing",
        "assets < 0 < missing",
    ],
)
def test_missing_observation_is_inconclusive_even_if_runtime_short_circuits(
    source: str,
) -> None:
    result = evaluate_expression(source, {"assets": 2})

    assert result.status == "inconclusive"
    assert result.value is None
    assert result.reason == "missing observation: missing"


@pytest.mark.parametrize("source", ["assets // zero", "assets % zero"])
def test_division_by_zero_is_inconclusive(source: str) -> None:
    result = evaluate_expression(source, {"assets": 2, "zero": 0})

    assert result.status == "inconclusive"
    assert result.value is None
    assert result.reason == "division by zero"


@pytest.mark.parametrize("source", ["f()", "x.y", "x[0]", "[x for x in y]"])
def test_expression_rejects_executable_syntax(source: str) -> None:
    with pytest.raises(ExpressionError):
        evaluate_expression(source, {"x": 1, "y": 2})


def test_expression_rejects_unsafe_node_even_when_short_circuited() -> None:
    with pytest.raises(ExpressionError):
        evaluate_expression("False and f()", {})


@pytest.mark.parametrize(
    "source",
    [
        "assets / 2",
        "assets if healthy else 0",
        "lambda: assets",
        "{assets}",
        "assets is None",
        "2 ** 257",
    ],
)
def test_expression_rejects_unsupported_or_unbounded_operations(source: str) -> None:
    with pytest.raises(ExpressionError):
        evaluate_expression(source, {"assets": 2, "healthy": True})


@pytest.mark.parametrize("source", ["assets +", "", "("])
def test_expression_rejects_malformed_syntax(source: str) -> None:
    with pytest.raises(ExpressionError, match="syntax"):
        evaluate_expression(source, {"assets": 2})


@pytest.mark.parametrize("value", [1.5, "2", None])
def test_expression_rejects_non_integer_observation_values(value: object) -> None:
    with pytest.raises(ExpressionError, match="int or bool"):
        evaluate_expression("assets > 0", {"assets": value})  # type: ignore[dict-item]
