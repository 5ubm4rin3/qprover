"""Canonical upper-triangular BQM for bounded transaction sequences."""

from __future__ import annotations

import math
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from types import MappingProxyType

STOP = "__STOP__"


def _frozen_mapping(value: Mapping) -> MappingProxyType:
    return MappingProxyType(dict(value))


def _exact_positive_int(value: object, label: str) -> int:
    if type(value) is not int or value <= 0:
        raise ValueError(f"{label} must be an exact positive integer")
    return value


def _finite_real(value: object, label: str, *, nonnegative: bool = False) -> float:
    if type(value) not in (int, float):
        raise ValueError(f"{label} must contain only int or float values")
    try:
        converted = float(value)
    except OverflowError as error:
        raise ValueError(f"{label} must contain only finite values") from error
    if not math.isfinite(converted):
        raise ValueError(f"{label} must contain only finite values")
    if nonnegative and converted < 0:
        raise ValueError(f"{label} must contain only nonnegative values")
    return converted


def _finite_derived(value: float, label: str) -> float:
    if not math.isfinite(value):
        raise ValueError(f"non-finite derived {label}")
    return value


def _finite_sum(values: Sequence[float], label: str) -> float:
    try:
        result = math.fsum(values)
    except OverflowError as error:
        raise ValueError(f"non-finite derived {label}") from error
    return _finite_derived(result, label)


@dataclass(frozen=True, slots=True)
class SearchProblem:
    """Public, label-neutral inputs to sequence optimization."""

    actions: tuple[str, ...]
    max_sequence_length: int
    utilities: Mapping[str, float] | None = None
    transitions: Mapping[tuple[str, str], float] | None = None
    repetition_limits: Mapping[str, int] | None = None
    discounts: tuple[float, ...] = ()
    utility_weight: float = 1.0
    transition_weight: float = 1.0
    revert_weight: float = 1.0
    length_weight: float = 0.05

    def __post_init__(self) -> None:
        actions = tuple(self.actions)
        if not actions or any(
            not isinstance(item, str) or not item for item in actions
        ):
            raise ValueError("actions must be nonempty strings")
        if len(set(actions)) != len(actions):
            raise ValueError("duplicate action identifier")
        if STOP in actions:
            raise ValueError("STOP is reserved")
        _exact_positive_int(self.max_sequence_length, "max_sequence_length")
        utilities = dict(self.utilities or {})
        transitions = dict(self.transitions or {})
        limits = dict(self.repetition_limits or {})
        known = set(actions)
        if any(
            type(key) is not tuple
            or len(key) != 2
            or any(type(endpoint) is not str for endpoint in key)
            for key in transitions
        ):
            raise ValueError("transition keys must be exact two-string action tuples")
        unknown = set(utilities) - known
        unknown.update(set(limits) - known)
        unknown.update(
            endpoint
            for pair in transitions
            for endpoint in pair
            if endpoint not in known
        )
        if unknown:
            raise ValueError(f"unknown action input: {sorted(unknown)[0]}")
        utilities = {
            action: _finite_real(utilities.get(action, 0.0), "utilities")
            for action in actions
        }
        limits = {
            action: _exact_positive_int(
                limits.get(action, self.max_sequence_length), "repetition limits"
            )
            for action in actions
        }
        transitions = {
            key: _finite_real(value, "transitions")
            for key, value in transitions.items()
        }
        weights = tuple(
            _finite_real(value, "weights", nonnegative=True)
            for value in (
                self.utility_weight,
                self.transition_weight,
                self.revert_weight,
                self.length_weight,
            )
        )
        discounts = self.discounts or (1.0,) * self.max_sequence_length
        if len(discounts) != self.max_sequence_length:
            raise ValueError("discounts must match max_sequence_length")
        discounts = tuple(
            _finite_real(value, "discounts", nonnegative=True) for value in discounts
        )
        object.__setattr__(self, "actions", actions)
        object.__setattr__(self, "utilities", _frozen_mapping(utilities))
        object.__setattr__(
            self,
            "transitions",
            _frozen_mapping(transitions),
        )
        object.__setattr__(self, "repetition_limits", _frozen_mapping(limits))
        object.__setattr__(self, "discounts", discounts)
        object.__setattr__(self, "utility_weight", weights[0])
        object.__setattr__(self, "transition_weight", weights[1])
        object.__setattr__(self, "revert_weight", weights[2])
        object.__setattr__(self, "length_weight", weights[3])


@dataclass(frozen=True, slots=True)
class SearchFeedback:
    """Observed public outcomes; never benchmark labels or known witnesses."""

    revert_penalties: Mapping[str, float] | None = None

    def __post_init__(self) -> None:
        penalties = {
            key: _finite_real(value, "revert penalties", nonnegative=True)
            for key, value in (self.revert_penalties or {}).items()
        }
        object.__setattr__(self, "revert_penalties", _frozen_mapping(penalties))

    @classmethod
    def empty(cls) -> SearchFeedback:
        return cls()


@dataclass(frozen=True, slots=True)
class ObjectiveComponents:
    one_hot: float
    stop_suffix: float
    repetition: float
    utility: float
    transition: float
    learned_revert: float
    length: float

    @property
    def total(self) -> float:
        return _finite_sum(tuple(self.as_dict().values()), "objective energy")

    def as_dict(self) -> dict[str, float]:
        return {
            "one_hot": self.one_hot,
            "stop_suffix": self.stop_suffix,
            "repetition": self.repetition,
            "utility": self.utility,
            "transition": self.transition,
            "learned_revert": self.learned_revert,
            "length": self.length,
        }


@dataclass(frozen=True, slots=True)
class FeasibilityAudit:
    feasible: bool
    one_hot_violations: tuple[int, ...]
    stop_suffix_violations: tuple[int, ...]
    repetition_violations: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class DecodedSample:
    sequence: tuple[str, ...]
    feasibility: FeasibilityAudit


@dataclass(frozen=True, slots=True)
class BinaryQuadraticModel:
    variables: tuple[str, ...]
    linear: Mapping[int, float]
    quadratic: Mapping[tuple[int, int], float]
    offset: float
    non_constraint_linear: Mapping[int, float]
    non_constraint_quadratic: Mapping[tuple[int, int], float]
    constraint_penalty: float
    problem: SearchProblem
    feedback: SearchFeedback

    def __post_init__(self) -> None:
        size = len(self.variables)
        if len(set(self.variables)) != size:
            raise ValueError("BQM variables must be unique")
        for index, coefficient in self.linear.items():
            if type(index) is not int or not 0 <= index < size:
                raise ValueError("linear coefficient index is outside the BQM")
            _finite_real(coefficient, "linear coefficients")
        for (first, second), coefficient in self.quadratic.items():
            if (
                type(first) is not int
                or type(second) is not int
                or not (0 <= first <= second < size)
            ):
                raise ValueError("quadratic coefficients must be upper triangular")
            _finite_real(coefficient, "quadratic coefficients")
        for index, coefficient in self.non_constraint_linear.items():
            if type(index) is not int or not 0 <= index < size:
                raise ValueError("non-constraint linear index is outside the BQM")
            _finite_real(coefficient, "non-constraint linear coefficients")
        for (first, second), coefficient in self.non_constraint_quadratic.items():
            if (
                type(first) is not int
                or type(second) is not int
                or not (0 <= first <= second < size)
            ):
                raise ValueError(
                    "non-constraint quadratic coefficients must be upper triangular"
                )
            _finite_real(coefficient, "non-constraint quadratic coefficients")
        _finite_real(self.offset, "offset")
        penalty = _finite_real(
            self.constraint_penalty, "constraint penalty", nonnegative=True
        )
        if penalty <= 0:
            raise ValueError("constraint penalty must be positive")
        object.__setattr__(self, "linear", _frozen_mapping(self.linear))
        object.__setattr__(self, "quadratic", _frozen_mapping(self.quadratic))
        object.__setattr__(
            self,
            "non_constraint_linear",
            _frozen_mapping(self.non_constraint_linear),
        )
        object.__setattr__(
            self,
            "non_constraint_quadratic",
            _frozen_mapping(self.non_constraint_quadratic),
        )

    @property
    def choices(self) -> tuple[str, ...]:
        return (*self.problem.actions, STOP)

    def repetition_indices(self, action: str) -> tuple[int, ...]:
        if action not in self.problem.actions:
            raise ValueError(f"unknown action: {action}")
        offset = self.problem.max_sequence_length * len(self.choices)
        for candidate in self.problem.actions:
            limit = self.problem.repetition_limits[candidate]
            auxiliary_count = (
                limit if 1 < limit < self.problem.max_sequence_length else 0
            )
            if candidate == action:
                return tuple(range(offset, offset + auxiliary_count))
            offset += auxiliary_count
        raise AssertionError("unreachable action lookup")

    def index(self, position: int, action: str) -> int:
        if type(position) is not int:
            raise ValueError("position must be an exact integer")
        if not 0 <= position < self.problem.max_sequence_length:
            raise ValueError("position is outside the sequence horizon")
        try:
            action_index = self.choices.index(action)
        except ValueError as error:
            raise ValueError(f"unknown action: {action}") from error
        return position * len(self.choices) + action_index

    def _bits(self, bits: Sequence[int]) -> tuple[int, ...]:
        values = tuple(bits)
        if len(values) != len(self.variables):
            raise ValueError("sample bit count does not match BQM variables")
        if any(type(value) is not int or value not in (0, 1) for value in values):
            raise ValueError("BQM samples must contain exact integers 0 or 1")
        return values

    def energy(self, bits: Sequence[int]) -> float:
        values = self._bits(bits)
        return _finite_sum(
            (
                self.offset,
                *(
                    coefficient * values[index]
                    for index, coefficient in self.linear.items()
                ),
                *(
                    coefficient * values[first] * values[second]
                    for (first, second), coefficient in self.quadratic.items()
                ),
            ),
            "BQM energy",
        )

    def objective_components(self, bits: Sequence[int]) -> ObjectiveComponents:
        values = self._bits(bits)
        problem = self.problem
        feedback = self.feedback
        selected = {
            (position, action): values[self.index(position, action)]
            for position in range(problem.max_sequence_length)
            for action in self.choices
        }
        one_hot = self.constraint_penalty * sum(
            (1 - sum(selected[position, action] for action in self.choices)) ** 2
            for position in range(problem.max_sequence_length)
        )
        stop_suffix = self.constraint_penalty * sum(
            selected[position, STOP] * selected[position + 1, action]
            for position in range(problem.max_sequence_length - 1)
            for action in problem.actions
        )
        repetition = self.constraint_penalty * sum(
            selected[first, action] * selected[second, action]
            for action in problem.actions
            if problem.repetition_limits[action] == 1
            for first in range(problem.max_sequence_length)
            for second in range(first + 1, problem.max_sequence_length)
        )
        repetition += self.constraint_penalty * sum(
            (
                sum(
                    selected[position, action]
                    for position in range(problem.max_sequence_length)
                )
                - sum(values[index] for index in self.repetition_indices(action))
            )
            ** 2
            for action in problem.actions
            if 1 < problem.repetition_limits[action] < problem.max_sequence_length
        )
        utility = -problem.utility_weight * sum(
            problem.discounts[position]
            * problem.utilities[action]
            * selected[position, action]
            for position in range(problem.max_sequence_length)
            for action in problem.actions
        )
        transition = -problem.transition_weight * sum(
            problem.transitions.get((first, second), 0.0)
            * selected[position, first]
            * selected[position + 1, second]
            for position in range(problem.max_sequence_length - 1)
            for first in problem.actions
            for second in problem.actions
        )
        learned_revert = problem.revert_weight * sum(
            feedback.revert_penalties.get(action, 0.0) * selected[position, action]
            for position in range(problem.max_sequence_length)
            for action in problem.actions
        )
        length = problem.length_weight * sum(
            selected[position, action]
            for position in range(problem.max_sequence_length)
            for action in problem.actions
        )
        return ObjectiveComponents(
            one_hot,
            stop_suffix,
            repetition,
            utility,
            transition,
            learned_revert,
            length,
        )

    def decode(self, bits: Sequence[int]) -> DecodedSample:
        values = self._bits(bits)
        one_hot: list[int] = []
        stop_suffix: list[int] = []
        sequence: list[str] = []
        stopped = False
        for position in range(self.problem.max_sequence_length):
            chosen = tuple(
                action
                for action in self.choices
                if values[self.index(position, action)]
            )
            if len(chosen) != 1:
                one_hot.append(position)
            if STOP in chosen:
                stopped = True
            non_stop = tuple(action for action in chosen if action != STOP)
            if stopped and non_stop:
                if position > 0:
                    stop_suffix.append(position - 1)
            elif not stopped and non_stop:
                sequence.append(non_stop[0])
        # Record exact adjacent STOP -> action violations, including ambiguous slots.
        stop_suffix = sorted(
            {
                position
                for position in range(self.problem.max_sequence_length - 1)
                if values[self.index(position, STOP)]
                and any(
                    values[self.index(position + 1, action)]
                    for action in self.problem.actions
                )
            }
        )
        counts = Counter(
            action
            for position in range(self.problem.max_sequence_length)
            for action in self.problem.actions
            if values[self.index(position, action)]
        )
        repetitions = tuple(
            action
            for action in self.problem.actions
            if counts[action] > self.problem.repetition_limits[action]
            or (
                self.repetition_indices(action)
                and counts[action]
                != sum(values[index] for index in self.repetition_indices(action))
            )
        )
        audit = FeasibilityAudit(
            feasible=not one_hot and not stop_suffix and not repetitions,
            one_hot_violations=tuple(one_hot),
            stop_suffix_violations=tuple(stop_suffix),
            repetition_violations=repetitions,
        )
        return DecodedSample(tuple(sequence), audit)

    def encode(self, sequence: Sequence[str]) -> tuple[int, ...]:
        actions = tuple(sequence)
        if len(actions) > self.problem.max_sequence_length:
            raise ValueError("sequence exceeds BQM horizon")
        if any(action not in self.problem.actions for action in actions):
            raise ValueError("sequence contains an unknown action")
        counts = Counter(actions)
        if any(
            counts[action] > self.problem.repetition_limits[action]
            for action in self.problem.actions
        ):
            raise ValueError("sequence exceeds a repetition limit")
        bits = [0] * len(self.variables)
        for position in range(self.problem.max_sequence_length):
            action = actions[position] if position < len(actions) else STOP
            bits[self.index(position, action)] = 1
        for action in self.problem.actions:
            for index in self.repetition_indices(action)[: counts[action]]:
                bits[index] = 1
        return tuple(bits)


def _add_linear(coefficients: dict[int, float], index: int, value: float) -> None:
    _finite_derived(value, "linear coefficient")
    coefficients[index] = _finite_derived(
        coefficients.get(index, 0.0) + value, "linear coefficient"
    )
    if coefficients[index] == 0:
        del coefficients[index]


def _add_quadratic(
    linear: dict[int, float],
    coefficients: dict[tuple[int, int], float],
    first: int,
    second: int,
    value: float,
) -> None:
    _finite_derived(value, "quadratic coefficient")
    if first == second:
        _add_linear(linear, first, value)
        return
    key = (min(first, second), max(first, second))
    coefficients[key] = _finite_derived(
        coefficients.get(key, 0.0) + value, "quadratic coefficient"
    )
    if coefficients[key] == 0:
        del coefficients[key]


class SequenceBQMBuilder:
    """Expand the declarative sequence objective into a canonical BQM."""

    def build(
        self,
        problem: SearchProblem,
        feedback: SearchFeedback,
    ) -> BinaryQuadraticModel:
        unknown_penalties = set(feedback.revert_penalties) - set(problem.actions)
        if unknown_penalties:
            raise ValueError(
                f"feedback references unknown action: {sorted(unknown_penalties)[0]}"
            )
        choices = (*problem.actions, STOP)
        variables = tuple(
            f"x[{position},{action}]"
            for position in range(problem.max_sequence_length)
            for action in choices
        )
        variables += tuple(
            f"repeat[{action},{occurrence}]"
            for action in problem.actions
            if 1 < problem.repetition_limits[action] < problem.max_sequence_length
            for occurrence in range(1, problem.repetition_limits[action] + 1)
        )

        def index(position: int, action: str) -> int:
            return position * len(choices) + choices.index(action)

        non_linear: dict[int, float] = {}
        non_quadratic: dict[tuple[int, int], float] = {}
        for position in range(problem.max_sequence_length):
            for action in problem.actions:
                coefficient = (
                    -problem.utility_weight
                    * problem.discounts[position]
                    * problem.utilities[action]
                    + problem.revert_weight * feedback.revert_penalties.get(action, 0.0)
                    + problem.length_weight
                )
                _finite_derived(coefficient, "objective coefficient")
                _add_linear(non_linear, index(position, action), coefficient)
        for position in range(problem.max_sequence_length - 1):
            for first in problem.actions:
                for second in problem.actions:
                    coefficient = -problem.transition_weight * problem.transitions.get(
                        (first, second), 0.0
                    )
                    _finite_derived(coefficient, "transition coefficient")
                    if coefficient:
                        _add_quadratic(
                            non_linear,
                            non_quadratic,
                            index(position, first),
                            index(position + 1, second),
                            coefficient,
                        )
        bound = _finite_sum(
            tuple(abs(value) for value in non_linear.values())
            + tuple(abs(value) for value in non_quadratic.values()),
            "non-constraint coefficient bound",
        )
        penalty = bound + 1.0
        if penalty <= bound:
            penalty = math.nextafter(bound, math.inf)
        if not math.isfinite(penalty) or penalty <= bound:
            raise ValueError("non-finite derived constraint penalty")
        linear = dict(non_linear)
        quadratic = dict(non_quadratic)
        offset = _finite_derived(
            penalty * problem.max_sequence_length, "constraint offset"
        )

        for position in range(problem.max_sequence_length):
            for action in choices:
                _add_linear(linear, index(position, action), -penalty)
            for first_offset, first in enumerate(choices):
                for second in choices[first_offset + 1 :]:
                    _add_quadratic(
                        linear,
                        quadratic,
                        index(position, first),
                        index(position, second),
                        2 * penalty,
                    )
        for position in range(problem.max_sequence_length - 1):
            for action in problem.actions:
                _add_quadratic(
                    linear,
                    quadratic,
                    index(position, STOP),
                    index(position + 1, action),
                    penalty,
                )
        for action in problem.actions:
            limit = problem.repetition_limits[action]
            if limit == 1:
                for first in range(problem.max_sequence_length):
                    for second in range(first + 1, problem.max_sequence_length):
                        _add_quadratic(
                            linear,
                            quadratic,
                            index(first, action),
                            index(second, action),
                            penalty,
                        )
                continue
            if limit >= problem.max_sequence_length:
                continue
            action_indices = tuple(
                index(position, action)
                for position in range(problem.max_sequence_length)
            )
            auxiliary_start = problem.max_sequence_length * len(choices) + sum(
                problem.repetition_limits[previous]
                for previous in problem.actions[: problem.actions.index(action)]
                if 1 < problem.repetition_limits[previous] < problem.max_sequence_length
            )
            auxiliary_indices = tuple(range(auxiliary_start, auxiliary_start + limit))
            for variable in (*action_indices, *auxiliary_indices):
                _add_linear(linear, variable, penalty)
            for first_offset, first in enumerate(action_indices):
                for second in action_indices[first_offset + 1 :]:
                    _add_quadratic(linear, quadratic, first, second, 2 * penalty)
            for first_offset, first in enumerate(auxiliary_indices):
                for second in auxiliary_indices[first_offset + 1 :]:
                    _add_quadratic(linear, quadratic, first, second, 2 * penalty)
            for first in range(problem.max_sequence_length):
                for auxiliary in auxiliary_indices:
                    _add_quadratic(
                        linear,
                        quadratic,
                        index(first, action),
                        auxiliary,
                        -2 * penalty,
                    )
        return BinaryQuadraticModel(
            variables=variables,
            linear=linear,
            quadratic=quadratic,
            offset=offset,
            non_constraint_linear=non_linear,
            non_constraint_quadratic=non_quadratic,
            constraint_penalty=penalty,
            problem=problem,
            feedback=feedback,
        )


@dataclass(frozen=True, slots=True)
class Sample:
    bits: tuple[int, ...]
    energy: float
    components: ObjectiveComponents
    decoded: DecodedSample

    def __post_init__(self) -> None:
        _finite_real(self.energy, "sample energy")


@dataclass(frozen=True, slots=True)
class SampleSet:
    samples: tuple[Sample, ...]
    metadata: Mapping[str, object]

    def __post_init__(self) -> None:
        if not self.samples:
            raise ValueError("a SampleSet cannot be empty")
        object.__setattr__(self, "metadata", _frozen_mapping(self.metadata))

    @property
    def first(self) -> Sample:
        return self.samples[0]


def sample_from_bits(bqm: BinaryQuadraticModel, bits: Sequence[int]) -> Sample:
    frozen = tuple(bits)
    return Sample(
        bits=frozen,
        energy=bqm.energy(frozen),
        components=bqm.objective_components(frozen),
        decoded=bqm.decode(frozen),
    )
