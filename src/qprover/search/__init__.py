"""Solver-independent search primitives and classical BQM backends."""

from qprover.search.annealing import AnnealingConfig, SimulatedAnnealingBackend
from qprover.search.base import Evaluation, SearchStrategy, StrategyStats
from qprover.search.bqm import (
    STOP,
    BinaryQuadraticModel,
    SearchFeedback,
    SearchProblem,
    SequenceBQMBuilder,
)
from qprover.search.controller import SearchController
from qprover.search.coverage import CoverageGuidedStrategy
from qprover.search.exact import ExactBackend, ExactConfig, exact_feasible_sequences
from qprover.search.qubo import QuboStrategy
from qprover.search.random import RandomStrategy
from qprover.search.risk import RiskGuidedStrategy

__all__ = [
    "STOP",
    "AnnealingConfig",
    "BinaryQuadraticModel",
    "CoverageGuidedStrategy",
    "Evaluation",
    "ExactBackend",
    "ExactConfig",
    "QuboStrategy",
    "RandomStrategy",
    "RiskGuidedStrategy",
    "SearchController",
    "SearchFeedback",
    "SearchProblem",
    "SearchStrategy",
    "SequenceBQMBuilder",
    "SimulatedAnnealingBackend",
    "StrategyStats",
    "exact_feasible_sequences",
]
