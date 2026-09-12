"""Domain Exceptions for Phase 9.5 Statistical Trigger Significance & Control Comparison."""

from __future__ import annotations


class StatisticalAnalysisError(Exception):
    """Base exception for Phase 9.5 statistical trigger analysis."""
    pass


class InsufficientSupportError(StatisticalAnalysisError):
    """Raised when evaluation sample count N < 10 for primary hypothesis testing."""
    pass


class BudgetExceededError(StatisticalAnalysisError):
    """Raised when requested inferences exceed Stage 1, Stage 2, or 16,000 hard ceiling."""
    pass


class PairingIntegrityError(StatisticalAnalysisError):
    """Raised when paired observation members fail cryptographic, project, or identity binding."""
    pass


class StatisticalComputationError(StatisticalAnalysisError):
    """Raised when numerical computation encounters invalid domain (e.g. NaN, negative probability)."""
    pass


class MultiplicityAdjustmentError(StatisticalAnalysisError):
    """Raised when multiple testing correction inputs are malformed or invalid."""
    pass


class CandidatePromotionError(StatisticalAnalysisError):
    """Raised when candidate promotion processing fails or exceeds capacity."""
    pass
