"""Domain-specific exceptions for Hierarchical Risk Aggregation Engine (Phase 12.4)."""

from aivara.core.exceptions import AivaraException


class UniversalRiskError(AivaraException):
    """Base exception for all universal risk aggregation errors."""
    pass


class NonFiniteRiskError(UniversalRiskError):
    """Raised when an intermediate or final risk calculation produces NaN or Inf."""
    pass


class RiskOutOfRangeError(UniversalRiskError):
    """Raised when a risk scalar violates the bounded invariant R in [0.0, 1.0]."""
    pass


class InvalidPolicyConfigurationError(UniversalRiskError):
    """Raised when risk aggregation parameters violate stability or governance bounds."""
    pass
