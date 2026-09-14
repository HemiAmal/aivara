"""Exceptions for Cross-Subsystem Correlation & Dependency Damping Engine (Phase 12.5)."""


class UniversalCorrelationError(Exception):
    """Base exception for all Phase 12.5 correlation engine errors."""
    pass


class InvalidCorrelationMatrixError(UniversalCorrelationError):
    """Raised when correlation matrix dimensions, values, or structure are invalid."""
    pass


class AsymmetricMatrixError(InvalidCorrelationMatrixError):
    """Raised when correlation matrix is not symmetric across its diagonal."""
    pass


class NonZeroDiagonalError(InvalidCorrelationMatrixError):
    """Raised when correlation matrix has non-zero diagonal entries."""
    pass


class InvalidDomainOrderError(InvalidCorrelationMatrixError):
    """Raised when canonical seven-domain ordering is violated."""
    pass


class CorrelationOutOfRangeError(InvalidCorrelationMatrixError):
    """Raised when correlation value falls outside [0.0, 1.0]."""
    pass


class NonFiniteCorrelationError(InvalidCorrelationMatrixError):
    """Raised when correlation value is NaN or infinite."""
    pass
