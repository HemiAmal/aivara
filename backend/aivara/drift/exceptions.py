"""Domain exceptions for Phase 11 Distribution Shift and Population Boundaries."""

from typing import Any, Dict, Optional
from aivara.core.exceptions import AivaraException


class DistributionBoundaryError(AivaraException):
    """Base exception for distribution shift boundary errors."""
    def __init__(
        self,
        message: str,
        code: str = "DISTRIBUTION_BOUNDARY_ERROR",
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        super().__init__(message, code=code, details=details)


class ProjectMismatchError(DistributionBoundaryError):
    """Raised when reference and target datasets belong to different projects."""
    def __init__(
        self,
        message: str = "Reference and target datasets must belong to the same project.",
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        super().__init__(message, code="PROJECT_MISMATCH", details=details)


class IncompatiblePopulationError(DistributionBoundaryError):
    """Raised when reference and target populations have incompatible schemas or dimensions."""
    def __init__(
        self,
        message: str,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        super().__init__(message, code="INCOMPATIBLE_POPULATIONS", details=details)


class InsufficientDataError(DistributionBoundaryError):
    """Raised when population sample size is below the mandatory minimum (N < 30)."""
    def __init__(
        self,
        message: str = "Population sample size is below minimum statistical threshold (N < 30).",
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        super().__init__(message, code="INSUFFICIENT_DATA", details=details)


class ResourceLimitExceededError(DistributionBoundaryError):
    """Raised when population size or feature dimensions exceed safety bounds."""
    def __init__(
        self,
        message: str,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        super().__init__(message, code="RESOURCE_LIMIT_EXCEEDED", details=details)


class InvalidPopulationError(DistributionBoundaryError):
    """Raised when population selection or dataset metadata is malformed or invalid."""
    def __init__(
        self,
        message: str,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        super().__init__(message, code="INVALID_POPULATION", details=details)


class DriftConflictError(DistributionBoundaryError):
    """Raised on state machine or resource conflicts during drift analysis."""
    def __init__(
        self,
        message: str,
        code: str = "DRIFT_CONFLICT",
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        super().__init__(message, code=code, details=details)


class IdempotencyConflictError(DriftConflictError):
    """Raised when an idempotency key is reused with differing request parameters."""
    def __init__(
        self,
        message: str = "Idempotency key previously submitted with differing request parameters.",
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        super().__init__(message, code="IDEMPOTENCY_CONFLICT", details=details)

