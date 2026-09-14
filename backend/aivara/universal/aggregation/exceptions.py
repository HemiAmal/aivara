"""Exceptions for Universal Project & Multi-Asset Risk Aggregation (Phase 12.9)."""

from __future__ import annotations

from typing import Any, Optional

from aivara.core.exceptions import AivaraException


class AggregationError(AivaraException, ValueError):
    """Base exception for all multi-asset and project risk aggregation errors."""

    def __init__(
        self,
        message: str,
        code: str = "AGGREGATION_ERROR",
        details: Optional[Any] = None,
    ) -> None:
        super().__init__(message, code=code, details=details)


class DependencyCycleError(AggregationError):
    """Raised when an asset dependency graph contains cyclic or self-referential relationships."""

    def __init__(self, message: str, details: Optional[Any] = None) -> None:
        super().__init__(message, code="DEPENDENCY_CYCLE_DETECTED", details=details)


class ScopeMismatchError(AggregationError):
    """Raised when an asset or dependency edge violates project tenancy isolation."""

    def __init__(self, message: str, details: Optional[Any] = None) -> None:
        super().__init__(message, code="SCOPE_MISMATCH", details=details)


class InvalidAssetRiskError(AggregationError):
    """Raised when an input asset risk score is non-finite or outside [0.0, 1.0]."""

    def __init__(self, message: str, details: Optional[Any] = None) -> None:
        super().__init__(message, code="INVALID_ASSET_RISK", details=details)


class DoubleCountingError(AggregationError):
    """Raised when identical evidence or findings are counted multiple times without ancestry collapse."""

    def __init__(self, message: str, details: Optional[Any] = None) -> None:
        super().__init__(message, code="DOUBLE_COUNTING_DETECTED", details=details)


class AggregationResourceLimitExceededError(AggregationError):
    """Raised when asset counts, chain depths, or dependency edge counts exceed security ceilings."""

    def __init__(self, message: str, details: Optional[Any] = None) -> None:
        super().__init__(message, code="AGGREGATION_RESOURCE_LIMIT_EXCEEDED", details=details)
