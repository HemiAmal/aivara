"""Domain exceptions for Phase 5.8 Contributor Aggregation Engine."""

from typing import Any, Dict, Optional


class ContributorAggregationError(Exception):
    """Base domain exception for Phase 5.8 Contributor Aggregation Engine."""

    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(message)
        self.message = message
        self.details = details or {}


class InvalidAttributionError(ContributorAggregationError):
    """Raised when contributor attribution weights violate mathematical invariants."""
    pass


class InsufficientContributorSupportError(ContributorAggregationError):
    """Raised when contributor exposure is insufficient for statistical operations."""
    pass


class InvalidBaselineError(ContributorAggregationError):
    """Raised when reference background baseline cannot be formed or evaluated."""
    pass


class MalformedEvidenceError(ContributorAggregationError):
    """Raised when incoming anomaly evidence data is malformed or unparseable."""
    pass
