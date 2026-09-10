"""Domain exceptions for Label-Flipping Detection Engine (Phase 5.6)."""

from typing import Any, Optional
from aivara.dataset.anomalies.exceptions import LabelAnomalyError


class LabelFlippingError(LabelAnomalyError):
    """Base exception for label flipping detection errors."""

    def __init__(
        self,
        message: str,
        code: str = "LABEL_FLIPPING_ERROR",
        details: Optional[Any] = None,
    ) -> None:
        super().__init__(message, code=code, details=details)


class InsufficientSupportError(LabelFlippingError):
    """Raised when transition sample support is inadequate for statistical analysis."""

    def __init__(self, message: str, details: Optional[Any] = None) -> None:
        super().__init__(message, code="INSUFFICIENT_SUPPORT", details=details)


class InvalidTransitionMatrixError(LabelFlippingError):
    """Raised when transition matrix dimensions or values violate mathematical invariants."""

    def __init__(self, message: str, details: Optional[Any] = None) -> None:
        super().__init__(message, code="INVALID_TRANSITION_MATRIX", details=details)
