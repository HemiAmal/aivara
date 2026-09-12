"""Typed Exceptions for Phase 9.3 Trigger Transformation Engine."""

from __future__ import annotations

from typing import Any, Optional
from aivara.core.exceptions import AivaraException


class TriggerTransformationError(AivaraException, ValueError):
    """Base exception for all trigger transformation failures."""

    def __init__(
        self,
        message: str,
        code: str = "TRIGGER_TRANSFORMATION_ERROR",
        details: Optional[Any] = None,
    ) -> None:
        super().__init__(message, code=code, details=details)


class InvalidInputError(TriggerTransformationError):
    """Raised when the input array is invalid, non-array, or corrupted."""

    def __init__(self, message: str, details: Optional[Any] = None) -> None:
        super().__init__(message, code="INVALID_INPUT", details=details)


class UnsupportedInputShapeError(TriggerTransformationError):
    """Raised when the input array has an unsupported rank or spatial shape."""

    def __init__(self, message: str, details: Optional[Any] = None) -> None:
        super().__init__(message, code="UNSUPPORTED_INPUT_SHAPE", details=details)


class UnsupportedDtypeError(TriggerTransformationError):
    """Raised when the input array dtype is unsupported or incompatible."""

    def __init__(self, message: str, details: Optional[Any] = None) -> None:
        super().__init__(message, code="UNSUPPORTED_DTYPE", details=details)


class NonFiniteInputError(TriggerTransformationError):
    """Raised when the input array contains NaN or Inf values."""

    def __init__(self, message: str, details: Optional[Any] = None) -> None:
        super().__init__(message, code="NON_FINITE_INPUT", details=details)


class CandidateInputMismatchError(TriggerTransformationError):
    """Raised when candidate input constraints are incompatible with the input array."""

    def __init__(self, message: str, details: Optional[Any] = None) -> None:
        super().__init__(message, code="CANDIDATE_INPUT_MISMATCH", details=details)


class InvalidPlacementError(TriggerTransformationError):
    """Raised when candidate placement is out of bounds or geometrically invalid on canvas."""

    def __init__(self, message: str, details: Optional[Any] = None) -> None:
        super().__init__(message, code="INVALID_PLACEMENT", details=details)


class TransformationBudgetExceededError(TriggerTransformationError):
    """Raised when batch size or memory bounds exceed safe execution limits."""

    def __init__(self, message: str, details: Optional[Any] = None) -> None:
        super().__init__(message, code="TRANSFORMATION_BUDGET_EXCEEDED", details=details)


class TransformationNumericalError(TriggerTransformationError):
    """Raised when transformation generates non-finite outputs (NaN/Inf) or numerical overflow."""

    def __init__(self, message: str, details: Optional[Any] = None) -> None:
        super().__init__(message, code="TRANSFORMATION_NUMERICAL_ERROR", details=details)
