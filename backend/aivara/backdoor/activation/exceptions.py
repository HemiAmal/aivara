"""Typed Exceptions for Phase 9.4 Trigger Activation & Comparison Subsystem."""

from __future__ import annotations

from typing import Any, Optional
from aivara.core.exceptions import AivaraException


class BackdoorActivationError(AivaraException, ValueError):
    """Base exception for all backdoor activation and comparison errors."""

    def __init__(
        self,
        message: str,
        code: str = "BACKDOOR_ACTIVATION_ERROR",
        details: Optional[Any] = None,
    ) -> None:
        super().__init__(message, code=code, details=details)


class InvalidExperimentConfigError(BackdoorActivationError):
    """Raised when experiment configuration or parameter settings fail validation."""

    def __init__(self, message: str, details: Optional[Any] = None) -> None:
        super().__init__(message, code="INVALID_EXPERIMENT_CONFIG", details=details)


class ConditionGenerationError(BackdoorActivationError):
    """Raised when control condition generation fails or magnitude matching is impossible."""

    def __init__(self, message: str, details: Optional[Any] = None) -> None:
        super().__init__(message, code="CONDITION_GENERATION_ERROR", details=details)


class ActivationCriteriaError(BackdoorActivationError):
    """Raised when activation criterion parameters or thresholds are invalid."""

    def __init__(self, message: str, details: Optional[Any] = None) -> None:
        super().__init__(message, code="ACTIVATION_CRITERIA_ERROR", details=details)


class ModelIntegrityFailureError(BackdoorActivationError):
    """Raised when model fingerprint or weights change unexpectedly during evaluation."""

    def __init__(self, message: str, details: Optional[Any] = None) -> None:
        super().__init__(message, code="MODEL_INTEGRITY_FAILURE", details=details)


class SourceInputIntegrityError(BackdoorActivationError):
    """Raised when source input array is unexpectedly mutated during evaluation."""

    def __init__(self, message: str, details: Optional[Any] = None) -> None:
        super().__init__(message, code="SOURCE_INPUT_INTEGRITY_ERROR", details=details)
