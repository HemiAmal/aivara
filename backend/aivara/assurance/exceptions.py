"""Exceptions for Multi-Modal Risk Integration Engine (Phase 11.9)."""

from __future__ import annotations

from typing import Any, Optional
from aivara.core.exceptions import AivaraException


class AssuranceIntegrationError(AivaraException):
    """Base exception for all Phase 11.9 assurance and risk integration errors."""

    def __init__(
        self,
        message: str,
        code: str = "ASSURANCE_INTEGRATION_ERROR",
        details: Optional[Any] = None,
    ) -> None:
        super().__init__(message, code=code, details=details)


class ProjectMismatchError(AssuranceIntegrationError):
    """Raised when evidence records or contracts contradict the target project scope."""

    def __init__(self, message: str, details: Optional[Any] = None) -> None:
        super().__init__(message, code="PROJECT_MISMATCH", details=details)


class ResourceLimitExceededError(AssuranceIntegrationError):
    """Raised when evidence volume or cluster count exceeds hard resource ceilings."""

    def __init__(self, message: str, details: Optional[Any] = None) -> None:
        super().__init__(message, code="RESOURCE_LIMIT_EXCEEDED", details=details)


class PolicyValidationError(AssuranceIntegrationError):
    """Raised when risk or decision policy configurations violate bounds or invariants."""

    def __init__(self, message: str, details: Optional[Any] = None) -> None:
        super().__init__(message, code="POLICY_VALIDATION_ERROR", details=details)


class InvalidEvidenceError(AssuranceIntegrationError):
    """Raised when an evidence record is malformed, has non-finite values, or is corrupted."""

    def __init__(self, message: str, details: Optional[Any] = None) -> None:
        super().__init__(message, code="INVALID_EVIDENCE", details=details)


class ConflictingEvidenceError(AssuranceIntegrationError):
    """Raised or emitted when high-confidence contradictory evidence deadlocks automated disposition."""

    def __init__(self, message: str, details: Optional[Any] = None) -> None:
        super().__init__(message, code="CONFLICTING_EVIDENCE", details=details)


class InsufficientEvidenceError(AssuranceIntegrationError):
    """Raised when required critical modalities are absent or sub-threshold."""

    def __init__(self, message: str, details: Optional[Any] = None) -> None:
        super().__init__(message, code="INSUFFICIENT_EVIDENCE", details=details)
