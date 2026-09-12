"""Typed Exception Classes for Phase 9.2 Trigger Candidate Generation."""

from __future__ import annotations

from typing import Any, Optional
from aivara.core.exceptions import AivaraException


class BackdoorCandidateError(AivaraException, ValueError):
    """Base exception for all backdoor trigger candidate errors."""

    def __init__(
        self,
        message: str,
        code: str = "BACKDOOR_CANDIDATE_ERROR",
        details: Optional[Any] = None,
    ) -> None:
        super().__init__(message, code=code, details=details)


class InvalidCandidateTypeError(BackdoorCandidateError):
    """Raised when an unsupported trigger candidate family is requested."""

    def __init__(self, message: str, details: Optional[Any] = None) -> None:
        super().__init__(message, code="INVALID_CANDIDATE_TYPE", details=details)


class InvalidCandidateParameterError(BackdoorCandidateError):
    """Raised when candidate configuration parameters fail validation."""

    def __init__(self, message: str, details: Optional[Any] = None) -> None:
        super().__init__(message, code="INVALID_CANDIDATE_PARAMETER", details=details)


class CandidateOutOfBoundsError(BackdoorCandidateError):
    """Raised when patch geometry or placement coordinates exceed the valid canvas domain."""

    def __init__(self, message: str, details: Optional[Any] = None) -> None:
        super().__init__(message, code="CANDIDATE_OUT_OF_BOUNDS", details=details)


class UnsupportedCandidateConfigurationError(BackdoorCandidateError):
    """Raised when candidate parameters are incompatible with the declared input constraints."""

    def __init__(self, message: str, details: Optional[Any] = None) -> None:
        super().__init__(message, code="UNSUPPORTED_CANDIDATE_CONFIGURATION", details=details)


class CandidateBudgetExceededError(BackdoorCandidateError):
    """Raised when requested candidate batch size exceeds the frozen MAX_CANDIDATES limit (16)."""

    def __init__(self, message: str, details: Optional[Any] = None) -> None:
        super().__init__(message, code="CANDIDATE_BUDGET_EXCEEDED", details=details)


class DuplicateCandidateError(BackdoorCandidateError):
    """Raised when duplicate candidate specifications with identical identity hashes are detected."""

    def __init__(self, message: str, details: Optional[Any] = None) -> None:
        super().__init__(message, code="DUPLICATE_CANDIDATE", details=details)


class InvalidSeedError(BackdoorCandidateError):
    """Raised when random seed is invalid or out of allowed integer range."""

    def __init__(self, message: str, details: Optional[Any] = None) -> None:
        super().__init__(message, code="INVALID_SEED", details=details)


class InvalidValueRangeError(BackdoorCandidateError):
    """Raised when candidate values violate the declared value range domain."""

    def __init__(self, message: str, details: Optional[Any] = None) -> None:
        super().__init__(message, code="INVALID_VALUE_RANGE", details=details)


class SecurityValidationError(BackdoorCandidateError):
    """Raised when candidate parameters contain dangerous or executable patterns."""

    def __init__(self, message: str, details: Optional[Any] = None) -> None:
        super().__init__(message, code="SECURITY_VALIDATION_ERROR", details=details)
