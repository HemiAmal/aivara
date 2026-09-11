"""Domain exceptions for AIVARA Model Integrity Subsystem (Phase 7).

All exceptions inherit from AivaraException and define structured error codes.
"""

from __future__ import annotations

from typing import Any, Dict, Optional
from aivara.core.exceptions import AivaraException


class ModelIntegrityError(AivaraException):
    """Base exception for all Model Integrity Engine operations."""

    def __init__(
        self,
        message: str,
        code: str = "MODEL_INTEGRITY_ERROR",
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        super().__init__(message, code=code, details=details)


class UntrustedArtifactSecurityError(ModelIntegrityError):
    """Raised when an artifact violates filesystem or security sandbox constraints."""

    def __init__(
        self,
        message: str,
        code: str = "ARTIFACT_SECURITY_VIOLATION",
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        super().__init__(message, code=code, details=details)


class ProhibitedFormatError(ModelIntegrityError):
    """Raised when an artifact format is prohibited (e.g. arbitrary pickle)."""

    def __init__(
        self,
        message: str,
        code: str = "PROHIBITED_MODEL_FORMAT",
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        super().__init__(message, code=code, details=details)


class ModelCorruptionError(ModelIntegrityError):
    """Raised when an artifact is structurally malformed or truncated."""

    def __init__(
        self,
        message: str,
        code: str = "MODEL_CORRUPTED",
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        super().__init__(message, code=code, details=details)


class ResourceLimitExceededError(ModelIntegrityError):
    """Raised when an artifact exceeds configured memory, size, or complexity limits."""

    def __init__(
        self,
        message: str,
        code: str = "RESOURCE_LIMIT_EXCEEDED",
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        super().__init__(message, code=code, details=details)


class ParsingError(ModelIntegrityError):
    """Raised when safe static parsing fails on a recognized format."""

    def __init__(
        self,
        message: str,
        code: str = "PARSING_ERROR",
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        super().__init__(message, code=code, details=details)
