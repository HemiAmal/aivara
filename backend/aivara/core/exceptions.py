"""AIVARA domain and API exception classes."""

from typing import Any, Optional


class AivaraException(Exception):
    """Base exception for all AIVARA domain errors."""

    def __init__(self, message: str, code: str = "INTERNAL_ERROR", details: Optional[Any] = None):
        super().__init__(message)
        self.message = message
        self.code = code
        self.details = details or {}


class NotFoundException(AivaraException):
    """Raised when an identified asset is not found."""

    def __init__(self, message: str, details: Optional[Any] = None):
        super().__init__(message, code="NOT_FOUND", details=details)


class ValidationException(AivaraException):
    """Raised when input validation or asset integrity validation fails."""

    def __init__(self, message: str, details: Optional[Any] = None):
        super().__init__(message, code="VALIDATION_FAILED", details=details)


class ConfigurationException(AivaraException):
    """Raised on invalid or conflicting system configuration."""

    def __init__(self, message: str, details: Optional[Any] = None):
        super().__init__(message, code="CONFIG_ERROR", details=details)
