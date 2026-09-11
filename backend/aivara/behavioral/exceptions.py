"""Exceptions for the AIVARA Behavioral Analysis Subsystem (Phase 8)."""

from __future__ import annotations

from typing import Any, Optional
from aivara.core.exceptions import AivaraException


class BehavioralError(AivaraException, ValueError):
    """Base exception for all Behavioral Analysis subsystem operations."""

    def __init__(
        self,
        message: str,
        code: str = "BEHAVIORAL_ERROR",
        details: Optional[Any] = None,
    ) -> None:
        super().__init__(message, code=code, details=details)


class ModelExecutionError(BehavioralError):
    """Raised when runtime model execution fails."""

    def __init__(
        self,
        message: str,
        code: str = "MODEL_EXECUTION_ERROR",
        details: Optional[Any] = None,
    ) -> None:
        super().__init__(message, code=code, details=details)


class ExecutionTimeoutError(ModelExecutionError):
    """Raised when model inference exceeds the allocated execution time limit."""

    def __init__(
        self,
        message: str = "Model execution exceeded the maximum permitted time limit.",
        code: str = "EXECUTION_TIMEOUT",
        details: Optional[Any] = None,
    ) -> None:
        super().__init__(message, code=code, details=details)


class ExecutionCancelledError(ModelExecutionError):
    """Raised when model execution is cancelled cooperatively."""

    def __init__(
        self,
        message: str = "Model execution was cancelled by caller.",
        code: str = "EXECUTION_CANCELLED",
        details: Optional[Any] = None,
    ) -> None:
        super().__init__(message, code=code, details=details)


class ResourceLimitExceededError(BehavioralError):
    """Raised when execution parameters or outputs exceed safety resource limits."""

    def __init__(
        self,
        message: str,
        code: str = "RESOURCE_LIMIT_EXCEEDED",
        details: Optional[Any] = None,
    ) -> None:
        super().__init__(message, code=code, details=details)


class ExecutionProviderUnavailableError(BehavioralError):
    """Raised when a requested execution provider (e.g., CUDA) is unavailable."""

    def __init__(
        self,
        message: str,
        code: str = "PROVIDER_UNAVAILABLE",
        details: Optional[Any] = None,
    ) -> None:
        super().__init__(message, code=code, details=details)


class UnsupportedExecutionFormatError(BehavioralError):
    """Raised when attempting to execute a model format that cannot be executed safely."""

    def __init__(
        self,
        message: str,
        code: str = "UNSUPPORTED_EXECUTION_FORMAT",
        details: Optional[Any] = None,
    ) -> None:
        super().__init__(message, code=code, details=details)


class ModelLoadingError(BehavioralError):
    """Raised when model artifact loading or session initialization fails."""

    def __init__(
        self,
        message: str,
        code: str = "MODEL_LOAD_ERROR",
        details: Optional[Any] = None,
    ) -> None:
        super().__init__(message, code=code, details=details)


class InvalidInputTensorError(BehavioralError):
    """Raised when input tensors violate contract, dimension, dtype, or finite-value constraints."""

    def __init__(
        self,
        message: str,
        code: str = "INVALID_INPUT",
        details: Optional[Any] = None,
    ) -> None:
        super().__init__(message, code=code, details=details)


class InvalidOutputTensorError(BehavioralError):
    """Raised when model output tensors violate dimension, dtype, size, or finite-value constraints."""

    def __init__(
        self,
        message: str,
        code: str = "INVALID_OUTPUT",
        details: Optional[Any] = None,
    ) -> None:
        super().__init__(message, code=code, details=details)


class SecuritySandboxViolationError(BehavioralError):
    """Raised when an execution violates containment or filesystem boundary constraints."""

    def __init__(
        self,
        message: str,
        code: str = "SECURITY_SANDBOX_VIOLATION",
        details: Optional[Any] = None,
    ) -> None:
        super().__init__(message, code=code, details=details)
