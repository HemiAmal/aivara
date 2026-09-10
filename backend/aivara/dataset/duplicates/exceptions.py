"""Domain exceptions for Near-Duplicate Detection Engine (Phase 5.4)."""

from typing import Any, Optional
from aivara.core.exceptions import AivaraException


class DuplicateDetectionError(AivaraException, ValueError):
    """Base exception for near-duplicate detection and perceptual indexing errors."""

    def __init__(
        self,
        message: str,
        code: str = "DUPLICATE_DETECTION_ERROR",
        details: Optional[Any] = None,
    ) -> None:
        super().__init__(message, code=code, details=details)


class InvalidPerceptualHashError(DuplicateDetectionError):
    """Raised when a perceptual hash string or value is malformed."""

    def __init__(self, message: str, details: Optional[Any] = None) -> None:
        super().__init__(message, code="INVALID_PERCEPTUAL_HASH", details=details)


class InvalidThresholdError(DuplicateDetectionError):
    """Raised when an invalid Hamming distance threshold is supplied."""

    def __init__(self, message: str, details: Optional[Any] = None) -> None:
        super().__init__(message, code="INVALID_THRESHOLD", details=details)


class EmptyIndexError(DuplicateDetectionError):
    """Raised when an operation requires an instantiated index but none exists."""

    def __init__(self, message: str, details: Optional[Any] = None) -> None:
        super().__init__(message, code="EMPTY_INDEX", details=details)


class BKTreeError(DuplicateDetectionError):
    """Raised when BK-tree operations encounter invalid parameters or structural corruption."""

    def __init__(self, message: str, details: Optional[Any] = None) -> None:
        super().__init__(message, code="BKTREE_ERROR", details=details)


class MultiIndexHashError(DuplicateDetectionError):
    """Raised when Multi-Index Hashing encounters configuration or partition errors."""

    def __init__(self, message: str, details: Optional[Any] = None) -> None:
        super().__init__(message, code="MIH_ERROR", details=details)
