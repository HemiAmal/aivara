"""Domain exceptions for Model Fingerprinting and Merkle Weight Engine (Phase 7.3)."""

from __future__ import annotations

from typing import Any, Dict, Optional
from aivara.model_integrity.exceptions import ModelIntegrityError


class FingerprintingError(ModelIntegrityError):
    """Base exception for all model fingerprinting failures."""

    def __init__(
        self,
        message: str,
        code: str = "FINGERPRINTING_ERROR",
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        super().__init__(message, code=code, details=details)


class WeightContentUnavailableError(FingerprintingError):
    """Raised when safe tensor content extraction cannot be performed."""

    def __init__(
        self,
        message: str,
        code: str = "WEIGHT_CONTENT_UNAVAILABLE",
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        super().__init__(message, code=code, details=details)


class InvalidMerkleProofError(FingerprintingError):
    """Raised when a Merkle inclusion proof is malformed or invalid."""

    def __init__(
        self,
        message: str,
        code: str = "INVALID_MERKLE_PROOF",
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        super().__init__(message, code=code, details=details)


class DuplicateTensorLeafError(FingerprintingError):
    """Raised when duplicate tensor names exist in leaf construction."""

    def __init__(
        self,
        message: str,
        code: str = "DUPLICATE_TENSOR_LEAF",
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        super().__init__(message, code=code, details=details)
