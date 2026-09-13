"""Exceptions for Universal Evidence Normalization & Adapters (Phase 12.2).

All exceptions inherit from AivaraException and provide machine-readable error codes.
"""

from typing import Any, Dict, Optional
from aivara.core.exceptions import AivaraException


class UniversalEvidenceError(AivaraException):
    """Base exception for all Phase 12 universal evidence normalization errors."""

    def __init__(
        self,
        message: str,
        code: str = "UNIVERSAL_EVIDENCE_ERROR",
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        super().__init__(message, code=code, details=details)


class ProjectMismatchError(UniversalEvidenceError):
    """Raised when evidence project_id does not match the target project."""

    def __init__(
        self,
        message: str = "Evidence project_id does not match target project context.",
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        super().__init__(message, code="PROJECT_MISMATCH", details=details)


class InvalidEvidenceError(UniversalEvidenceError):
    """Raised when an evidence record is malformed, has non-finite floats, or invalid structure."""

    def __init__(
        self,
        message: str = "Evidence record is malformed or contains invalid metrics.",
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        super().__init__(message, code="INVALID_EVIDENCE", details=details)


class UnknownDomainError(UniversalEvidenceError):
    """Raised when an unrecognized assurance domain is presented."""

    def __init__(
        self,
        message: str = "Unknown or unregistered assurance domain.",
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        super().__init__(message, code="UNKNOWN_DOMAIN", details=details)


class DuplicateAdapterError(UniversalEvidenceError):
    """Raised when attempting to register multiple adapters for the same domain."""

    def __init__(
        self,
        message: str = "Adapter already registered for this domain.",
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        super().__init__(message, code="DUPLICATE_ADAPTER", details=details)


class AdapterMismatchError(UniversalEvidenceError):
    """Raised when an adapter is invoked with incompatible input domain."""

    def __init__(
        self,
        message: str = "Adapter domain mismatch with input evidence.",
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        super().__init__(message, code="ADAPTER_MISMATCH", details=details)


class AncestryIntegrityError(UniversalEvidenceError):
    """Raised when evidence ancestry is corrupted or internally contradictory."""

    def __init__(
        self,
        message: str = "Evidence ancestry path is corrupted or invalid.",
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        super().__init__(message, code="ANCESTRY_INTEGRITY_ERROR", details=details)


class UniversalResourceLimitExceededError(UniversalEvidenceError):
    """Raised when evidence count or graph boundaries exceed hard safety limits."""

    def __init__(
        self,
        message: str = "Universal evidence count exceeds hard safety budget.",
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        super().__init__(message, code="RESOURCE_LIMIT_EXCEEDED", details=details)


class PayloadSizeExceededError(UniversalEvidenceError):
    """Raised when an individual evidence payload exceeds maximum allowed size."""

    def __init__(
        self,
        message: str = "Evidence payload size exceeds maximum limit.",
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        super().__init__(message, code="PAYLOAD_SIZE_EXCEEDED", details=details)


class SourceHashMismatchError(InvalidEvidenceError):
    """Raised when supplied source payload hash does not match recomputed SHA-256 digest."""

    def __init__(
        self,
        message: str = "Supplied source payload hash does not match recomputed SHA-256 digest.",
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        super().__init__(message=message, details=details)
        self.code = "SOURCE_HASH_MISMATCH"


class ProvenanceHashValidationError(InvalidEvidenceError):
    """Raised when provenance hashes are malformed or invalid."""

    def __init__(
        self,
        message: str = "Provenance hash is invalid or malformed.",
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        super().__init__(message=message, details=details)
        self.code = "PROVENANCE_HASH_INVALID"


class ConfidenceValidationError(InvalidEvidenceError):
    """Raised when confidence values are non-finite, out of [0.0, 1.0], or invalid for proof layer."""

    def __init__(
        self,
        message: str = "Confidence value is invalid or violates proof layer invariant.",
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        super().__init__(message=message, details=details)
        self.code = "CONFIDENCE_VALIDATION_ERROR"

