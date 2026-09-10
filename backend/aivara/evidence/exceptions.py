"""Domain exceptions for AIVARA Evidence and Provenance Engine (Phase 5.9)."""

from typing import Any, Optional

from aivara.core.exceptions import AivaraException


class EvidenceError(AivaraException):
    """Base exception for all evidence and provenance binding operations."""

    def __init__(self, message: str, code: str = "EVIDENCE_ERROR", details: Optional[Any] = None) -> None:
        super().__init__(message, code=code, details=details)


class EvidenceValidationError(EvidenceError):
    """Raised when evidence content or payload fails validation invariants."""

    def __init__(self, message: str, details: Optional[Any] = None) -> None:
        super().__init__(message, code="EVIDENCE_VALIDATION_ERROR", details=details)


class EvidenceIdentityError(EvidenceError):
    """Raised on failure during deterministic canonical evidence hashing or identity verification."""

    def __init__(self, message: str, details: Optional[Any] = None) -> None:
        super().__init__(message, code="EVIDENCE_IDENTITY_ERROR", details=details)


class ExecutionIdentityError(EvidenceError):
    """Raised on malformed or incomplete execution identity parameters."""

    def __init__(self, message: str, details: Optional[Any] = None) -> None:
        super().__init__(message, code="EXECUTION_IDENTITY_ERROR", details=details)


class ProvenanceBindingError(EvidenceError):
    """Raised when binding evidence or findings to cryptographic provenance fails."""

    def __init__(self, message: str, details: Optional[Any] = None) -> None:
        super().__init__(message, code="PROVENANCE_BINDING_ERROR", details=details)


class CrossProjectContaminationError(EvidenceError):
    """Raised when attempting to bind evidence, datasets, models, or provenance across different projects."""

    def __init__(self, message: str, details: Optional[Any] = None) -> None:
        super().__init__(message, code="CROSS_PROJECT_CONTAMINATION", details=details)


class StaleDatasetVersionError(EvidenceError):
    """Raised when evidence references a dataset version or fingerprint that does not match current state."""

    def __init__(self, message: str, details: Optional[Any] = None) -> None:
        super().__init__(message, code="STALE_DATASET_VERSION", details=details)


class ModelMismatchError(EvidenceError):
    """Raised when model weights or structural fingerprints do not match registered records."""

    def __init__(self, message: str, details: Optional[Any] = None) -> None:
        super().__init__(message, code="MODEL_MISMATCH", details=details)


class MissingProvenanceError(EvidenceError):
    """Raised when cryptographic provenance is required for verification but unavailable."""

    def __init__(self, message: str, details: Optional[Any] = None) -> None:
        super().__init__(message, code="MISSING_PROVENANCE", details=details)


class IdempotencyCollisionError(EvidenceError):
    """Raised when an execution identity collision or unexpected mutation occurs during idempotent retrieval."""

    def __init__(self, message: str, details: Optional[Any] = None) -> None:
        super().__init__(message, code="IDEMPOTENCY_COLLISION", details=details)


class VocabularyViolationError(EvidenceError):
    """Raised when finding descriptions or recommendations use forbidden accusatory vocabulary."""

    def __init__(self, message: str, details: Optional[Any] = None) -> None:
        super().__init__(message, code="VOCABULARY_VIOLATION", details=details)
