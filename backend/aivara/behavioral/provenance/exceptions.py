"""Typed exceptions for Phase 8.7 Behavioral Evidence & Provenance Binding."""

from __future__ import annotations

from typing import Optional
from aivara.core.exceptions import AivaraException


class BehavioralProvenanceError(AivaraException):
    """Base exception for behavioral evidence and provenance binding operations."""

    def __init__(self, message: str, code: str = "BEHAVIORAL_PROVENANCE_ERROR") -> None:
        super().__init__(message, code=code)


class BehavioralEvidenceIdentityError(BehavioralProvenanceError):
    """Raised when evidence content is invalid or cannot be deterministically hashed."""

    def __init__(self, message: str) -> None:
        super().__init__(message, code="BEHAVIORAL_EVIDENCE_IDENTITY_ERROR")


class BehavioralExecutionIdentityError(BehavioralProvenanceError):
    """Raised when execution identity payload is incomplete or invalid."""

    def __init__(self, message: str) -> None:
        super().__init__(message, code="BEHAVIORAL_EXECUTION_IDENTITY_ERROR")


class BehavioralEvidenceValidationError(BehavioralProvenanceError):
    """Raised when evidence fails validation checks."""

    def __init__(self, message: str) -> None:
        super().__init__(message, code="BEHAVIORAL_EVIDENCE_VALIDATION_ERROR")


class CrossProjectBindingError(BehavioralProvenanceError):
    """Raised when an attempt is made to bind or verify evidence across disparate projects."""

    def __init__(self, message: str) -> None:
        super().__init__(message, code="CROSS_PROJECT_BINDING_ERROR")


class EvidenceTamperedError(BehavioralProvenanceError):
    """Raised when cryptographic evidence integrity or signature verification fails due to tampering."""

    def __init__(self, message: str) -> None:
        super().__init__(message, code="EVIDENCE_TAMPERED_ERROR")


class EvidenceImmutableError(BehavioralProvenanceError):
    """Raised when an attempt is made to mutate sealed evidence content."""

    def __init__(self, message: str = "Sealed behavioral evidence is immutable and cannot be modified.") -> None:
        super().__init__(message, code="EVIDENCE_IMMUTABLE_ERROR")


class IdempotencyConflictError(BehavioralProvenanceError):
    """Raised when an analytical replay conflict or mismatched payload is encountered."""

    def __init__(self, message: str) -> None:
        super().__init__(message, code="IDEMPOTENCY_CONFLICT_ERROR")


class NonFiniteValueError(BehavioralProvenanceError):
    """Raised when a non-finite floating point value (NaN, Inf, -Inf) is passed to canonical evidence."""

    def __init__(self, message: str) -> None:
        super().__init__(message, code="NON_FINITE_VALUE_ERROR")


class SignerUnavailableError(BehavioralProvenanceError):
    """Raised when the specified signing key is missing or cannot be accessed."""

    def __init__(self, message: str) -> None:
        super().__init__(message, code="SIGNER_UNAVAILABLE_ERROR")
