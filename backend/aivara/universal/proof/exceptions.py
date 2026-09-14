"""Custom exceptions for Phase 12.8 Universal Proof & Provenance Integration."""

from typing import Any, Dict, Optional


class ProofError(Exception):
    """Base exception for all Phase 12.8 proof and provenance integration errors."""

    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(message)
        self.message = message
        self.details = details or {}


class ProofVerificationError(ProofError):
    """Raised when proof verification encounters an invalid cryptographic condition."""
    pass


class ProvenanceIntegrityError(ProofError):
    """Raised when provenance record hash, canonical structure, or signature is broken."""
    pass


class ProvenanceTamperError(ProvenanceIntegrityError):
    """Raised when explicit tampering (e.g. payload modification, hash mismatch) is detected."""
    pass


class ProvenanceReplayError(ProofError):
    """Raised when nonce reuse, sequence collision, or replay is detected."""
    pass


class ScopeMismatchError(ProofError):
    """Raised when project ID or asset ID does not match between evidence and provenance."""
    pass


class AncestryMismatchError(ProofError):
    """Raised when ancestry path fields differ between evidence and signed provenance."""
    pass


class ProofResourceLimitExceededError(ProofError):
    """Raised when proof verification exceeds global bounded resource limits."""
    pass
