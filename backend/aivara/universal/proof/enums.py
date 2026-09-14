"""Enumerations for Phase 12.8 Universal Proof & Provenance Integration.

Enforces:
- Granular proof verification statuses (VERIFIED, INVALID, MISSING, UNAVAILABLE, TAMPERED, REPLAY_DETECTED).
- Controlled taxonomy of cryptographic check types.
- Strict versioning enums for proof contracts.
"""

from enum import Enum


class ProofVerificationStatus(str, Enum):
    """Authoritative categorical outcome of cryptographic proof and provenance verification."""
    VERIFIED = "VERIFIED"                # Complete cryptographic verification succeeded (confidence = 1.0)
    INVALID = "INVALID"                  # Proof exists but cryptographic verification failed (e.g. signature mismatch)
    MISSING = "MISSING"                  # No proof or provenance record is attached/available
    UNAVAILABLE = "UNAVAILABLE"          # Provenance reference exists but material is unreachable / unresolvable
    TAMPERED = "TAMPERED"                # Hash-chain breakage or canonical payload hash modification detected
    REPLAY_DETECTED = "REPLAY_DETECTED"  # Nonce/sequence collision, duplicate identity, or stale replay detected

    @property
    def is_verified(self) -> bool:
        """True only if the status represents verified cryptographic proof."""
        return self == ProofVerificationStatus.VERIFIED

    @property
    def is_fatal_failure(self) -> bool:
        """True if the status represents a hard cryptographic compromise or failure."""
        return self in (
            ProofVerificationStatus.INVALID,
            ProofVerificationStatus.TAMPERED,
            ProofVerificationStatus.REPLAY_DETECTED,
        )


class ProofCheckType(str, Enum):
    """Specific cryptographic validation check performed during proof integration."""
    RECORD_HASH = "RECORD_HASH"                  # SHA-256 JCS canonical payload hash matches stored record_hash
    PREVIOUS_HASH = "PREVIOUS_HASH"              # Hash chain previous_record_hash continuity
    SEQUENCE_CONTINUITY = "SEQUENCE_CONTINUITY"  # Monotonically increasing sequence number
    NONCE_UNIQUENESS = "NONCE_UNIQUENESS"        # Nonce format and replay uniqueness check
    SIGNATURE_VALIDITY = "SIGNATURE_VALIDITY"    # Ed25519 digital signature verification over canonical payload
    KEY_STATUS = "KEY_STATUS"                    # Signer key status and identity verification
    EVIDENCE_BINDING = "EVIDENCE_BINDING"        # Evidence hash/ID matches provenance record payload
    FINDING_BINDING = "FINDING_BINDING"          # Finding ID and attributes correctly reference evidence
    ANCESTRY_BINDING = "ANCESTRY_BINDING"        # 5-tuple ancestry path matches signed provenance ancestry
    SCOPE_CONSISTENCY = "SCOPE_CONSISTENCY"      # Project ID and Asset ID match across evidence and provenance


class ProofSchemaVersion(str, Enum):
    """SemVer for Universal Proof Integration contracts."""
    V1_0 = "1.0.0"
