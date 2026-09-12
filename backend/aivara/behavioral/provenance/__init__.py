"""Phase 8.7 — Evidence & Provenance Binding Subsystem for Behavioral Verification."""

from __future__ import annotations

from aivara.behavioral.provenance.enums import (
    BehavioralEvidenceType,
    BehavioralFindingStatus,
    BehavioralFindingType,
    EvidenceLifecycleState,
)
from aivara.behavioral.provenance.exceptions import (
    BehavioralEvidenceIdentityError,
    BehavioralEvidenceValidationError,
    BehavioralExecutionIdentityError,
    BehavioralProvenanceError,
    CrossProjectBindingError,
    EvidenceImmutableError,
    EvidenceTamperedError,
    IdempotencyConflictError,
    NonFiniteValueError,
    SignerUnavailableError,
)
from aivara.behavioral.provenance.schemas import (
    BehavioralEvidence,
    BehavioralEvidenceContent,
    BehavioralVerificationResult,
    BehavioralVerificationVector,
)
from aivara.behavioral.provenance.identity import (
    build_behavioral_execution_payload,
    build_canonical_behavioral_evidence_dict,
    compute_behavioral_evidence_hash,
    compute_behavioral_execution_identity_hash,
    is_valid_hash,
    sanitize_numeric_value,
)
from aivara.behavioral.provenance.evidence import (
    build_anomaly_evidence_content,
    create_behavioral_evidence,
    seal_behavioral_evidence,
    to_phase5_evidence_payload,
)
from aivara.behavioral.provenance.binding import (
    BehavioralProvenanceBindingService,
)
from aivara.behavioral.provenance.verifier import (
    BehavioralProvenanceVerifier,
)
from aivara.behavioral.provenance.idempotency import (
    resolve_idempotent_behavioral_scan,
)

__all__ = [
    "BehavioralEvidenceType",
    "BehavioralFindingStatus",
    "BehavioralFindingType",
    "EvidenceLifecycleState",
    "BehavioralProvenanceError",
    "BehavioralEvidenceIdentityError",
    "BehavioralExecutionIdentityError",
    "BehavioralEvidenceValidationError",
    "CrossProjectBindingError",
    "EvidenceTamperedError",
    "EvidenceImmutableError",
    "IdempotencyConflictError",
    "NonFiniteValueError",
    "SignerUnavailableError",
    "BehavioralEvidenceContent",
    "BehavioralEvidence",
    "BehavioralVerificationVector",
    "BehavioralVerificationResult",
    "build_canonical_behavioral_evidence_dict",
    "compute_behavioral_evidence_hash",
    "build_behavioral_execution_payload",
    "compute_behavioral_execution_identity_hash",
    "is_valid_hash",
    "sanitize_numeric_value",
    "build_anomaly_evidence_content",
    "create_behavioral_evidence",
    "seal_behavioral_evidence",
    "to_phase5_evidence_payload",
    "BehavioralProvenanceBindingService",
    "BehavioralProvenanceVerifier",
    "resolve_idempotent_behavioral_scan",
]
