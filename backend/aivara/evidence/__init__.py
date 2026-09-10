"""AIVARA Evidence and Provenance Package (Phase 5.9).

Provides:
  - Deterministic canonical Evidence and Execution Identity hashing.
  - Evidence and Finding domain schemas and invariants.
  - Conceptual N:M Evidence <-> Finding binding and backward traceability.
  - Cryptographic Provenance sealing and verification integration.
  - Complete air-gapped, offline assurance services without DB schema modifications.
"""

from aivara.evidence.binding import EvidenceFindingBinder
from aivara.evidence.exceptions import (
    CrossProjectContaminationError,
    EvidenceError,
    EvidenceIdentityError,
    EvidenceValidationError,
    ExecutionIdentityError,
    IdempotencyCollisionError,
    MissingProvenanceError,
    ModelMismatchError,
    ProvenanceBindingError,
    StaleDatasetVersionError,
    VocabularyViolationError,
)
from aivara.evidence.identity import (
    build_canonical_evidence_content,
    build_canonical_execution_payload,
    compute_evidence_hash,
    compute_execution_identity_hash,
    is_valid_evidence_hash,
)
from aivara.evidence.provenance import ProvenanceBindingAdapter
from aivara.evidence.schemas import (
    EvidenceContent,
    EvidencePayload,
    EvidenceProvenanceVerificationResult,
    EvidenceType,
    ExecutionIdentityPayload,
    FindingSynthesisPayload,
    ProvenanceStatus,
    ScanExecutionStatus,
    TraceabilityChain,
    TraceabilityNode,
)
from aivara.evidence.service import EvidenceProvenanceService
from aivara.evidence.validators import (
    validate_confidence_bounds,
    validate_evidence_payload,
    validate_finding_payload,
    validate_finding_vocabulary,
    validate_numeric_metrics,
    validate_project_isolation,
)

__all__ = [
    "EvidenceFindingBinder",
    "CrossProjectContaminationError",
    "EvidenceError",
    "EvidenceIdentityError",
    "EvidenceValidationError",
    "ExecutionIdentityError",
    "IdempotencyCollisionError",
    "MissingProvenanceError",
    "ModelMismatchError",
    "ProvenanceBindingError",
    "StaleDatasetVersionError",
    "VocabularyViolationError",
    "build_canonical_evidence_content",
    "build_canonical_execution_payload",
    "compute_evidence_hash",
    "compute_execution_identity_hash",
    "is_valid_evidence_hash",
    "ProvenanceBindingAdapter",
    "EvidenceContent",
    "EvidencePayload",
    "EvidenceProvenanceVerificationResult",
    "EvidenceType",
    "ExecutionIdentityPayload",
    "FindingSynthesisPayload",
    "ProvenanceStatus",
    "ScanExecutionStatus",
    "TraceabilityChain",
    "TraceabilityNode",
    "EvidenceProvenanceService",
    "validate_confidence_bounds",
    "validate_evidence_payload",
    "validate_finding_payload",
    "validate_finding_vocabulary",
    "validate_numeric_metrics",
    "validate_project_isolation",
]
