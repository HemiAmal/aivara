"""Phase 12.8 — Universal Proof & Provenance Integration.

Provides cryptographic verification, provenance binding, ancestry and scope isolation,
and immutable UniversalProofAssessment integration across universal evidence.
"""

from aivara.universal.proof.enums import (
    ProofCheckType,
    ProofSchemaVersion,
    ProofVerificationStatus,
)
from aivara.universal.proof.exceptions import (
    AncestryMismatchError,
    ProofError,
    ProofResourceLimitExceededError,
    ProofVerificationError,
    ProvenanceIntegrityError,
    ProvenanceReplayError,
    ProvenanceTamperError,
    ScopeMismatchError,
)
from aivara.universal.proof.hashing import (
    compute_proof_assessment_hash,
    compute_proof_result_hash,
)
from aivara.universal.proof.schemas import (
    MAX_EVIDENCE_PROOFS,
    MAX_PROVENANCE_RECORDS,
    ProofVerificationCheck,
    ProofVerificationResult,
    UniversalProofAssessment,
)
from aivara.universal.proof.engine import UniversalProofIntegrationEngine

__all__ = [
    # Enums
    "ProofVerificationStatus",
    "ProofCheckType",
    "ProofSchemaVersion",
    # Exceptions
    "ProofError",
    "ProofVerificationError",
    "ProvenanceIntegrityError",
    "ProvenanceTamperError",
    "ProvenanceReplayError",
    "ScopeMismatchError",
    "AncestryMismatchError",
    "ProofResourceLimitExceededError",
    # Schemas
    "MAX_EVIDENCE_PROOFS",
    "MAX_PROVENANCE_RECORDS",
    "ProofVerificationCheck",
    "ProofVerificationResult",
    "UniversalProofAssessment",
    # Hashing
    "compute_proof_result_hash",
    "compute_proof_assessment_hash",
    # Engine
    "UniversalProofIntegrationEngine",
]
