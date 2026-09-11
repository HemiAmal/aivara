"""Evidence Generation & Cryptographic Provenance Binding Module (Phase 7.6).

Connects Model Integrity assessments (fingerprints, contract verification, and comparison)
to AIVARA's Phase 5.9 Evidence/Finding engine and Phase 4 Cryptographic Provenance ledger.
"""

from aivara.model_integrity.evidence.builders import (
    build_artifact_identity_evidence,
    build_comparison_evidence,
    build_contract_evidence,
    build_master_fingerprint_evidence,
    build_structural_fingerprint_evidence,
    build_tensor_attribution_evidence,
    build_weight_merkle_evidence,
)
from aivara.model_integrity.evidence.mapping import (
    map_model_integrity_to_findings,
)
from aivara.model_integrity.evidence.schemas import (
    ModelEvidenceType,
    ModelIntegrityAssessmentPayload,
)
from aivara.model_integrity.evidence.service import (
    ModelIntegrityEvidenceService,
)

__all__ = [
    # Core Service
    "ModelIntegrityEvidenceService",
    # Schemas & Enums
    "ModelEvidenceType",
    "ModelIntegrityAssessmentPayload",
    # Builder Functions
    "build_artifact_identity_evidence",
    "build_structural_fingerprint_evidence",
    "build_weight_merkle_evidence",
    "build_contract_evidence",
    "build_master_fingerprint_evidence",
    "build_comparison_evidence",
    "build_tensor_attribution_evidence",
    # Mapping Function
    "map_model_integrity_to_findings",
]
