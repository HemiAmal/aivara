"""Pydantic schemas and domain models for AIVARA Evidence and Provenance Engine (Phase 5.9).

Enforces:
  - Strict immutability (frozen ConfigDict).
  - Explicit evidence types and provenance states.
  - Deterministic canonical serialization schemas.
  - Conceptual N:M relationship between findings and evidence.
  - Zero risk scoring calculation (reserved for Phase 12).
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Union

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from aivara.domain.schemas import (
    AnalysisMode,
    Disposition,
    EvidenceLayer,
    Severity,
)


def utcnow() -> datetime:
    """Return timezone-aware current UTC datetime."""
    return datetime.now(timezone.utc)


# =====================================================================
# Domain Enums
# =====================================================================

class EvidenceType(str, Enum):
    """Controlled taxonomy of analytical and cryptographic evidence types."""

    DATASET_FINGERPRINT_MANIFEST = "dataset_fingerprint_manifest"
    MERKLE_INCLUSION_PROOF = "merkle_inclusion_proof"
    NEAR_DUPLICATE_RELATIONSHIP = "near_duplicate_relationship"
    LABEL_ANOMALY_SCORE = "label_anomaly_score"
    LABEL_FLIPPING_TRANSITION = "label_flipping_transition"
    IMAGE_QUALITY_METRICS = "image_quality_metrics"
    OOD_DISTANCE_SCORE = "ood_distance_score"
    DISTRIBUTION_SHIFT_EVIDENCE = "distribution_shift_evidence"
    CONTRIBUTOR_AGGREGATION_PROFILE = "contributor_aggregation_profile"
    CRYPTOGRAPHIC_PROVENANCE_RECORD = "cryptographic_provenance_record"
    GENERIC_DETECTION_EVIDENCE = "generic_detection_evidence"


class ProvenanceStatus(str, Enum):
    """Cryptographic provenance evaluation states (Frozen Phase 5.9.1 taxonomy).

    1. VERIFIED: Cryptographic verification succeeds (signature valid, hashes match, unbroken chain).
    2. INVALID: Cryptographic integrity/authenticity verification actually fails (tampered hash, invalid signature).
    3. MISSING: Expected provenance record is not found in the ledger database.
    4. UNAVAILABLE: Provenance tracking not initialized, or required verification capability/key is unavailable.
    5. MISMATCHED: Provenance exists but context does not match expected finding/dataset/model context.
    6. UNVERIFIABLE: Available record information is insufficient or malformed to establish a verification result.
    """

    VERIFIED = "VERIFIED"
    INVALID = "INVALID"
    MISSING = "MISSING"
    UNAVAILABLE = "UNAVAILABLE"
    MISMATCHED = "MISMATCHED"
    UNVERIFIABLE = "UNVERIFIABLE"

    # Contextual sub-state aliases:
    INCOMPLETE = "INCOMPLETE"
    UNKNOWN_FINGERPRINT = "UNKNOWN_FINGERPRINT"
    FINGERPRINT_MISMATCH = "FINGERPRINT_MISMATCH"
    SIGNATURE_INVALID = "SIGNATURE_INVALID"
    STALE_DATASET_VERSION = "STALE_DATASET_VERSION"
    MODEL_MISMATCH = "MODEL_MISMATCH"
    CROSS_PROJECT_REJECTED = "CROSS_PROJECT_REJECTED"


class ScanExecutionStatus(str, Enum):
    """Execution completeness and integrity status of an analytical scan."""

    COMPLETED = "COMPLETED"
    PARTIAL_SUCCESS = "PARTIAL_SUCCESS"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"
    FAILED = "FAILED"
    IDEMPOTENT_HIT = "IDEMPOTENT_HIT"


# =====================================================================
# Canonical Evidence & Execution Identity Payloads (Immutable)
# =====================================================================

class EvidenceContent(BaseModel):
    """Canonical, deterministic content of an analytical evidence item.

    Contains exclusively the immutable, semantic attributes required to compute
    the deterministic evidence_hash via RFC 8785 (JCS) and SHA-256.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    evidence_layer: EvidenceLayer = Field(..., description="Detection layer vs proof layer")
    evidence_type: str = Field(..., min_length=1, max_length=100, description="Evidence taxonomy type")
    project_id: str = Field(..., min_length=1, max_length=36, description="Project identifier")
    dataset_version_id: str = Field(..., min_length=1, max_length=36, description="Dataset version identifier")
    dataset_fingerprint: str = Field(..., min_length=64, max_length=64, description="64-hex SHA-256 manifest hash")
    target_asset_type: str = Field(..., min_length=1, max_length=50, description="Asset type (sample, annotation, contributor, model, dataset)")
    target_asset_id: str = Field(..., min_length=1, max_length=255, description="Target asset identifier")
    target_asset_hash: str = Field(..., min_length=1, max_length=64, description="SHA-256 hash of target asset content or NONE")
    detector_id: str = Field(..., min_length=1, max_length=100, description="Unique detector identifier")
    detector_version: str = Field(..., min_length=1, max_length=50, description="Detector semver string")
    detector_config_hash: str = Field(..., min_length=64, max_length=64, description="64-hex SHA-256 hash of detector parameters")
    model_fingerprint: str = Field(default="NONE", max_length=64, description="Model weight hash or NONE / UNAVAILABLE")
    reference_fingerprint: str = Field(default="NONE", max_length=64, description="Reference dataset manifest hash or NONE")
    measurements: Dict[str, Any] = Field(default_factory=dict, description="Deterministic numeric and categorical measurements")


class ExecutionIdentityPayload(BaseModel):
    """Structured canonical payload defining the complete analytical execution identity.

    Guarantees: 'If a change can alter the analytical result, that change MUST participate
    in execution identity.' Used to compute the deterministic ExecutionIdentityHash for idempotency.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    project_id: str = Field(..., min_length=1, max_length=36)
    dataset_version_id: str = Field(..., min_length=1, max_length=36)
    dataset_fingerprint: str = Field(..., min_length=64, max_length=64)
    detector_id: str = Field(..., min_length=1, max_length=100)
    detector_version: str = Field(..., min_length=1, max_length=50)
    engine_version: str = Field(..., min_length=1, max_length=50)
    policy_version: str = Field(default="DEFAULT", max_length=50)
    preprocessing_hash: str = Field(default="STANDARD_V1", max_length=64)
    model_id: str = Field(default="NONE", max_length=36)
    model_fingerprint: str = Field(default="NONE", max_length=64)
    model_version: str = Field(default="NONE", max_length=50)
    reference_dataset_id: str = Field(default="NONE", max_length=36)
    reference_dataset_fingerprint: str = Field(default="NONE", max_length=64)
    detector_config_hash: str = Field(..., min_length=64, max_length=64)


# =====================================================================
# Evidence & Finding Payloads (API & Persistence Bridge)
# =====================================================================

class EvidencePayload(BaseModel):
    """In-memory representation of an evidence item ready for synthesis and persistence."""

    model_config = ConfigDict(frozen=True)

    title: str = Field(..., min_length=1, max_length=500)
    description: Optional[str] = None
    evidence_layer: EvidenceLayer = Field(..., description="detection or proof")
    evidence_type: str = Field(..., min_length=1, max_length=100)
    confidence: Optional[float] = Field(None, ge=0.0, le=1.0)
    artifact_path: Optional[str] = None
    artifact_hash: Optional[str] = Field(None, max_length=64)
    data_json: Dict[str, Any] = Field(default_factory=dict)
    evidence_hash: Optional[str] = Field(None, max_length=64)
    target_asset_type: str = Field(..., min_length=1, max_length=50)
    target_asset_id: str = Field(..., min_length=1, max_length=255)
    target_asset_hash: str = Field(default="NONE", max_length=64)
    dataset_version_id: Optional[str] = None
    dataset_fingerprint: Optional[str] = None
    detector_id: Optional[str] = None
    detector_version: Optional[str] = None
    detector_config_hash: Optional[str] = None
    model_fingerprint: Optional[str] = None
    reference_fingerprint: Optional[str] = None
    measurements: Dict[str, Any] = Field(default_factory=dict)


class FindingSynthesisPayload(BaseModel):
    """Payload for synthesizing a Finding and binding primary and derived evidence."""

    model_config = ConfigDict(frozen=True)

    project_id: str = Field(..., min_length=1, max_length=36)
    audit_run_id: Optional[str] = None
    engine_id: str = Field(..., min_length=1, max_length=100)
    engine_version: Optional[str] = Field(None, max_length=50)
    evidence_layer: EvidenceLayer
    finding_type: str = Field(..., min_length=1, max_length=100)
    title: str = Field(..., min_length=1, max_length=500)
    description: Optional[str] = None
    severity: Severity
    confidence: float = Field(..., ge=0.0, le=1.0)
    affected_asset_type: str = Field(..., min_length=1, max_length=50)
    affected_asset_id: str = Field(..., min_length=1, max_length=255)
    disposition: Disposition = Disposition.REVIEW
    analysis_mode: AnalysisMode = AnalysisMode.NOT_APPLICABLE
    recommendation: Optional[str] = None
    status: str = "open"
    primary_evidence_items: List[EvidencePayload] = Field(default_factory=list, description="Directly originated evidence items")
    referenced_evidence_ids: List[str] = Field(default_factory=list, description="Secondary/derived evidence IDs for N:M synthesis")
    referenced_evidence_hashes: List[str] = Field(default_factory=list, description="Secondary/derived evidence hashes")
    metadata_json: Dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def validate_proof_layer_confidence(self):
        """Enforce ADR-028: Proof-layer findings MUST have confidence = 1.0."""
        if self.evidence_layer == EvidenceLayer.PROOF and self.confidence != 1.0:
            raise ValueError("Proof-layer findings must have confidence = 1.0")
        return self


# =====================================================================
# Traceability & Provenance Verification Schemas
# =====================================================================

class TraceabilityNode(BaseModel):
    """Single node in an evidence-finding backward traceability graph."""

    model_config = ConfigDict(frozen=True)

    entity_type: str = Field(..., description="finding, evidence, sample, dataset_version, contributor, model, provenance")
    entity_id: str = Field(..., description="Unique entity identifier")
    entity_hash: Optional[str] = Field(None, description="SHA-256 hash of entity content if applicable")
    attributes: Dict[str, Any] = Field(default_factory=dict)
    parent_ids: List[str] = Field(default_factory=list)


class TraceabilityChain(BaseModel):
    """Complete backward traceability graph for a finding."""

    model_config = ConfigDict(frozen=True)

    finding_id: str
    project_id: str
    dataset_version_id: Optional[str] = None
    dataset_fingerprint: Optional[str] = None
    nodes: Dict[str, TraceabilityNode] = Field(default_factory=dict)
    primary_evidence_ids: List[str] = Field(default_factory=list)
    secondary_evidence_ids: List[str] = Field(default_factory=list)
    provenance_record_id: Optional[str] = None
    provenance_status: ProvenanceStatus = ProvenanceStatus.UNAVAILABLE


class EvidenceProvenanceVerificationResult(BaseModel):
    """Cryptographic and analytical verification summary for evidence bound to provenance."""

    model_config = ConfigDict(frozen=True)

    finding_id: str
    provenance_record_id: Optional[str] = None
    provenance_status: ProvenanceStatus
    cryptographic_validity: bool
    evidence_count: int
    verified_evidence_hashes: List[str] = Field(default_factory=list)
    unverified_evidence_hashes: List[str] = Field(default_factory=list)
    warnings: List[str] = Field(default_factory=list)
    errors: List[str] = Field(default_factory=list)
