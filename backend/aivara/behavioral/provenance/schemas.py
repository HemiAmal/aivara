"""Pydantic schemas and domain models for Phase 8.7 Behavioral Evidence & Provenance Binding."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field

from aivara.domain.schemas import EvidenceLayer
from aivara.evidence.schemas import ProvenanceStatus
from aivara.behavioral.provenance.enums import (
    BehavioralEvidenceType,
    BehavioralFindingStatus,
    BehavioralFindingType,
    EvidenceLifecycleState,
)


def utcnow_iso() -> str:
    """Return timezone-aware current UTC ISO-8601 string."""
    return datetime.now(timezone.utc).isoformat()


class BehavioralEvidenceContent(BaseModel):
    """Deterministic, immutable semantic content of a behavioral evidence item.

    Participates directly in RFC 8785 (JCS) canonical serialization and SHA-256 evidence hashing.
    Contains zero mutable state, database UUIDs, or un-canonicalized floating-point values.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    evidence_layer: EvidenceLayer = Field(..., description="Detection layer vs proof layer")
    evidence_type: BehavioralEvidenceType = Field(..., description="Controlled behavioral evidence type")
    project_id: str = Field(..., min_length=1, max_length=36, description="Project identifier")
    model_id: str = Field(..., min_length=1, max_length=255, description="Model identifier")
    model_fingerprint: str = Field(..., min_length=1, max_length=64, description="Phase 7 Master Model Fingerprint")
    task_type: str = Field(..., min_length=1, max_length=50, description="Task domain")
    observation_id: str = Field(..., min_length=1, max_length=255, description="Observation identifier")
    baseline_id: str = Field(..., min_length=1, max_length=255, description="Reference baseline identifier")
    baseline_type: str = Field(..., min_length=1, max_length=50, description="Baseline origin type")
    comparison_id: str = Field(default="NONE", max_length=255, description="Comparison profile ID or NONE")
    sensitivity_id: str = Field(default="NONE", max_length=255, description="Sensitivity experiment ID or NONE")
    anomaly_analysis_id: str = Field(default="NONE", max_length=255, description="Anomaly analysis digest or NONE")
    input_hash: str = Field(..., min_length=1, max_length=64, description="Deterministic input dataset/tensor hash")
    output_hash: str = Field(..., min_length=1, max_length=64, description="Deterministic output tensor/prediction hash")
    preprocessing_hash: str = Field(default="STANDARD_V1", max_length=64, description="Preprocessing pipeline hash")
    detector_id: str = Field(..., min_length=1, max_length=100, description="Unique detector/analysis identifier")
    detector_version: str = Field(..., min_length=1, max_length=50, description="Detector semver")
    detector_config_hash: str = Field(..., min_length=64, max_length=64, description="64-hex SHA-256 parameter hash")
    policy_version: str = Field(default="1.0.0", max_length=50, description="Statistical policy version")
    engine_version: str = Field(default="1.0.0", max_length=50, description="AIVARA behavioral engine version")
    result_status: str = Field(..., max_length=50, description="NORMAL | ANOMALOUS | INSUFFICIENT_SUPPORT | etc.")
    support_status: str = Field(..., max_length=50, description="ADEQUATE_SUPPORT | INSUFFICIENT_SUPPORT | etc.")
    comparability_status: str = Field(default="COMPARABLE", max_length=50, description="COMPARABLE | INCOMPARABLE")
    metrics: List[Dict[str, Any]] = Field(default_factory=list, description="Sorted list of metric evaluation dicts")
    families: Dict[str, Dict[str, Any]] = Field(default_factory=dict, description="Family-level summary dicts")
    limitations: List[str] = Field(default_factory=list, description="Sorted list of documented analytical limitations")


class BehavioralEvidence(BaseModel):
    """Full representation of a behavioral evidence item with lifecycle and hash."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    evidence_id: str = Field(..., min_length=64, max_length=64, description="Deterministic SHA-256 evidence hash")
    lifecycle_state: EvidenceLifecycleState = Field(default=EvidenceLifecycleState.DRAFT)
    content: BehavioralEvidenceContent
    created_at: str = Field(default_factory=utcnow_iso)
    provenance_record_id: Optional[str] = None
    provenance_status: ProvenanceStatus = ProvenanceStatus.UNAVAILABLE


class BehavioralVerificationVector(BaseModel):
    """Detailed multi-dimensional verification vector for behavioral assurance."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    evidence_identity_valid: bool = Field(..., description="Canonical content hash matches evidence_id")
    analysis_identity_valid: bool = Field(..., description="Anomaly analysis digest matches content")
    observation_identity_valid: bool = Field(..., description="Observation ID matches content")
    baseline_identity_valid: bool = Field(..., description="Baseline ID matches content")
    model_identity_valid: bool = Field(..., description="Model ID & fingerprint match content")
    provenance_hash_valid: bool = Field(..., description="Provenance record payload matches record_hash")
    signature_valid: bool = Field(..., description="Ed25519 signature is cryptographically valid")
    chain_valid: bool = Field(..., description="Previous record hash links correctly")
    sequence_valid: bool = Field(..., description="Sequence number is monotonically valid")
    nonce_valid: bool = Field(..., description="Nonce is fresh and unique")
    project_isolation_valid: bool = Field(..., description="Project ID is consistent across all items")
    signer_status: str = Field(..., description="ACTIVE | ROTATED | REVOKED | EXPIRED | UNKNOWN_SIGNER | NONE")
    failures: List[str] = Field(default_factory=list, description="List of detected verification failures")
    limitations: List[str] = Field(default_factory=list, description="List of verification limitations/warnings")


class BehavioralVerificationResult(BaseModel):
    """Overall cryptographic and analytical verification result for behavioral evidence."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    evidence_id: str
    project_id: str
    model_id: str
    overall_status: ProvenanceStatus
    verification_vector: BehavioralVerificationVector
    message: str
    verified_at: str = Field(default_factory=utcnow_iso)
