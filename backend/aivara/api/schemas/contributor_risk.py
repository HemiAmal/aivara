"""REST API schemas for Contributor Risk Engine (Phase 6.3).

Adheres strictly to ADR-030 (Multi-Dimensional Profile Vector, No Scalar Score)
and ADR-034 (Detection vs Proof Profile Separation).
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field


class ContributorRiskAssessmentRequest(BaseModel):
    """Request payload to trigger Contributor Risk assessment."""

    model_config = ConfigDict(frozen=True)

    contributor_id: str = Field(..., min_length=1, description="Contributor UUID or External ID")
    dataset_version_id: Optional[str] = Field(None, description="Optional target dataset version UUID")
    seal_provenance: bool = Field(default=False, description="Whether to seal assessment into Phase 4 provenance chain")
    signer_key_id: Optional[str] = Field(None, description="Signer key ID for cryptographic provenance sealing")
    signer_passphrase: Optional[str] = Field(None, description="Passphrase for encrypted signer key")


class BaselineInfoRead(BaseModel):
    """Contextual reference baseline details."""

    model_config = ConfigDict(frozen=True)

    baseline_type: str
    baseline_value: float
    support_sample_count: float
    reference_population: str
    is_fallback: bool = False
    stratum_identifier: Optional[str] = None
    limitations: List[str] = Field(default_factory=list)


class DetectionDimensionRead(BaseModel):
    """Detection layer analytical risk dimension."""

    model_config = ConfigDict(frozen=True)

    dimension_id: str
    evidence_layer: str = "detection"
    status: str
    observed_rate: Optional[float] = None
    shrunk_rate: Optional[float] = None
    baseline: Optional[BaselineInfoRead] = None
    differential: Optional[float] = None
    standard_error: Optional[float] = None
    confidence: float
    support_state: str
    primary_evidence_ids: List[str] = Field(default_factory=list)
    limitations: List[str] = Field(default_factory=list)
    details: Dict[str, Any] = Field(default_factory=dict)


class ProofDimensionRead(BaseModel):
    """Proof layer cryptographic provenance dimension (Strictly Isolated)."""

    model_config = ConfigDict(frozen=True)

    dimension_id: str = "DIM_PROVENANCE_INTEGRITY"
    evidence_layer: str = "proof"
    verification_status: str
    confidence: float = 1.0
    signer_key_id: Optional[str] = None
    signature_present: bool = False
    chain_valid: Optional[bool] = None
    nonce_valid: Optional[bool] = None
    tamper_detected: bool = False
    primary_evidence_ids: List[str] = Field(default_factory=list)
    limitations: List[str] = Field(default_factory=list)


class EvidenceFamilyRead(BaseModel):
    """Dependency-Aware Evidence Family (ADR-034)."""

    model_config = ConfigDict(frozen=True)

    family_id: str
    family_name: str
    evidence_layer: str
    constituent_dimensions: List[str]
    dominant_differential: Optional[float] = None
    dominant_dimension_id: Optional[str] = None
    evidence_count: int = 0
    is_proof_layer: bool = False


class RiskIndicatorRead(BaseModel):
    """Neutral, evidence-backed risk observation (ADR-035)."""

    model_config = ConfigDict(frozen=True)

    indicator_id: str
    dimension_id: str
    severity: str
    confidence: float
    summary: str
    limitations: List[str] = Field(default_factory=list)


class DetectionProfileRead(BaseModel):
    """Detection layer profile grouping all 4 analytical dimensions."""

    model_config = ConfigDict(frozen=True)

    label_reliability: DetectionDimensionRead
    transition_asymmetry: DetectionDimensionRead
    quality_divergence: DetectionDimensionRead
    distribution_shift: DetectionDimensionRead
    effective_exposure: float


class ProofProfileRead(BaseModel):
    """Proof layer profile containing isolated cryptographic provenance."""

    model_config = ConfigDict(frozen=True)

    provenance_integrity: ProofDimensionRead


class ContributorRiskProfileRead(BaseModel):
    """Complete, immutable Contributor Risk Profile response."""

    model_config = ConfigDict(frozen=True)

    contributor_id: str
    project_id: str
    dataset_version_id: Optional[str] = None
    effective_sample_count: float
    support_state: str
    profile_status: str
    detection_profile: DetectionProfileRead
    proof_profile: ProofProfileRead
    evidence_families: List[EvidenceFamilyRead] = Field(default_factory=list)
    risk_indicators: List[RiskIndicatorRead] = Field(default_factory=list)
    created_at: str


class ContributorEvidenceGraphRead(BaseModel):
    """Backward-traceable Contributor Evidence Graph."""

    model_config = ConfigDict(frozen=True)

    contributor_id: str
    project_id: str
    dataset_version_id: Optional[str] = None
    effective_exposure: float
    total_attributed_samples: int
    attributed_samples: List[Dict[str, Any]] = Field(default_factory=list)
    evidence_items: List[Dict[str, Any]] = Field(default_factory=list)
    findings: List[Dict[str, Any]] = Field(default_factory=list)
    dimensions: List[str] = Field(default_factory=list)
