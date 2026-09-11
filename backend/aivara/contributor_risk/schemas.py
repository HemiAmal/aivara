"""Immutable domain models and schemas for Contributor Risk Engine (Phase 6).

Adheres strictly to ADR-028, ADR-030 through ADR-039, and the foundational semantic invariants:
1. ANOMALY != MALICIOUSNESS
2. DETECTION EVIDENCE != PROOF OF GUILT
3. TECHNICAL SECURITY TERMINOLOGY IS PERMITTED; UNSUPPORTED INTENT INFERENCE IS NOT.
4. PROOF-LAYER IS STRICTLY SEPARATED FROM DETECTION-LAYER NUMERICAL METRICS.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Sequence, Tuple
from pydantic import BaseModel, ConfigDict, Field, field_validator


# =====================================================================
# Enumerations
# =====================================================================

class SupportState(str, Enum):
    """Statistical sample support state tiers for conservative risk estimation."""
    UNVERIFIABLE = "UNVERIFIABLE"         # Nc < 3: zero evaluation
    LOW_SUPPORT = "LOW_SUPPORT"           # 3 <= Nc < 10: heavy shrinkage (>=67%), notices only
    MODERATE_SUPPORT = "MODERATE_SUPPORT" # 10 <= Nc < 30: active empirical Bayes shrinkage
    ADEQUATE_SUPPORT = "ADEQUATE_SUPPORT" # Nc >= 30: fully calibrated empirical vector


class EvaluationStatus(str, Enum):
    """Status indicator for specific dimensional evaluations."""
    AVAILABLE = "AVAILABLE"
    LOW_SUPPORT = "LOW_SUPPORT"
    MODERATE_SUPPORT = "MODERATE_SUPPORT"
    ADEQUATE_SUPPORT = "ADEQUATE_SUPPORT"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"
    INSUFFICIENT_BASELINE = "INSUFFICIENT_BASELINE"
    UNVERIFIABLE = "UNVERIFIABLE"
    UNAVAILABLE = "UNAVAILABLE"
    INCOMPATIBLE = "INCOMPATIBLE"


class RiskDimensionId(str, Enum):
    """Authoritative identifiers for the 5 contributor risk dimensions."""
    DIM_LABEL_RELIABILITY = "DIM_LABEL_RELIABILITY"
    DIM_TRANSITION_ASYM = "DIM_TRANSITION_ASYM"
    DIM_QUALITY_DIVERGENCE = "DIM_QUALITY_DIVERGENCE"
    DIM_DISTRIBUTION_SHIFT = "DIM_DISTRIBUTION_SHIFT"
    DIM_PROVENANCE_INTEGRITY = "DIM_PROVENANCE_INTEGRITY"


class EvidenceFamilyId(str, Enum):
    """Dependency-Aware Evidence Families (ADR-034)."""
    LABEL_INTEGRITY = "LABEL_INTEGRITY"             # Detection Layer
    PHYSICAL_QUALITY = "PHYSICAL_QUALITY"           # Detection Layer
    DISTRIBUTION_SHIFT = "DISTRIBUTION_SHIFT"       # Detection Layer
    CRYPTOGRAPHIC_PROVENANCE = "CRYPTOGRAPHIC_PROVENANCE"  # Proof Layer (Strictly Isolated)


class BaselineType(str, Enum):
    """Type of reference baseline utilized for comparison."""
    LEAVE_ONE_OUT = "LEAVE_ONE_OUT"
    CLASS_CONDITIONAL = "CLASS_CONDITIONAL"
    SUBGROUP = "SUBGROUP"
    GLOBAL_DATASET = "GLOBAL_DATASET"


class OverallProfileStatus(str, Enum):
    """Deterministic, rule-based interpretation of the contributor profile."""
    PROVENANCE_INTEGRITY_VIOLATION = "PROVENANCE_INTEGRITY_VIOLATION"
    UNVERIFIED_PROVENANCE = "UNVERIFIED_PROVENANCE"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"
    ELEVATED_ANOMALY_CONCENTRATION = "ELEVATED_ANOMALY_CONCENTRATION"
    MODERATE_DEVIATION = "MODERATE_DEVIATION"
    BASELINE_CONGRUENT = "BASELINE_CONGRUENT"


# =====================================================================
# Baseline Abstraction
# =====================================================================

class ContextualBaseline(BaseModel):
    """Contextual reference baseline explaining the comparison population (ADR-031)."""

    model_config = ConfigDict(frozen=True)

    baseline_type: BaselineType
    baseline_value: float = Field(..., ge=0.0, le=1.0, description="Background baseline rate in [0.0, 1.0]")
    support_sample_count: float = Field(..., ge=0.0, description="Total sample volume in the reference population")
    reference_population: str = Field(..., min_length=1, description="Description of the reference population")
    is_fallback: bool = Field(default=False, description="True if fell back from subgroup to global LOO")
    stratum_identifier: Optional[str] = Field(default=None, description="Class ID or subgroup name if stratified")
    limitations: List[str] = Field(default_factory=list)
    metadata_json: Dict[str, Any] = Field(default_factory=dict)


# =====================================================================
# Detection Dimensions (Layer 1)
# =====================================================================

class DetectionDimension(BaseModel):
    """Base model for all probabilistic, evidence-backed detection dimensions."""

    model_config = ConfigDict(frozen=True)

    dimension_id: RiskDimensionId
    evidence_layer: str = Field(default="detection", description="ADR-028 compliance: strictly 'detection'")
    status: EvaluationStatus = Field(default=EvaluationStatus.AVAILABLE)
    observed_rate: Optional[float] = Field(default=None, ge=0.0, le=1.0, description="Raw empirical rate")
    shrunk_rate: Optional[float] = Field(default=None, ge=0.0, le=1.0, description="Posterior shrunk rate")
    baseline: Optional[ContextualBaseline] = None
    differential: Optional[float] = Field(default=None, description="Delta = shrunk_rate - baseline_value")
    standard_error: Optional[float] = Field(default=None, ge=0.0, description="Standard error of the differential")
    confidence: float = Field(default=0.0, ge=0.0, le=1.0, description="Statistical confidence in [0.0, 1.0]")
    support_state: SupportState = Field(default=SupportState.UNVERIFIABLE)
    primary_evidence_ids: Tuple[str, ...] = Field(default_factory=tuple)
    finding_ids: Tuple[str, ...] = Field(default_factory=tuple)
    limitations: List[str] = Field(default_factory=list)

    @field_validator("primary_evidence_ids", "finding_ids", mode="before")
    @classmethod
    def _coerce_tuples(cls, v: Any) -> Tuple[str, ...]:
        if isinstance(v, (list, tuple)):
            return tuple(str(x) for x in v)
        return v


class LabelReliabilityDimension(DetectionDimension):
    """Dimension 1: Confident Learning anomaly rate differential against class-conditional baseline."""
    dimension_id: RiskDimensionId = Field(default=RiskDimensionId.DIM_LABEL_RELIABILITY)
    anomalous_sample_exposure: float = Field(default=0.0, ge=0.0)
    evaluated_sample_exposure: float = Field(default=0.0, ge=0.0)


class TransitionAsymmetryDimension(DetectionDimension):
    """Dimension 2: Directional label-flipping concentration and noise concentration index."""
    dimension_id: RiskDimensionId = Field(default=RiskDimensionId.DIM_TRANSITION_ASYM)
    targeted_flip_score: float = Field(default=0.0, ge=0.0, le=1.0)
    noise_concentration_index: float = Field(default=0.0, ge=0.0, le=1.0)
    directional_class_pairs: List[Dict[str, Any]] = Field(default_factory=list)


class QualityDivergenceDimension(DetectionDimension):
    """Dimension 3: Physical image degradation rate differential (blur, exposure, artifacts)."""
    dimension_id: RiskDimensionId = Field(default=RiskDimensionId.DIM_QUALITY_DIVERGENCE)
    metric_differentials: Dict[str, float] = Field(default_factory=dict)
    underexposure_differential: float = Field(default=0.0)
    blur_differential: float = Field(default=0.0)


class DistributionShiftDimension(DetectionDimension):
    """Dimension 4: Out-of-Distribution (OOD) feature distance against reference dataset."""
    dimension_id: RiskDimensionId = Field(default=RiskDimensionId.DIM_DISTRIBUTION_SHIFT)
    mean_feature_distance: Optional[float] = None
    reference_dataset_id: Optional[str] = None
    feature_extraction_status: str = Field(default="tier1_statistical_only")


# =====================================================================
# Proof Dimension (Layer 2)
# =====================================================================

class ProvenanceIntegrityDimension(BaseModel):
    """Dimension 5: Cryptographic proof-layer integrity (ADR-028, ADR-034).

    STRICTLY ISOLATED from detection-layer numerical metrics.
    Proof confidence is strictly 1.0.
    """

    model_config = ConfigDict(frozen=True)

    dimension_id: RiskDimensionId = Field(default=RiskDimensionId.DIM_PROVENANCE_INTEGRITY)
    evidence_layer: str = Field(default="proof", description="ADR-028 compliance: strictly 'proof'")
    verification_status: str = Field(..., description="VERIFIED, INVALID, MISSING, UNAVAILABLE, etc.")
    confidence: float = Field(default=1.0, ge=1.0, le=1.0, description="Proof-layer confidence strictly 1.0")
    signer_key_id: Optional[str] = None
    signature_present: bool = Field(default=False)
    chain_valid: Optional[bool] = None
    nonce_valid: Optional[bool] = None
    tamper_detected: bool = Field(default=False)
    primary_evidence_ids: Tuple[str, ...] = Field(default_factory=tuple)
    limitations: List[str] = Field(default_factory=list)

    @field_validator("primary_evidence_ids", mode="before")
    @classmethod
    def _coerce_tuples(cls, v: Any) -> Tuple[str, ...]:
        if isinstance(v, (list, tuple)):
            return tuple(str(x) for x in v)
        return v


# =====================================================================
# Profiles & Families
# =====================================================================

class DetectionProfile(BaseModel):
    """Structured collection of detection-layer risk dimensions (ADR-030)."""

    model_config = ConfigDict(frozen=True)

    label_reliability: LabelReliabilityDimension
    transition_asymmetry: TransitionAsymmetryDimension
    quality_divergence: QualityDivergenceDimension
    distribution_shift: DistributionShiftDimension
    effective_exposure: float = Field(..., ge=0.0)


class ProofProfile(BaseModel):
    """Structured collection of proof-layer cryptographic dimensions (ADR-030, ADR-034)."""

    model_config = ConfigDict(frozen=True)

    provenance_integrity: ProvenanceIntegrityDimension


class DependencyAwareEvidenceFamily(BaseModel):
    """Architectural grouping of related detector outputs with family-level dominance (ADR-034)."""

    model_config = ConfigDict(frozen=True)

    family_id: EvidenceFamilyId
    family_name: str
    evidence_layer: str  # detection | proof
    constituent_dimensions: Tuple[RiskDimensionId, ...]
    dominant_differential: Optional[float] = None
    dominant_dimension_id: Optional[RiskDimensionId] = None
    evidence_count: int = Field(default=0, ge=0)
    is_proof_layer: bool = Field(default=False)


class ContributorRiskIndicator(BaseModel):
    """Neutral, evidence-backed risk observation (ADR-035)."""

    model_config = ConfigDict(frozen=True)

    indicator_id: str
    dimension_id: RiskDimensionId
    severity: str  # critical, high, medium, low, info
    confidence: float = Field(..., ge=0.0, le=1.0)
    summary: str
    limitations: List[str] = Field(default_factory=list)


class ContributorRiskProfile(BaseModel):
    """Complete, immutable Contributor Risk Profile for a single contributor."""

    model_config = ConfigDict(frozen=True)

    contributor_id: str = Field(..., min_length=1)
    project_id: str = Field(..., min_length=1)
    dataset_version_id: Optional[str] = None
    effective_sample_count: float = Field(..., ge=0.0)
    support_state: SupportState
    profile_status: OverallProfileStatus
    detection_profile: DetectionProfile
    proof_profile: ProofProfile
    evidence_families: Tuple[DependencyAwareEvidenceFamily, ...] = Field(default_factory=tuple)
    risk_indicators: Tuple[ContributorRiskIndicator, ...] = Field(default_factory=tuple)
    metadata_json: Dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


# =====================================================================
# Configuration
# =====================================================================

class ContributorRiskConfig(BaseModel):
    """Deterministic configuration parameters for Contributor Risk Engine."""

    model_config = ConfigDict(frozen=True)

    prior_sample_weight_m0: float = Field(default=20.0, ge=1.0, description="Frozen prior weight M_0 for Empirical Bayes")
    min_support_threshold: float = Field(default=3.0, ge=1.0, description="Minimum effective samples for evaluation")
    moderate_support_threshold: float = Field(default=10.0, ge=3.0, description="Threshold for moderate support state")
    adequate_support_threshold: float = Field(default=30.0, ge=10.0, description="Threshold for adequate support state")
    elevated_differential_threshold: float = Field(default=0.20, ge=0.01, le=1.0, description="Delta threshold for ELEVATED status")
    moderate_differential_threshold: float = Field(default=0.10, ge=0.01, le=1.0, description="Delta threshold for MODERATE status")
    min_class_support_for_stratification: int = Field(default=10, ge=2, description="Min class samples to use class baseline")
