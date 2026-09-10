"""Domain schemas and immutable data transfer models for Phase 5.8 Contributor Aggregation Engine."""

from enum import Enum
from typing import Any, Dict, List, Optional, Tuple
from pydantic import BaseModel, ConfigDict, Field, field_validator


class ContributorCategory(str, Enum):
    """Controlled analytical taxonomy for contributor aggregation findings."""
    CONTRIBUTOR_ANOMALY_CONCENTRATION = "CONTRIBUTOR_ANOMALY_CONCENTRATION"
    CONTRIBUTOR_LABEL_TRANSITION = "CONTRIBUTOR_LABEL_TRANSITION"
    CONTRIBUTOR_OOD_CONCENTRATION = "CONTRIBUTOR_OOD_CONCENTRATION"
    CONTRIBUTOR_QUALITY_CONCENTRATION = "CONTRIBUTOR_QUALITY_CONCENTRATION"
    CONTRIBUTOR_DUPLICATE_CONCENTRATION = "CONTRIBUTOR_DUPLICATE_CONCENTRATION"
    CONTRIBUTOR_CLASS_DISTRIBUTION = "CONTRIBUTOR_CLASS_DISTRIBUTION"
    CONTRIBUTOR_MULTI_SIGNAL_EVIDENCE = "CONTRIBUTOR_MULTI_SIGNAL_EVIDENCE"
    INSUFFICIENT_CONTRIBUTOR_SUPPORT = "INSUFFICIENT_CONTRIBUTOR_SUPPORT"
    UNATTRIBUTED_EVIDENCE = "UNATTRIBUTED_EVIDENCE"


class ContributorEvidenceMetric(BaseModel):
    """Statistical summary of a single evidence dimension for a contributor."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    metric_name: str = Field(..., min_length=1, description="Evidence metric identifier (e.g. label_anomaly, ood, quality)")
    contributor_count: float = Field(..., ge=0.0, description="Weighted anomaly count attributed to contributor")
    contributor_exposure: float = Field(..., ge=0.0, description="Weighted total exposure (sample count) for contributor")
    contributor_rate: float = Field(..., ge=0.0, le=1.0, description="Empirical anomaly rate: count / exposure")
    wilson_lower_bound: float = Field(..., ge=0.0, le=1.0, description="Conservative 95% Wilson confidence lower bound")
    wilson_upper_bound: float = Field(..., ge=0.0, le=1.0, description="95% Wilson confidence upper bound")
    background_count: float = Field(..., ge=0.0, description="Leave-one-out background anomaly count")
    background_exposure: float = Field(..., ge=0.0, description="Leave-one-out background total exposure")
    background_rate: Optional[float] = Field(default=None, ge=0.0, le=1.0, description="Leave-one-out background anomaly rate")
    rate_differential: Optional[float] = Field(default=None, description="Rate differential: contributor_rate - background_rate")
    standard_error: Optional[float] = Field(default=None, ge=0.0, description="Standard error of the rate differential SE(Delta)")
    anomaly_share: float = Field(..., ge=0.0, le=1.0, description="Fraction of total dataset anomalies attributed to contributor")
    baseline_status: str = Field(
        default="VALID", description="Baseline comparison status: VALID, INSUFFICIENT_BACKGROUND_SUPPORT"
    )
    subgroup_metrics: Dict[str, Dict[str, Any]] = Field(
        default_factory=dict, description="Stratified subgroup metrics (e.g. class, sensor) when metadata exists"
    )


class ContributorEvidenceProfile(BaseModel):
    """Comprehensive statistical evidence profile for a single contributor."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    contributor_id: str = Field(..., min_length=1, description="Normalized contributor identifier or UNATTRIBUTED")
    total_samples_contributed: int = Field(..., ge=0, description="Raw count of samples associated with contributor")
    weighted_sample_exposure: float = Field(..., ge=0.0, description="Sum of fractional attribution weights across samples")
    shared_sample_count: int = Field(..., ge=0, description="Number of samples shared with co-contributors")
    metrics: Dict[str, ContributorEvidenceMetric] = Field(
        default_factory=dict, description="Per-evidence-type statistical metrics"
    )
    class_distribution: Dict[str, float] = Field(
        default_factory=dict, description="Proportion of contributor samples per class"
    )
    class_entropy: float = Field(..., ge=0.0, description="Shannon entropy of class distribution in bits")
    evidence_diversity_count: int = Field(..., ge=0, description="Count of distinct anomaly signal categories with elevated rate")
    is_sufficient_support: bool = Field(..., description="Whether contributor has sufficient exposure (n >= 5)")


class ContributorScanFinding(BaseModel):
    """Immutable, strongly-typed finding emitted by Phase 5.8."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    finding_id: str = Field(..., min_length=1, description="Deterministic unique finding identifier")
    contributor_id: str = Field(..., min_length=1, description="Associated contributor identifier")
    category: ContributorCategory = Field(..., description="Taxonomic finding category")
    evidence_layer: str = Field(default="detection", description="ADR-028 evidence layer (always 'detection')")
    severity: str = Field(default="LOW", description="Severity: LOW, MEDIUM, HIGH, CRITICAL")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Statistical confidence score")
    profile: Optional[ContributorEvidenceProfile] = Field(default=None, description="Supporting contributor profile")
    explanation: str = Field(..., min_length=1, description="Objective, non-accusatory explanation of evidence")
    limitations: Tuple[str, ...] = Field(default_factory=tuple, description="Statistical and methodological limitations")

    @field_validator("explanation")
    @classmethod
    def _validate_non_malicious_language(cls, v: str) -> str:
        prohibited = [
            "malicious", "poison", "sabotage", "attacker", "guilt", "fraud",
            "tamper", "backdoor", "threat", "quarantine", "culpab"
        ]
        lower_v = v.lower()
        for word in prohibited:
            if word in lower_v:
                raise ValueError(f"Prohibited malicious attribution term '{word}' found in finding explanation.")
        return v


class ContributorAggregationConfig(BaseModel):
    """Configuration thresholds for Phase 5.8 Contributor Aggregation Engine."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    min_contributor_support: int = Field(default=5, ge=1, description="Minimum exposure to generate statistical findings")
    min_dataset_support: int = Field(default=25, ge=1, description="Minimum total dataset samples required")
    min_subgroup_support: int = Field(default=5, ge=1, description="Minimum subgroup samples for stratified baselines")
    wilson_confidence: float = Field(default=0.95, ge=0.5, le=0.999, description="Confidence level for Wilson intervals")
    concentration_hhi_threshold: float = Field(default=0.40, ge=0.0, le=1.0, description="HHI threshold for anomaly concentration")
    anomaly_share_threshold: float = Field(default=0.50, ge=0.0, le=1.0, description="Share of dataset anomalies threshold")
    transition_differential_threshold: float = Field(default=0.30, ge=0.0, le=1.0, description="Delta T threshold for transition findings")
    diversity_metric_rate_threshold: float = Field(default=0.05, ge=0.0, le=1.0, description="Rate threshold for diversity counting")
    deterministic_seed: int = Field(default=42, description="Seed for deterministic sorting and tie-breaking")


class ContributorAggregationResult(BaseModel):
    """Top-level aggregation result summarizing Phase 5.8 audit execution."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    scan_id: str = Field(..., min_length=1, description="Deterministic scan identifier")
    dataset_name: str = Field(..., min_length=1, description="Audited dataset name")
    dataset_fingerprint: str = Field(..., min_length=64, max_length=64, description="Hexadecimal dataset Merkle root / fingerprint")
    total_contributors: int = Field(..., ge=0, description="Total unique contributors in dataset")
    profiled_contributors: int = Field(..., ge=0, description="Count of contributors meeting support threshold")
    unattributed_sample_count: int = Field(..., ge=0, description="Number of samples without contributor metadata")
    anomaly_hhi: Dict[str, float] = Field(default_factory=dict, description="Herfindahl-Hirschman Index per anomaly type")
    profiles: Dict[str, ContributorEvidenceProfile] = Field(default_factory=dict, description="Contributor ID to profile mapping")
    findings: Tuple[ContributorScanFinding, ...] = Field(default_factory=tuple, description="Deterministically sorted findings")
    diagnostics: Dict[str, Any] = Field(default_factory=dict, description="Execution telemetry and diagnostic metadata")
