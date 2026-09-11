"""Pydantic schemas and domain models for Phase 8.6 Behavioral Anomaly Detection."""

from __future__ import annotations

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field
from aivara.behavioral.anomaly.enums import (
    AnomalyFamilyType,
    AnomalyStatus,
    MetricAnomalyStatus,
    MetricDirection,
    SupportStatus,
)


class BehavioralAnomalyMetric(BaseModel):
    """Detailed statistical anomaly evaluation for a single behavioral scalar metric."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    metric_name: str = Field(..., description="Canonical metric identifier")
    family: AnomalyFamilyType = Field(..., description="Associated behavioral metric family")
    direction: MetricDirection = Field(..., description="Directionality of extremeness")
    observed_value: Optional[float] = Field(None, description="Observed scalar value (None if invalid/missing)")
    baseline_count: int = Field(..., ge=0, description="Count of eligible baseline samples")
    baseline_median: Optional[float] = Field(None, description="Median of eligible baseline population")
    baseline_mad: Optional[float] = Field(None, description="MAD of eligible baseline population")
    robust_z: Optional[float] = Field(None, description="Signed robust z-score (None if MAD == 0 or non-finite)")
    absolute_robust_z: Optional[float] = Field(None, description="Absolute robust z-score")
    empirical_extremeness: Optional[float] = Field(
        None,
        ge=0.0,
        le=1.0,
        description="Empirical tail probability / extremeness in [0.0, 1.0]",
    )
    validity_status: str = Field("VALID", description="VALID | UNDEFINED | UNAVAILABLE | UNVERIFIABLE | INCOMPATIBLE")
    anomaly_status: MetricAnomalyStatus = Field(..., description="Individual statistical anomaly classification")
    reason: Optional[str] = Field(None, description="Explanation of calculation or anomaly status")


class BehavioralAnomalyFamily(BaseModel):
    """Structured summary of behavioral evidence within a cohesive metric family."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    family_name: AnomalyFamilyType = Field(..., description="Behavioral family identifier")
    support_status: SupportStatus = Field(..., description="Family-level statistical sample support status")
    metric_count: int = Field(..., ge=0, description="Total declared metrics in this family")
    valid_metric_count: int = Field(..., ge=0, description="Number of valid evaluated metrics")
    anomalous_metric_count: int = Field(..., ge=0, description="Number of metrics classified as ANOMALOUS")
    dominant_metric: Optional[str] = Field(None, description="Name of the most extreme metric in family")
    dominant_extremeness: Optional[float] = Field(None, description="Extremeness or absolute z of dominant metric")
    family_status: AnomalyStatus = Field(..., description="Family-level anomaly status")
    explanation: str = Field(..., description="Human-readable deterministic explanation of family findings")


class BaselineSummary(BaseModel):
    """Summary of reference population eligibility and trust filtering."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    baseline_id: str = Field(..., description="Reference baseline identifier")
    baseline_type: str = Field(..., description="Baseline origin type")
    total_baseline_count: int = Field(..., ge=0, description="Total observations in reference pool")
    eligible_baseline_count: int = Field(..., ge=0, description="Eligible observations included in statistics")
    excluded_baseline_count: int = Field(..., ge=0, description="Observations excluded due to invalid trust or errors")
    exclusion_reasons: Dict[str, int] = Field(
        default_factory=dict,
        description="Histogram of reasons for excluding baseline observations",
    )


class BehavioralAnomalyAnalysis(BaseModel):
    """Immutable domain representation of a completed Behavioral Anomaly Detection analysis."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    analysis_id: str = Field(..., description="Deterministic 64-char lowercase SHA-256 analysis digest")
    project_id: str = Field(..., description="Multi-tenant project identifier")
    model_id: str = Field(..., description="Model asset identifier")
    model_fingerprint: str = Field(..., description="Phase 7 Master Model Fingerprint")
    baseline_id: str = Field(..., description="Reference baseline identifier")
    baseline_type: str = Field(..., description="Reference baseline origin type")
    observation_id: str = Field(..., description="Target observation identifier")
    task_type: str = Field(..., description="Task domain (classification, detection, segmentation, generic)")
    analysis_version: str = Field("1.0.0", description="Analysis engine version")
    policy_version: str = Field("1.0.0", description="Statistical policy version")
    overall_status: AnomalyStatus = Field(..., description="Overall behavioral anomaly assessment")
    support_status: SupportStatus = Field(..., description="Overall baseline support status")
    comparability_status: str = Field("COMPARABLE", description="COMPARABLE | INCOMPARABLE")
    families: Dict[str, BehavioralAnomalyFamily] = Field(..., description="Family-level summary records")
    metrics: List[BehavioralAnomalyMetric] = Field(..., description="Evaluated metric list in canonical sort order")
    threshold_policy: Dict[str, Any] = Field(..., description="Canonical serialization of applied threshold policy")
    baseline_summary: BaselineSummary = Field(..., description="Baseline sample eligibility and trust breakdown")
    explanation: str = Field(..., description="Overall deterministic human-readable explanation")
    limitations: List[str] = Field(default_factory=list, description="Documented limitations or caveats")
    created_at: str = Field(..., description="ISO 8601 UTC timestamp")
