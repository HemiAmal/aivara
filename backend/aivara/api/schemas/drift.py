"""Distribution Shift & Data Drift API Schemas (Phase 11.10).

Defines Pydantic v2 schemas for:
  - Drift analysis requests across 7 canonical analysis types:
    (DATASET, FEATURE, IMAGE, REPRESENTATION, TEMPORAL, SOURCE, MULTIMODAL)
  - Subsystem configuration blocks (temporal, source, representation, multimodal)
  - In-memory drift task management and deterministic stage transitions
  - Real-time Server-Sent Events (SSE) progress broadcasting
  - Comprehensive drift analysis results and feature summaries
  - Static subsystem capabilities descriptors
"""

from __future__ import annotations

import math
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field, field_validator


def _validate_finite_float(val: Optional[float], name: str) -> Optional[float]:
    if val is not None:
        if math.isnan(val) or math.isinf(val):
            raise ValueError(f"Field '{name}' must be a finite float, got {val}")
    return val


class DriftAnalysisTypeEnum(str, Enum):
    """Canonical analysis types supported by the distribution shift subsystem."""
    DATASET = "DATASET"
    FEATURE = "FEATURE"
    IMAGE = "IMAGE"
    REPRESENTATION = "REPRESENTATION"
    TEMPORAL = "TEMPORAL"
    SOURCE = "SOURCE"
    MULTIMODAL = "MULTIMODAL"


class DriftTaskStatusEnum(str, Enum):
    """Execution lifecycle states for an asynchronous drift analysis task."""
    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    CANCEL_REQUESTED = "CANCEL_REQUESTED"
    CANCELLED = "CANCELLED"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


# =====================================================================
# 1. Configuration Sub-Schemas
# =====================================================================

class TemporalAnalysisConfig(BaseModel):
    """Configuration for temporal windowed drift evaluation."""
    model_config = ConfigDict(extra="forbid")

    window_strategy: str = Field(default="FIXED_INTERVAL", max_length=50)
    window_duration_seconds: Optional[float] = Field(default=86400.0, ge=60.0)
    comparison_topology: str = Field(default="BASELINE_AND_ADJACENT", max_length=50)
    max_windows: int = Field(default=50, ge=2, le=50)

    @field_validator("window_duration_seconds")
    @classmethod
    def validate_duration(cls, v: Optional[float]) -> Optional[float]:
        return _validate_finite_float(v, "window_duration_seconds")

    def to_canonical_dict(self) -> Dict[str, Any]:
        return {
            "comparison_topology": self.comparison_topology,
            "max_windows": int(self.max_windows),
            "window_duration_seconds": float(self.window_duration_seconds) if self.window_duration_seconds is not None else None,
            "window_strategy": self.window_strategy,
        }


class SourceAnalysisConfig(BaseModel):
    """Configuration for contributor and source-aware drift evaluation."""
    model_config = ConfigDict(extra="forbid")

    source_metadata_key: str = Field(default="source_group_id", min_length=1, max_length=100)
    max_source_groups: int = Field(default=50, ge=2, le=50)
    evaluate_simpsons_confounding: bool = Field(default=True)

    def to_canonical_dict(self) -> Dict[str, Any]:
        return {
            "evaluate_simpsons_confounding": bool(self.evaluate_simpsons_confounding),
            "max_source_groups": int(self.max_source_groups),
            "source_metadata_key": self.source_metadata_key,
        }


class RepresentationAnalysisConfig(BaseModel):
    """Configuration for embedding / representation drift evaluation."""
    model_config = ConfigDict(extra="forbid")

    embedding_dimension: int = Field(default=384, ge=1, le=4096)
    statistical_method: str = Field(default="KERNEL_MMD", max_length=50)
    permutation_iterations: int = Field(default=100, ge=10, le=100)
    l2_normalize: bool = Field(default=True)

    def to_canonical_dict(self) -> Dict[str, Any]:
        return {
            "embedding_dimension": int(self.embedding_dimension),
            "l2_normalize": bool(self.l2_normalize),
            "permutation_iterations": int(self.permutation_iterations),
            "statistical_method": self.statistical_method,
        }


class MultiModalAssuranceConfig(BaseModel):
    """Configuration for multi-modal risk synthesis."""
    model_config = ConfigDict(extra="forbid")

    correlation_damping_factor: float = Field(default=0.10, ge=0.0, le=0.50)
    review_threshold: float = Field(default=0.30, ge=0.0, le=1.0)
    quarantine_threshold: float = Field(default=0.65, ge=0.0, le=1.0)
    reject_threshold: float = Field(default=0.85, ge=0.0, le=1.0)

    @field_validator("correlation_damping_factor", "review_threshold", "quarantine_threshold", "reject_threshold")
    @classmethod
    def validate_floats(cls, v: float, info: Any) -> float:
        _validate_finite_float(v, info.field_name)
        return v

    def to_canonical_dict(self) -> Dict[str, Any]:
        return {
            "correlation_damping_factor": float(self.correlation_damping_factor),
            "quarantine_threshold": float(self.quarantine_threshold),
            "reject_threshold": float(self.reject_threshold),
            "review_threshold": float(self.review_threshold),
        }


# =====================================================================
# 2. Request Schemas
# =====================================================================

class DriftAnalysisCreateRequest(BaseModel):
    """Request payload to initiate distribution shift analysis."""
    model_config = ConfigDict(extra="forbid")

    reference_dataset_id: str = Field(..., min_length=1, max_length=64, description="Unique identifier of the reference baseline dataset")
    reference_dataset_version_id: Optional[str] = Field(default=None, max_length=64, description="Optional version identifier of reference dataset")
    target_dataset_id: str = Field(..., min_length=1, max_length=64, description="Unique identifier of the target comparison dataset")
    target_dataset_version_id: Optional[str] = Field(default=None, max_length=64, description="Optional version identifier of target dataset")
    analysis_type: DriftAnalysisTypeEnum = Field(default=DriftAnalysisTypeEnum.DATASET, description="Modality / scope of drift analysis")
    feature_names: Optional[List[str]] = Field(default=None, description="Optional explicit feature column filter")
    alpha_significance: float = Field(default=0.05, gt=0.0, lt=1.0, description="Significance level alpha for hypothesis testing")
    effect_size_threshold: Optional[float] = Field(default=None, gt=0.0, description="Optional minimum effect size threshold")
    sample_budget: int = Field(default=5000, ge=30, le=5000, description="Maximum sample budget per population")
    idempotency_key: Optional[str] = Field(default=None, max_length=64, description="Client idempotency key")
    temporal_config: Optional[TemporalAnalysisConfig] = None
    source_config: Optional[SourceAnalysisConfig] = None
    representation_config: Optional[RepresentationAnalysisConfig] = None
    multimodal_config: Optional[MultiModalAssuranceConfig] = None

    @field_validator("alpha_significance")
    @classmethod
    def validate_alpha(cls, v: float) -> float:
        _validate_finite_float(v, "alpha_significance")
        return v

    @field_validator("effect_size_threshold")
    @classmethod
    def validate_effect(cls, v: Optional[float]) -> Optional[float]:
        return _validate_finite_float(v, "effect_size_threshold")

    def to_canonical_dict(self, project_id: str) -> Dict[str, Any]:
        """Convert to strictly sorted canonical dictionary for RFC 8785 request fingerprinting."""
        return {
            "alpha_significance": float(self.alpha_significance),
            "analysis_type": self.analysis_type.value,
            "effect_size_threshold": float(self.effect_size_threshold) if self.effect_size_threshold is not None else None,
            "feature_names": sorted(self.feature_names) if self.feature_names is not None else None,
            "multimodal_config": self.multimodal_config.to_canonical_dict() if self.multimodal_config else None,
            "project_id": project_id,
            "reference_dataset_id": self.reference_dataset_id,
            "reference_dataset_version_id": self.reference_dataset_version_id,
            "representation_config": self.representation_config.to_canonical_dict() if self.representation_config else None,
            "sample_budget": int(self.sample_budget),
            "source_config": self.source_config.to_canonical_dict() if self.source_config else None,
            "target_dataset_id": self.target_dataset_id,
            "target_dataset_version_id": self.target_dataset_version_id,
            "temporal_config": self.temporal_config.to_canonical_dict() if self.temporal_config else None,
        }


# =====================================================================
# 3. Response Schemas
# =====================================================================

class DriftTaskResponse(BaseModel):
    """Response returned upon submitting or polling a drift analysis task."""
    model_config = ConfigDict(extra="ignore")

    task_id: str
    project_id: str
    analysis_type: DriftAnalysisTypeEnum
    status: DriftTaskStatusEnum
    progress_percent: float
    current_stage: str
    stage_description: Optional[str] = None
    created_at: str
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    error_message: Optional[str] = None
    idempotency_key: Optional[str] = None


class DriftFeatureSummaryItem(BaseModel):
    """Summary of drift evaluation for a single feature or dimension."""
    model_config = ConfigDict(extra="ignore")

    feature_name: str
    feature_type: str
    statistical_method: str
    statistic_value: float
    p_value: float
    p_value_adjusted: float
    is_drift_detected: bool
    drift_impact_level: str


class DriftAnalysisResultResponse(BaseModel):
    """Authoritative complete result of a distribution shift analysis."""
    model_config = ConfigDict(extra="ignore")

    task_id: str
    project_id: str
    analysis_type: DriftAnalysisTypeEnum
    reference_dataset_id: str
    target_dataset_id: str
    evaluation_status: str
    overall_disposition: str
    normalized_operational_exposure_index: float
    risk_level: str
    features_evaluated_count: int
    features_drifted_count: int
    feature_summaries: List[DriftFeatureSummaryItem] = Field(default_factory=list)
    boundary_hash: str
    analysis_result_hash: str
    integrated_profile_hash: Optional[str] = None
    provenance_record_id: Optional[str] = None
    findings_count: int = 0
    evidence_count: int = 0
    rationale: str
    limitations: List[str] = Field(default_factory=list)
    executed_at: str


class DriftProgressEvent(BaseModel):
    """Real-time Server-Sent Event broadcast payload."""
    model_config = ConfigDict(extra="ignore")

    sequence_number: int
    event_id: str
    task_id: str
    stage: str
    progress_percent: float
    message: str
    timestamp: str
    payload: Optional[Dict[str, Any]] = None


class DriftCapabilitiesResponse(BaseModel):
    """Descriptors of supported subsystem capabilities."""
    model_config = ConfigDict(extra="ignore")

    api_version: str = "1.0.0"
    schema_version: str = "1.0"
    supported_analysis_types: List[str]
    supported_statistical_methods: List[str]
    max_sample_budget: int = 5000
    min_sample_floor: int = 30
    max_embedding_dimension: int = 4096
    max_temporal_windows: int = 50
    max_source_groups: int = 50
