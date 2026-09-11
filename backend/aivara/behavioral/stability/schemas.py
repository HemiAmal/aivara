"""Pydantic domain representations and schemas for Phase 8.5 Output Consistency & Stability Analysis."""

from __future__ import annotations

from enum import Enum
from typing import Any, Dict, List, Optional, Tuple
from pydantic import BaseModel, ConfigDict, Field, field_serializer
import numpy as np


class ComparisonType(str, Enum):
    """Categorization of output comparison context."""

    REPEATABILITY = "REPEATABILITY"
    PERTURBATION_RESPONSE = "PERTURBATION_RESPONSE"
    REFERENCE_COMPARISON = "REFERENCE_COMPARISON"
    GROUND_TRUTH_EVALUATION = "GROUND_TRUTH_EVALUATION"
    GENERIC_TENSOR_COMPARISON = "GENERIC_TENSOR_COMPARISON"


class MetricValidityStatus(str, Enum):
    """Validity outcome status of an evaluated comparison metric."""

    VALID = "VALID"
    UNDEFINED = "UNDEFINED"
    UNAVAILABLE = "UNAVAILABLE"
    UNVERIFIABLE = "UNVERIFIABLE"
    INCOMPATIBLE = "INCOMPATIBLE"


class MetricResult(BaseModel):
    """Deterministic, strongly-typed outcome of an individual stability or comparison metric."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    metric_name: str = Field(..., description="Canonical metric identifier")
    value: Optional[float] = Field(None, description="Calculated scalar metric value (None if undefined/invalid)")
    unit: Optional[str] = Field(None, description="Metric unit (e.g., probability, delta, pixels, ratio)")
    validity_status: MetricValidityStatus = Field(
        MetricValidityStatus.VALID,
        description="Metric calculation validity status",
    )
    support_count: int = Field(1, ge=0, description="Number of evaluated samples/elements supporting metric")
    formula_version: str = Field("1.0.0", description="Mathematical formulation version")
    details: Dict[str, Any] = Field(default_factory=dict, description="Diagnostic telemetry or sub-distributions")


class ClassificationStabilityMetrics(BaseModel):
    """Collection of classification stability and consistency metrics."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    prediction_agreement: MetricResult = Field(..., description="Top-1 prediction equality indicator (1.0 or 0.0)")
    top_k_overlap: Optional[MetricResult] = Field(None, description="Jaccard overlap across top-k predicted classes")
    confidence_delta: Optional[MetricResult] = Field(None, description="Difference in top-1 confidence score")
    kl_divergence: Optional[MetricResult] = Field(None, description="Kullback-Leibler divergence (probabilities only)")
    js_divergence: Optional[MetricResult] = Field(None, description="Jensen-Shannon divergence (probabilities only)")
    entropy_delta: Optional[MetricResult] = Field(None, description="Absolute difference in prediction entropy")
    margin_delta: Optional[MetricResult] = Field(None, description="Difference in top-1 vs top-2 prediction margin")


class DetectionMatchRecord(BaseModel):
    """Deterministic bipartite matching pairing between two detections."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    candidate_idx: int = Field(..., ge=0, description="Index in candidate detection list")
    reference_idx: int = Field(..., ge=0, description="Index in reference detection list")
    iou: float = Field(..., ge=0.0, le=1.0, description="Intersection-over-Union overlap")
    class_match: bool = Field(..., description="Whether predicted classes match identically")
    candidate_class: str = Field(..., description="Candidate class label")
    reference_class: str = Field(..., description="Reference class label")
    candidate_confidence: float = Field(..., ge=0.0, le=1.0, description="Candidate detection score")
    reference_confidence: float = Field(..., ge=0.0, le=1.0, description="Reference detection score")
    confidence_delta: float = Field(..., description="Candidate confidence minus reference confidence")
    box_displacement: float = Field(..., ge=0.0, description="Centroid Euclidean displacement in pixels")


class DetectionStabilityMetrics(BaseModel):
    """Collection of object detection consistency metrics based on deterministic bipartite matching."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    matched_detection_count: int = Field(..., ge=0, description="Number of successfully paired detections")
    unmatched_candidate_count: int = Field(..., ge=0, description="Candidate detections with no valid match")
    unmatched_reference_count: int = Field(..., ge=0, description="Reference detections with no valid match")
    count_delta: int = Field(..., description="Candidate count minus reference count")
    mean_matched_iou: Optional[MetricResult] = Field(None, description="Mean IoU across matched detections")
    class_agreement_rate: Optional[MetricResult] = Field(None, description="Class agreement proportion among matched boxes")
    mean_confidence_delta: Optional[MetricResult] = Field(None, description="Mean confidence delta across matched boxes")
    mean_box_displacement: Optional[MetricResult] = Field(None, description="Mean centroid displacement in pixels")
    matches: List[DetectionMatchRecord] = Field(default_factory=list, description="Explicit deterministic matches")


class SegmentationStabilityMetrics(BaseModel):
    """Collection of segmentation consistency metrics preserving strict ground-truth vs reference distinction."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    evaluation_case: str = Field(..., description="GROUND_TRUTH_mIoU | REFERENCE_MASK_AGREEMENT | UNAVAILABLE")
    ground_truth_miou: Optional[MetricResult] = Field(None, description="True mIoU (populated ONLY if dense GT exists)")
    reference_mask_agreement: Optional[MetricResult] = Field(
        None,
        description="Reference model mask agreement (Strictly model-to-model overlap; NOT ground-truth mIoU)",
    )
    pixel_agreement_rate: Optional[MetricResult] = Field(None, description="Proportion of identically classified pixels")
    per_class_iou: Dict[str, float] = Field(default_factory=dict, description="Per-class IoU breakdown")
    area_proportion_deltas: Dict[str, float] = Field(default_factory=dict, description="Per-class area percentage deltas")


class GenericTensorStabilityMetrics(BaseModel):
    """Task-agnostic mathematical tensor distance and consistency metrics."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    shape_match: bool = Field(..., description="Whether tensor shapes match identically")
    dtype_match: bool = Field(..., description="Whether tensor dtypes match identically")
    element_count: int = Field(..., ge=0, description="Total elements evaluated")
    l1_distance: MetricResult = Field(..., description="Sum of absolute differences")
    l2_distance: MetricResult = Field(..., description="Euclidean Frobenius distance")
    relative_l2_distance: Optional[MetricResult] = Field(None, description="Relative L2 distance normalized by reference norm")
    cosine_similarity: Optional[MetricResult] = Field(None, description="Cosine similarity (between -1.0 and 1.0)")
    max_absolute_difference: MetricResult = Field(..., description="Chebyshev L-infinity norm")
    mean_absolute_difference: MetricResult = Field(..., description="Mean absolute error (MAE)")
    finite_value_agreement: MetricResult = Field(..., description="Proportion of finite vs non-finite element agreement")


class RepeatabilityAnalysisResult(BaseModel):
    """Quantitative measurement of model output determinism across identical repeated executions."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    analysis_id: str = Field(..., description="Deterministic 64-char SHA-256 analysis digest")
    project_id: str = Field(..., description="Multi-tenant project identifier")
    model_id: str = Field(..., description="Model asset identifier")
    model_fingerprint: str = Field(..., description="Phase 7 Master Model Fingerprint")
    repeat_count: int = Field(..., ge=2, description="Number of identical repeated executions evaluated")
    prediction_agreement_rate: float = Field(..., ge=0.0, le=1.0, description="Top-1 prediction agreement across runs")
    max_numerical_delta: float = Field(..., ge=0.0, description="Maximum absolute float difference across runs")
    mean_numerical_delta: float = Field(..., ge=0.0, description="Mean absolute float difference across runs")
    determinism_status: str = Field(..., description="DETERMINISTIC | NUMERICALLY_STABLE | NONDETERMINISTIC")
    execution_provider: str = Field(..., description="Execution provider (e.g. CPUExecutionProvider)")
    device: str = Field(..., description="Execution device")
    runtime_version: str = Field(..., description="Runtime version")
    precision: str = Field(..., description="Floating-point precision")
    limitations: List[str] = Field(default_factory=list, description="Documented measurement limitations")
    created_at: str = Field(..., description="ISO 8601 UTC timestamp")


class PerturbationSensitivityResult(BaseModel):
    """Quantitative measurement of model output change relative to controlled input change."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    sensitivity_id: str = Field(..., description="Deterministic 64-char SHA-256 sensitivity digest")
    project_id: str = Field(..., description="Multi-tenant project identifier")
    model_id: str = Field(..., description="Model asset identifier")
    source_input_hash: str = Field(..., description="Source input SHA-256 digest")
    perturbed_input_hash: str = Field(..., description="Perturbed input SHA-256 digest")
    perturbation_id: str = Field(..., description="Phase 8.4 perturbation digest")
    perturbation_type: str = Field(..., description="Applied perturbation type")
    input_distance_l1: float = Field(..., ge=0.0, description="Input L1 pixel distance")
    input_distance_l2: float = Field(..., ge=0.0, description="Input L2 pixel distance")
    input_distance_rmse: float = Field(..., ge=0.0, description="Input RMSE pixel distance")
    output_distance_l1: Optional[float] = Field(None, ge=0.0, description="Output L1 distance")
    output_distance_l2: Optional[float] = Field(None, ge=0.0, description="Output L2 distance")
    sensitivity_ratio: Optional[float] = Field(
        None,
        description="Normalized ratio: output_delta / input_delta (None if input_delta == 0)",
    )
    input_unchanged: bool = Field(False, description="Whether input remained unchanged (delta == 0)")
    output_changed: bool = Field(False, description="Whether output changed under perturbation")
    sensitivity_status: str = Field(
        "VALID",
        description="VALID | NOT_APPLICABLE | UNDEFINED_NON_FINITE_DENOMINATOR | UNVERIFIABLE",
    )
    prediction_changed: bool = Field(..., description="Whether top-1 prediction changed under perturbation")
    confidence_delta: Optional[float] = Field(None, description="Perturbed confidence minus source confidence")
    task_metrics: Dict[str, Any] = Field(default_factory=dict, description="Task-specific consistency measurements")
    created_at: str = Field(..., description="ISO 8601 UTC timestamp")


class BehavioralComparisonResult(BaseModel):
    """Immutable domain representation of a pairwise or reference consistency comparison."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    comparison_id: str = Field(..., description="Deterministic 64-char SHA-256 comparison digest")
    comparison_type: ComparisonType = Field(..., description="Origin context of comparison")
    project_id: str = Field(..., description="Multi-tenant project identifier")
    source_observation_id: str = Field(..., description="Source observation or baseline identifier")
    target_observation_id: str = Field(..., description="Target observation or candidate identifier")
    task_type: str = Field(..., description="Task domain (classification, detection, segmentation, generic)")
    classification: Optional[ClassificationStabilityMetrics] = None
    detection: Optional[DetectionStabilityMetrics] = None
    segmentation: Optional[SegmentationStabilityMetrics] = None
    generic_tensor: Optional[GenericTensorStabilityMetrics] = None
    is_compatible: bool = Field(True, description="Whether compared observations were fully compatible")
    limitations: List[str] = Field(default_factory=list, description="Documented validity constraints or edge cases")
    execution_context: Dict[str, Any] = Field(default_factory=dict, description="Execution environment telemetry")
    created_at: str = Field(..., description="ISO 8601 UTC timestamp")
