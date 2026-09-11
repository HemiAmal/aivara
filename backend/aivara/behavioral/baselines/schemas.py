"""Pydantic schemas and domain models for Behavioral Baselines and Reference Profiles (Phase 8.3)."""

from __future__ import annotations

from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field


class BaselineType(str, Enum):
    """Categorization of behavioral baseline origin."""

    TRUSTED_REFERENCE_MODEL = "TRUSTED_REFERENCE_MODEL"
    REFERENCE_EXECUTION_PROFILE = "REFERENCE_EXECUTION_PROFILE"
    HISTORICAL_PROFILE = "HISTORICAL_PROFILE"
    EXPECTED_BEHAVIOR_SPECIFICATION = "EXPECTED_BEHAVIOR_SPECIFICATION"
    NO_BASELINE = "NO_BASELINE"


class BaselineTrustStatus(str, Enum):
    """Integrity and cryptographic trust state of a behavioral baseline."""

    VERIFIED = "VERIFIED"
    UNVERIFIABLE = "UNVERIFIABLE"
    INVALID = "INVALID"
    UNAVAILABLE = "UNAVAILABLE"


class BaselineSupportStatus(str, Enum):
    """Statistical sample support categorization for behavioral baselines."""

    ADEQUATE_SUPPORT = "ADEQUATE_SUPPORT"
    INSUFFICIENT_SUPPORT = "INSUFFICIENT_SUPPORT"
    UNAVAILABLE = "UNAVAILABLE"


class BaselineStatus(str, Enum):
    """Overall usability and validity classification of a behavioral baseline."""

    VALID = "VALID"
    INSUFFICIENT_SUPPORT = "INSUFFICIENT_SUPPORT"
    UNAVAILABLE = "UNAVAILABLE"
    UNVERIFIABLE = "UNVERIFIABLE"
    INVALID = "INVALID"
    INCOMPATIBLE = "INCOMPATIBLE"


class InputItemDescriptor(BaseModel):
    """Deterministic description of a single evaluated test input sample."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    input_id: str = Field(..., description="Unique sample identifier")
    input_hash: str = Field(..., description="64-char lowercase SHA-256 hash of raw input tensor/bytes")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Optional non-semantic sample metadata")


class InputSetDescriptor(BaseModel):
    """Deterministic, canonically ordered representation of an observation input dataset."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    input_set_id: str = Field(..., description="Deterministic 64-char SHA-256 digest of canonically sorted inputs")
    sample_count: int = Field(..., ge=0, description="Total number of evaluated samples")
    input_names: List[str] = Field(..., description="Sorted names of input tensors fed to the model")
    input_shapes: Dict[str, List[int]] = Field(..., description="Canonical shapes per input tensor name")
    inputs: List[InputItemDescriptor] = Field(..., description="Sorted list of input descriptors")


class DistributionStats(BaseModel):
    """Comprehensive, numerically stable summary statistics for a metric sequence."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    count: int = Field(..., ge=0, description="Sample count")
    min: float = Field(..., description="Minimum value")
    max: float = Field(..., description="Maximum value")
    mean: float = Field(..., description="Arithmetic mean")
    median: float = Field(..., description="50th percentile (median)")
    std: float = Field(..., ge=0.0, description="Sample standard deviation")
    p25: float = Field(..., description="25th percentile")
    p75: float = Field(..., description="75th percentile")
    p95: float = Field(..., description="95th percentile")


class ClassificationBehaviorProfile(BaseModel):
    """Deterministic behavioral profile for classification tasks."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    output_type: str = Field("probabilities", description="probabilities | logits | scores | unknown")
    class_count: int = Field(..., ge=1, description="Number of output classes / dimensionality")
    sample_count: int = Field(..., ge=0, description="Total evaluated samples")
    prediction_frequency: Dict[str, int] = Field(..., description="Counts per class prediction")
    prediction_proportions: Dict[str, float] = Field(..., description="Normalized ratio per class in [0.0, 1.0]")
    top1_distribution: Dict[str, int] = Field(..., description="Distribution of top-1 class indices")
    confidence_stats: Optional[DistributionStats] = Field(None, description="Confidence statistics across samples")
    entropy_stats: Optional[DistributionStats] = Field(None, description="Entropy statistics (probabilities only)")
    margin_stats: Optional[DistributionStats] = Field(None, description="Prediction margin (p_top1 - p_top2) statistics")
    finite_output_rate: float = Field(1.0, ge=0.0, le=1.0, description="Proportion of valid finite outputs")


class DetectionBehaviorProfile(BaseModel):
    """Deterministic behavioral profile for object detection tasks."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    sample_count: int = Field(..., ge=0, description="Total evaluated samples")
    total_detections: int = Field(..., ge=0, description="Sum of all bounding box detections")
    detection_count_stats: DistributionStats = Field(..., description="Statistics of per-image detection counts")
    class_frequency: Dict[str, int] = Field(..., description="Counts per detected object class")
    confidence_stats: Optional[DistributionStats] = Field(None, description="Box confidence statistics")
    box_area_stats: Optional[DistributionStats] = Field(None, description="Normalized bounding box area statistics")
    empty_detection_rate: float = Field(..., ge=0.0, le=1.0, description="Rate of images with zero detections")
    finite_output_rate: float = Field(1.0, ge=0.0, le=1.0, description="Rate of finite valid outputs")


class SegmentationBehaviorProfile(BaseModel):
    """Deterministic behavioral profile for semantic / instance segmentation tasks."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    sample_count: int = Field(..., ge=0, description="Total evaluated samples")
    class_pixel_counts: Dict[str, int] = Field(..., description="Total pixel counts per segmented class")
    class_area_proportions: Dict[str, float] = Field(..., description="Pixel proportions across total evaluated area")
    mask_shape: List[int] = Field(..., description="Spatial shape of output mask [H, W]")
    ground_truth_miou: Optional[float] = Field(
        None,
        ge=0.0,
        le=1.0,
        description="Ground-truth mIoU (Strictly populated ONLY when dense ground truth masks exist)",
    )
    reference_mask_agreement: Optional[float] = Field(
        None,
        ge=0.0,
        le=1.0,
        description="Reference model mask agreement (Strictly model-to-model overlap; NOT ground-truth mIoU)",
    )
    evaluation_case: str = Field(
        "UNAVAILABLE",
        description="GROUND_TRUTH_mIoU | REFERENCE_MASK_AGREEMENT | UNAVAILABLE",
    )


class NumericalProfile(BaseModel):
    """Summary of raw tensor numerical characteristics and finite-value integrity."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    tensor_stats: Dict[str, Dict[str, float]] = Field(
        ...,
        description="Per-tensor statistics (min, max, mean, std, finite_rate, nan_rate, inf_rate)",
    )


class LatencyProfile(BaseModel):
    """Execution latency distribution bounded by explicit runtime hardware parameters."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    sample_count: int = Field(..., ge=0, description="Number of timed inferences")
    stats: DistributionStats = Field(..., description="Latency statistics in milliseconds")
    execution_provider: str = Field(..., description="Execution provider (e.g., CPUExecutionProvider)")
    device: str = Field(..., description="Device string (e.g. cpu, cuda:0)")
    runtime_version: str = Field(..., description="Runtime engine version")
    precision: str = Field(..., description="Floating-point precision")


class RepeatabilityProfile(BaseModel):
    """Deterministic summary of repeat-execution stability observations."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    repeated_runs: int = Field(..., ge=1, description="Number of identical repeated executions")
    prediction_agreement_rate: float = Field(..., ge=0.0, le=1.0, description="Top-1 prediction agreement across runs")
    max_numerical_delta: float = Field(..., ge=0.0, description="Maximum absolute float difference across runs")
    determinism_status: str = Field("DETERMINISTIC", description="DETERMINISTIC | NUMERICALLY_STABLE | NONDETERMINISTIC")


class ExpectedBehaviorSpecification(BaseModel):
    """Explicit contractual behavioral constraints supplied by users or specifications."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    expected_classes: Optional[List[str]] = Field(None, description="Required or valid class vocabulary")
    expected_output_dimensions: Optional[Dict[str, List[int]]] = Field(None, description="Expected output shapes")
    min_confidence: Optional[float] = Field(None, ge=0.0, le=1.0, description="Minimum expected confidence")
    max_confidence: Optional[float] = Field(None, ge=0.0, le=1.0, description="Maximum expected confidence")
    max_latency_ms: Optional[float] = Field(None, ge=0.0, description="Maximum allowed latency in milliseconds")
    custom_rules: Dict[str, Any] = Field(default_factory=dict, description="Arbitrary explicit constraint rules")
    is_user_specified: bool = Field(True, description="Flag explicitly noting expectation is user-supplied, not learned truth")


class BehavioralProfileAggregate(BaseModel):
    """Aggregate profile binding task-specific metrics, numerical telemetry, and latency."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    task_type: str = Field(..., description="classification | object_detection | segmentation | generic")
    classification: Optional[ClassificationBehaviorProfile] = None
    detection: Optional[DetectionBehaviorProfile] = None
    segmentation: Optional[SegmentationBehaviorProfile] = None
    numerical: NumericalProfile
    latency: LatencyProfile
    repeatability: Optional[RepeatabilityProfile] = None


class BehavioralBaseline(BaseModel):
    """Canonical sealed behavioral baseline / reference profile."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    baseline_id: str = Field(..., description="Deterministic 64-char SHA-256 baseline identity hash")
    baseline_type: BaselineType = Field(..., description="Origin classification of baseline")
    trust_status: BaselineTrustStatus = Field(..., description="Cryptographic/integrity trust state")
    support_status: BaselineSupportStatus = Field(..., description="Sample support adequacy state")
    baseline_status: BaselineStatus = Field(..., description="Overall baseline operational status")
    project_id: str = Field(..., description="Multi-tenant project identifier")
    model_id: str = Field(..., description="Model asset identifier")
    model_fingerprint: str = Field(..., description="Phase 7 Master Model Fingerprint (H_master)")
    task_type: str = Field(..., description="Task classification")
    input_set_identity: str = Field(..., description="Deterministic input set SHA-256 digest")
    preprocessing_hash: Optional[str] = Field(None, description="Preprocessing contract digest")
    execution_provider: str = Field("CPUExecutionProvider", description="Execution provider")
    device: str = Field("cpu", description="Execution device")
    precision: str = Field("float32", description="Precision format")
    profile: BehavioralProfileAggregate = Field(..., description="Aggregate behavioral profile")
    profile_hash: str = Field(..., description="Deterministic 64-char SHA-256 JCS digest of profile")
    expected_specifications: Optional[ExpectedBehaviorSpecification] = Field(
        None,
        description="Optional user/system specified behavioral constraints",
    )
    reference_model_id: Optional[str] = Field(None, description="Reference model ID if baseline_type is reference model")
    reference_model_fingerprint: Optional[str] = Field(None, description="Reference model H_master")
    limitations: List[str] = Field(default_factory=list, description="Documented limitations or missing data indicators")
    created_at: str = Field(..., description="ISO 8601 UTC timestamp of baseline generation")
