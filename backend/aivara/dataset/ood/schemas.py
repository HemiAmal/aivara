"""Domain schemas and immutable data transfer models for Phase 5.7 OOD & Image Quality."""

from enum import Enum
from typing import Any, Dict, List, Optional, Tuple
from pydantic import BaseModel, ConfigDict, Field, field_validator


class FeatureExtractionStatus(str, Enum):
    """Status of visual feature extraction pipeline."""
    TIER1_STATISTICAL_ONLY = "tier1_statistical_only"
    TIER1_FALLBACK = "tier1_fallback"
    TIER2_DEEP_EMBEDDING = "tier2_deep_embedding"
    FEATURE_EXTRACTOR_AVAILABLE = "feature_extractor_available"
    FEATURE_EXTRACTOR_UNAVAILABLE = "feature_extractor_unavailable"
    FEATURE_EXTRACTOR_INCOMPATIBLE = "feature_extractor_incompatible"
    FEATURE_EXTRACTION_FAILED = "feature_extraction_failed"


class ReferenceMode(str, Enum):
    """Operational mode for establishing reference visual distribution."""
    INTERNAL_DATASET_BASELINE = "internal_dataset_baseline"
    EXPLICIT_REFERENCE_DATASET = "explicit_reference_dataset"
    FROZEN_DOMAIN_REFERENCE = "frozen_domain_reference"


class OODCategory(str, Enum):
    """Controlled analytical taxonomy for IQA, OOD, and Distribution Shift findings."""
    IMAGE_CORRUPTION = "IMAGE_CORRUPTION"
    BLUR_ANOMALY = "BLUR_ANOMALY"
    EXPOSURE_UNDEREXPOSED = "EXPOSURE_UNDEREXPOSED"
    EXPOSURE_OVEREXPOSED = "EXPOSURE_OVEREXPOSED"
    NOISE_ANOMALY = "NOISE_ANOMALY"
    COMPRESSION_BLOCKINESS = "COMPRESSION_BLOCKINESS"
    RESOLUTION_ANOMALY = "RESOLUTION_ANOMALY"
    ASPECT_RATIO_ANOMALY = "ASPECT_RATIO_ANOMALY"
    COLOR_CAST_ANOMALY = "COLOR_CAST_ANOMALY"
    GLOBAL_OOD = "GLOBAL_OOD"
    LOCAL_SUBGROUP_OOD = "LOCAL_SUBGROUP_OOD"
    OPERATIONAL_DISTRIBUTION_SHIFT = "OPERATIONAL_DISTRIBUTION_SHIFT"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"
    INSUFFICIENT_REFERENCE_SUPPORT = "INSUFFICIENT_REFERENCE_SUPPORT"
    UNVERIFIABLE = "UNVERIFIABLE"
    FEATURE_EXTRACTOR_UNAVAILABLE = "FEATURE_EXTRACTOR_UNAVAILABLE"
    SECURITY_VALIDATION_FAILED = "SECURITY_VALIDATION_FAILED"
    FALLBACK_GLOBAL_OOD = "FALLBACK_GLOBAL_OOD"


class ImageQualityMetrics(BaseModel):
    """Deterministic, objective physical image quality measurements."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    blur_laplacian_var: float = Field(..., ge=0.0, description="Variance of Laplacian focus score")
    sharpness_tenengrad: float = Field(..., ge=0.0, description="Tenengrad gradient sharpness score")
    mean_luminance: float = Field(..., ge=0.0, le=255.0, description="Mean pixel luminance [0, 255]")
    rms_contrast: float = Field(..., ge=0.0, description="RMS luminance contrast")
    underexposure_ratio: float = Field(..., ge=0.0, le=1.0, description="Fraction of clipped shadow pixels (Y < 15)")
    overexposure_ratio: float = Field(..., ge=0.0, le=1.0, description="Fraction of clipped highlight pixels (Y > 240)")
    mean_saturation: float = Field(..., ge=0.0, le=1.0, description="Mean HSV saturation [0, 1]")
    color_cast_delta: float = Field(..., ge=0.0, description="CIELAB chromaticity divergence delta")
    noise_variance: float = Field(..., ge=0.0, description="Estimated spatial noise variance (Immerkaer)")
    snr_db: float = Field(..., description="Estimated Signal-to-Noise Ratio in dB")
    jpeg_blockiness: float = Field(..., ge=0.0, description="JPEG 8x8 block boundary discontinuity step ratio")
    width: int = Field(..., ge=1, description="Image pixel width")
    height: int = Field(..., ge=1, description="Image pixel height")
    aspect_ratio: float = Field(..., gt=0.0, description="Width / Height aspect ratio")
    uniform_region_ratio: float = Field(..., ge=0.0, le=1.0, description="Fraction of uniform zero-variance patches")
    composite_quality_score: float = Field(..., ge=0.0, le=1.0, description="Composite quality index [0.0 = degraded, 1.0 = pristine]")


class ImageQualityConfig(BaseModel):
    """Configuration thresholds for Image Quality Analysis."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    min_blur_laplacian_var: float = Field(default=25.0, ge=0.0, description="Laplacian variance below which image is flagged as blurred")
    max_underexposure_ratio: float = Field(default=0.40, ge=0.0, le=1.0, description="Underexposure shadow clipping threshold")
    max_overexposure_ratio: float = Field(default=0.30, ge=0.0, le=1.0, description="Overexposure highlight clipping threshold")
    min_rms_contrast: float = Field(default=10.0, ge=0.0, description="Minimum acceptable RMS contrast")
    max_noise_variance: float = Field(default=150.0, ge=0.0, description="Maximum acceptable spatial noise variance")
    min_snr_db: float = Field(default=10.0, description="Minimum acceptable Signal-to-Noise Ratio in dB")
    max_jpeg_blockiness: float = Field(default=2.5, ge=0.0, description="Maximum acceptable JPEG 8x8 blockiness metric")
    max_color_cast_delta: float = Field(default=45.0, ge=0.0, description="Maximum CIELAB chromaticity divergence")
    min_dimension: int = Field(default=32, ge=1, description="Minimum pixel dimension")
    max_dimension: int = Field(default=10000, ge=1, description="Maximum pixel dimension")
    min_aspect_ratio: float = Field(default=0.15, gt=0.0, description="Minimum width/height aspect ratio")
    max_aspect_ratio: float = Field(default=6.5, gt=0.0, description="Maximum width/height aspect ratio")
    max_uniform_region_ratio: float = Field(default=0.75, ge=0.0, le=1.0, description="Maximum uniform region fraction")


class OODScore(BaseModel):
    """Out-of-Distribution distance and novelty scoring metrics."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    global_knn_distance: float = Field(..., ge=0.0, description="Average distance to k nearest global reference neighbors")
    local_class_knn_distance: Optional[float] = Field(default=None, ge=0.0, description="Distance to class-specific neighbors")
    is_global_ood: bool = Field(..., description="Whether global distance exceeds calibrated threshold")
    is_local_ood: Optional[bool] = Field(default=None, description="Whether class distance exceeds threshold")
    calibrated_threshold: float = Field(..., ge=0.0, description="MAD-calibrated reference threshold")
    normalized_novelty_score: float = Field(..., ge=0.0, le=1.0, description="Calibrated OOD novelty index [0.0 = central, 1.0 = extreme]")
    subgroup_status: Optional[str] = Field(default=None, description="Subgroup status (e.g. FALLBACK_GLOBAL_OOD)")
    nearest_reference_sample_ids: Tuple[str, ...] = Field(default_factory=tuple)


class DistributionShiftEvidence(BaseModel):
    """Dataset-level statistical divergence and operational drift evidence."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    mmd_statistic: float = Field(..., ge=0.0, description="Maximum Mean Discrepancy against reference")
    energy_distance: float = Field(..., ge=0.0, description="Energy distance between sample and reference sets")
    is_shift_detected: bool = Field(..., description="Whether shift metric exceeds calibrated threshold")
    p_value_estimate: Optional[float] = Field(default=None, ge=0.0, le=1.0, description="Permutation test p-value")
    affected_sample_count: int = Field(..., ge=0)
    is_targeted: bool = Field(default=False, description="Whether shift is concentrated in single contributor")
    primary_shift_factors: Tuple[str, ...] = Field(default_factory=tuple, description="Identified shift axes (e.g. luminance, blur, palette)")


class ReferenceDistribution(BaseModel):
    """Metadata describing the established reference visual distribution."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    reference_mode: ReferenceMode = Field(..., description="Reference establishment strategy")
    reference_identity: str = Field(..., min_length=1, description="Dataset fingerprint or reference identifier")
    reference_sample_count: int = Field(..., ge=0, description="Number of samples in reference pool")
    feature_method: str = Field(..., min_length=1, description="Descriptor method (e.g. tier1_spatial_histogram, tier2_resnet50)")
    feature_dimension: int = Field(..., ge=1, description="Feature vector dimensionality D")
    median_distance: float = Field(..., ge=0.0, description="Reference pairwise/knn median distance")
    mad_distance: float = Field(..., ge=0.0, description="Reference Median Absolute Deviation (MAD)")
    calibrated_threshold: float = Field(..., ge=0.0, description="Derived decision threshold: median + beta * MAD")
    class_reference_counts: Dict[str, int] = Field(default_factory=dict, description="Per-class reference sample counts")


class OODScanFinding(BaseModel):
    """Immutable, strongly-typed finding emitted by Phase 5.7."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    finding_id: str = Field(..., min_length=1, description="Deterministic unique finding identifier")
    sample_id: str = Field(..., min_length=1, description="Associated sample identifier")
    annotation_id: Optional[str] = Field(default=None, description="Optional bounding box annotation ID for RoI analysis")
    category: OODCategory = Field(..., description="Controlled category from evidence taxonomy")
    evidence_layer: str = Field(default="detection", description="ADR-028 evidence layer (always 'detection')")
    severity: str = Field(default="LOW", description="Severity: LOW, MEDIUM, HIGH, CRITICAL")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Detector confidence score")
    contributors: Tuple[str, ...] = Field(default_factory=tuple, description="Associated contributor IDs for metadata preservation")
    quality_metrics: Optional[ImageQualityMetrics] = Field(default=None, description="Physical image quality measurements if evaluated")
    ood_score: Optional[OODScore] = Field(default=None, description="OOD distance scoring if evaluated")
    explanation: str = Field(..., min_length=1, description="Objective, non-accusatory explanation of evidence")
    limitations: Tuple[str, ...] = Field(default_factory=tuple, description="Known statistical or methodological limitations")

    @field_validator("explanation")
    @classmethod
    def _validate_non_malicious_language(cls, v: str) -> str:
        prohibited = ["malicious", "poison", "sabotage", "attacker", "guilt", "fraud", "tamper", "backdoor"]
        lower_v = v.lower()
        for word in prohibited:
            if word in lower_v:
                raise ValueError(f"Prohibited malicious attribution term '{word}' found in finding explanation.")
        return v


class OODConfig(BaseModel):
    """Comprehensive configuration for Phase 5.7 OOD & Image Quality Engine."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    k_neighbors: int = Field(default=10, ge=1, description="Number of nearest neighbors for kNN distance")
    mad_beta: float = Field(default=3.5, ge=1.0, description="Multiplier for MAD threshold calibration")
    min_dataset_size_guardrail: int = Field(default=25, ge=1, description="Minimum samples required to run OOD scan")
    min_reference_size_guardrail: int = Field(default=25, ge=1, description="Minimum reference samples required")
    min_class_support_guardrail: int = Field(default=5, ge=1, description="Minimum class samples for class-conditional OOD")
    max_subsample_shift: int = Field(default=2000, ge=10, description="Max points subsampled for MMD/Energy calculation")
    deterministic_seed: int = Field(default=42, description="Seed for deterministic RNG operations")
    iqa_config: ImageQualityConfig = Field(default_factory=ImageQualityConfig)


class OODScanResult(BaseModel):
    """Top-level scan result summarizing Phase 5.7 audit execution."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    scan_id: str = Field(..., min_length=1, description="Deterministic scan identifier")
    dataset_name: str = Field(..., min_length=1, description="Audited dataset name")
    dataset_fingerprint: str = Field(..., min_length=64, max_length=64, description="Hexadecimal dataset Merkle root / fingerprint")
    total_samples: int = Field(..., ge=0, description="Total samples in dataset")
    scanned_samples: int = Field(..., ge=0, description="Samples successfully analyzed")
    feature_extraction_status: FeatureExtractionStatus = Field(..., description="Feature extractor operational status")
    quality_anomaly_count: int = Field(..., ge=0, description="Count of samples with quality degradation")
    ood_sample_count: int = Field(..., ge=0, description="Count of samples exceeding OOD threshold")
    reference_distribution: Optional[ReferenceDistribution] = Field(default=None, description="Calibrated reference metadata")
    distribution_shift: Optional[DistributionShiftEvidence] = Field(default=None, description="Dataset-level distribution shift evidence")
    findings: Tuple[OODScanFinding, ...] = Field(default_factory=tuple, description="Deterministically sorted findings")
    diagnostics: Dict[str, Any] = Field(default_factory=dict, description="Scan execution telemetry and diagnostics")
