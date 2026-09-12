"""Domain models for Phase 10.4 Preprocessing & Contract Integrity."""

from __future__ import annotations

import math
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field, field_validator

from aivara.inference.enums import InferenceIntegrityStatus, InputLayout
from aivara.inference.input.models import InputFinding
from aivara.inference.preprocessing.enums import (
    AspectRatioPolicy,
    ClippingPolicy,
    ColorSpace,
    InterpolationMode,
    PaddingMode,
    PreprocessingOpType,
    RoundingPolicy,
)


class ResizeParams(BaseModel):
    """Parameters for deterministic image/spatial resize."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    target_width: int = Field(..., gt=0, le=8192, description="Target spatial width (1-8192)")
    target_height: int = Field(..., gt=0, le=8192, description="Target spatial height (1-8192)")
    interpolation: InterpolationMode = Field(
        InterpolationMode.BILINEAR,
        description="Deterministic interpolation algorithm",
    )
    aspect_ratio_policy: AspectRatioPolicy = Field(
        AspectRatioPolicy.STRETCH,
        description="Aspect ratio scaling policy",
    )


class CropParams(BaseModel):
    """Parameters for deterministic spatial cropping."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    x: int = Field(..., ge=0, le=8192, description="Upper-left horizontal coordinate")
    y: int = Field(..., ge=0, le=8192, description="Upper-left vertical coordinate")
    width: int = Field(..., gt=0, le=8192, description="Crop window width")
    height: int = Field(..., gt=0, le=8192, description="Crop window height")
    normalized: bool = Field(False, description="Whether coordinates are in normalized [0, 1] range")


class PadParams(BaseModel):
    """Parameters for deterministic spatial padding."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    top: int = Field(..., ge=0, le=8192, description="Pixels added to top edge")
    bottom: int = Field(..., ge=0, le=8192, description="Pixels added to bottom edge")
    left: int = Field(..., ge=0, le=8192, description="Pixels added to left edge")
    right: int = Field(..., ge=0, le=8192, description="Pixels added to right edge")
    mode: PaddingMode = Field(PaddingMode.CONSTANT, description="Padding boundary mode")
    value: float = Field(0.0, description="Fill value for CONSTANT mode")

    @field_validator("value")
    @classmethod
    def validate_finite_value(cls, v: float) -> float:
        if not math.isfinite(v):
            raise ValueError("Padding value must be a finite floating-point number")
        return v


class ChannelConvertParams(BaseModel):
    """Parameters for deterministic color space / channel conversion."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    source_space: ColorSpace = Field(..., description="Source color space")
    target_space: ColorSpace = Field(..., description="Target destination color space")


class DtypeConvertParams(BaseModel):
    """Parameters for deterministic numerical data type conversion."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    source_dtype: str = Field(..., min_length=1, max_length=32, description="Expected input dtype (e.g. uint8, float32)")
    target_dtype: str = Field(..., min_length=1, max_length=32, description="Target converted dtype (e.g. float32, float64)")
    rounding_policy: RoundingPolicy = Field(
        RoundingPolicy.HALF_TO_EVEN,
        description="Rounding policy when converting floating point to integer",
    )
    clipping_policy: ClippingPolicy = Field(
        ClippingPolicy.CLIP_TO_RANGE,
        description="Clipping policy for out-of-range destination values",
    )


class NormalizeParams(BaseModel):
    """Parameters for per-channel statistical normalization or scaling."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    mean: List[float] = Field(..., min_length=1, max_length=1024, description="Per-channel subtraction mean")
    std: List[float] = Field(..., min_length=1, max_length=1024, description="Per-channel divisor std (> 0)")
    scale: Optional[float] = Field(None, description="Optional multiplicative scale factor (e.g. 1/255)")
    clip_min: Optional[float] = Field(None, description="Optional lower post-normalization bound")
    clip_max: Optional[float] = Field(None, description="Optional upper post-normalization bound")

    @field_validator("mean", "std")
    @classmethod
    def validate_finite_vectors(cls, v: List[float]) -> List[float]:
        for val in v:
            if not math.isfinite(val):
                raise ValueError("Normalization parameters must be finite floating-point numbers")
        return v

    @field_validator("std")
    @classmethod
    def validate_positive_std(cls, v: List[float]) -> List[float]:
        for val in v:
            if val <= 0.0:
                raise ValueError("Standard deviation values must be strictly positive (> 0.0)")
        return v

    @field_validator("scale", "clip_min", "clip_max")
    @classmethod
    def validate_optional_finite(cls, v: Optional[float]) -> Optional[float]:
        if v is not None and not math.isfinite(v):
            raise ValueError("Optional normalization parameters must be finite numbers")
        return v


class ValueRangeScaleParams(BaseModel):
    """Parameters for affine linear range remapping: [src_min, src_max] -> [tgt_min, tgt_max]."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    source_min: float = Field(..., description="Expected source minimum")
    source_max: float = Field(..., description="Expected source maximum (> source_min)")
    target_min: float = Field(..., description="Target remapped minimum")
    target_max: float = Field(..., description="Target remapped maximum (> target_min)")
    clip: bool = Field(True, description="Whether to clip output values to [target_min, target_max]")

    @field_validator("source_min", "source_max", "target_min", "target_max")
    @classmethod
    def validate_finite_range(cls, v: float) -> float:
        if not math.isfinite(v):
            raise ValueError("Value range parameters must be finite floating-point numbers")
        return v


class PreprocessingOperation(BaseModel):
    """Single deterministic preprocessing operation in an ordered recipe."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    op_type: PreprocessingOpType = Field(..., description="Operation classification")
    op_version: str = Field("1.0", max_length=16, description="Operation algorithm specification version")
    parameters: Dict[str, Any] = Field(default_factory=dict, description="Deterministic operation parameters")
    description: Optional[str] = Field(None, max_length=255, description="Human-readable operation description")


class InputAssumption(BaseModel):
    """Declared assumptions about the incoming tensor prior to preprocessing."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    expected_layout: Optional[InputLayout] = Field(None, description="Expected input tensor layout")
    expected_dtype: Optional[str] = Field(None, max_length=32, description="Expected input data type")
    expected_channels: Optional[int] = Field(None, gt=0, le=1024, description="Expected input channel count")
    expected_rank: Optional[int] = Field(None, ge=1, le=8, description="Expected tensor rank")
    expected_shape: Optional[List[Optional[int]]] = Field(None, description="Expected input shape if fixed")
    expected_value_range: Optional[List[float]] = Field(None, min_length=2, max_length=2, description="Expected range [min, max]")


class OutputGuarantee(BaseModel):
    """Declared guarantees about the resulting tensor after preprocessing."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    target_layout: Optional[InputLayout] = Field(None, description="Guaranteed preprocessed layout")
    target_dtype: Optional[str] = Field(None, max_length=32, description="Guaranteed preprocessed data type")
    target_channels: Optional[int] = Field(None, gt=0, le=1024, description="Guaranteed channel count")
    target_shape: Optional[List[Optional[int]]] = Field(None, description="Guaranteed spatial/tensor shape")
    target_value_range: Optional[List[float]] = Field(None, min_length=2, max_length=2, description="Guaranteed range [min, max]")


class PreprocessingContract(BaseModel):
    """Declarative, deterministic, content-addressed preprocessing specification."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: str = Field("1.0", max_length=16, description="Schema version of contract")
    contract_version: str = Field("1.0", max_length=16, description="Contract algorithm version")
    name: str = Field(..., min_length=1, max_length=255, description="Name or identifier of preprocessing contract")
    input_assumption: InputAssumption = Field(default_factory=InputAssumption, description="Input prerequisite assumptions")
    operations: List[PreprocessingOperation] = Field(
        default_factory=list,
        max_length=32,
        description="Strictly ordered sequence of deterministic operations",
    )
    output_guarantee: OutputGuarantee = Field(default_factory=OutputGuarantee, description="Output guarantees")
    contract_hash: str = Field(
        ...,
        pattern=r"^[0-9a-f]{64}$",
        description="64-character lowercase hex SHA-256 digest of canonical contract descriptor",
    )
    findings: List[InputFinding] = Field(default_factory=list, description="Validation findings")
    details: Dict[str, Any] = Field(default_factory=dict, description="Audit metadata")


class ContractVerificationResult(BaseModel):
    """Result of pure cryptographic verification of a PreprocessingContract."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    is_valid: bool = Field(..., description="Whether contract hash matches canonical recomputation")
    status: InferenceIntegrityStatus = Field(..., description="Overall contract verification status")
    computed_hash: str = Field(..., description="Locally recomputed contract hash")
    expected_hash: str = Field(..., description="Recorded contract hash from envelope")
    findings: List[InputFinding] = Field(default_factory=list, description="Observational findings")
    details: Dict[str, Any] = Field(default_factory=dict, description="Verification telemetry")


class CompatibilityAssessment(BaseModel):
    """Result of compatibility validation between input, preprocessing contract, and model contract."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    is_compatible: bool = Field(..., description="Whether input and model contracts are fully compatible with preprocessing")
    status: InferenceIntegrityStatus = Field(..., description="Overall compatibility status (VERIFIED, MISMATCHED, UNAVAILABLE)")
    input_compatible: bool = Field(..., description="Whether input satisfies preprocessing input assumptions")
    model_compatible: bool = Field(..., description="Whether preprocessing output guarantees satisfy model input contract")
    findings: List[InputFinding] = Field(default_factory=list, description="Structured compatibility findings")
    details: Dict[str, Any] = Field(default_factory=dict, description="Diagnostic details")


class TransformedInputIdentity(BaseModel):
    """Deterministic cryptographic identity of preprocessed tensor bytes (distinct from contract identity)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: str = Field("1.0", max_length=16, description="Schema version")
    input_id: str = Field(..., pattern=r"^[0-9a-f]{64}$", description="Original input identifier")
    binding_hash: str = Field(..., pattern=r"^[0-9a-f]{64}$", description="InputModelBinding hash")
    contract_hash: str = Field(..., pattern=r"^[0-9a-f]{64}$", description="PreprocessingContract hash (what should happen)")
    transformed_canonical_hash: str = Field(
        ...,
        pattern=r"^[0-9a-f]{64}$",
        description="SHA-256 of preprocessed tensor bytes (what did happen)",
    )
    dtype: str = Field(..., description="Preprocessed tensor data type")
    shape: List[int] = Field(..., description="Preprocessed tensor shape")
    layout: InputLayout = Field(InputLayout.UNKNOWN, description="Preprocessed tensor layout")
    byte_size: int = Field(0, ge=0, description="Preprocessed contiguous byte size")
    element_count: int = Field(0, ge=0, description="Total preprocessed element count")
    finite: bool = Field(True, description="Whether preprocessed values are strictly finite (no NaN/Inf)")
    transformation_status: InferenceIntegrityStatus = Field(
        InferenceIntegrityStatus.VERIFIED,
        description="Transformation execution integrity status",
    )
    findings: List[InputFinding] = Field(default_factory=list, description="Observational transformation findings")
    details: Dict[str, Any] = Field(default_factory=dict, description="Execution telemetry")
