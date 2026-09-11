"""Pydantic domain models, schemas, and parameter specifications for Phase 8.4 Perturbation Engine."""

from __future__ import annotations

from enum import Enum
from typing import Any, Dict, List, Optional, Tuple
from pydantic import BaseModel, ConfigDict, Field, field_serializer, model_validator
import numpy as np


class PerturbationType(str, Enum):
    """Supported deterministic perturbation algorithms."""

    GAUSSIAN_NOISE = "GAUSSIAN_NOISE"
    UNIFORM_NOISE = "UNIFORM_NOISE"
    BRIGHTNESS = "BRIGHTNESS"
    CONTRAST = "CONTRAST"
    GAUSSIAN_BLUR = "GAUSSIAN_BLUR"
    JPEG_COMPRESSION = "JPEG_COMPRESSION"
    SPATIAL_TRANSLATION = "SPATIAL_TRANSLATION"


class PerturbationResultStatus(str, Enum):
    """Operational status of a perturbation transform or experiment."""

    SUCCESS = "SUCCESS"
    INVALID_PARAMETER = "INVALID_PARAMETER"
    UNSUPPORTED_INPUT = "UNSUPPORTED_INPUT"
    UNVERIFIABLE_INPUT = "UNVERIFIABLE_INPUT"
    RESOURCE_LIMIT = "RESOURCE_LIMIT"
    TRANSFORMATION_ERROR = "TRANSFORMATION_ERROR"


class BorderPolicy(str, Enum):
    """Boundary padding policy for spatial transformations."""

    REPLICATE = "REPLICATE"
    CONSTANT = "CONSTANT"
    REFLECT = "REFLECT"


class ImageDType(str, Enum):
    """Supported image numerical representation formats."""

    UINT8 = "uint8"
    FLOAT32 = "float32"
    FLOAT64 = "float64"


# =====================================================================
# Central Resource Ceilings & Bounds
# =====================================================================

class PerturbationLimits(BaseModel):
    """Centrally configurable hard ceilings for perturbation parameters and resource usage."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    max_noise_std: float = Field(1.0, ge=0.0, description="Maximum standard deviation for Gaussian noise")
    max_noise_amplitude: float = Field(1.0, ge=0.0, description="Maximum amplitude for uniform noise")
    min_brightness_factor: float = Field(0.0, ge=0.0, description="Minimum brightness scaling factor")
    max_brightness_factor: float = Field(5.0, le=10.0, description="Maximum brightness scaling factor")
    min_contrast_factor: float = Field(0.0, ge=0.0, description="Minimum contrast scaling factor")
    max_contrast_factor: float = Field(5.0, le=10.0, description="Maximum contrast scaling factor")
    max_blur_kernel_size: int = Field(31, ge=3, le=63, description="Maximum kernel size for Gaussian blur (must be odd)")
    max_blur_sigma: float = Field(10.0, ge=0.01, le=50.0, description="Maximum sigma for Gaussian blur")
    min_jpeg_quality: int = Field(1, ge=1, le=100, description="Minimum JPEG compression quality")
    max_jpeg_quality: int = Field(100, ge=1, le=100, description="Maximum JPEG compression quality")
    max_translation_pixels: int = Field(100, ge=0, description="Maximum pixel translation offset")
    max_image_elements: int = Field(50_000_000, ge=1, description="Maximum elements in a single image tensor")
    max_perturbations_per_experiment: int = Field(100, ge=1, le=500, description="Maximum perturbation batch size")


DEFAULT_PERTURBATION_LIMITS = PerturbationLimits()


# =====================================================================
# Parameter Specifications per Transform
# =====================================================================

class GaussianNoiseParams(BaseModel):
    """Parameters for deterministic Gaussian noise addition."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    mean: float = Field(0.0, description="Mean of the Gaussian noise distribution")
    std: float = Field(0.05, ge=0.0, le=1.0, description="Standard deviation of the noise")
    seed: int = Field(42, description="Deterministic PRNG seed")


class UniformNoiseParams(BaseModel):
    """Parameters for deterministic Uniform noise addition."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    min_val: float = Field(-0.05, description="Lower bound of uniform noise")
    max_val: float = Field(0.05, description="Upper bound of uniform noise")
    seed: int = Field(42, description="Deterministic PRNG seed")

    @model_validator(mode="after")
    def validate_bounds(self) -> UniformNoiseParams:
        if self.min_val > self.max_val:
            raise ValueError(f"min_val ({self.min_val}) cannot exceed max_val ({self.max_val})")
        return self


class BrightnessParams(BaseModel):
    """Parameters for deterministic brightness scaling."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    factor: float = Field(1.1, ge=0.0, le=5.0, description="Multiplicative brightness scaling factor")


class ContrastParams(BaseModel):
    """Parameters for deterministic contrast adjustment."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    factor: float = Field(1.1, ge=0.0, le=5.0, description="Linear contrast scaling factor")


class GaussianBlurParams(BaseModel):
    """Parameters for deterministic Gaussian blur filtering."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    kernel_size: int = Field(3, ge=3, le=31, description="Odd kernel dimension (e.g. 3, 5, 7)")
    sigma: float = Field(1.0, ge=0.01, le=10.0, description="Gaussian kernel standard deviation")

    @model_validator(mode="after")
    def validate_kernel_odd(self) -> GaussianBlurParams:
        if self.kernel_size % 2 == 0:
            raise ValueError(f"kernel_size ({self.kernel_size}) must be an odd positive integer")
        return self


class JpegCompressionParams(BaseModel):
    """Parameters for deterministic JPEG compression encoding/decoding."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    quality: int = Field(75, ge=1, le=100, description="JPEG compression quality level (1-100)")


class SpatialTranslationParams(BaseModel):
    """Parameters for deterministic 2D spatial pixel translation."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    dx: int = Field(2, ge=-100, le=100, description="Horizontal pixel displacement (positive = right)")
    dy: int = Field(2, ge=-100, le=100, description="Vertical pixel displacement (positive = down)")
    border_policy: BorderPolicy = Field(BorderPolicy.REPLICATE, description="Boundary pixel padding mode")
    fill_value: float = Field(0.0, description="Fill value when border_policy is CONSTANT")


# =====================================================================
# Experiment & Specification Schemas
# =====================================================================

class PerturbationSpecification(BaseModel):
    """Strongly-typed declarative specification of a controlled perturbation."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    perturbation_type: PerturbationType = Field(..., description="Target perturbation algorithm")
    parameters: Dict[str, Any] = Field(..., description="Canonical parameter dictionary")
    seed: Optional[int] = Field(None, description="Deterministic PRNG seed if stochastic")


class PerturbationResult(BaseModel):
    """Execution result of applying a controlled perturbation to an input."""

    model_config = ConfigDict(extra="forbid", arbitrary_types_allowed=True)

    status: PerturbationResultStatus = Field(..., description="Transformation outcome status")
    perturbation_id: str = Field(..., description="Deterministic 64-char SHA-256 perturbation digest")
    source_input_hash: str = Field(..., description="Deterministic 64-char SHA-256 hash of original input")
    perturbed_input_hash: Optional[str] = Field(None, description="Deterministic 64-char SHA-256 hash of result")
    perturbed_array: Optional[Any] = Field(None, description="Resulting numpy ndarray (None if failed)")
    error_message: Optional[str] = Field(None, description="Safe error description if status != SUCCESS")
    execution_metadata: Dict[str, Any] = Field(default_factory=dict, description="Diagnostic telemetry")

    @field_serializer("perturbed_array")
    def serialize_perturbed_array(self, v: Any, _info) -> Any:
        if isinstance(v, np.ndarray):
            return {"shape": list(v.shape), "dtype": str(v.dtype)}
        return v


class PerturbationExperiment(BaseModel):
    """Immutable domain representation of a completed perturbation experiment."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    experiment_id: str = Field(..., description="Deterministic 64-char SHA-256 experiment digest")
    project_id: str = Field(..., description="Multi-tenant project identifier")
    model_id: Optional[str] = Field(None, description="Associated model asset ID if evaluated")
    source_input_id: str = Field(..., description="Source sample identifier")
    source_input_hash: str = Field(..., description="Source sample canonical digest")
    perturbation_id: str = Field(..., description="Deterministic 64-char SHA-256 perturbation digest")
    perturbation_type: PerturbationType = Field(..., description="Applied perturbation algorithm")
    parameters: Dict[str, Any] = Field(..., description="Canonical perturbation parameters")
    seed: Optional[int] = Field(None, description="PRNG seed if applicable")
    implementation_version: str = Field("1.0.0", description="Implementation version of perturbation engine")
    input_shape: List[int] = Field(..., description="Shape of original input array")
    input_dtype: str = Field(..., description="DType of original input array")
    output_shape: Optional[List[int]] = Field(None, description="Shape of perturbed output array")
    output_dtype: Optional[str] = Field(None, description="DType of perturbed output array")
    source_value_range: List[float] = Field(..., description="Declared or observed value range of source [min, max]")
    result_value_range: Optional[List[float]] = Field(None, description="Observed value range of result [min, max]")
    status: PerturbationResultStatus = Field(..., description="Experiment status")
    created_at: str = Field(..., description="ISO 8601 UTC timestamp")
