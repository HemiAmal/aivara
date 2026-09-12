"""Immutable Pydantic Models for Trigger Candidate Specifications (Phase 9.2)."""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple, Union
import numpy as np
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from aivara.backdoor.candidates.enums import (
    BlendModeEnum,
    ColorSpaceEnum,
    CornerLocationEnum,
    PatchShapeEnum,
    PerturbationModeEnum,
    PlacementModeEnum,
    TexturePrimitiveEnum,
    TriggerFamilyEnum,
    ValueRangeEnum,
)
from aivara.backdoor.candidates.validators import (
    MAX_RELATIVE_HEIGHT,
    MAX_RELATIVE_RADIUS,
    MAX_RELATIVE_WIDTH,
    MIN_RELATIVE_DIMENSION,
    validate_finite_number,
    validate_security_dict,
    validate_seed,
)


# =====================================================================
# 1. Family-Specific Parameter Models
# =====================================================================

class SpatialPatchParameters(BaseModel):
    """Parameters for SPATIAL_PATCH trigger candidate."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    shape: PatchShapeEnum = Field(PatchShapeEnum.SQUARE, description="Geometric shape of the patch")
    relative_width: float = Field(0.10, ge=MIN_RELATIVE_DIMENSION, le=MAX_RELATIVE_WIDTH, description="Patch width relative to canvas [0.01, 0.50]")
    relative_height: float = Field(0.10, ge=MIN_RELATIVE_DIMENSION, le=MAX_RELATIVE_HEIGHT, description="Patch height relative to canvas [0.01, 0.50]")
    relative_radius: Optional[float] = Field(None, ge=MIN_RELATIVE_DIMENSION, le=MAX_RELATIVE_RADIUS, description="Radius for circular patch [0.01, 0.25]")
    fill_color: List[float] = Field(default_factory=lambda: [1.0, 1.0, 1.0], description="RGB fill color values in [0.0, 1.0]")
    alpha: float = Field(1.0, ge=0.0, le=1.0, description="Patch opacity blend factor [0.0, 1.0]")
    blend_mode: BlendModeEnum = Field(BlendModeEnum.REPLACE, description="Color blending mode")

    @field_validator("fill_color")
    @classmethod
    def validate_fill_color(cls, v: List[float]) -> List[float]:
        if not (1 <= len(v) <= 4):
            raise ValueError("fill_color must have between 1 and 4 channel components.")
        for i, c in enumerate(v):
            validate_finite_number(c, f"fill_color[{i}]", min_val=0.0, max_val=1.0)
        return list(v)


class ColorPatternPatchParameters(BaseModel):
    """Parameters for COLOR_PATTERN_PATCH trigger candidate."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    color_space: ColorSpaceEnum = Field(ColorSpaceEnum.RGB, description="Target color space")
    channel_deltas: List[float] = Field(default_factory=lambda: [0.5, -0.3, 0.2], description="Per-channel shift values in [-1.0, 1.0]")
    relative_width: float = Field(0.15, ge=MIN_RELATIVE_DIMENSION, le=MAX_RELATIVE_WIDTH, description="Patch width relative to canvas")
    relative_height: float = Field(0.15, ge=MIN_RELATIVE_DIMENSION, le=MAX_RELATIVE_HEIGHT, description="Patch height relative to canvas")
    alpha: float = Field(0.8, ge=0.0, le=1.0, description="Blending opacity")
    blend_mode: BlendModeEnum = Field(BlendModeEnum.ALPHA_BLEND, description="Color blend mode")

    @field_validator("channel_deltas")
    @classmethod
    def validate_channel_deltas(cls, v: List[float]) -> List[float]:
        if not (1 <= len(v) <= 4):
            raise ValueError("channel_deltas must have between 1 and 4 channel components.")
        for i, c in enumerate(v):
            validate_finite_number(c, f"channel_deltas[{i}]", min_val=-1.0, max_val=1.0)
        return list(v)


class TextureGridParameters(BaseModel):
    """Parameters for TEXTURE_GRID periodic pattern trigger candidate."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    primitive: TexturePrimitiveEnum = Field(TexturePrimitiveEnum.CHECKER, description="Periodic texture primitive")
    stride_pixels: int = Field(8, ge=2, le=128, description="Grid stride in pixels")
    line_width_pixels: int = Field(2, ge=1, le=32, description="Line width or checker block width")
    amplitude: float = Field(0.25, ge=0.01, le=1.0, description="Pattern modulation amplitude in [0.01, 1.0]")
    alpha: float = Field(0.5, ge=0.0, le=1.0, description="Overall texture opacity")
    color_channels: List[float] = Field(default_factory=lambda: [1.0, 1.0, 1.0], description="Modulation color vector")
    phase_offset: float = Field(0.0, ge=0.0, le=1.0, description="Spatial phase offset [0.0, 1.0]")

    @field_validator("color_channels")
    @classmethod
    def validate_color_channels(cls, v: List[float]) -> List[float]:
        if not (1 <= len(v) <= 4):
            raise ValueError("color_channels must have between 1 and 4 components.")
        for i, c in enumerate(v):
            validate_finite_number(c, f"color_channels[{i}]", min_val=0.0, max_val=1.0)
        return list(v)


class LocalizedPerturbationParameters(BaseModel):
    """Parameters for LOCALIZED_PERTURBATION trigger candidate."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    mode: PerturbationModeEnum = Field(PerturbationModeEnum.ADDITIVE_GAUSSIAN, description="Perturbation distribution mode")
    relative_width: float = Field(0.20, ge=MIN_RELATIVE_DIMENSION, le=MAX_RELATIVE_WIDTH, description="Perturbation window relative width")
    relative_height: float = Field(0.20, ge=MIN_RELATIVE_DIMENSION, le=MAX_RELATIVE_HEIGHT, description="Perturbation window relative height")
    amplitude: float = Field(0.10, ge=0.001, le=1.0, description="Maximum perturbation magnitude")
    noise_std: float = Field(0.05, ge=0.001, le=0.50, description="Gaussian noise standard deviation")
    clip_min: float = Field(0.0, description="Lower clamping bound")
    clip_max: float = Field(1.0, description="Upper clamping bound")

    @model_validator(mode="after")
    def validate_clip_bounds(self) -> LocalizedPerturbationParameters:
        if self.clip_min >= self.clip_max:
            raise ValueError(f"clip_min ({self.clip_min}) must be strictly less than clip_max ({self.clip_max}).")
        return self


# =====================================================================
# 2. Placement and Constraint Models
# =====================================================================

class PlacementSpec(BaseModel):
    """Specification of spatial candidate placement on input canvas."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    mode: PlacementModeEnum = Field(PlacementModeEnum.FIXED_CORNER, description="Placement coordinate mode")
    corner: Optional[CornerLocationEnum] = Field(CornerLocationEnum.BOTTOM_RIGHT, description="Corner location if mode is FIXED_CORNER")
    normalized_x: Optional[float] = Field(None, ge=0.0, le=1.0, description="Normalized X coordinate in [0.0, 1.0]")
    normalized_y: Optional[float] = Field(None, ge=0.0, le=1.0, description="Normalized Y coordinate in [0.0, 1.0]")
    grid_row: Optional[int] = Field(None, ge=0, le=7, description="Grid row index if mode is GRID_CELL [0..7]")
    grid_col: Optional[int] = Field(None, ge=0, le=7, description="Grid column index if mode is GRID_CELL [0..7]")

    @model_validator(mode="after")
    def validate_placement_consistency(self) -> PlacementSpec:
        if self.mode == PlacementModeEnum.NORMALIZED_POSITION:
            if self.normalized_x is None or self.normalized_y is None:
                raise ValueError("NORMALIZED_POSITION requires normalized_x and normalized_y.")
        elif self.mode == PlacementModeEnum.GRID_CELL:
            if self.grid_row is None or self.grid_col is None:
                raise ValueError("GRID_CELL requires grid_row and grid_col.")
        elif self.mode == PlacementModeEnum.FIXED_CORNER:
            if self.corner is None:
                raise ValueError("FIXED_CORNER requires corner location.")
        return self


class InputConstraints(BaseModel):
    """Declared input domain constraints for the candidate."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    supported_ranks: List[int] = Field(default_factory=lambda: [2, 3, 4], description="Supported tensor ranks (2=HW, 3=CHW/HWC, 4=NCHW/NHWC)")
    min_spatial_shape: Tuple[int, int] = Field((16, 16), description="Minimum (height, width) spatial dimensions")
    max_spatial_shape: Tuple[int, int] = Field((4096, 4096), description="Maximum (height, width) spatial dimensions")
    expected_channels: Optional[int] = Field(3, description="Expected channel count (e.g. 1 or 3)")
    value_range: ValueRangeEnum = Field(ValueRangeEnum.UNIT_FLOAT, description="Expected input value range")


# =====================================================================
# 3. Canonical Trigger Candidate Specification
# =====================================================================

class TriggerCandidateSpec(BaseModel):
    """Immutable, canonical trigger candidate specification (Phase 9.2)."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: str = Field("1.0.0", description="Specification schema version")
    candidate_id: str = Field(..., description="Unique deterministic candidate identifier")
    candidate_family: TriggerFamilyEnum = Field(..., description="Frozen v1 trigger family")
    parameters: Dict[str, Any] = Field(..., description="Validated family-specific parameters")
    placement: PlacementSpec = Field(default_factory=PlacementSpec, description="Placement specification")
    input_constraints: InputConstraints = Field(default_factory=InputConstraints, description="Input domain constraints")
    random_seed: int = Field(42, description="Deterministic PCG64 random seed")
    transformation_version: str = Field("1.0.0", description="Transformation algorithm version")
    candidate_hash: str = Field(..., description="Deterministic 64-hex SHA-256 JCS identity digest")

    @field_validator("random_seed")
    @classmethod
    def validate_spec_seed(cls, v: int) -> int:
        return validate_seed(v)

    @field_validator("parameters")
    @classmethod
    def validate_spec_parameters(cls, v: Dict[str, Any]) -> Dict[str, Any]:
        validate_security_dict(v, "parameters")
        return dict(v)


# =====================================================================
# 4. Pattern Array Output Representation
# =====================================================================

class GeneratedPattern:
    """In-memory synthesized pattern array and mask."""

    def __init__(
        self,
        candidate_spec: TriggerCandidateSpec,
        target_shape: Tuple[int, int, int],  # (height, width, channels)
        pattern_array: np.ndarray,
        mask_array: np.ndarray,
    ) -> None:
        if pattern_array.shape != target_shape:
            raise ValueError(f"Pattern array shape {pattern_array.shape} does not match target shape {target_shape}.")
        if mask_array.shape != (target_shape[0], target_shape[1]):
            raise ValueError(f"Mask array shape {mask_array.shape} does not match spatial dimensions {(target_shape[0], target_shape[1])}.")

        self.candidate_spec = candidate_spec
        self.target_shape = target_shape
        self.pattern_array = np.ascontiguousarray(pattern_array, dtype=np.float32)
        self.mask_array = np.ascontiguousarray(mask_array, dtype=np.float32)

    @property
    def candidate_id(self) -> str:
        return self.candidate_spec.candidate_id

    @property
    def candidate_hash(self) -> str:
        return self.candidate_spec.candidate_hash

    @property
    def candidate_family(self) -> TriggerFamilyEnum:
        return self.candidate_spec.candidate_family
