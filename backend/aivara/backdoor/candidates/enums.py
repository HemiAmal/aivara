"""Enumerations for Trigger Candidate Taxonomy and Parameters (Phase 9.2)."""

from __future__ import annotations

from enum import Enum


class TriggerFamilyEnum(str, Enum):
    """Frozen v1 supported trigger candidate families (ADR-062)."""
    SPATIAL_PATCH = "SPATIAL_PATCH"
    COLOR_PATTERN_PATCH = "COLOR_PATTERN_PATCH"
    TEXTURE_GRID = "TEXTURE_GRID"
    LOCALIZED_PERTURBATION = "LOCALIZED_PERTURBATION"


class PlacementModeEnum(str, Enum):
    """Supported candidate placement modes."""
    FIXED_CORNER = "FIXED_CORNER"
    NORMALIZED_POSITION = "NORMALIZED_POSITION"
    GRID_CELL = "GRID_CELL"


class CornerLocationEnum(str, Enum):
    """Predefined fixed corner placements."""
    TOP_LEFT = "TOP_LEFT"
    TOP_RIGHT = "TOP_RIGHT"
    BOTTOM_LEFT = "BOTTOM_LEFT"
    BOTTOM_RIGHT = "BOTTOM_RIGHT"
    CENTER = "CENTER"


class PatchShapeEnum(str, Enum):
    """Supported geometric patch shapes."""
    RECTANGLE = "RECTANGLE"
    SQUARE = "SQUARE"
    CIRCLE = "CIRCLE"


class TexturePrimitiveEnum(str, Enum):
    """Deterministic periodic pattern primitives."""
    CHECKER = "CHECKER"
    GRID = "GRID"
    STRIPE_HORIZONTAL = "STRIPE_HORIZONTAL"
    STRIPE_VERTICAL = "STRIPE_VERTICAL"
    DOT_GRID = "DOT_GRID"


class PerturbationModeEnum(str, Enum):
    """Perturbation noise modes."""
    ADDITIVE_GAUSSIAN = "ADDITIVE_GAUSSIAN"
    ADDITIVE_UNIFORM = "ADDITIVE_UNIFORM"
    MULTIPLICATIVE_UNIFORM = "MULTIPLICATIVE_UNIFORM"


class ColorSpaceEnum(str, Enum):
    """Color parameterization representations."""
    RGB = "RGB"
    HSV_SHIFT = "HSV_SHIFT"
    LUMINANCE_SHIFT = "LUMINANCE_SHIFT"


class BlendModeEnum(str, Enum):
    """Pattern alpha blending mode."""
    REPLACE = "REPLACE"
    ALPHA_BLEND = "ALPHA_BLEND"
    ADDITIVE = "ADDITIVE"


class ValueRangeEnum(str, Enum):
    """Declared value range domain for candidate data."""
    UNIT_FLOAT = "UNIT_FLOAT"          # [0.0, 1.0]
    ZERO_CENTERED = "ZERO_CENTERED"    # [-1.0, 1.0]
    BYTE_INTEGER = "BYTE_INTEGER"      # [0, 255]
