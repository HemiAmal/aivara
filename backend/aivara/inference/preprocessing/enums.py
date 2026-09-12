"""Authoritative enums for AIVARA Phase 10.4 Preprocessing & Contract Integrity."""

from __future__ import annotations

from enum import Enum


class PreprocessingOpType(str, Enum):
    """Supported deterministic preprocessing operation types."""

    RESIZE = "RESIZE"
    CROP = "CROP"
    PAD = "PAD"
    CHANNEL_CONVERT = "CHANNEL_CONVERT"
    DTYPE_CONVERT = "DTYPE_CONVERT"
    NORMALIZE = "NORMALIZE"
    VALUE_RANGE_SCALE = "VALUE_RANGE_SCALE"
    NO_OP = "NO_OP"


class InterpolationMode(str, Enum):
    """Supported deterministic image resize interpolation algorithms."""

    NEAREST = "NEAREST"
    BILINEAR = "BILINEAR"
    BICUBIC = "BICUBIC"


class PaddingMode(str, Enum):
    """Supported deterministic padding boundary behaviors."""

    CONSTANT = "CONSTANT"
    REFLECT = "REFLECT"
    SYMMETRIC = "SYMMETRIC"
    REPLICATE = "REPLICATE"


class ColorSpace(str, Enum):
    """Canonical color spaces and channel arrangements."""

    RGB = "RGB"
    BGR = "BGR"
    GRAYSCALE = "GRAYSCALE"
    RGBA = "RGBA"
    BGRA = "BGRA"


class AspectRatioPolicy(str, Enum):
    """Aspect ratio handling when target dimensions differ from input aspect ratio."""

    STRETCH = "STRETCH"
    PRESERVE_PAD = "PRESERVE_PAD"
    PRESERVE_CROP = "PRESERVE_CROP"


class RoundingPolicy(str, Enum):
    """Deterministic rounding policy for floating-point to integer conversions."""

    HALF_TO_EVEN = "HALF_TO_EVEN"
    FLOOR = "FLOOR"
    CEIL = "CEIL"
    ROUND = "ROUND"


class ClippingPolicy(str, Enum):
    """Clipping policy for values exceeding destination range or bounds."""

    CLIP_TO_RANGE = "CLIP_TO_RANGE"
    NO_CLIP = "NO_CLIP"
    ERROR_ON_OUT_OF_RANGE = "ERROR_ON_OUT_OF_RANGE"
