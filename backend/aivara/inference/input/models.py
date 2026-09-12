"""Data transfer and domain identity models for inference inputs."""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple
from pydantic import BaseModel, ConfigDict, Field

from aivara.inference.enums import (
    InferenceIntegrityStatus,
    InputKind,
    InputLayout,
    ValueRangeKind,
)


class TensorMetadata(BaseModel):
    """Structural and numerical metadata extracted from a validated tensor."""

    model_config = ConfigDict(frozen=True)

    rank: int
    shape: Tuple[int, ...]
    dtype: str
    layout: InputLayout
    element_count: int
    byte_size: int
    finite: bool
    min_value: Optional[float] = None
    max_value: Optional[float] = None
    value_range: ValueRangeKind = ValueRangeKind.UNKNOWN
    c_contiguous_byte_hash: str


class ImageFileMetadata(BaseModel):
    """Metadata extracted from a validated image file input."""

    model_config = ConfigDict(frozen=True)

    file_path: str
    file_size_bytes: int
    width: int
    height: int
    channels: int
    color_space: str
    format_name: str
    raw_file_hash: str
    canonical_pixel_hash: str


class StructuredInputMetadata(BaseModel):
    """Metadata extracted from structured JSON-compatible input data."""

    model_config = ConfigDict(frozen=True)

    top_level_type: str
    element_count: int
    canonical_byte_size: int
    canonical_hash: str


class InputFinding(BaseModel):
    """Structured, observational validation finding."""

    model_config = ConfigDict(frozen=True)

    code: str
    message: str
    details: Dict[str, Any] = Field(default_factory=dict)


class InputIdentity(BaseModel):
    """Deterministic, content-addressed identity and validation envelope for an inference input."""

    model_config = ConfigDict(frozen=True)

    input_id: str
    input_kind: InputKind
    canonical_hash: str
    raw_file_hash: Optional[str] = None
    canonical_pixel_hash: Optional[str] = None
    dtype: Optional[str] = None
    shape: Optional[Tuple[int, ...]] = None
    layout: InputLayout = InputLayout.UNKNOWN
    rank: Optional[int] = None
    batch_size: Optional[int] = None
    channels: Optional[int] = None
    width: Optional[int] = None
    height: Optional[int] = None
    value_range: ValueRangeKind = ValueRangeKind.UNKNOWN
    finite: bool = True
    byte_size: int = 0
    element_count: int = 0
    validation_status: InferenceIntegrityStatus = InferenceIntegrityStatus.VERIFIED
    schema_version: str = "1.0"
    findings: List[InputFinding] = Field(default_factory=list)
    details: Dict[str, Any] = Field(default_factory=dict)
