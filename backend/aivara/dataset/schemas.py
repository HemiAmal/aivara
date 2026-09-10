"""Canonical domain schemas for dataset ingestion and normalization (Phase 5).

All canonical schemas are strictly immutable (frozen=True), deterministic,
serializable, and decoupled from source dataset formats.
"""

from enum import Enum
from typing import Any, Dict, List, Optional, Tuple
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class DatasetFormat(str, Enum):
    """Supported dataset formats."""
    COCO = "coco"
    YOLO = "yolo"
    IMAGEFOLDER = "imagefolder"
    GENERIC = "generic"


class CanonicalBBox(BaseModel):
    """Canonical representation of an 2D axis-aligned bounding box.

    Coordinate Convention:
      - Origin (0.0, 0.0): Top-Left corner of the image frame.
      - x_min, y_min: Absolute pixel coordinates of the top-left corner (>= 0.0).
      - width, height: Absolute pixel dimensions (> 0.0).
      - x_max = x_min + width
      - y_max = y_min + height
      - Coordinates are absolute (pixel-space, float64).
    """

    model_config = ConfigDict(frozen=True)

    x_min: float = Field(..., ge=0.0, description="Top-left X coordinate in absolute pixels")
    y_min: float = Field(..., ge=0.0, description="Top-left Y coordinate in absolute pixels")
    width: float = Field(..., gt=0.0, description="Bounding box width in absolute pixels")
    height: float = Field(..., gt=0.0, description="Bounding box height in absolute pixels")
    confidence: Optional[float] = Field(default=1.0, ge=0.0, le=1.0, description="Detection confidence or 1.0 for GT")

    @property
    def x_max(self) -> float:
        """Right boundary coordinate in pixels."""
        return self.x_min + self.width

    @property
    def y_max(self) -> float:
        """Bottom boundary coordinate in pixels."""
        return self.y_min + self.height

    @property
    def area(self) -> float:
        """Pixel area of the bounding box."""
        return self.width * self.height

    @property
    def center(self) -> Tuple[float, float]:
        """Center coordinate (x_center, y_center) in absolute pixels."""
        return (self.x_min + self.width / 2.0, self.y_min + self.height / 2.0)

    def as_coco_bbox(self) -> Tuple[float, float, float, float]:
        """Return as standard COCO bbox: (x_min, y_min, width, height)."""
        return (self.x_min, self.y_min, self.width, self.height)

    def as_pascal_bbox(self) -> Tuple[float, float, float, float]:
        """Return as standard Pascal VOC bbox: (x_min, y_min, x_max, y_max)."""
        return (self.x_min, self.y_min, self.x_max, self.y_max)


class CanonicalAnnotation(BaseModel):
    """Canonical representation of an object detection or classification annotation.

    Guarantees deterministic sorting order and immutable attribute access.
    """

    model_config = ConfigDict(frozen=True)

    annotation_id: str = Field(..., min_length=1, description="Deterministic unique annotation identifier")
    category_id: int = Field(..., ge=0, description="Non-negative integer category identifier")
    category_name: str = Field(..., min_length=1, description="Normalized human-readable class name")
    bbox: Optional[CanonicalBBox] = Field(default=None, description="Optional bounding box for object detection")
    segmentation: Optional[Tuple[Tuple[float, ...], ...]] = Field(
        default=None, description="Optional polygon coordinate sequences"
    )
    area: Optional[float] = Field(default=None, ge=0.0, description="Optional pixel area")
    is_crowd: bool = Field(default=False, description="Flag for crowd/group annotations")
    attributes: Dict[str, Any] = Field(default_factory=dict, description="Arbitrary additional attributes")

    @field_validator("segmentation", mode="before")
    @classmethod
    def _coerce_segmentation(cls, v: Any) -> Optional[Tuple[Tuple[float, ...], ...]]:
        if v is None:
            return None
        if isinstance(v, (list, tuple)):
            coerced_poly = []
            for poly in v:
                if isinstance(poly, (list, tuple)):
                    coerced_poly.append(tuple(float(x) for x in poly))
            return tuple(coerced_poly)
        return v


class CanonicalCategory(BaseModel):
    """Canonical representation of a dataset category/class definition."""

    model_config = ConfigDict(frozen=True)

    category_id: int = Field(..., ge=0, description="Non-negative integer category identifier")
    category_name: str = Field(..., min_length=1, description="Normalized category label")
    supercategory: Optional[str] = Field(default=None, description="Optional supercategory hierarchy label")


class CanonicalSample(BaseModel):
    """Canonical representation of a single image sample in a dataset.

    Contains structural image metadata and deterministically ordered annotations.
    All paths use forward slashes and are relative to the dataset root.
    """

    model_config = ConfigDict(frozen=True)

    sample_id: str = Field(..., min_length=1, description="Deterministic unique sample identifier")
    relative_path: str = Field(..., min_length=1, description="Normalized forward-slash relative path")
    file_size_bytes: int = Field(..., ge=0, description="File size on disk in bytes")
    width: int = Field(..., ge=1, description="Image pixel width")
    height: int = Field(..., ge=1, description="Image pixel height")
    channels: int = Field(default=3, ge=1, description="Number of color channels (e.g. 1, 3, 4)")
    color_space: str = Field(default="RGB", description="Detected color space (e.g. RGB, RGBA, L, CMYK)")
    annotations: Tuple[CanonicalAnnotation, ...] = Field(
        default_factory=tuple, description="Deterministically sorted list of sample annotations"
    )
    contributors: Tuple[str, ...] = Field(
        default_factory=tuple, description="Optional list of associated contributor IDs"
    )
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Source-specific metadata")

    @field_validator("annotations", mode="before")
    @classmethod
    def _coerce_annotations(cls, v: Any) -> Tuple[CanonicalAnnotation, ...]:
        if isinstance(v, (list, tuple)):
            return tuple(v)
        return v

    @field_validator("contributors", mode="before")
    @classmethod
    def _coerce_contributors(cls, v: Any) -> Tuple[str, ...]:
        if isinstance(v, (list, tuple)):
            return tuple(str(x) for x in v)
        return v

    @field_validator("relative_path")
    @classmethod
    def _validate_relative_path(cls, v: str) -> str:
        if "\\" in v:
            raise ValueError("relative_path must use forward slashes exclusively")
        if v.startswith("/") or v.startswith("../") or "/../" in v or v.endswith("/.."):
            raise ValueError(f"relative_path '{v}' contains illegal path traversal or absolute components")
        return v


class CanonicalDatasetManifest(BaseModel):
    """Immutable, versioned canonical manifest of an entire dataset."""

    model_config = ConfigDict(frozen=True)

    schema_version: str = Field(default="1.0", description="Canonical manifest schema version")
    format: DatasetFormat = Field(..., description="Detected and ingested source dataset format")
    dataset_name: str = Field(..., min_length=1, description="Dataset name / identifier")
    sample_count: int = Field(..., ge=0, description="Total valid samples in manifest")
    annotation_count: int = Field(..., ge=0, description="Total annotations across all samples")
    categories: Tuple[CanonicalCategory, ...] = Field(
        default_factory=tuple, description="Deterministically ordered category list"
    )
    samples: Tuple[CanonicalSample, ...] = Field(
        default_factory=tuple, description="Deterministically ordered samples list (lexicographical by path)"
    )
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Top-level dataset metadata")

    @field_validator("categories", mode="before")
    @classmethod
    def _coerce_categories(cls, v: Any) -> Tuple[CanonicalCategory, ...]:
        if isinstance(v, (list, tuple)):
            return tuple(v)
        return v

    @field_validator("samples", mode="before")
    @classmethod
    def _coerce_samples(cls, v: Any) -> Tuple[CanonicalSample, ...]:
        if isinstance(v, (list, tuple)):
            return tuple(v)
        return v


class DatasetIngestionResult(BaseModel):
    """Structured result returned by the Dataset Ingestion Engine."""

    model_config = ConfigDict(frozen=True)

    format: DatasetFormat
    dataset_root: str
    manifest: CanonicalDatasetManifest
    total_samples: int = Field(..., ge=0)
    valid_samples: int = Field(..., ge=0)
    invalid_samples: int = Field(default=0, ge=0)
    total_annotations: int = Field(..., ge=0)
    categories: List[CanonicalCategory] = Field(default_factory=list)
    warnings: List[str] = Field(default_factory=list)
    capability_info: Dict[str, Any] = Field(default_factory=dict)
