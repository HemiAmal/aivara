"""Dataset API request and response schemas (Phase 5.10)."""

from __future__ import annotations

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field


class FormatDetectRequest(BaseModel):
    """Request payload to detect dataset format on local filesystem."""

    model_config = ConfigDict(extra="forbid")

    dataset_path: str = Field(..., min_length=1, description="Path to dataset root directory")


class FormatDetectResponse(BaseModel):
    """Result of format detection."""

    model_config = ConfigDict(extra="forbid")

    detected_format: str = Field(..., description="Detected format (coco, yolo, imagefolder)")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Detection confidence")
    details: Dict[str, Any] = Field(default_factory=dict, description="Metadata explaining detection")


class DatasetIngestRequest(BaseModel):
    """Request payload to ingest and normalize a dataset."""

    model_config = ConfigDict(extra="forbid")

    project_id: str = Field(..., min_length=1, max_length=36, description="Project identifier")
    dataset_id: Optional[str] = Field(None, max_length=36, description="Existing dataset ID or None to create")
    dataset_name: Optional[str] = Field(None, max_length=255, description="Dataset name if creating new dataset")
    dataset_path: str = Field(..., min_length=1, description="Path to source dataset on disk")
    format: Optional[str] = Field(None, description="Explicit format override (coco, yolo, imagefolder) or auto-detect")
    version_name: str = Field("v1.0", max_length=50, description="Semantic version string")
    description: Optional[str] = Field(None, max_length=1000, description="Optional version description")


class DatasetIngestResponse(BaseModel):
    """Result of dataset ingestion and normalization."""

    model_config = ConfigDict(extra="forbid")

    dataset_id: str
    version_id: str
    project_id: str
    format: str
    sample_count: int
    annotation_count: int
    category_count: int
    dataset_fingerprint: str
    merkle_root: str
    status: str = "INGESTED"
    validation_warnings: List[str] = Field(default_factory=list)
