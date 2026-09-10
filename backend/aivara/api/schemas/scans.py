"""Scan orchestration request, response, and SSE event schemas (Phase 5.10)."""

from __future__ import annotations

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field


class ScanCreateRequest(BaseModel):
    """Request payload to initiate or queue a dataset integrity scan."""

    model_config = ConfigDict(extra="forbid")

    project_id: str = Field(..., min_length=1, max_length=36, description="Project identifier")
    dataset_version_id: str = Field(..., min_length=1, max_length=36, description="Dataset version identifier")
    detectors: Optional[List[str]] = Field(
        None,
        description="Selective list of detectors to execute (fingerprint, duplicates, label_anomalies, label_flipping, ood_quality, contributors). If omitted, runs all.",
    )
    seal_provenance: bool = Field(True, description="Whether to seal the scan with Phase 4 cryptographic provenance")
    signer_key_id: Optional[str] = Field(None, description="Optional key ID for Ed25519 provenance signing")
    signer_passphrase: Optional[str] = Field(None, description="Optional passphrase for private key decryption")
    allow_idempotent_reuse: bool = Field(True, description="Whether to return IDEMPOTENT_HIT if identical execution exists")
    sample_limit: Optional[int] = Field(None, ge=1, description="Optional sample limit for partial scan testing")
    config_overrides: Optional[Dict[str, Any]] = Field(None, description="Detector-specific configuration parameter overrides")


class ScanReadResponse(BaseModel):
    """Structured representation of a dataset integrity scan."""

    model_config = ConfigDict(extra="forbid")

    scan_id: str
    project_id: str
    dataset_version_id: str
    execution_identity_hash: Optional[str] = None
    status: str = Field(..., description="QUEUED, RUNNING, COMPLETED, PARTIAL, FAILED, CANCELLED, IDEMPOTENT_HIT")
    progress_percent: float = Field(0.0, ge=0.0, le=100.0)
    current_stage: Optional[str] = None
    processed_samples: int = 0
    expected_samples: int = 0
    finding_ids: List[str] = Field(default_factory=list)
    evidence_count: int = 0
    provenance_record_id: Optional[str] = None
    error_message: Optional[str] = None
    started_at: Optional[str] = None
    completed_at: Optional[str] = None


class ScanProgressEvent(BaseModel):
    """Structured SSE event payload for real-time progress streaming."""

    model_config = ConfigDict(extra="forbid")

    scan_id: str
    event_type: str = Field(
        ...,
        description="scan.queued, scan.started, scan.progress, scan.detector.completed, scan.evidence.created, scan.completed, scan.partial, scan.cancelled, scan.failed",
    )
    progress_percent: float = Field(0.0, ge=0.0, le=100.0)
    stage: str
    message: str
    timestamp: str
    data: Dict[str, Any] = Field(default_factory=dict)
