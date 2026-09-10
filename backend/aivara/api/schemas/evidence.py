"""Evidence and Finding API request and response schemas (Phase 5.10)."""

from __future__ import annotations

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field


class EvidenceVerifyRequest(BaseModel):
    """Request to verify deterministic canonical evidence hash."""

    model_config = ConfigDict(extra="forbid")

    evidence_payload: Dict[str, Any] = Field(..., description="Canonical evidence dictionary")
    expected_hash: str = Field(..., min_length=64, max_length=64, description="Expected SHA-256 evidence hash")


class EvidenceVerifyResponse(BaseModel):
    """Verification result of an evidence hash."""

    model_config = ConfigDict(extra="forbid")

    is_valid: bool
    computed_hash: str
    expected_hash: str


class EvidenceItemRead(BaseModel):
    """Structured view of a persisted evidence record."""

    model_config = ConfigDict(from_attributes=True)

    id: str
    finding_id: Optional[str] = None
    evidence_hash: Optional[str] = None
    evidence_type: str
    evidence_layer: str
    title: str
    description: Optional[str] = None
    confidence: Optional[float] = None
    measurements: Dict[str, Any] = Field(default_factory=dict)
    data_json: Dict[str, Any] = Field(default_factory=dict)
    created_at: str


class FindingDetailRead(BaseModel):
    """Detailed view of a synthesized finding including cited evidence."""

    model_config = ConfigDict(from_attributes=True)

    id: str
    project_id: str
    finding_type: str
    engine_id: Optional[str] = None
    title: str
    description: Optional[str] = None
    severity: str
    confidence: Optional[float] = None
    disposition: Optional[str] = None
    affected_asset_type: Optional[str] = None
    affected_asset_id: Optional[str] = None
    primary_evidence_hashes: List[str] = Field(default_factory=list)
    referenced_evidence_ids: List[str] = Field(default_factory=list)
    provenance_record_id: Optional[str] = None
    metadata_json: Dict[str, Any] = Field(default_factory=dict)
    created_at: str
