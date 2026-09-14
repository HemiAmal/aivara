"""Pydantic V2 schemas for Universal Risk API and Task Integration (Phase 12.10)."""

from __future__ import annotations

from datetime import datetime, timezone
import math
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from aivara.crypto.hashing import hash_canonical_data
from aivara.universal.api.enums import (
    UniversalAPISchemaVersion,
    UniversalPipelineStage,
    UniversalTaskStatus,
)


def utcnow_iso() -> str:
    """Return timezone-aware current UTC datetime as ISO-8601 string."""
    return datetime.now(timezone.utc).isoformat()


class UniversalAssuranceTaskCreateRequest(BaseModel):
    """Immutable request schema for submitting a Universal Assurance Task."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    project_id: Optional[str] = Field(default=None, min_length=1, max_length=128)
    asset_ids: List[str] = Field(default_factory=list, max_length=500)
    evidence_items: List[Dict[str, Any]] = Field(default_factory=list, max_length=5000)
    dependency_edges: List[Dict[str, Any]] = Field(default_factory=list, max_length=2000)
    asset_roles: Dict[str, str] = Field(default_factory=dict)
    risk_policy_version: str = Field(default="1.0.0", max_length=64)
    decision_policy_version: str = Field(default="1.0.0", max_length=64)
    idempotency_key: Optional[str] = Field(default=None, max_length=128)

    @field_validator("asset_ids")
    @classmethod
    def validate_asset_ids(cls, v: List[str]) -> List[str]:
        for aid in v:
            if not aid or len(aid) > 128:
                raise ValueError("Each asset ID must be a non-empty string with max length 128")
        return sorted(list(set(v)))


class UniversalTaskResponse(BaseModel):
    """Response schema representing an in-memory or persisted assurance task."""

    model_config = ConfigDict(frozen=True)

    task_id: str = Field(..., min_length=1, max_length=128)
    project_id: str = Field(..., min_length=1, max_length=128)
    status: UniversalTaskStatus
    progress_percent: float = Field(..., ge=0.0, le=100.0)
    current_stage: UniversalPipelineStage
    stage_description: str = Field(default="")
    created_at: str
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    error_message: Optional[str] = None
    result_reference: Optional[str] = None


class UniversalProgressEvent(BaseModel):
    """Server-Sent Event (SSE) progress payload."""

    model_config = ConfigDict(frozen=True)

    task_id: str
    stage: UniversalPipelineStage
    progress_percent: float
    description: str
    timestamp: str = Field(default_factory=utcnow_iso)


class UniversalAssuranceResultResponse(BaseModel):
    """Complete, immutable result schema for a Universal Assurance evaluation."""

    model_config = ConfigDict(frozen=True)

    task_id: str
    project_id: str
    status: UniversalTaskStatus
    schema_version: str = Field(default=UniversalAPISchemaVersion.V1_0.value)
    decision: str
    project_risk_score: float = Field(..., ge=0.0, le=1.0)
    project_risk_level: str
    peak_asset_id: Optional[str] = None
    peak_asset_risk: float = Field(..., ge=0.0, le=1.0)
    asset_count: int = Field(default=0, ge=0)
    chain_count: int = Field(default=0, ge=0)
    proof_override_triggered: bool = False
    escalation_reason: Optional[str] = None
    hierarchical_hash: str = Field(default="", max_length=64)
    asset_assessments: List[Dict[str, Any]] = Field(default_factory=list)
    chain_assessments: List[Dict[str, Any]] = Field(default_factory=list)
    proof_assessments: List[Dict[str, Any]] = Field(default_factory=list)
    created_at_utc: str = Field(default_factory=utcnow_iso)


class UniversalCapabilitiesResponse(BaseModel):
    """Capabilities and configuration limits of the Universal Risk Engine."""

    model_config = ConfigDict(frozen=True)

    service_name: str = "AIVARA Universal Assurance Engine"
    schema_version: str = UniversalAPISchemaVersion.V1_0.value
    supported_subsystems: List[str] = Field(
        default_factory=lambda: [
            "DATASET_INTEGRITY",
            "CONTRIBUTOR_RISK",
            "MODEL_INTEGRITY",
            "BEHAVIORAL_ANALYSIS",
            "BACKDOOR_TRIGGER",
            "INFERENCE_INTEGRITY",
            "DISTRIBUTION_SHIFT",
        ]
    )
    supported_asset_roles: List[str] = Field(
        default_factory=lambda: ["CORE_DEPLOYED", "SUPPORTING_INPUT", "PERIPHERAL_SAMPLE"]
    )
    max_assets_per_request: int = 500
    max_edges_per_request: int = 2000
    max_evidence_per_request: int = 5000
    max_chain_depth: int = 5
    concurrency_limit: int = 4
