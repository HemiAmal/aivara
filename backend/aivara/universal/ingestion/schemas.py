"""Immutable Pydantic V2 schemas and contracts for Cross-Subsystem Evidence Ingestion (Phase 12.4)."""

from __future__ import annotations

import math
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Union
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from aivara.domain.schemas import EvidenceLayer, Severity
from aivara.universal.enums import AncestryStatus, SubsystemDomain
from aivara.universal.hashing import (
    compute_canonical_jcs_bytes,
    compute_sha256_digest,
    validate_finite_numerical_data,
)
from aivara.universal.schemas import AncestryPath
from aivara.universal.ingestion.enums import (
    IngestionErrorType,
    IngestionSchemaVersion,
    IngestionStatus,
)


def utcnow_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


class UpstreamEvidenceItem(BaseModel):
    """Input envelope for raw upstream evidence or finding."""
    model_config = ConfigDict(frozen=True)

    project_id: str = Field(..., min_length=1, max_length=128)
    domain: SubsystemDomain
    evidence_id: Optional[str] = Field(default=None, max_length=128)
    finding_id: Optional[str] = Field(default=None, max_length=128)
    evidence_type: str = Field(default="generic_evidence", max_length=128)
    evidence_layer: EvidenceLayer = Field(default=EvidenceLayer.DETECTION)
    severity: Severity = Field(default=Severity.INFO)
    confidence: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    asset_id: Optional[str] = Field(default=None, max_length=128)
    asset_type: str = Field(default="asset", max_length=64)
    ancestry: Optional[Dict[str, Any]] = None
    data_json: Dict[str, Any] = Field(default_factory=dict)
    source_payload_hash: Optional[str] = Field(default=None, max_length=64)
    provenance_hash: Optional[str] = Field(default=None, max_length=64)

    @field_validator("data_json")
    @classmethod
    def validate_data_finite(cls, v: Dict[str, Any]) -> Dict[str, Any]:
        validate_finite_numerical_data(v)
        return v


class EvidenceIngestionRecord(BaseModel):
    """Immutable trace record for an ingested evidence item."""
    model_config = ConfigDict(frozen=True)

    ingestion_record_id: str = Field(..., min_length=1, max_length=128)
    project_id: str = Field(..., min_length=1, max_length=128)
    source_domain: SubsystemDomain
    source_evidence_id: str = Field(..., min_length=1, max_length=128)
    source_finding_id: Optional[str] = Field(default=None, max_length=128)
    source_payload_hash: str = Field(..., min_length=64, max_length=64)
    normalized_evidence_id: str = Field(..., min_length=1, max_length=128)
    canonical_hash: str = Field(..., min_length=64, max_length=64)
    asset_id: str = Field(..., min_length=1, max_length=128)
    asset_type: str = Field(default="asset", max_length=64)
    evidence_layer: EvidenceLayer
    severity: Severity
    confidence: float = Field(..., ge=0.0, le=1.0)
    ancestry_path: Optional[AncestryPath] = None
    ancestry_status: AncestryStatus = Field(default=AncestryStatus.VERIFIED)
    status: IngestionStatus = Field(default=IngestionStatus.INGESTED)
    error_type: Optional[IngestionErrorType] = None
    error_message: Optional[str] = None
    bound_to_graph: bool = Field(default=False)
    ingestion_hash: str = Field(default="", max_length=64)

    @model_validator(mode="after")
    def compute_ingestion_hash(self) -> EvidenceIngestionRecord:
        if not self.ingestion_hash:
            canonical_dict = self.to_canonical_dict()
            computed = compute_sha256_digest(compute_canonical_jcs_bytes(canonical_dict))
            object.__setattr__(self, "ingestion_hash", computed)
        return self

    def to_canonical_dict(self) -> Dict[str, Any]:
        return {
            "asset_id": self.asset_id,
            "asset_type": self.asset_type,
            "bound_to_graph": self.bound_to_graph,
            "canonical_hash": self.canonical_hash,
            "confidence": float(self.confidence),
            "evidence_layer": self.evidence_layer.value,
            "ingestion_record_id": self.ingestion_record_id,
            "normalized_evidence_id": self.normalized_evidence_id,
            "project_id": self.project_id,
            "severity": self.severity.value,
            "source_domain": self.source_domain.value,
            "source_evidence_id": self.source_evidence_id,
            "source_finding_id": self.source_finding_id,
            "source_payload_hash": self.source_payload_hash,
            "status": self.status.value,
        }


class IngestionReport(BaseModel):
    """Immutable batch ingestion execution summary."""
    model_config = ConfigDict(frozen=True)

    schema_version: str = Field(default=IngestionSchemaVersion.V1_0.value)
    project_id: str = Field(..., min_length=1, max_length=128)
    total_items: int = Field(default=0, ge=0)
    ingested_count: int = Field(default=0, ge=0)
    duplicate_count: int = Field(default=0, ge=0)
    rejected_count: int = Field(default=0, ge=0)
    records: List[EvidenceIngestionRecord] = Field(default_factory=list)
    graph_merkle_root: Optional[str] = Field(default=None, max_length=64)
    ingestion_report_hash: str = Field(default="", max_length=64)
    created_at_utc: str = Field(default_factory=utcnow_iso)

    @model_validator(mode="after")
    def compute_report_hash(self) -> IngestionReport:
        if not self.ingestion_report_hash:
            canonical_summary = {
                "duplicate_count": self.duplicate_count,
                "graph_merkle_root": self.graph_merkle_root,
                "ingested_count": self.ingested_count,
                "project_id": self.project_id,
                "record_hashes": [r.ingestion_hash for r in sorted(self.records, key=lambda x: x.ingestion_record_id)],
                "rejected_count": self.rejected_count,
                "schema_version": self.schema_version,
                "total_items": self.total_items,
            }
            computed = compute_sha256_digest(compute_canonical_jcs_bytes(canonical_summary))
            object.__setattr__(self, "ingestion_report_hash", computed)
        return self
