"""Pydantic schemas and domain contracts for Universal Evidence Normalization (Phase 12.2).

Guarantees:
- Strict immutability (frozen ConfigDict).
- Separation of evidence from findings, risk scores, and disposition decisions.
- Deterministic canonical dictionary serialization for RFC 8785 JCS + SHA-256 hashing.
- Explicit proof layer validation (Confidence == 1.0).
- Mandatory finite-float validation.
"""

from __future__ import annotations

import math
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from aivara.domain.schemas import EvidenceLayer, Severity
from aivara.universal.enums import (
    AncestryStatus,
    EnvelopeVersion,
    SchemaVersion,
    SubsystemDomain,
)
from aivara.universal.exceptions import InvalidEvidenceError
from aivara.universal.hashing import (
    compute_envelope_hash,
    compute_payload_hash,
    validate_finite_numerical_data,
)


def utcnow_iso() -> str:
    """Return formatted UTC ISO-8601 timestamp string."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


class AncestryPath(BaseModel):
    """Immutable evidence ancestry vector tracking physical artifact provenance."""
    model_config = ConfigDict(frozen=True)

    sample_id: Optional[str] = Field(default=None, max_length=128)
    dataset_version_id: Optional[str] = Field(default=None, max_length=128)
    model_fingerprint: Optional[str] = Field(default=None, max_length=128)
    window_id: Optional[str] = Field(default=None, max_length=128)
    source_id: Optional[str] = Field(default=None, max_length=128)
    extra_keys: Dict[str, str] = Field(default_factory=dict)

    def is_empty(self) -> bool:
        """Check if all ancestry fields are absent."""
        return not (
            self.sample_id
            or self.dataset_version_id
            or self.model_fingerprint
            or self.window_id
            or self.source_id
            or self.extra_keys
        )

    def to_canonical_dict(self) -> Dict[str, Any]:
        """Produce deterministic sorted dictionary for canonical hashing."""
        d: Dict[str, Any] = {
            "dataset_version_id": self.dataset_version_id or "",
            "extra_keys": {k: str(v) for k, v in sorted(self.extra_keys.items())},
            "model_fingerprint": self.model_fingerprint or "",
            "sample_id": self.sample_id or "",
            "source_id": self.source_id or "",
            "window_id": self.window_id or "",
        }
        return d


class UniversalEvidenceEnvelope(BaseModel):
    """Authoritative, content-addressed Universal Evidence Envelope contract."""
    model_config = ConfigDict(frozen=True)

    schema_version: str = Field(default=SchemaVersion.V1_0.value)
    envelope_version: str = Field(default=EnvelopeVersion.V1_0.value)
    evidence_id: str = Field(..., min_length=1, max_length=128)
    project_id: str = Field(..., min_length=1, max_length=128)
    domain: SubsystemDomain
    evidence_type: str = Field(..., min_length=1, max_length=100)
    evidence_layer: EvidenceLayer
    severity: Severity = Field(default=Severity.INFO)
    confidence: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    primary_asset_type: str = Field(default="dataset", max_length=50)
    primary_asset_id: str = Field(default="unknown", max_length=128)
    finding_id: Optional[str] = Field(default=None, max_length=128)
    source_record_id: Optional[str] = Field(default=None, max_length=128)
    source_entity_type: Optional[str] = Field(default=None, max_length=50)
    ancestry_status: AncestryStatus = Field(default=AncestryStatus.VERIFIED)
    ancestry_path: AncestryPath = Field(default_factory=AncestryPath)
    parent_evidence_ids: List[str] = Field(default_factory=list)
    derived_from_evidence_ids: List[str] = Field(default_factory=list)
    source_payload_hash: str = Field(..., min_length=64, max_length=64)
    normalized_payload_hash: str = Field(..., min_length=64, max_length=64)
    provenance_record_ids: List[str] = Field(default_factory=list)
    provenance_hashes: List[str] = Field(default_factory=list)
    data_json: Dict[str, Any] = Field(default_factory=dict)
    metadata_json: Dict[str, Any] = Field(default_factory=dict)
    created_at_utc: str = Field(default_factory=utcnow_iso)
    canonical_hash: str = Field(default="", max_length=64)

    @field_validator("confidence")
    @classmethod
    def validate_confidence_finite(cls, v: Optional[float]) -> Optional[float]:
        if v is None:
            return None
        if math.isnan(v) or math.isinf(v):
            raise InvalidEvidenceError(f"Confidence must be a finite float, got {v}")
        if v < 0.0 or v > 1.0:
            raise InvalidEvidenceError(f"Confidence must be in [0.0, 1.0], got {v}")
        return float(v)

    @field_validator("data_json", "metadata_json")
    @classmethod
    def validate_nested_floats(cls, v: Dict[str, Any]) -> Dict[str, Any]:
        validate_finite_numerical_data(v)
        return v

    @model_validator(mode="after")
    def validate_proof_and_compute_hash(self) -> UniversalEvidenceEnvelope:
        # Proof layer invariant
        if self.evidence_layer == EvidenceLayer.PROOF:
            if self.confidence is not None and self.confidence != 1.0:
                raise InvalidEvidenceError("Proof-layer evidence must have confidence exactly 1.0.")
            if self.confidence is None:
                object.__setattr__(self, "confidence", 1.0)
        
        # Validate provenance hashes format
        for ph in self.provenance_hashes:
            if not isinstance(ph, str) or len(ph) != 64 or not all(c in "0123456789abcdefABCDEF" for c in ph):
                raise InvalidEvidenceError(f"Provenance hash '{ph}' is not a valid 64-character hex SHA-256 digest.")

        # Compute canonical hash if not provided or to verify
        canonical_dict = self.to_canonical_dict()
        computed_hash = compute_envelope_hash(canonical_dict)
        if not self.canonical_hash:
            object.__setattr__(self, "canonical_hash", computed_hash)
        elif self.canonical_hash != computed_hash:
            raise InvalidEvidenceError(
                f"Canonical hash mismatch. Expected {computed_hash}, got {self.canonical_hash}"
            )
        return self

    def to_canonical_dict(self) -> Dict[str, Any]:
        """Produce deterministic sorted dictionary for RFC 8785 JCS canonical hashing."""
        return {
            "ancestry_path": self.ancestry_path.to_canonical_dict(),
            "ancestry_status": self.ancestry_status.value,
            "confidence": float(self.confidence) if self.confidence is not None else None,
            "derived_from_evidence_ids": sorted(self.derived_from_evidence_ids),
            "domain": self.domain.value,
            "envelope_version": self.envelope_version,
            "evidence_id": self.evidence_id,
            "evidence_layer": self.evidence_layer.value,
            "evidence_type": self.evidence_type,
            "finding_id": self.finding_id or "",
            "normalized_payload_hash": self.normalized_payload_hash,
            "parent_evidence_ids": sorted(self.parent_evidence_ids),
            "primary_asset_id": self.primary_asset_id,
            "primary_asset_type": self.primary_asset_type,
            "project_id": self.project_id,
            "provenance_hashes": sorted(self.provenance_hashes),
            "provenance_record_ids": sorted(self.provenance_record_ids),
            "schema_version": self.schema_version,
            "severity": self.severity.value,
            "source_entity_type": self.source_entity_type or "",
            "source_payload_hash": self.source_payload_hash,
            "source_record_id": self.source_record_id or "",
        }


class NormalizationReport(BaseModel):
    """Summary of a universal evidence batch normalization operation."""
    model_config = ConfigDict(frozen=True)

    project_id: str
    total_ingested: int
    total_normalized: int
    total_deduplicated: int
    total_rejected: int
    domain_breakdown: Dict[str, int]
    envelopes: List[UniversalEvidenceEnvelope]
    rejection_reasons: List[Dict[str, Any]] = Field(default_factory=list)
    report_hash: str = Field(default="", max_length=64)

    @model_validator(mode="after")
    def compute_report_hash(self) -> NormalizationReport:
        if not self.report_hash:
            summary_dict = {
                "domain_breakdown": {k: int(v) for k, v in sorted(self.domain_breakdown.items())},
                "envelope_hashes": [e.canonical_hash for e in self.envelopes],
                "project_id": self.project_id,
                "total_deduplicated": self.total_deduplicated,
                "total_ingested": self.total_ingested,
                "total_normalized": self.total_normalized,
                "total_rejected": self.total_rejected,
            }
            computed_hash = compute_payload_hash(summary_dict)
            object.__setattr__(self, "report_hash", computed_hash)
        return self
