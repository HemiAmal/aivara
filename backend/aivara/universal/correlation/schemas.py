"""Immutable schemas and contracts for Cross-Subsystem Correlation & Dependency Damping (Phase 12.5)."""

from __future__ import annotations

import math
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from aivara.universal.enums import SubsystemDomain
from aivara.universal.hashing import (
    compute_canonical_jcs_bytes,
    compute_sha256_digest,
    validate_finite_numerical_data,
)
from aivara.universal.risk.enums import EvidenceSufficiencyStatus
from aivara.universal.risk.exceptions import NonFiniteRiskError, RiskOutOfRangeError
from aivara.universal.correlation.enums import CorrelationSchemaVersion, CorrelationStatus


def utcnow_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


class DomainCorrelationSummary(BaseModel):
    """Analytical summary of single domain's activity, mean severity, and cross-domain attenuation."""
    model_config = ConfigDict(frozen=True)

    domain: SubsystemDomain
    is_active: bool
    finding_count: int = Field(default=0, ge=0)
    evidence_count: int = Field(default=0, ge=0)
    detection_count: int = Field(default=0, ge=0)
    proof_count: int = Field(default=0, ge=0)
    mean_severity: float = Field(default=0.0, ge=0.0, le=1.0)
    attenuation_factor: float = Field(default=1.0, ge=0.0, le=1.0)
    damped_mean_severity: float = Field(default=0.0, ge=0.0, le=1.0)

    @field_validator("mean_severity", "attenuation_factor", "damped_mean_severity")
    @classmethod
    def validate_finite_scores(cls, v: float, info) -> float:
        if math.isnan(v) or math.isinf(v):
            raise NonFiniteRiskError(f"Field '{info.field_name}' must be finite, got {v}")
        if v < 0.0 or v > 1.0:
            raise RiskOutOfRangeError(f"Field '{info.field_name}' must be in [0.0, 1.0], got {v}")
        return round(float(v), 6)

    def to_canonical_dict(self) -> Dict[str, Any]:
        return {
            "attenuation_factor": float(self.attenuation_factor),
            "damped_mean_severity": float(self.damped_mean_severity),
            "detection_count": self.detection_count,
            "domain": self.domain.value,
            "evidence_count": self.evidence_count,
            "finding_count": self.finding_count,
            "is_active": self.is_active,
            "mean_severity": float(self.mean_severity),
            "proof_count": self.proof_count,
        }


class CrossDomainContributionTrace(BaseModel):
    """Explainable trace explaining cross-domain damping between a pair of domains."""
    model_config = ConfigDict(frozen=True)

    target_domain: SubsystemDomain
    source_domain: SubsystemDomain
    correlation_coefficient: float = Field(..., ge=0.0, le=1.0)
    source_mean_severity: float = Field(..., ge=0.0, le=1.0)
    attenuation_multiplier: float = Field(..., ge=0.0, le=1.0)

    @field_validator("correlation_coefficient", "source_mean_severity", "attenuation_multiplier")
    @classmethod
    def validate_finite_trace(cls, v: float, info) -> float:
        if math.isnan(v) or math.isinf(v):
            raise NonFiniteRiskError(f"Trace field '{info.field_name}' must be finite, got {v}")
        if v < 0.0 or v > 1.0:
            raise RiskOutOfRangeError(f"Trace field '{info.field_name}' must be in [0.0, 1.0], got {v}")
        return round(float(v), 6)

    def to_canonical_dict(self) -> Dict[str, Any]:
        return {
            "attenuation_multiplier": float(self.attenuation_multiplier),
            "correlation_coefficient": float(self.correlation_coefficient),
            "source_domain": self.source_domain.value,
            "source_mean_severity": float(self.source_mean_severity),
            "target_domain": self.target_domain.value,
        }


class CrossDomainCorrelationAssessment(BaseModel):
    """Immutable analytical assessment of cross-domain correlation and dependency damping.
    
    Contains quantitative correlation metrics and analytical data quality states.
    Does NOT contain policy dispositions or decision routing.
    """
    model_config = ConfigDict(frozen=True)

    schema_version: str = Field(default=CorrelationSchemaVersion.V1_0.value)
    project_id: str = Field(..., min_length=1, max_length=128)
    matrix_hash: str = Field(..., min_length=64, max_length=64)
    graph_merkle_root: Optional[str] = Field(default=None, max_length=64)
    hierarchical_hash: Optional[str] = Field(default=None, max_length=64)
    status: CorrelationStatus = Field(default=CorrelationStatus.VALID)
    domain_summaries: List[DomainCorrelationSummary] = Field(default_factory=list)
    traces: List[CrossDomainContributionTrace] = Field(default_factory=list)
    overall_attenuation_factor: float = Field(default=1.0, ge=0.0, le=1.0)
    evidence_sufficiency: EvidenceSufficiencyStatus = Field(default=EvidenceSufficiencyStatus.SUFFICIENT)
    correlation_hash: str = Field(default="", max_length=64)
    created_at_utc: str = Field(default_factory=utcnow_iso)

    @field_validator("overall_attenuation_factor")
    @classmethod
    def validate_attenuation(cls, v: float) -> float:
        if math.isnan(v) or math.isinf(v):
            raise NonFiniteRiskError(f"Overall attenuation factor must be finite, got {v}")
        if v < 0.0 or v > 1.0:
            raise RiskOutOfRangeError(f"Overall attenuation factor must be in [0.0, 1.0], got {v}")
        return round(float(v), 6)

    @model_validator(mode="after")
    def compute_correlation_hash(self) -> CrossDomainCorrelationAssessment:
        if not self.correlation_hash:
            canonical_summary = {
                "domain_summaries": [s.to_canonical_dict() for s in sorted(self.domain_summaries, key=lambda x: x.domain.value)],
                "evidence_sufficiency": self.evidence_sufficiency.value,
                "graph_merkle_root": self.graph_merkle_root,
                "hierarchical_hash": self.hierarchical_hash,
                "matrix_hash": self.matrix_hash,
                "overall_attenuation_factor": float(self.overall_attenuation_factor),
                "project_id": self.project_id,
                "schema_version": self.schema_version,
                "status": self.status.value,
                "trace_count": len(self.traces),
            }
            computed = compute_sha256_digest(compute_canonical_jcs_bytes(canonical_summary))
            object.__setattr__(self, "correlation_hash", computed)
        return self
