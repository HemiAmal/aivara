"""Pydantic V2 immutable schemas and contracts for Hierarchical Risk Aggregation (Phase 12.4)."""

from __future__ import annotations

import math
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from aivara.domain.schemas import Severity
from aivara.universal.enums import SubsystemDomain
from aivara.universal.hashing import (
    compute_canonical_jcs_bytes,
    compute_sha256_digest,
    validate_finite_numerical_data,
)
from aivara.universal.risk.enums import (
    AggregationSchemaVersion,
    AggregationStage,
    EvidenceSufficiencyStatus,
    RiskLevel,
)
from aivara.universal.risk.exceptions import NonFiniteRiskError, RiskOutOfRangeError


def utcnow_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def compute_risk_level(risk: float) -> RiskLevel:
    if risk >= 0.85:
        return RiskLevel.CRITICAL
    elif risk >= 0.65:
        return RiskLevel.HIGH
    elif risk >= 0.30:
        return RiskLevel.MEDIUM
    elif risk > 0.0:
        return RiskLevel.LOW
    return RiskLevel.NONE


class RiskContribution(BaseModel):
    """Immutable trace record capturing a specific finding or evidence item's contribution."""
    model_config = ConfigDict(frozen=True)

    contribution_id: str = Field(..., min_length=1, max_length=128)
    stage: AggregationStage
    source_id: str = Field(..., min_length=1, max_length=128)
    target_id: str = Field(..., min_length=1, max_length=128)
    domain: Optional[SubsystemDomain] = None
    severity: Optional[Severity] = None
    confidence: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    raw_score: float = Field(..., ge=0.0, le=1.0)
    effective_score: float = Field(..., ge=0.0, le=1.0)
    ancestry_cluster_id: Optional[str] = None
    ancestry_status: EvidenceSufficiencyStatus = Field(default=EvidenceSufficiencyStatus.SUFFICIENT)
    provenance_hashes: List[str] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)
    contribution_hash: str = Field(default="", max_length=64)

    @field_validator("raw_score", "effective_score")
    @classmethod
    def validate_finite_scores(cls, v: float, info) -> float:
        if math.isnan(v) or math.isinf(v):
            raise NonFiniteRiskError(f"Contribution score '{info.field_name}' must be finite, got {v}")
        if v < 0.0 or v > 1.0:
            raise RiskOutOfRangeError(f"Contribution score '{info.field_name}' must be in [0.0, 1.0], got {v}")
        return float(v)

    @field_validator("metadata")
    @classmethod
    def validate_metadata(cls, v: Dict[str, Any]) -> Dict[str, Any]:
        validate_finite_numerical_data(v)
        return v

    @model_validator(mode="after")
    def compute_contribution_hash(self) -> RiskContribution:
        if not self.contribution_hash:
            canonical_dict = self.to_canonical_dict()
            computed = compute_sha256_digest(compute_canonical_jcs_bytes(canonical_dict))
            object.__setattr__(self, "contribution_hash", computed)
        return self

    def to_canonical_dict(self) -> Dict[str, Any]:
        return {
            "ancestry_cluster_id": self.ancestry_cluster_id,
            "ancestry_status": self.ancestry_status.value,
            "confidence": float(self.confidence) if self.confidence is not None else None,
            "contribution_id": self.contribution_id,
            "domain": self.domain.value if self.domain else None,
            "effective_score": float(self.effective_score),
            "provenance_hashes": sorted(self.provenance_hashes),
            "raw_score": float(self.raw_score),
            "severity": self.severity.value if self.severity else None,
            "source_id": self.source_id,
            "stage": self.stage.value,
            "target_id": self.target_id,
        }


class AssetRiskAssessment(BaseModel):
    """Immutable Tier-1 risk quantification for a specific asset A."""
    model_config = ConfigDict(frozen=True)

    project_id: str = Field(..., min_length=1, max_length=128)
    asset_id: str = Field(..., min_length=1, max_length=128)
    asset_type: str = Field(default="asset", min_length=1, max_length=64)
    risk_score: float = Field(..., ge=0.0, le=1.0)
    risk_level: RiskLevel
    evidence_sufficiency: EvidenceSufficiencyStatus = Field(default=EvidenceSufficiencyStatus.SUFFICIENT)
    finding_count: int = Field(default=0, ge=0)
    evidence_count: int = Field(default=0, ge=0)
    cluster_count: int = Field(default=0, ge=0)
    contributions: List[RiskContribution] = Field(default_factory=list)
    assessment_hash: str = Field(default="", max_length=64)

    @field_validator("risk_score")
    @classmethod
    def validate_risk(cls, v: float) -> float:
        if math.isnan(v) or math.isinf(v):
            raise NonFiniteRiskError(f"Asset risk score must be a finite float, got {v}")
        if v < 0.0 or v > 1.0:
            raise RiskOutOfRangeError(f"Asset risk score must be in [0.0, 1.0], got {v}")
        return float(v)

    @model_validator(mode="after")
    def compute_assessment_hash(self) -> AssetRiskAssessment:
        if not self.assessment_hash:
            canonical_dict = self.to_canonical_dict()
            computed = compute_sha256_digest(compute_canonical_jcs_bytes(canonical_dict))
            object.__setattr__(self, "assessment_hash", computed)
        return self

    def to_canonical_dict(self) -> Dict[str, Any]:
        return {
            "asset_id": self.asset_id,
            "asset_type": self.asset_type,
            "cluster_count": self.cluster_count,
            "contribution_hashes": [c.contribution_hash for c in sorted(self.contributions, key=lambda x: x.contribution_id)],
            "evidence_count": self.evidence_count,
            "evidence_sufficiency": self.evidence_sufficiency.value,
            "finding_count": self.finding_count,
            "project_id": self.project_id,
            "risk_level": self.risk_level.value,
            "risk_score": float(self.risk_score),
        }


class ChainRiskAssessment(BaseModel):
    """Immutable Tier-2 compounding lineage risk between two linked assets."""
    model_config = ConfigDict(frozen=True)

    project_id: str = Field(..., min_length=1, max_length=128)
    source_asset_id: str = Field(..., min_length=1, max_length=128)
    target_asset_id: str = Field(..., min_length=1, max_length=128)
    source_risk: float = Field(..., ge=0.0, le=1.0)
    target_risk: float = Field(..., ge=0.0, le=1.0)
    chain_risk_score: float = Field(..., ge=0.0, le=1.0)
    propagation_factor: float = Field(default=0.25, ge=0.0, le=0.50)
    chain_hash: str = Field(default="", max_length=64)

    @field_validator("source_risk", "target_risk", "chain_risk_score")
    @classmethod
    def validate_chain_scores(cls, v: float, info) -> float:
        if math.isnan(v) or math.isinf(v):
            raise NonFiniteRiskError(f"Chain score '{info.field_name}' must be finite, got {v}")
        if v < 0.0 or v > 1.0:
            raise RiskOutOfRangeError(f"Chain score '{info.field_name}' must be in [0.0, 1.0], got {v}")
        return float(v)

    @model_validator(mode="after")
    def compute_chain_hash(self) -> ChainRiskAssessment:
        if not self.chain_hash:
            canonical_dict = self.to_canonical_dict()
            computed = compute_sha256_digest(compute_canonical_jcs_bytes(canonical_dict))
            object.__setattr__(self, "chain_hash", computed)
        return self

    def to_canonical_dict(self) -> Dict[str, Any]:
        return {
            "chain_risk_score": float(self.chain_risk_score),
            "project_id": self.project_id,
            "propagation_factor": float(self.propagation_factor),
            "source_asset_id": self.source_asset_id,
            "source_risk": float(self.source_risk),
            "target_asset_id": self.target_asset_id,
            "target_risk": float(self.target_risk),
        }


class ProjectRiskAssessment(BaseModel):
    """Immutable Tier-3 overall project operational risk evaluation."""
    model_config = ConfigDict(frozen=True)

    project_id: str = Field(..., min_length=1, max_length=128)
    project_risk_score: float = Field(..., ge=0.0, le=1.0)
    risk_level: RiskLevel
    peak_asset_risk: float = Field(..., ge=0.0, le=1.0)
    peak_asset_id: Optional[str] = None
    asset_count: int = Field(default=0, ge=0)
    chain_count: int = Field(default=0, ge=0)
    assessment_hash: str = Field(default="", max_length=64)

    @field_validator("project_risk_score", "peak_asset_risk")
    @classmethod
    def validate_project_scores(cls, v: float, info) -> float:
        if math.isnan(v) or math.isinf(v):
            raise NonFiniteRiskError(f"Project score '{info.field_name}' must be finite, got {v}")
        if v < 0.0 or v > 1.0:
            raise RiskOutOfRangeError(f"Project score '{info.field_name}' must be in [0.0, 1.0], got {v}")
        return float(v)

    @model_validator(mode="after")
    def compute_assessment_hash(self) -> ProjectRiskAssessment:
        if not self.assessment_hash:
            canonical_dict = self.to_canonical_dict()
            computed = compute_sha256_digest(compute_canonical_jcs_bytes(canonical_dict))
            object.__setattr__(self, "assessment_hash", computed)
        return self

    def to_canonical_dict(self) -> Dict[str, Any]:
        return {
            "asset_count": self.asset_count,
            "chain_count": self.chain_count,
            "peak_asset_id": self.peak_asset_id,
            "peak_asset_risk": float(self.peak_asset_risk),
            "project_id": self.project_id,
            "project_risk_score": float(self.project_risk_score),
            "risk_level": self.risk_level.value,
        }


class HierarchicalRiskAssessment(BaseModel):
    """Immutable complete hierarchical multi-asset risk synthesis result."""
    model_config = ConfigDict(frozen=True)

    schema_version: str = Field(default=AggregationSchemaVersion.V1_0.value)
    project_id: str = Field(..., min_length=1, max_length=128)
    graph_hash: str = Field(..., min_length=64, max_length=64)
    config_hash: str = Field(..., min_length=64, max_length=64)
    project_assessment: ProjectRiskAssessment
    asset_assessments: List[AssetRiskAssessment] = Field(default_factory=list)
    chain_assessments: List[ChainRiskAssessment] = Field(default_factory=list)
    evidence_sufficiency: EvidenceSufficiencyStatus = Field(default=EvidenceSufficiencyStatus.SUFFICIENT)
    total_contributions: int = Field(default=0, ge=0)
    hierarchical_hash: str = Field(default="", max_length=64)
    created_at_utc: str = Field(default_factory=utcnow_iso)

    @model_validator(mode="after")
    def compute_hierarchical_hash(self) -> HierarchicalRiskAssessment:
        if not self.hierarchical_hash:
            canonical_summary = {
                "asset_assessment_hashes": [a.assessment_hash for a in sorted(self.asset_assessments, key=lambda x: x.asset_id)],
                "chain_assessment_hashes": [c.chain_hash for c in sorted(self.chain_assessments, key=lambda x: (x.source_asset_id, x.target_asset_id))],
                "config_hash": self.config_hash,
                "evidence_sufficiency": self.evidence_sufficiency.value,
                "graph_hash": self.graph_hash,
                "project_assessment_hash": self.project_assessment.assessment_hash,
                "project_id": self.project_id,
                "schema_version": self.schema_version,
                "total_contributions": self.total_contributions,
            }
            computed = compute_sha256_digest(compute_canonical_jcs_bytes(canonical_summary))
            object.__setattr__(self, "hierarchical_hash", computed)
        return self
