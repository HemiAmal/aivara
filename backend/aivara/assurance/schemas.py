"""Immutable domain schemas for Multi-Modal Risk Integration Engine (Phase 11.9).

Adheres to ADR-028, ADR-102, and core AIVARA invariants:
1. Proof Layer (Confidence == 1.0) is non-compensable and strictly isolated from Detection metrics.
2. Multi-modal evidence sharing asset ancestry is cluster-damped to prevent double counting.
3. Risk scores represent Normalized Operational Exposure Indices, NOT probabilities of attack.
4. All canonical structures serialize to RFC 8785 JCS for SHA-256 content addressing.
"""

from __future__ import annotations

import math
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from aivara.assurance.enums import (
    DependencyRelation,
    EvidenceCategory,
    IntegrationEvaluationStatus,
)
from aivara.domain.schemas import Disposition, EvidenceLayer, Severity


# Default category severity weights for risk aggregation
DEFAULT_CATEGORY_WEIGHTS: Dict[str, float] = {
    EvidenceCategory.CRYPTOGRAPHIC_PROOF.value: 1.00,
    EvidenceCategory.DATASET_INTEGRITY.value: 0.70,
    EvidenceCategory.MODEL_INTEGRITY.value: 0.85,
    EvidenceCategory.INFERENCE_INTEGRITY.value: 0.90,
    EvidenceCategory.BEHAVIORAL_ANOMALY.value: 0.65,
    EvidenceCategory.TRIGGER_ACTIVATION.value: 0.80,
    EvidenceCategory.CONTRIBUTOR_RISK.value: 0.50,
    EvidenceCategory.DISTRIBUTION_SHIFT.value: 0.60,
    EvidenceCategory.UNCLASSIFIED.value: 0.30,
}


def _validate_finite_float(val: Optional[float], name: str) -> Optional[float]:
    if val is not None:
        if math.isnan(val) or math.isinf(val):
            raise ValueError(f"Field '{name}' must be a finite float, got {val}")
    return val


class EvidenceReference(BaseModel):
    """Lightweight, content-addressed reference to an upstream evidence record."""
    model_config = ConfigDict(frozen=True)

    evidence_id: str = Field(..., min_length=1, max_length=64)
    project_id: str = Field(..., min_length=1, max_length=64)
    evidence_layer: EvidenceLayer
    evidence_type: str = Field(..., min_length=1, max_length=100)
    evidence_category: EvidenceCategory = Field(default=EvidenceCategory.DISTRIBUTION_SHIFT)
    title: str = Field(..., min_length=1, max_length=500)
    description: Optional[str] = None
    confidence: float = Field(..., ge=0.0, le=1.0)
    severity: Severity = Field(default=Severity.INFO)
    target_asset_type: str = Field(default="dataset", max_length=50)
    target_asset_id: str = Field(default="unknown", max_length=64)
    ancestry_keys: Dict[str, str] = Field(default_factory=dict)
    evidence_hash: str = Field(..., min_length=64, max_length=64)
    data_json: Dict[str, Any] = Field(default_factory=dict)

    @field_validator("confidence")
    @classmethod
    def validate_confidence(cls, v: float) -> float:
        _validate_finite_float(v, "confidence")
        return v

    @model_validator(mode="after")
    def validate_proof_confidence(self) -> EvidenceReference:
        if self.evidence_layer == EvidenceLayer.PROOF and self.confidence != 1.0:
            raise ValueError("Proof-layer evidence must have confidence = 1.0")
        return self

    def to_canonical_dict(self) -> Dict[str, Any]:
        """Convert to strictly sorted dictionary for RFC 8785 JCS hashing."""
        return {
            "ancestry_keys": {k: str(v) for k, v in sorted(self.ancestry_keys.items())},
            "confidence": float(self.confidence),
            "evidence_category": self.evidence_category.value,
            "evidence_hash": self.evidence_hash,
            "evidence_id": self.evidence_id,
            "evidence_layer": self.evidence_layer.value,
            "evidence_type": self.evidence_type,
            "project_id": self.project_id,
            "severity": self.severity.value,
            "target_asset_id": self.target_asset_id,
            "target_asset_type": self.target_asset_type,
            "title": self.title,
        }


class ModalityCluster(BaseModel):
    """Cluster of evidence items sharing primary asset ancestry to prevent double counting."""
    model_config = ConfigDict(frozen=True)

    cluster_id: str = Field(..., min_length=1, max_length=64)
    primary_asset_type: str = Field(..., max_length=50)
    primary_asset_id: str = Field(..., max_length=64)
    evidence_category: EvidenceCategory
    evidence_ids: List[str] = Field(default_factory=list)
    max_confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    max_severity_weight: float = Field(default=0.0, ge=0.0, le=1.0)
    cluster_score: float = Field(default=0.0, ge=0.0, le=1.0)

    def to_canonical_dict(self) -> Dict[str, Any]:
        return {
            "cluster_id": self.cluster_id,
            "cluster_score": float(self.cluster_score),
            "evidence_category": self.evidence_category.value,
            "evidence_ids": sorted(self.evidence_ids),
            "max_confidence": float(self.max_confidence),
            "max_severity_weight": float(self.max_severity_weight),
            "primary_asset_id": self.primary_asset_id,
            "primary_asset_type": self.primary_asset_type,
        }


class RiskPolicy(BaseModel):
    """Configurable, versioned risk weighting and damping policy (ADR-102)."""
    model_config = ConfigDict(frozen=True)

    schema_version: str = Field(default="1.0", max_length=20)
    policy_version: str = Field(default="1.0", max_length=50)
    policy_name: str = Field(default="default_risk_policy", max_length=100)
    correlation_damping_factor: float = Field(default=0.10, ge=0.0, le=0.50)
    category_weights: Dict[str, float] = Field(default_factory=lambda: dict(DEFAULT_CATEGORY_WEIGHTS))
    risk_policy_hash: str = Field(default="", max_length=64)

    @field_validator("correlation_damping_factor")
    @classmethod
    def validate_damping(cls, v: float) -> float:
        _validate_finite_float(v, "correlation_damping_factor")
        return v

    def to_canonical_dict(self) -> Dict[str, Any]:
        return {
            "category_weights": {k: float(v) for k, v in sorted(self.category_weights.items())},
            "correlation_damping_factor": float(self.correlation_damping_factor),
            "policy_name": self.policy_name,
            "policy_version": self.policy_version,
            "schema_version": self.schema_version,
        }


class DecisionPolicy(BaseModel):
    """Configurable, versioned policy disposition thresholds and dispatch rules (ADR-102)."""
    model_config = ConfigDict(frozen=True)

    schema_version: str = Field(default="1.0", max_length=20)
    policy_version: str = Field(default="1.0", max_length=50)
    policy_name: str = Field(default="default_decision_policy", max_length=100)
    review_threshold: float = Field(default=0.30, ge=0.0, le=1.0)
    quarantine_threshold: float = Field(default=0.65, ge=0.0, le=1.0)
    reject_threshold: float = Field(default=0.85, ge=0.0, le=1.0)
    proof_rejection_mandatory: bool = Field(default=True)
    insufficient_evidence_action: Disposition = Field(default=Disposition.REVIEW)
    decision_policy_hash: str = Field(default="", max_length=64)

    @model_validator(mode="after")
    def validate_threshold_order(self) -> DecisionPolicy:
        if not (self.review_threshold <= self.quarantine_threshold <= self.reject_threshold):
            raise ValueError(
                f"Decision thresholds must satisfy review ({self.review_threshold}) <= "
                f"quarantine ({self.quarantine_threshold}) <= reject ({self.reject_threshold})"
            )
        return self

    def to_canonical_dict(self) -> Dict[str, Any]:
        return {
            "insufficient_evidence_action": self.insufficient_evidence_action.value,
            "policy_name": self.policy_name,
            "policy_version": self.policy_version,
            "proof_rejection_mandatory": self.proof_rejection_mandatory,
            "quarantine_threshold": float(self.quarantine_threshold),
            "reject_threshold": float(self.reject_threshold),
            "review_threshold": float(self.review_threshold),
            "schema_version": self.schema_version,
        }


class SynthesizedFinding(BaseModel):
    """Normalized representation of a synthesized multi-modal finding."""
    model_config = ConfigDict(frozen=True)

    finding_id: str = Field(..., min_length=1, max_length=64)
    finding_type: str = Field(..., min_length=1, max_length=100)
    title: str = Field(..., min_length=1, max_length=500)
    description: str = Field(..., min_length=1)
    evidence_layer: EvidenceLayer = Field(default=EvidenceLayer.DETECTION)
    severity: Severity = Field(default=Severity.MEDIUM)
    confidence: float = Field(..., ge=0.0, le=1.0)
    disposition: Disposition = Field(default=Disposition.REVIEW)
    affected_asset_type: str = Field(default="dataset", max_length=50)
    affected_asset_id: str = Field(default="unknown", max_length=64)
    linked_evidence_ids: List[str] = Field(default_factory=list)

    def to_canonical_dict(self) -> Dict[str, Any]:
        return {
            "affected_asset_id": self.affected_asset_id,
            "affected_asset_type": self.affected_asset_type,
            "confidence": float(self.confidence),
            "description": self.description,
            "disposition": self.disposition.value,
            "evidence_layer": self.evidence_layer.value,
            "finding_id": self.finding_id,
            "finding_type": self.finding_type,
            "linked_evidence_ids": sorted(self.linked_evidence_ids),
            "severity": self.severity.value,
            "title": self.title,
        }


class IntegratedAssuranceProfile(BaseModel):
    """Authoritative, content-addressed multi-modal integrated assurance evaluation profile."""
    model_config = ConfigDict(frozen=True)

    schema_version: str = Field(default="1.0", max_length=20)
    analysis_version: str = Field(default="1.0", max_length=20)
    project_id: str = Field(..., min_length=1, max_length=64)
    target_asset_type: str = Field(..., min_length=1, max_length=50)
    target_asset_id: str = Field(..., min_length=1, max_length=64)
    overall_disposition: Disposition
    overall_risk_score: float = Field(..., ge=0.0, le=1.0)
    risk_level: str = Field(..., min_length=1, max_length=20)
    evaluation_status: IntegrationEvaluationStatus = Field(default=IntegrationEvaluationStatus.EVALUATED)
    proof_violations_count: int = Field(default=0, ge=0)
    detection_findings_count: int = Field(default=0, ge=0)
    evidence_set_hash: str = Field(..., min_length=64, max_length=64)
    risk_policy_hash: str = Field(..., min_length=64, max_length=64)
    decision_policy_hash: str = Field(..., min_length=64, max_length=64)
    integrated_profile_hash: str = Field(..., min_length=64, max_length=64)
    component_scores: Dict[str, float] = Field(default_factory=dict)
    rationale: str = Field(..., min_length=1)
    clusters: List[ModalityCluster] = Field(default_factory=list)
    synthesized_findings: List[SynthesizedFinding] = Field(default_factory=list)
    deduplicated_evidence_count: int = Field(default=0, ge=0)
    limitations: List[str] = Field(default_factory=list)
    metadata_json: Dict[str, Any] = Field(default_factory=dict)

    def to_canonical_dict(self) -> Dict[str, Any]:
        """Convert to strictly sorted canonical dictionary for RFC 8785 JCS hashing."""
        return {
            "analysis_version": self.analysis_version,
            "clusters": [c.to_canonical_dict() for c in self.clusters],
            "component_scores": {k: float(v) for k, v in sorted(self.component_scores.items())},
            "decision_policy_hash": self.decision_policy_hash,
            "deduplicated_evidence_count": int(self.deduplicated_evidence_count),
            "detection_findings_count": int(self.detection_findings_count),
            "evaluation_status": self.evaluation_status.value,
            "evidence_set_hash": self.evidence_set_hash,
            "overall_disposition": self.overall_disposition.value,
            "overall_risk_score": float(self.overall_risk_score),
            "project_id": self.project_id,
            "proof_violations_count": int(self.proof_violations_count),
            "risk_level": self.risk_level,
            "risk_policy_hash": self.risk_policy_hash,
            "schema_version": self.schema_version,
            "synthesized_findings": [f.to_canonical_dict() for f in self.synthesized_findings],
            "target_asset_id": self.target_asset_id,
            "target_asset_type": self.target_asset_type,
        }
