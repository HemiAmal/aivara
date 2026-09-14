"""Pydantic V2 immutable schemas and contracts for Universal Proof & Provenance Integration (Phase 12.8)."""

from __future__ import annotations

import math
import uuid
from datetime import datetime, timezone
from decimal import Decimal, ROUND_HALF_UP
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from aivara.domain.schemas import EvidenceLayer
from aivara.universal.enums import SubsystemDomain
from aivara.universal.hashing import validate_finite_numerical_data
from aivara.universal.policy.enums import UniversalDecision
from aivara.universal.proof.enums import (
    ProofCheckType,
    ProofSchemaVersion,
    ProofVerificationStatus,
)
from aivara.universal.proof.exceptions import (
    ProofError,
    ProofResourceLimitExceededError,
)
from aivara.universal.proof.hashing import (
    compute_proof_assessment_hash,
    compute_proof_result_hash,
)
from aivara.universal.schemas import AncestryPath

# Global Resource Ceilings (Phase 12.1 / 12.8)
MAX_EVIDENCE_PROOFS = 5000
MAX_PROVENANCE_RECORDS = 5000


def utcnow_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def round_decimal_6(val: float) -> float:
    """Deterministic rounding to 6 decimal places."""
    d = Decimal(str(val)).quantize(Decimal("0.000001"), rounding=ROUND_HALF_UP)
    return float(d)


class ProofVerificationCheck(BaseModel):
    """Immutable diagnostic record of an individual cryptographic check."""
    model_config = ConfigDict(frozen=True)

    check_type: ProofCheckType
    passed: bool
    message: str = Field(default="", max_length=512)
    details: Dict[str, Any] = Field(default_factory=dict)

    def to_canonical_dict(self) -> Dict[str, Any]:
        return {
            "check_type": self.check_type.value,
            "message": self.message,
            "passed": self.passed,
        }


class ProofVerificationResult(BaseModel):
    """Authoritative, immutable cryptographic verification outcome for a single evidence item."""
    model_config = ConfigDict(frozen=True)

    schema_version: str = Field(default=ProofSchemaVersion.V1_0.value)
    evidence_id: str = Field(..., min_length=1, max_length=128)
    evidence_hash: str = Field(..., min_length=64, max_length=64)
    evidence_layer: EvidenceLayer
    proof_status: ProofVerificationStatus
    provenance_id: Optional[str] = Field(default=None, max_length=128)
    provenance_record_hash: Optional[str] = Field(default=None, max_length=64)
    finding_id: Optional[str] = Field(default=None, max_length=128)
    domain: Optional[SubsystemDomain] = None
    project_id: str = Field(..., min_length=1, max_length=128)
    asset_id: str = Field(..., min_length=1, max_length=128)
    ancestry_path: Optional[AncestryPath] = None
    checks: List[ProofVerificationCheck] = Field(default_factory=list)
    failure_reason: Optional[str] = Field(default=None, max_length=512)
    proof_confidence: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    detection_confidence: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    proof_result_hash: str = Field(default="", max_length=64)
    created_at_utc: str = Field(default_factory=utcnow_iso)

    @field_validator("proof_confidence", "detection_confidence")
    @classmethod
    def validate_finite_confidences(cls, v: Optional[float]) -> Optional[float]:
        if v is None:
            return None
        if math.isnan(v) or math.isinf(v):
            raise ProofError(f"Confidence value must be finite, got {v}")
        return round_decimal_6(v)

    @model_validator(mode="after")
    def validate_proof_confidence_invariants_and_hash(self) -> ProofVerificationResult:
        # INVARIANT: Only VERIFIED status receives proof_confidence == 1.0
        if self.proof_status == ProofVerificationStatus.VERIFIED:
            if self.proof_confidence != 1.0:
                object.__setattr__(self, "proof_confidence", 1.0)
        else:
            # Non-verified proof must never claim 1.0 confidence
            if self.proof_confidence == 1.0:
                object.__setattr__(self, "proof_confidence", 0.0)

        # Compute proof_result_hash if empty
        if not self.proof_result_hash:
            canonical_dict = self.to_canonical_dict()
            computed = compute_proof_result_hash(canonical_dict)
            object.__setattr__(self, "proof_result_hash", computed)

        return self

    def to_canonical_dict(self) -> Dict[str, Any]:
        return {
            "ancestry_path": self.ancestry_path.to_canonical_dict() if self.ancestry_path else None,
            "asset_id": self.asset_id,
            "checks": [c.to_canonical_dict() for c in sorted(self.checks, key=lambda x: x.check_type.value)],
            "detection_confidence": float(self.detection_confidence) if self.detection_confidence is not None else None,
            "domain": self.domain.value if self.domain else None,
            "evidence_hash": self.evidence_hash,
            "evidence_id": self.evidence_id,
            "evidence_layer": self.evidence_layer.value,
            "failure_reason": self.failure_reason,
            "finding_id": self.finding_id,
            "project_id": self.project_id,
            "proof_confidence": float(self.proof_confidence) if self.proof_confidence is not None else None,
            "proof_status": self.proof_status.value,
            "provenance_id": self.provenance_id,
            "provenance_record_hash": self.provenance_record_hash,
            "schema_version": self.schema_version,
        }


class UniversalProofAssessment(BaseModel):
    """Aggregated, authoritative proof assessment across all evaluated evidence for an asset/project."""
    model_config = ConfigDict(frozen=True)

    schema_version: str = Field(default=ProofSchemaVersion.V1_0.value)
    assessment_id: str = Field(default_factory=lambda: f"prf_ass_{uuid.uuid4().hex[:16]}")
    project_id: str = Field(..., min_length=1, max_length=128)
    asset_id: str = Field(..., min_length=1, max_length=128)
    overall_proof_status: ProofVerificationStatus
    total_evidence_evaluated: int = Field(default=0, ge=0)
    verified_count: int = Field(default=0, ge=0)
    invalid_count: int = Field(default=0, ge=0)
    missing_count: int = Field(default=0, ge=0)
    unavailable_count: int = Field(default=0, ge=0)
    tampered_count: int = Field(default=0, ge=0)
    replay_count: int = Field(default=0, ge=0)
    proof_override_required: bool = Field(default=False)
    override_decision: Optional[UniversalDecision] = None
    evidence_results: List[ProofVerificationResult] = Field(default_factory=list)
    assessment_hash: str = Field(default="", max_length=64)
    created_at_utc: str = Field(default_factory=utcnow_iso)

    @field_validator("evidence_results")
    @classmethod
    def validate_evidence_results_limit(cls, v: List[ProofVerificationResult]) -> List[ProofVerificationResult]:
        if len(v) > MAX_EVIDENCE_PROOFS:
            raise ProofResourceLimitExceededError(
                f"Evidence proof results count ({len(v)}) exceeds maximum limit of {MAX_EVIDENCE_PROOFS}"
            )
        return v

    @model_validator(mode="after")
    def compute_assessment_hash_post(self) -> UniversalProofAssessment:
        if not self.assessment_hash:
            canonical_dict = self.to_canonical_dict()
            computed = compute_proof_assessment_hash(canonical_dict)
            object.__setattr__(self, "assessment_hash", computed)
        return self

    def to_canonical_dict(self) -> Dict[str, Any]:
        return {
            "asset_id": self.asset_id,
            "evidence_result_hashes": [
                r.proof_result_hash for r in sorted(self.evidence_results, key=lambda x: x.evidence_id)
            ],
            "invalid_count": self.invalid_count,
            "missing_count": self.missing_count,
            "overall_proof_status": self.overall_proof_status.value,
            "override_decision": self.override_decision.value if self.override_decision else None,
            "project_id": self.project_id,
            "proof_override_required": self.proof_override_required,
            "replay_count": self.replay_count,
            "schema_version": self.schema_version,
            "tampered_count": self.tampered_count,
            "total_evidence_evaluated": self.total_evidence_evaluated,
            "unavailable_count": self.unavailable_count,
            "verified_count": self.verified_count,
        }
