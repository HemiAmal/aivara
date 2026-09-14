"""Pydantic V2 immutable schemas and contracts for Universal Policy & Decision Engine (Phase 12.7)."""

from __future__ import annotations

import math
import uuid
from datetime import datetime, timezone
from decimal import Decimal, ROUND_HALF_UP
from typing import Any, Dict, List, Optional, Union
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from aivara.universal.hashing import validate_finite_numerical_data
from aivara.universal.policy.enums import (
    PolicyReasonCode,
    PolicySchemaVersion,
    RuleConditionOperator,
    UniversalDecision,
)
from aivara.universal.policy.exceptions import (
    DuplicateRuleIdError,
    InvalidPolicyError,
    PolicyResourceLimitExceededError,
    ThresholdConfigurationError,
    ThresholdGapError,
    ThresholdOverlapError,
)
from aivara.universal.policy.hashing import compute_decision_hash, compute_policy_hash

# Global Resource Governance Limits (Phase 12.1 / 12.7)
MAX_POLICY_RULES = 100
MAX_RULE_ID_LENGTH = 128
MAX_REASON_SUMMARY_LENGTH = 512
MAX_TRACE_RULE_ENTRIES = 100


def utcnow_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def round_decimal_6(val: float) -> float:
    """Deterministic rounding to 6 decimal places."""
    d = Decimal(str(val)).quantize(Decimal("0.000001"), rounding=ROUND_HALF_UP)
    return float(d)


class RiskThresholdBand(BaseModel):
    """Immutable contiguous risk interval mapping a risk score to a baseline decision."""
    model_config = ConfigDict(frozen=True)

    band_name: str = Field(..., min_length=1, max_length=64)
    min_score: float = Field(..., ge=0.0, le=1.0)
    max_score: float = Field(..., ge=0.0, le=1.0)
    decision: UniversalDecision
    reason_code: PolicyReasonCode
    inclusive_min: bool = Field(default=True)
    inclusive_max: bool = Field(default=False)

    @field_validator("min_score", "max_score")
    @classmethod
    def validate_finite_bounds(cls, v: float, info) -> float:
        if math.isnan(v) or math.isinf(v):
            raise ThresholdConfigurationError(f"Threshold bound '{info.field_name}' must be finite, got {v}")
        return round_decimal_6(v)

    @model_validator(mode="after")
    def validate_interval(self) -> RiskThresholdBand:
        if self.min_score > self.max_score:
            raise ThresholdConfigurationError(
                f"Threshold band '{self.band_name}': min_score ({self.min_score}) > max_score ({self.max_score})"
            )
        if self.min_score == self.max_score and not (self.inclusive_min and self.inclusive_max):
            raise ThresholdConfigurationError(
                f"Threshold band '{self.band_name}': zero-width interval must be inclusive on both ends"
            )
        return self

    def contains(self, score: float) -> bool:
        """Evaluate if the given score falls strictly within this band."""
        rounded = round_decimal_6(score)
        min_ok = (rounded >= self.min_score) if self.inclusive_min else (rounded > self.min_score)
        max_ok = (rounded <= self.max_score) if self.inclusive_max else (rounded < self.max_score)
        return min_ok and max_ok

    def to_canonical_dict(self) -> Dict[str, Any]:
        return {
            "band_name": self.band_name,
            "decision": self.decision.value,
            "inclusive_max": self.inclusive_max,
            "inclusive_min": self.inclusive_min,
            "max_score": float(self.max_score),
            "min_score": float(self.min_score),
            "reason_code": self.reason_code.value,
        }


class PolicyRuleCondition(BaseModel):
    """Declarative, safe condition descriptor without arbitrary code execution."""
    model_config = ConfigDict(frozen=True)

    field: str = Field(..., min_length=1, max_length=128)
    operator: RuleConditionOperator
    value: Any = Field(...)

    @field_validator("field")
    @classmethod
    def validate_field_safe(cls, v: str) -> str:
        # Prevent injection or eval syntax
        if any(c in v for c in [";", "\n", "\r", "(", ")", "[", "]", "{", "}", "__"]):
            raise InvalidPolicyError(f"Invalid characters in condition field: {v}")
        return v

    def to_canonical_dict(self) -> Dict[str, Any]:
        return {
            "field": self.field,
            "operator": self.operator.value,
            "value": self.value,
        }


class PolicyRule(BaseModel):
    """Immutable declarative rule evaluated in deterministic priority order."""
    model_config = ConfigDict(frozen=True)

    rule_id: str = Field(..., min_length=1, max_length=MAX_RULE_ID_LENGTH)
    rule_name: str = Field(..., min_length=1, max_length=256)
    description: str = Field(default="", max_length=512)
    conditions: List[PolicyRuleCondition] = Field(..., min_length=1)
    target_decision: UniversalDecision
    reason_code: PolicyReasonCode = Field(default=PolicyReasonCode.POLICY_RULE_ESCALATION)
    reason_summary: str = Field(default="", max_length=MAX_REASON_SUMMARY_LENGTH)
    priority: int = Field(default=100, ge=1, le=1000)
    enabled: bool = Field(default=True)

    def to_canonical_dict(self) -> Dict[str, Any]:
        return {
            "conditions": [c.to_canonical_dict() for c in self.conditions],
            "description": self.description,
            "enabled": self.enabled,
            "priority": self.priority,
            "reason_code": self.reason_code.value,
            "reason_summary": self.reason_summary,
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "target_decision": self.target_decision.value,
        }


class UniversalPolicy(BaseModel):
    """Authoritative, versioned, immutable policy definition with cryptographic identity."""
    model_config = ConfigDict(frozen=True)

    schema_version: str = Field(default=PolicySchemaVersion.V1_0.value)
    policy_id: str = Field(..., min_length=1, max_length=128)
    policy_version: str = Field(default="1.0.0", min_length=1, max_length=64)
    policy_name: str = Field(default="Universal Security Policy", min_length=1, max_length=256)
    description: str = Field(default="", max_length=512)
    enabled: bool = Field(default=True)
    thresholds: List[RiskThresholdBand] = Field(default_factory=list)
    rules: List[PolicyRule] = Field(default_factory=list)
    default_decision: UniversalDecision = Field(default=UniversalDecision.REJECT)
    default_reason_code: PolicyReasonCode = Field(default=PolicyReasonCode.POLICY_DEFAULT_FALLBACK)
    policy_hash: str = Field(default="", max_length=64)
    created_at_utc: str = Field(default_factory=utcnow_iso)

    @field_validator("rules")
    @classmethod
    def validate_rules_limits_and_uniqueness(cls, v: List[PolicyRule]) -> List[PolicyRule]:
        if len(v) > MAX_POLICY_RULES:
            raise PolicyResourceLimitExceededError(
                f"Policy rule count ({len(v)}) exceeds limit of {MAX_POLICY_RULES}"
            )
        seen_ids = set()
        for r in v:
            if r.rule_id in seen_ids:
                raise DuplicateRuleIdError(f"Duplicate rule_id detected: {r.rule_id}")
            seen_ids.add(r.rule_id)
        return v

    @field_validator("thresholds")
    @classmethod
    def validate_thresholds_contiguous(cls, v: List[RiskThresholdBand]) -> List[RiskThresholdBand]:
        if not v:
            return v

        # Check total thresholds limit
        if len(v) > 20:
            raise PolicyResourceLimitExceededError("Too many threshold bands defined (max 20)")

        # Sort bands by min_score
        sorted_bands = sorted(v, key=lambda b: (b.min_score, b.max_score))

        # Check start from 0.0
        if sorted_bands[0].min_score != 0.0 or not sorted_bands[0].inclusive_min:
            raise ThresholdGapError(
                f"Threshold bands must start at 0.0 inclusive, starts at {sorted_bands[0].min_score}"
            )

        # Check contiguous bounds without gaps or overlaps
        for i in range(len(sorted_bands) - 1):
            curr = sorted_bands[i]
            nxt = sorted_bands[i + 1]

            if curr.max_score < nxt.min_score:
                raise ThresholdGapError(
                    f"Threshold gap detected between '{curr.band_name}' (max={curr.max_score}) and '{nxt.band_name}' (min={nxt.min_score})"
                )
            if curr.max_score > nxt.min_score:
                raise ThresholdOverlapError(
                    f"Threshold overlap detected between '{curr.band_name}' (max={curr.max_score}) and '{nxt.band_name}' (min={nxt.min_score})"
                )
            if curr.inclusive_max and nxt.inclusive_min:
                raise ThresholdOverlapError(
                    f"Threshold boundary point {curr.max_score} is inclusive in both '{curr.band_name}' and '{nxt.band_name}'"
                )
            if not curr.inclusive_max and not nxt.inclusive_min:
                raise ThresholdGapError(
                    f"Threshold boundary point {curr.max_score} is excluded in both '{curr.band_name}' and '{nxt.band_name}'"
                )

        # Check end reaches 1.0 inclusive
        last = sorted_bands[-1]
        if last.max_score != 1.0 or not last.inclusive_max:
            raise ThresholdGapError(
                f"Threshold bands must end at 1.0 inclusive, ends at {last.max_score} (inclusive={last.inclusive_max})"
            )

        return v

    @model_validator(mode="after")
    def compute_and_verify_policy_hash(self) -> UniversalPolicy:
        canonical_dict = self.to_canonical_dict()
        computed = compute_policy_hash(canonical_dict)
        if self.policy_hash:
            if self.policy_hash != computed:
                raise InvalidPolicyError(
                    f"Policy hash mismatch: declared '{self.policy_hash}' != computed '{computed}'"
                )
        else:
            object.__setattr__(self, "policy_hash", computed)
        return self

    def to_canonical_dict(self) -> Dict[str, Any]:
        return {
            "default_decision": self.default_decision.value,
            "default_reason_code": self.default_reason_code.value,
            "description": self.description,
            "enabled": self.enabled,
            "policy_id": self.policy_id,
            "policy_name": self.policy_name,
            "policy_version": self.policy_version,
            "rules": [r.to_canonical_dict() for r in sorted(self.rules, key=lambda x: (x.priority, x.rule_id))],
            "schema_version": self.schema_version,
            "thresholds": [
                t.to_canonical_dict() for t in sorted(self.thresholds, key=lambda x: (x.min_score, x.max_score))
            ],
        }

    @classmethod
    def get_default_policy(cls, policy_id: str = "default_universal_policy", policy_version: str = "1.0.0") -> UniversalPolicy:
        """Standard 4-tier default risk threshold policy conforming to Phase 12.1/12.6 specifications."""
        bands = [
            RiskThresholdBand(
                band_name="ACCEPT_BAND",
                min_score=0.0,
                max_score=0.30,
                decision=UniversalDecision.ACCEPT,
                reason_code=PolicyReasonCode.RISK_BELOW_REVIEW_THRESHOLD,
                inclusive_min=True,
                inclusive_max=False,
            ),
            RiskThresholdBand(
                band_name="REVIEW_BAND",
                min_score=0.30,
                max_score=0.65,
                decision=UniversalDecision.REVIEW,
                reason_code=PolicyReasonCode.RISK_IN_REVIEW_BAND,
                inclusive_min=True,
                inclusive_max=False,
            ),
            RiskThresholdBand(
                band_name="QUARANTINE_BAND",
                min_score=0.65,
                max_score=0.85,
                decision=UniversalDecision.QUARANTINE,
                reason_code=PolicyReasonCode.RISK_IN_QUARANTINE_BAND,
                inclusive_min=True,
                inclusive_max=False,
            ),
            RiskThresholdBand(
                band_name="REJECT_BAND",
                min_score=0.85,
                max_score=1.00,
                decision=UniversalDecision.REJECT,
                reason_code=PolicyReasonCode.RISK_ABOVE_REJECT_THRESHOLD,
                inclusive_min=True,
                inclusive_max=True,
            ),
        ]
        return cls(
            policy_id=policy_id,
            policy_version=policy_version,
            policy_name="Default Universal Risk Policy",
            description="Authoritative default risk band policy for AIVARA assurance.",
            thresholds=bands,
            rules=[],
            default_decision=UniversalDecision.REJECT,
            default_reason_code=PolicyReasonCode.POLICY_DEFAULT_FALLBACK,
        )


class DecisionReason(BaseModel):
    """Structured, immutable explanation of the final decision outcome."""
    model_config = ConfigDict(frozen=True)

    reason_code: PolicyReasonCode
    reason_summary: str = Field(..., max_length=MAX_REASON_SUMMARY_LENGTH)
    triggering_rule_id: Optional[str] = Field(default=None, max_length=MAX_RULE_ID_LENGTH)
    threshold_band: Optional[str] = Field(default=None, max_length=64)
    evaluated_risk: float = Field(..., ge=0.0, le=1.0)
    escalation_applied: bool = Field(default=False)
    matched_rule_ids: List[str] = Field(default_factory=list)

    @field_validator("evaluated_risk")
    @classmethod
    def validate_risk(cls, v: float) -> float:
        return round_decimal_6(v)

    def to_canonical_dict(self) -> Dict[str, Any]:
        return {
            "escalation_applied": self.escalation_applied,
            "evaluated_risk": float(self.evaluated_risk),
            "matched_rule_ids": sorted(self.matched_rule_ids),
            "reason_code": self.reason_code.value,
            "reason_summary": self.reason_summary,
            "threshold_band": self.threshold_band,
            "triggering_rule_id": self.triggering_rule_id,
        }


class ThresholdEvaluationTrace(BaseModel):
    """Trace record of the risk threshold band evaluation."""
    model_config = ConfigDict(frozen=True)

    band_name: str
    min_score: float
    max_score: float
    baseline_decision: UniversalDecision
    reason_code: PolicyReasonCode

    def to_canonical_dict(self) -> Dict[str, Any]:
        return {
            "band_name": self.band_name,
            "baseline_decision": self.baseline_decision.value,
            "max_score": float(self.max_score),
            "min_score": float(self.min_score),
            "reason_code": self.reason_code.value,
        }


class RuleEvaluationTrace(BaseModel):
    """Trace record of a single policy rule evaluation."""
    model_config = ConfigDict(frozen=True)

    rule_id: str
    priority: int
    matched: bool
    target_decision: UniversalDecision
    condition_summary: str

    def to_canonical_dict(self) -> Dict[str, Any]:
        return {
            "condition_summary": self.condition_summary,
            "matched": self.matched,
            "priority": self.priority,
            "rule_id": self.rule_id,
            "target_decision": self.target_decision.value,
        }


class DecisionTrace(BaseModel):
    """Comprehensive, deterministic audit trail of the complete decision evaluation process."""
    model_config = ConfigDict(frozen=True)

    policy_id: str
    policy_version: str
    policy_hash: str
    risk_assessment_hash: str
    evaluated_risk_score: float
    asset_id: str
    project_id: str
    threshold_evaluation: Optional[ThresholdEvaluationTrace] = None
    rule_evaluations: List[RuleEvaluationTrace] = Field(default_factory=list)
    matched_rule_ids: List[str] = Field(default_factory=list)
    final_decision: UniversalDecision
    reason: DecisionReason

    def to_canonical_dict(self) -> Dict[str, Any]:
        return {
            "asset_id": self.asset_id,
            "evaluated_risk_score": float(self.evaluated_risk_score),
            "final_decision": self.final_decision.value,
            "matched_rule_ids": sorted(self.matched_rule_ids),
            "policy_hash": self.policy_hash,
            "policy_id": self.policy_id,
            "policy_version": self.policy_version,
            "project_id": self.project_id,
            "reason": self.reason.to_canonical_dict(),
            "risk_assessment_hash": self.risk_assessment_hash,
            "rule_evaluations": [r.to_canonical_dict() for r in self.rule_evaluations],
            "threshold_evaluation": self.threshold_evaluation.to_canonical_dict() if self.threshold_evaluation else None,
        }


class UniversalPolicyDecision(BaseModel):
    """Authoritative, cryptographically verifiable decision output of Phase 12.7."""
    model_config = ConfigDict(frozen=True)

    schema_version: str = Field(default=PolicySchemaVersion.V1_0.value)
    decision_id: str = Field(default_factory=lambda: f"dec_{uuid.uuid4().hex[:16]}")
    project_id: str = Field(..., min_length=1, max_length=128)
    asset_id: str = Field(..., min_length=1, max_length=128)
    policy_id: str = Field(..., min_length=1, max_length=128)
    policy_version: str = Field(..., min_length=1, max_length=64)
    policy_hash: str = Field(..., min_length=64, max_length=64)
    risk_assessment_hash: str = Field(..., min_length=64, max_length=64)
    risk_score: float = Field(..., ge=0.0, le=1.0)
    decision: UniversalDecision
    reason: DecisionReason
    trace: DecisionTrace
    decision_hash: str = Field(default="", max_length=64)
    created_at_utc: str = Field(default_factory=utcnow_iso)

    @field_validator("risk_score")
    @classmethod
    def validate_risk(cls, v: float) -> float:
        return round_decimal_6(v)

    @model_validator(mode="after")
    def compute_decision_hash_post(self) -> UniversalPolicyDecision:
        if not self.decision_hash:
            canonical_dict = self.to_canonical_dict()
            computed = compute_decision_hash(canonical_dict)
            object.__setattr__(self, "decision_hash", computed)
        return self

    def to_canonical_dict(self) -> Dict[str, Any]:
        """Deterministic canonical descriptor for SHA-256 content addressing (excludes non-deterministic metadata like timestamps)."""
        return {
            "asset_id": self.asset_id,
            "decision": self.decision.value,
            "matched_rule_ids": sorted(self.reason.matched_rule_ids),
            "policy_hash": self.policy_hash,
            "policy_id": self.policy_id,
            "policy_version": self.policy_version,
            "project_id": self.project_id,
            "reason_code": self.reason.reason_code.value,
            "risk_assessment_hash": self.risk_assessment_hash,
            "risk_score": float(self.risk_score),
            "schema_version": self.schema_version,
            "threshold_band": self.reason.threshold_band,
            "triggering_rule_id": self.reason.triggering_rule_id,
        }
