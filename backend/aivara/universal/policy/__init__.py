"""Phase 12.7 — Universal Policy & Decision Engine.

Provides immutable schemas, deterministic rule evaluation, and cryptographic
decision verification for converting Phase 12.6 UniversalRiskAssessment instances
into authoritative security decisions (ACCEPT, REVIEW, QUARANTINE, REJECT).
"""

from aivara.universal.policy.enums import (
    PolicyReasonCode,
    PolicySchemaVersion,
    RuleConditionOperator,
    UniversalDecision,
)
from aivara.universal.policy.exceptions import (
    DuplicateRuleIdError,
    InvalidPolicyError,
    InvalidRiskInputError,
    PolicyError,
    PolicyEvaluationError,
    PolicyResourceLimitExceededError,
    RulePrecedenceError,
    ThresholdConfigurationError,
    ThresholdGapError,
    ThresholdOverlapError,
)
from aivara.universal.policy.hashing import (
    compute_decision_hash,
    compute_policy_hash,
)
from aivara.universal.policy.schemas import (
    DecisionReason,
    DecisionTrace,
    PolicyRule,
    PolicyRuleCondition,
    RiskThresholdBand,
    RuleEvaluationTrace,
    ThresholdEvaluationTrace,
    UniversalPolicy,
    UniversalPolicyDecision,
)
from aivara.universal.policy.engine import UniversalPolicyEngine

__all__ = [
    # Enums
    "UniversalDecision",
    "PolicySchemaVersion",
    "PolicyReasonCode",
    "RuleConditionOperator",
    # Exceptions
    "PolicyError",
    "InvalidPolicyError",
    "InvalidRiskInputError",
    "ThresholdConfigurationError",
    "ThresholdGapError",
    "ThresholdOverlapError",
    "DuplicateRuleIdError",
    "RulePrecedenceError",
    "PolicyEvaluationError",
    "PolicyResourceLimitExceededError",
    # Schemas
    "RiskThresholdBand",
    "PolicyRuleCondition",
    "PolicyRule",
    "UniversalPolicy",
    "DecisionReason",
    "ThresholdEvaluationTrace",
    "RuleEvaluationTrace",
    "DecisionTrace",
    "UniversalPolicyDecision",
    # Hashing
    "compute_policy_hash",
    "compute_decision_hash",
    # Engine
    "UniversalPolicyEngine",
]
