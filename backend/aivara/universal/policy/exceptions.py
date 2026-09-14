"""Custom exceptions for Phase 12.7 Universal Policy & Decision Engine."""

from typing import Any, Dict, Optional


class PolicyError(Exception):
    """Base exception for all Phase 12.7 policy and decision errors."""

    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(message)
        self.message = message
        self.details = details or {}


class InvalidPolicyError(PolicyError):
    """Raised when a policy definition fails structural, semantic, or cryptographic validation."""
    pass


class InvalidRiskInputError(PolicyError):
    """Raised when the input UniversalRiskAssessment is malformed, out of range, or fails hash verification."""
    pass


class ThresholdConfigurationError(InvalidPolicyError):
    """Raised when decision threshold bands are improperly configured."""
    pass


class ThresholdGapError(ThresholdConfigurationError):
    """Raised when decision threshold bands leave gaps in the [0.0, 1.0] interval."""
    pass


class ThresholdOverlapError(ThresholdConfigurationError):
    """Raised when decision threshold bands overlap with each other."""
    pass


class DuplicateRuleIdError(InvalidPolicyError):
    """Raised when multiple rules in a policy declare identical rule IDs."""
    pass


class RulePrecedenceError(InvalidPolicyError):
    """Raised when rule priority or evaluation order is invalid or ambiguous."""
    pass


class PolicyEvaluationError(PolicyError):
    """Raised when runtime evaluation of a policy encounters an unexpected internal state."""
    pass


class PolicyResourceLimitExceededError(PolicyError):
    """Raised when policy configuration or rule count exceeds global bounded resource limits."""
    pass
