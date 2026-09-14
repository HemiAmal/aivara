"""Enumerations for Phase 12.7 Universal Policy & Decision Engine.

Enforces:
- Canonical decision vocabulary: ACCEPT, REVIEW, QUARANTINE, REJECT.
- Strict monotonic decision ordering: ACCEPT < REVIEW < QUARANTINE < REJECT.
- Standardized, auditable policy reason codes.
- Safe, declarative rule condition operators.
"""

from enum import Enum
from functools import total_ordering


@total_ordering
class UniversalDecision(str, Enum):
    """Authoritative Phase 12 security decision outcome with strict monotonic ordering.
    
    Precedence / Restriction Order:
    ACCEPT (least restrictive) < REVIEW < QUARANTINE < REJECT (most restrictive).
    """
    ACCEPT = "ACCEPT"
    REVIEW = "REVIEW"
    QUARANTINE = "QUARANTINE"
    REJECT = "REJECT"

    @property
    def severity_rank(self) -> int:
        """Numerical severity rank for monotonic comparison."""
        ranks = {
            UniversalDecision.ACCEPT: 1,
            UniversalDecision.REVIEW: 2,
            UniversalDecision.QUARANTINE: 3,
            UniversalDecision.REJECT: 4,
        }
        return ranks[self]

    def _get_rank(self, other: object) -> int:
        if isinstance(other, UniversalDecision):
            return other.severity_rank
        if isinstance(other, str):
            try:
                return UniversalDecision(other).severity_rank
            except ValueError:
                raise TypeError(f"Cannot compare UniversalDecision with {type(other).__name__} ({other})")
        raise TypeError(f"Cannot compare UniversalDecision with {type(other).__name__}")

    def __lt__(self, other: object) -> bool:
        try:
            return self.severity_rank < self._get_rank(other)
        except TypeError:
            return NotImplemented

    def __le__(self, other: object) -> bool:
        try:
            return self.severity_rank <= self._get_rank(other)
        except TypeError:
            return NotImplemented

    def __gt__(self, other: object) -> bool:
        try:
            return self.severity_rank > self._get_rank(other)
        except TypeError:
            return NotImplemented

    def __ge__(self, other: object) -> bool:
        try:
            return self.severity_rank >= self._get_rank(other)
        except TypeError:
            return NotImplemented

    def __eq__(self, other: object) -> bool:
        if isinstance(other, UniversalDecision):
            return self.value == other.value
        if isinstance(other, str):
            return self.value == other
        return False

    def __hash__(self) -> int:
        return hash(self.value)


class PolicySchemaVersion(str, Enum):
    """SemVer for Universal Policy and Decision schemas."""
    V1_0 = "1.0.0"


class PolicyReasonCode(str, Enum):
    """Standardized machine-readable decision explanation codes."""
    # Threshold-based reasons
    RISK_BELOW_REVIEW_THRESHOLD = "RISK_BELOW_REVIEW_THRESHOLD"
    RISK_IN_REVIEW_BAND = "RISK_IN_REVIEW_BAND"
    RISK_IN_QUARANTINE_BAND = "RISK_IN_QUARANTINE_BAND"
    RISK_ABOVE_REJECT_THRESHOLD = "RISK_ABOVE_REJECT_THRESHOLD"

    # Rule-based escalation reasons
    POLICY_RULE_ESCALATION = "POLICY_RULE_ESCALATION"
    INSUFFICIENT_ANCESTRY_ESCALATION = "INSUFFICIENT_ANCESTRY_ESCALATION"
    CRITICAL_FINDING_ESCALATION = "CRITICAL_FINDING_ESCALATION"
    DOMAIN_THRESHOLD_ESCALATION = "DOMAIN_THRESHOLD_ESCALATION"

    # Default / Fallback reasons
    POLICY_DEFAULT_FALLBACK = "POLICY_DEFAULT_FALLBACK"
    POLICY_DEFAULT_REJECT = "POLICY_DEFAULT_REJECT"

    # Error / Validation codes
    INVALID_POLICY = "INVALID_POLICY"
    INVALID_RISK_INPUT = "INVALID_RISK_INPUT"


class RuleConditionOperator(str, Enum):
    """Supported safe, declarative comparison operators for policy rules."""
    EQUALS = "EQUALS"
    NOT_EQUALS = "NOT_EQUALS"
    GREATER_THAN = "GREATER_THAN"
    GREATER_EQUAL = "GREATER_EQUAL"
    LESS_THAN = "LESS_THAN"
    LESS_EQUAL = "LESS_EQUAL"
    IN = "IN"
    CONTAINS = "CONTAINS"
