"""Enumerations for Phase 9.5 Statistical Trigger Significance & Control Comparison."""

from __future__ import annotations

from enum import Enum


class StatisticalStatusEnum(str, Enum):
    """Execution and evaluation status for statistical hypothesis testing."""
    COMPLETED = "COMPLETED"
    INSUFFICIENT_SUPPORT = "INSUFFICIENT_SUPPORT"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    UNAVAILABLE = "UNAVAILABLE"
    UNVERIFIABLE = "UNVERIFIABLE"
    INCOMPARABLE = "INCOMPARABLE"
    INVALID_INPUT = "INVALID_INPUT"
    RESOURCE_LIMIT = "RESOURCE_LIMIT"
    EXECUTION_FAILED = "EXECUTION_FAILED"


class StatisticalSignificanceEnum(str, Enum):
    """Empirical significance decision under configured alpha threshold."""
    SIGNIFICANT = "SIGNIFICANT"
    NOT_SIGNIFICANT = "NOT_SIGNIFICANT"
    NOT_EVALUATED = "NOT_EVALUATED"


class StatisticalResultTaxonomyEnum(str, Enum):
    """Frozen Phase 9.1 evidence-based observational result taxonomy (ADR-083)."""
    NO_TRIGGER_EVIDENCE = "NO_TRIGGER_EVIDENCE"
    NORMAL_SENSITIVITY_ONLY = "NORMAL_SENSITIVITY_ONLY"
    TRIGGER_CANDIDATE_OBSERVED = "TRIGGER_CANDIDATE_OBSERVED"
    TARGETED_EFFECT_DETECTED = "TARGETED_EFFECT_DETECTED"
    STRONG_TRIGGER_CONSISTENCY = "STRONG_TRIGGER_CONSISTENCY"
    INSUFFICIENT_SUPPORT = "INSUFFICIENT_SUPPORT"
    INCOMPARABLE = "INCOMPARABLE"
    UNAVAILABLE = "UNAVAILABLE"
    UNVERIFIABLE = "UNVERIFIABLE"


class MultipleTestingMethodEnum(str, Enum):
    """Multiplicity adjustment methods."""
    BENJAMINI_HOCHBERG = "BENJAMINI_HOCHBERG"      # FDR control for candidate comparisons
    HOLM_BONFERRONI = "HOLM_BONFERRONI"            # FWER step-down for spatial grid cells
    NONE = "NONE"


class StagePromotionStatusEnum(str, Enum):
    """Eligibility status for advancing from Stage 1 screening to Stage 2 expansion."""
    PROMOTED = "PROMOTED"
    NOT_PROMOTED_LOW_TAR = "NOT_PROMOTED_LOW_TAR"
    NOT_PROMOTED_LOW_TSR = "NOT_PROMOTED_LOW_TSR"
    NOT_PROMOTED_LOW_SEPARATION = "NOT_PROMOTED_LOW_SEPARATION"
    NOT_PROMOTED_RANK_EXCEEDED = "NOT_PROMOTED_RANK_EXCEEDED"
    NOT_APPLICABLE_NO_TARGET = "NOT_APPLICABLE_NO_TARGET"
    INSUFFICIENT_SUPPORT = "INSUFFICIENT_SUPPORT"
