"""Enumerations and categorization models for Phase 8.6 Behavioral Anomaly Detection."""

from __future__ import annotations

from enum import Enum


class AnomalyStatus(str, Enum):
    """Overall behavioral anomaly assessment status."""

    NORMAL = "NORMAL"
    ANOMALOUS = "ANOMALOUS"
    INSUFFICIENT_SUPPORT = "INSUFFICIENT_SUPPORT"
    PARTIALLY_ANALYZED = "PARTIALLY_ANALYZED"
    UNAVAILABLE = "UNAVAILABLE"
    INCOMPARABLE = "INCOMPARABLE"
    UNVERIFIABLE = "UNVERIFIABLE"


class MetricAnomalyStatus(str, Enum):
    """Individual metric anomaly determination."""

    NORMAL = "NORMAL"
    ANOMALOUS = "ANOMALOUS"
    INSUFFICIENT_SUPPORT = "INSUFFICIENT_SUPPORT"
    UNAVAILABLE = "UNAVAILABLE"
    UNVERIFIABLE = "UNVERIFIABLE"
    INCOMPATIBLE = "INCOMPATIBLE"


class SupportStatus(str, Enum):
    """Sample support adequacy categorization."""

    INSUFFICIENT_SUPPORT = "INSUFFICIENT_SUPPORT"
    LOW_SUPPORT = "LOW_SUPPORT"
    MODERATE_SUPPORT = "MODERATE_SUPPORT"
    ADEQUATE_SUPPORT = "ADEQUATE_SUPPORT"


class MetricDirection(str, Enum):
    """Directionality of metric indicating what values are considered statistically extreme."""

    LOWER_IS_EXTREME = "LOWER_IS_EXTREME"
    HIGHER_IS_EXTREME = "HIGHER_IS_EXTREME"
    TWO_SIDED = "TWO_SIDED"


class AnomalyFamilyType(str, Enum):
    """Behavioral metric family grouping to avoid naive independence assumptions."""

    REPEATABILITY = "REPEATABILITY"
    OUTPUT_CONSISTENCY = "OUTPUT_CONSISTENCY"
    PERTURBATION_SENSITIVITY = "PERTURBATION_SENSITIVITY"
    EXECUTION_STABILITY = "EXECUTION_STABILITY"


class AnomalyBaselineType(str, Enum):
    """Origin context of behavioral reference baseline population."""

    BASELINE_REFERENCE = "BASELINE_REFERENCE"
    REPEATED_EXECUTION_REFERENCE = "REPEATED_EXECUTION_REFERENCE"
    PERTURBATION_REFERENCE = "PERTURBATION_REFERENCE"
    HISTORICAL_PROFILE = "HISTORICAL_PROFILE"
    TRUSTED_REFERENCE_MODEL = "TRUSTED_REFERENCE_MODEL"
