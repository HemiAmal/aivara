"""Controlled enumerations and taxonomies for Phase 8.7 Behavioral Evidence & Provenance Binding."""

from __future__ import annotations

from enum import Enum


class BehavioralEvidenceType(str, Enum):
    """Controlled taxonomy of analytical behavioral evidence types."""

    BEHAVIORAL_BASELINE = "BEHAVIORAL_BASELINE"
    BEHAVIORAL_COMPARISON = "BEHAVIORAL_COMPARISON"
    BEHAVIORAL_REPEATABILITY = "BEHAVIORAL_REPEATABILITY"
    BEHAVIORAL_PERTURBATION = "BEHAVIORAL_PERTURBATION"
    BEHAVIORAL_STABILITY = "BEHAVIORAL_STABILITY"
    BEHAVIORAL_ANOMALY = "BEHAVIORAL_ANOMALY"


class EvidenceLifecycleState(str, Enum):
    """Lifecycle state of an evidence payload."""

    DRAFT = "DRAFT"
    SEALED = "SEALED"


class BehavioralFindingType(str, Enum):
    """Taxonomy of behavioral finding types."""

    BEHAVIORAL_ANOMALY = "BEHAVIORAL_ANOMALY"
    BEHAVIORAL_INSTABILITY = "BEHAVIORAL_INSTABILITY"
    BEHAVIORAL_BASELINE_PROFILE = "BEHAVIORAL_BASELINE_PROFILE"
    BEHAVIORAL_COMPARISON_PROFILE = "BEHAVIORAL_COMPARISON_PROFILE"


class BehavioralFindingStatus(str, Enum):
    """Controlled analytical statuses for behavioral findings.

    NOTE: Terms like MALICIOUS, COMPROMISED, ATTACK, or BACKDOOR are strictly forbidden.
    """

    NORMAL = "NORMAL"
    ANOMALOUS = "ANOMALOUS"
    INSUFFICIENT_SUPPORT = "INSUFFICIENT_SUPPORT"
    PARTIALLY_ANALYZED = "PARTIALLY_ANALYZED"
    UNAVAILABLE = "UNAVAILABLE"
    INCOMPARABLE = "INCOMPARABLE"
    UNVERIFIABLE = "UNVERIFIABLE"
