"""Enumerations for Multi-Modal Risk Integration Engine (Phase 11.9)."""

from __future__ import annotations

from enum import Enum


class EvidenceCategory(str, Enum):
    """Categorical family classification for multi-modal evidence items."""
    CRYPTOGRAPHIC_PROOF = "CRYPTOGRAPHIC_PROOF"
    DATASET_INTEGRITY = "DATASET_INTEGRITY"
    CONTRIBUTOR_RISK = "CONTRIBUTOR_RISK"
    MODEL_INTEGRITY = "MODEL_INTEGRITY"
    BEHAVIORAL_ANOMALY = "BEHAVIORAL_ANOMALY"
    TRIGGER_ACTIVATION = "TRIGGER_ACTIVATION"
    INFERENCE_INTEGRITY = "INFERENCE_INTEGRITY"
    DISTRIBUTION_SHIFT = "DISTRIBUTION_SHIFT"
    UNCLASSIFIED = "UNCLASSIFIED"


class DependencyRelation(str, Enum):
    """Type of evidential lineage or ancestry dependency relationship."""
    DERIVED_FROM = "DERIVED_FROM"
    SHARES_ANCESTRY = "SHARES_ANCESTRY"
    SAME_POPULATION = "SAME_POPULATION"
    SAME_MODEL = "SAME_MODEL"
    SAME_SOURCE = "SAME_SOURCE"
    SAME_TIME_WINDOW = "SAME_TIME_WINDOW"
    INDEPENDENT = "INDEPENDENT"


class IntegrationEvaluationStatus(str, Enum):
    """Overall status of the multi-modal evidence integration evaluation."""
    EVALUATED = "EVALUATED"
    INSUFFICIENT_DATA = "INSUFFICIENT_DATA"
    CONFLICTING_EVIDENCE = "CONFLICTING_EVIDENCE"
    PROOF_VIOLATION = "PROOF_VIOLATION"
    ERROR = "ERROR"
