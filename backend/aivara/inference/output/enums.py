"""Enums for Phase 10.6 Output Schema & Numerical Integrity subsystem."""

from __future__ import annotations

from enum import Enum


class TaskType(str, Enum):
    """Supported machine learning task domain types in AIVARA."""

    CLASSIFICATION = "classification"
    OBJECT_DETECTION = "object_detection"
    SEGMENTATION = "segmentation"
    EMBEDDING = "embedding"
    GENERIC = "generic"


class OutputKind(str, Enum):
    """Categorical classification of model raw and transformed outputs."""

    LOGITS = "LOGITS"
    PROBABILITIES = "PROBABILITIES"
    CLASS_SCORES = "CLASS_SCORES"
    BOUNDING_BOXES = "BOUNDING_BOXES"
    SEGMENTATION_MASKS = "SEGMENTATION_MASKS"
    EMBEDDING_VECTOR = "EMBEDDING_VECTOR"
    STRUCTURED = "STRUCTURED"


class NumericalSanityStatus(str, Enum):
    """Categorical classification of tensor numerical health and domain validity."""

    FINITE = "FINITE"
    NONFINITE = "NONFINITE"
    DOMAIN_VALID = "DOMAIN_VALID"
    DOMAIN_INVALID = "DOMAIN_INVALID"
    UNAVAILABLE = "UNAVAILABLE"


class OutputStructuralStatus(str, Enum):
    """Structural compliance status against declared model output contract."""

    VALID = "VALID"
    INVALID = "INVALID"
    MISMATCHED = "MISMATCHED"
    UNAVAILABLE = "UNAVAILABLE"
    UNVERIFIABLE = "UNVERIFIABLE"
