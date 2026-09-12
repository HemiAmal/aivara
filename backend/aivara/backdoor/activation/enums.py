"""Enumerations for Phase 9.4 Trigger Activation & Controlled Behavioral Comparison."""

from __future__ import annotations

from enum import Enum


class BackdoorConditionEnum(str, Enum):
    """Frozen v1 four-condition evaluation taxonomy (ADR-088)."""
    CLEAN = "CLEAN"
    ACTIVE_TRIGGER = "ACTIVE_TRIGGER"
    LOCATION_SHUFFLED = "LOCATION_SHUFFLED"
    MAGNITUDE_MATCHED_NOISE = "MAGNITUDE_MATCHED_NOISE"
    REFERENCE_MODEL = "REFERENCE_MODEL"


class BackdoorSupportStatusEnum(str, Enum):
    """Statistical sample support eligibility taxonomy (ADR-088)."""
    INSUFFICIENT_SUPPORT = "INSUFFICIENT_SUPPORT"
    SUPPORT_ELIGIBLE = "SUPPORT_ELIGIBLE"


class BackdoorComparisonStatusEnum(str, Enum):
    """Execution and assessment status taxonomy (ADR-088)."""
    COMPLETED = "COMPLETED"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    UNAVAILABLE = "UNAVAILABLE"
    UNVERIFIABLE = "UNVERIFIABLE"
    INCOMPARABLE = "INCOMPARABLE"
    INVALID_INPUT = "INVALID_INPUT"
    RESOURCE_LIMIT = "RESOURCE_LIMIT"
    EXECUTION_FAILED = "EXECUTION_FAILED"
    INTEGRITY_FAILURE = "INTEGRITY_FAILURE"


class ActivationCriterionTypeEnum(str, Enum):
    """Task-aware activation criterion types across supported model modalities."""
    # Classification
    PREDICTION_CHANGED = "PREDICTION_CHANGED"
    TARGET_MATCHED = "TARGET_MATCHED"
    CONFIDENCE_DELTA_THRESHOLD = "CONFIDENCE_DELTA_THRESHOLD"

    # Object Detection
    DETECTION_COUNT_DELTA = "DETECTION_COUNT_DELTA"
    DETECTION_IOU_DROP = "DETECTION_IOU_DROP"
    DETECTION_TARGET_CLASS_INJECTED = "DETECTION_TARGET_CLASS_INJECTED"

    # Semantic Segmentation
    SEGMENTATION_GT_MIOU_DROP = "SEGMENTATION_GT_MIOU_DROP"
    SEGMENTATION_REFERENCE_MASK_AGREEMENT_DROP = "SEGMENTATION_REFERENCE_MASK_AGREEMENT_DROP"
    SEGMENTATION_TARGET_CLASS_EMERGENCE = "SEGMENTATION_TARGET_CLASS_EMERGENCE"
    SEGMENTATION_MASK_DISAGREEMENT = "SEGMENTATION_MASK_DISAGREEMENT"

    # Generic Tensor
    TENSOR_DISTANCE_THRESHOLD = "TENSOR_DISTANCE_THRESHOLD"


class ActivationDecisionEnum(str, Enum):
    """Activation decision status per paired observation."""
    ACTIVATED = "ACTIVATED"
    NOT_ACTIVATED = "NOT_ACTIVATED"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    UNAVAILABLE = "UNAVAILABLE"
    INSUFFICIENT_SUPPORT = "INSUFFICIENT_SUPPORT"
