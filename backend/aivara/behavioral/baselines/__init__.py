"""Behavioral Baselines & Reference Profile Engine package (Phase 8.3)."""

from aivara.behavioral.baselines.comparability import validate_baseline_comparability
from aivara.behavioral.baselines.input_set import (
    build_input_set_descriptor,
    compute_sample_input_hash,
)
from aivara.behavioral.baselines.profiles import (
    build_classification_profile,
    build_detection_profile,
    build_latency_profile,
    build_numerical_profile,
    build_segmentation_profile,
    compute_canonical_profile_hash,
    compute_distribution_stats,
    compute_miou_score,
)
from aivara.behavioral.baselines.schemas import (
    BaselineStatus,
    BaselineSupportStatus,
    BaselineTrustStatus,
    BaselineType,
    BehavioralBaseline,
    BehavioralProfileAggregate,
    ClassificationBehaviorProfile,
    DetectionBehaviorProfile,
    DistributionStats,
    ExpectedBehaviorSpecification,
    InputItemDescriptor,
    InputSetDescriptor,
    LatencyProfile,
    NumericalProfile,
    RepeatabilityProfile,
    SegmentationBehaviorProfile,
)
from aivara.behavioral.baselines.service import BehavioralBaselineService

__all__ = [
    # Schemas & Enums
    "BaselineType",
    "BaselineTrustStatus",
    "BaselineSupportStatus",
    "BaselineStatus",
    "InputItemDescriptor",
    "InputSetDescriptor",
    "DistributionStats",
    "ClassificationBehaviorProfile",
    "DetectionBehaviorProfile",
    "SegmentationBehaviorProfile",
    "NumericalProfile",
    "LatencyProfile",
    "RepeatabilityProfile",
    "ExpectedBehaviorSpecification",
    "BehavioralProfileAggregate",
    "BehavioralBaseline",
    # Functions & Builders
    "compute_sample_input_hash",
    "build_input_set_descriptor",
    "compute_distribution_stats",
    "build_classification_profile",
    "build_detection_profile",
    "build_segmentation_profile",
    "compute_miou_score",
    "build_numerical_profile",
    "build_latency_profile",
    "compute_canonical_profile_hash",
    "validate_baseline_comparability",
    # Core Service
    "BehavioralBaselineService",
]
