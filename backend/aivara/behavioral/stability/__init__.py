"""AIVARA Output Consistency & Stability Analysis Engine (Phase 8.5)."""

from aivara.behavioral.stability.identity import (
    compute_comparison_id,
    compute_metric_id,
    compute_repeatability_analysis_id,
    compute_sensitivity_id,
)
from aivara.behavioral.stability.metrics import (
    compute_box_iou,
    compute_classification_stability_metrics,
    compute_detection_stability_metrics,
    compute_generic_tensor_stability_metrics,
    compute_input_distance,
    compute_segmentation_stability_metrics,
)
from aivara.behavioral.stability.schemas import (
    BehavioralComparisonResult,
    ClassificationStabilityMetrics,
    ComparisonType,
    DetectionMatchRecord,
    DetectionStabilityMetrics,
    GenericTensorStabilityMetrics,
    MetricResult,
    MetricValidityStatus,
    PerturbationSensitivityResult,
    RepeatabilityAnalysisResult,
    SegmentationStabilityMetrics,
)
from aivara.behavioral.stability.service import OutputStabilityAnalysisService

__all__ = [
    # Schemas & Enums
    "ComparisonType",
    "MetricValidityStatus",
    "MetricResult",
    "ClassificationStabilityMetrics",
    "DetectionMatchRecord",
    "DetectionStabilityMetrics",
    "SegmentationStabilityMetrics",
    "GenericTensorStabilityMetrics",
    "RepeatabilityAnalysisResult",
    "PerturbationSensitivityResult",
    "BehavioralComparisonResult",
    # Service
    "OutputStabilityAnalysisService",
    # Identity Functions
    "compute_comparison_id",
    "compute_metric_id",
    "compute_repeatability_analysis_id",
    "compute_sensitivity_id",
    # Mathematical Metric Calculators
    "compute_classification_stability_metrics",
    "compute_box_iou",
    "compute_detection_stability_metrics",
    "compute_segmentation_stability_metrics",
    "compute_generic_tensor_stability_metrics",
    "compute_input_distance",
]
