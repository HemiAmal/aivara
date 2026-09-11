"""Behavioral family definitions, metric mappings, and structured family-level aggregation."""

from __future__ import annotations

from typing import Dict, List, Optional
from aivara.behavioral.anomaly.enums import (
    AnomalyFamilyType,
    AnomalyStatus,
    MetricAnomalyStatus,
    MetricDirection,
    SupportStatus,
)
from aivara.behavioral.anomaly.explanations import format_family_explanation
from aivara.behavioral.anomaly.policy import AnomalyThresholdPolicy
from aivara.behavioral.anomaly.schemas import BehavioralAnomalyFamily, BehavioralAnomalyMetric


# Directionality mappings
METRIC_DIRECTIONS: Dict[str, MetricDirection] = {
    # Repeatability
    "prediction_agreement_rate": MetricDirection.LOWER_IS_EXTREME,
    "max_numerical_delta": MetricDirection.HIGHER_IS_EXTREME,
    "mean_numerical_delta": MetricDirection.HIGHER_IS_EXTREME,
    # Classification Consistency
    "prediction_agreement": MetricDirection.LOWER_IS_EXTREME,
    "top_k_overlap": MetricDirection.LOWER_IS_EXTREME,
    "confidence_delta": MetricDirection.TWO_SIDED,
    "kl_divergence": MetricDirection.HIGHER_IS_EXTREME,
    "js_divergence": MetricDirection.HIGHER_IS_EXTREME,
    "entropy_delta": MetricDirection.TWO_SIDED,
    "margin_delta": MetricDirection.TWO_SIDED,
    # Detection Consistency
    "mean_matched_iou": MetricDirection.LOWER_IS_EXTREME,
    "class_agreement_rate": MetricDirection.LOWER_IS_EXTREME,
    "count_delta": MetricDirection.TWO_SIDED,
    "mean_confidence_delta": MetricDirection.TWO_SIDED,
    "mean_box_displacement": MetricDirection.HIGHER_IS_EXTREME,
    # Segmentation Consistency
    "ground_truth_miou": MetricDirection.LOWER_IS_EXTREME,
    "reference_mask_agreement": MetricDirection.LOWER_IS_EXTREME,
    "pixel_agreement_rate": MetricDirection.LOWER_IS_EXTREME,
    # Generic Tensor Consistency
    "l1_distance": MetricDirection.HIGHER_IS_EXTREME,
    "l2_distance": MetricDirection.HIGHER_IS_EXTREME,
    "relative_l2_distance": MetricDirection.HIGHER_IS_EXTREME,
    "cosine_similarity": MetricDirection.LOWER_IS_EXTREME,
    "max_absolute_difference": MetricDirection.HIGHER_IS_EXTREME,
    "mean_absolute_difference": MetricDirection.HIGHER_IS_EXTREME,
    "finite_value_agreement": MetricDirection.LOWER_IS_EXTREME,
    # Perturbation Sensitivity
    "sensitivity_ratio": MetricDirection.HIGHER_IS_EXTREME,
    "output_distance_l1": MetricDirection.HIGHER_IS_EXTREME,
    "output_distance_l2": MetricDirection.HIGHER_IS_EXTREME,
    "prediction_changed": MetricDirection.HIGHER_IS_EXTREME,
    # Execution Stability
    "latency_ms": MetricDirection.HIGHER_IS_EXTREME,
    "finite_value_rate": MetricDirection.LOWER_IS_EXTREME,
    "empty_detection_rate": MetricDirection.HIGHER_IS_EXTREME,
}


METRIC_FAMILY_MAP: Dict[str, AnomalyFamilyType] = {
    # Repeatability
    "prediction_agreement_rate": AnomalyFamilyType.REPEATABILITY,
    "max_numerical_delta": AnomalyFamilyType.REPEATABILITY,
    "mean_numerical_delta": AnomalyFamilyType.REPEATABILITY,
    # Output Consistency
    "prediction_agreement": AnomalyFamilyType.OUTPUT_CONSISTENCY,
    "top_k_overlap": AnomalyFamilyType.OUTPUT_CONSISTENCY,
    "confidence_delta": AnomalyFamilyType.OUTPUT_CONSISTENCY,
    "kl_divergence": AnomalyFamilyType.OUTPUT_CONSISTENCY,
    "js_divergence": AnomalyFamilyType.OUTPUT_CONSISTENCY,
    "entropy_delta": AnomalyFamilyType.OUTPUT_CONSISTENCY,
    "margin_delta": AnomalyFamilyType.OUTPUT_CONSISTENCY,
    "mean_matched_iou": AnomalyFamilyType.OUTPUT_CONSISTENCY,
    "class_agreement_rate": AnomalyFamilyType.OUTPUT_CONSISTENCY,
    "count_delta": AnomalyFamilyType.OUTPUT_CONSISTENCY,
    "mean_confidence_delta": AnomalyFamilyType.OUTPUT_CONSISTENCY,
    "mean_box_displacement": AnomalyFamilyType.OUTPUT_CONSISTENCY,
    "ground_truth_miou": AnomalyFamilyType.OUTPUT_CONSISTENCY,
    "reference_mask_agreement": AnomalyFamilyType.OUTPUT_CONSISTENCY,
    "pixel_agreement_rate": AnomalyFamilyType.OUTPUT_CONSISTENCY,
    "l1_distance": AnomalyFamilyType.OUTPUT_CONSISTENCY,
    "l2_distance": AnomalyFamilyType.OUTPUT_CONSISTENCY,
    "relative_l2_distance": AnomalyFamilyType.OUTPUT_CONSISTENCY,
    "cosine_similarity": AnomalyFamilyType.OUTPUT_CONSISTENCY,
    "max_absolute_difference": AnomalyFamilyType.OUTPUT_CONSISTENCY,
    "mean_absolute_difference": AnomalyFamilyType.OUTPUT_CONSISTENCY,
    "finite_value_agreement": AnomalyFamilyType.OUTPUT_CONSISTENCY,
    # Perturbation Sensitivity
    "sensitivity_ratio": AnomalyFamilyType.PERTURBATION_SENSITIVITY,
    "output_distance_l1": AnomalyFamilyType.PERTURBATION_SENSITIVITY,
    "output_distance_l2": AnomalyFamilyType.PERTURBATION_SENSITIVITY,
    "prediction_changed": AnomalyFamilyType.PERTURBATION_SENSITIVITY,
    # Execution Stability
    "latency_ms": AnomalyFamilyType.EXECUTION_STABILITY,
    "finite_value_rate": AnomalyFamilyType.EXECUTION_STABILITY,
    "empty_detection_rate": AnomalyFamilyType.EXECUTION_STABILITY,
}


def get_metric_direction(metric_name: str) -> MetricDirection:
    """Get directionality for a metric, defaulting to TWO_SIDED if unmapped."""
    return METRIC_DIRECTIONS.get(metric_name, MetricDirection.TWO_SIDED)


def get_metric_family(metric_name: str) -> AnomalyFamilyType:
    """Get behavioral family for a metric, defaulting to OUTPUT_CONSISTENCY if unmapped."""
    return METRIC_FAMILY_MAP.get(metric_name, AnomalyFamilyType.OUTPUT_CONSISTENCY)


def aggregate_family_results(
    family_name: AnomalyFamilyType,
    metrics: List[BehavioralAnomalyMetric],
    policy: AnomalyThresholdPolicy,
) -> BehavioralAnomalyFamily:
    """Aggregate individual metric evaluations into a structured family-level record."""
    total_metrics = len(metrics)
    if total_metrics == 0:
        return BehavioralAnomalyFamily(
            family_name=family_name,
            support_status=SupportStatus.INSUFFICIENT_SUPPORT,
            metric_count=0,
            valid_metric_count=0,
            anomalous_metric_count=0,
            dominant_metric=None,
            dominant_extremeness=None,
            family_status=AnomalyStatus.UNAVAILABLE,
            explanation=f"Behavioral family '{family_name.value}' has no declared metrics.",
        )

    valid_metrics = [m for m in metrics if m.validity_status == "VALID" and m.observed_value is not None]
    valid_count = len(valid_metrics)
    anomalous_metrics = [m for m in valid_metrics if m.anomaly_status == MetricAnomalyStatus.ANOMALOUS]
    anomalous_count = len(anomalous_metrics)

    # Determine overall family support from maximum baseline count among valid metrics
    if valid_metrics:
        max_support_count = max(m.baseline_count for m in valid_metrics)
    else:
        max_support_count = max((m.baseline_count for m in metrics), default=0)

    if max_support_count < policy.min_support_count:
        family_support = SupportStatus.INSUFFICIENT_SUPPORT
    elif max_support_count < policy.low_support_count:
        family_support = SupportStatus.LOW_SUPPORT
    elif max_support_count < policy.adequate_support_count:
        family_support = SupportStatus.MODERATE_SUPPORT
    else:
        family_support = SupportStatus.ADEQUATE_SUPPORT

    dominant_metric: Optional[str] = None
    dominant_extremeness: Optional[float] = None

    if anomalous_metrics:
        # Sort anomalous metrics by absolute_robust_z descending, then empirical_extremeness ascending, then name
        def sort_key(m: BehavioralAnomalyMetric):
            z_score = m.absolute_robust_z if m.absolute_robust_z is not None else 0.0
            ext = m.empirical_extremeness if m.empirical_extremeness is not None else 1.0
            return (-z_score, ext, m.metric_name)

        sorted_anomalies = sorted(anomalous_metrics, key=sort_key)
        best = sorted_anomalies[0]
        dominant_metric = best.metric_name
        dominant_extremeness = best.absolute_robust_z if best.absolute_robust_z is not None else best.empirical_extremeness
        family_status = AnomalyStatus.ANOMALOUS

    elif valid_count == 0:
        # Check reasons among invalid metrics
        statuses = {m.validity_status for m in metrics}
        if "UNVERIFIABLE" in statuses:
            family_status = AnomalyStatus.UNVERIFIABLE
        elif "INCOMPATIBLE" in statuses:
            family_status = AnomalyStatus.INCOMPARABLE
        else:
            family_status = AnomalyStatus.UNAVAILABLE

    elif family_support == SupportStatus.INSUFFICIENT_SUPPORT:
        family_status = AnomalyStatus.INSUFFICIENT_SUPPORT

    elif valid_count == total_metrics:
        family_status = AnomalyStatus.NORMAL
    else:
        family_status = AnomalyStatus.NORMAL if valid_count > 0 else AnomalyStatus.PARTIALLY_ANALYZED

    explanation = format_family_explanation(
        family_name=family_name,
        status=family_status,
        support_status=family_support,
        anomalous_count=anomalous_count,
        valid_count=valid_count,
        dominant_metric=dominant_metric,
        dominant_extremeness=dominant_extremeness,
    )

    return BehavioralAnomalyFamily(
        family_name=family_name,
        support_status=family_support,
        metric_count=total_metrics,
        valid_metric_count=valid_count,
        anomalous_metric_count=anomalous_count,
        dominant_metric=dominant_metric,
        dominant_extremeness=dominant_extremeness,
        family_status=family_status,
        explanation=explanation,
    )
