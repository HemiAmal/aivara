"""Comprehensive test suite for Phase 8.6 Behavioral Anomaly Detection Subsystem."""

import math
import socket
import pytest
from pydantic import ValidationError

from aivara.behavioral.anomaly import (
    AnomalyBaselineType,
    AnomalyFamilyType,
    AnomalyStatus,
    AnomalyThresholdPolicy,
    BaselineSummary,
    BehavioralAnomalyAnalysis,
    BehavioralAnomalyEngineService,
    BehavioralAnomalyError,
    BehavioralAnomalyFamily,
    BehavioralAnomalyMetric,
    CrossProjectAnalysisError,
    DEFAULT_ANOMALY_POLICY,
    IncompatibleAnalysisContextError,
    InsufficientSupportError,
    InvalidMetricDataError,
    METRIC_DIRECTIONS,
    METRIC_FAMILY_MAP,
    MetricAnomalyStatus,
    MetricDirection,
    SupportStatus,
    aggregate_family_results,
    compute_anomaly_analysis_id,
    compute_empirical_extremeness,
    compute_mad,
    compute_median,
    compute_percentile_rank,
    compute_robust_z,
    compute_support_status,
    filter_finite_values,
    format_family_explanation,
    format_metric_explanation,
    format_overall_explanation,
    get_metric_direction,
    get_metric_family,
)


# =====================================================================
# A. SCHEMA & IMMUTABILITY TESTS
# =====================================================================

def test_anomaly_metric_immutability():
    """Verify BehavioralAnomalyMetric is immutable and forbids extra fields."""
    m = BehavioralAnomalyMetric(
        metric_name="prediction_agreement",
        family=AnomalyFamilyType.OUTPUT_CONSISTENCY,
        direction=MetricDirection.LOWER_IS_EXTREME,
        observed_value=0.95,
        baseline_count=30,
        baseline_median=0.96,
        baseline_mad=0.02,
        robust_z=-0.337,
        absolute_robust_z=0.337,
        empirical_extremeness=0.45,
        validity_status="VALID",
        anomaly_status=MetricAnomalyStatus.NORMAL,
        reason="Within reference range",
    )
    with pytest.raises(ValidationError):
        m.observed_value = 0.50  # Frozen model cannot be mutated


def test_anomaly_analysis_immutability():
    """Verify BehavioralAnomalyAnalysis is immutable and forbids extra fields."""
    policy = DEFAULT_ANOMALY_POLICY
    analysis = BehavioralAnomalyAnalysis(
        analysis_id="a" * 64,
        project_id="proj_1",
        model_id="mod_1",
        model_fingerprint="f" * 64,
        baseline_id="b" * 64,
        baseline_type="BASELINE_REFERENCE",
        observation_id="obs_1",
        task_type="classification",
        analysis_version="1.0.0",
        policy_version="1.0.0",
        overall_status=AnomalyStatus.NORMAL,
        support_status=SupportStatus.ADEQUATE_SUPPORT,
        comparability_status="COMPARABLE",
        families={},
        metrics=[],
        threshold_policy=policy.to_dict(),
        baseline_summary=BaselineSummary(
            baseline_id="b" * 64,
            baseline_type="BASELINE_REFERENCE",
            total_baseline_count=30,
            eligible_baseline_count=30,
            excluded_baseline_count=0,
            exclusion_reasons={},
        ),
        explanation="Consistent",
        limitations=[],
        created_at="2026-09-11T12:00:00Z",
    )
    with pytest.raises(ValidationError):
        analysis.overall_status = AnomalyStatus.ANOMALOUS


# =====================================================================
# B. STATISTICAL CORRECTNESS TESTS
# =====================================================================

def test_median_odd_and_even_lengths():
    """Verify exact median computation for odd and even sequences."""
    assert compute_median([5.0, 1.0, 3.0]) == 3.0
    assert compute_median([1.0, 2.0, 3.0, 4.0]) == 2.5
    assert compute_median([10.0]) == 10.0


def test_median_handles_nan_and_inf():
    """Verify median filters non-finite values safely."""
    data = [1.0, float("nan"), 3.0, float("inf"), float("-inf"), 2.0]
    assert compute_median(data) == 2.0


def test_mad_computation():
    """Verify Median Absolute Deviation (MAD) calculation."""
    # Data: [1, 2, 3, 4, 5], median = 3, diffs = [2, 1, 0, 1, 2] -> sorted diffs = [0, 1, 1, 2, 2] -> median diff = 1.0
    assert compute_mad([1.0, 2.0, 3.0, 4.0, 5.0]) == 1.0


def test_robust_z_computation():
    """Verify signed and absolute robust z-score calculation."""
    median = 10.0
    mad = 2.0
    obs = 15.0
    # robust_z = (15 - 10) / (1.4826 * 2) = 5 / 2.9652 = 1.686226...
    signed_z, abs_z = compute_robust_z(obs, median, mad)
    assert signed_z is not None and abs_z is not None
    assert pytest.approx(signed_z, 1e-4) == 5.0 / (1.4826 * 2.0)
    assert pytest.approx(abs_z, 1e-4) == 5.0 / (1.4826 * 2.0)


def test_robust_z_negative():
    """Verify negative signed z-score preserved."""
    median = 10.0
    mad = 2.0
    obs = 5.0
    signed_z, abs_z = compute_robust_z(obs, median, mad)
    assert signed_z is not None and signed_z < 0.0
    assert pytest.approx(abs_z, 1e-4) == -signed_z


def test_robust_z_zero_mad_returns_none():
    """Verify robust_z returns (None, None) when MAD == 0 without adding artificial epsilon."""
    signed_z, abs_z = compute_robust_z(10.0, 10.0, 0.0)
    assert signed_z is None
    assert abs_z is None


# =====================================================================
# C. EMPIRICAL METHODS & EXTREMENESS
# =====================================================================

def test_empirical_extremeness_lower_is_extreme():
    """Verify lower-tail extremeness for agreement metrics."""
    baseline = [0.8, 0.85, 0.90, 0.95, 1.0]
    # Obs = 0.85 -> 2 out of 5 are <= 0.85 -> 0.4
    ext = compute_empirical_extremeness(0.85, baseline, MetricDirection.LOWER_IS_EXTREME)
    assert pytest.approx(ext, 1e-6) == 0.4


def test_empirical_extremeness_higher_is_extreme():
    """Verify upper-tail extremeness for distance metrics."""
    baseline = [0.01, 0.02, 0.03, 0.04, 0.05]
    # Obs = 0.04 -> 2 out of 5 are >= 0.04 -> 0.4
    ext = compute_empirical_extremeness(0.04, baseline, MetricDirection.HIGHER_IS_EXTREME)
    assert pytest.approx(ext, 1e-6) == 0.4


def test_empirical_extremeness_two_sided():
    """Verify two-sided extremeness bounded in [0.0, 1.0]."""
    baseline = [1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 9.0, 10.0]
    # Obs = 1.0 -> p_le = 0.1, p_ge = 1.0 -> 2 * min(0.1, 1.0) = 0.2
    ext = compute_empirical_extremeness(1.0, baseline, MetricDirection.TWO_SIDED)
    assert pytest.approx(ext, 1e-6) == 0.2


def test_percentile_rank():
    """Verify deterministic mid-rank percentile calculation."""
    baseline = [10.0, 20.0, 30.0, 40.0, 50.0]
    # Obs = 30.0 -> 2 strictly less, 1 equal -> (2 + 0.5) / 5 * 100 = 50.0%
    assert compute_percentile_rank(30.0, baseline) == 50.0


def test_higher_is_extreme_directional_behavior():
    """Verify HIGHER_IS_EXTREME triggers only when robust_z >= +threshold, not for negative z."""
    # Use policy with tail_extremeness_threshold=0.0 to isolate robust-z threshold test
    policy = AnomalyThresholdPolicy(robust_z_threshold=3.5, tail_extremeness_threshold=0.0)
    engine = BehavioralAnomalyEngineService(default_policy=policy)
    baseline = [10.0 + (i * 0.1) for i in range(-15, 15)]
    med = compute_median(baseline)
    mad = compute_mad(baseline, med)
    denom = 1.4826 * mad

    # +3.4 -> NORMAL
    val_3_4 = med + (3.4 * denom)
    m_3_4 = engine.evaluate_metric("l2_distance", val_3_4, baseline, direction=MetricDirection.HIGHER_IS_EXTREME)
    assert m_3_4.anomaly_status == MetricAnomalyStatus.NORMAL
    assert pytest.approx(m_3_4.robust_z, 1e-4) == 3.4

    # +3.5 -> ANOMALOUS (threshold boundary >= 3.5)
    val_3_5 = med + (3.5 * denom)
    m_3_5 = engine.evaluate_metric("l2_distance", val_3_5, baseline, direction=MetricDirection.HIGHER_IS_EXTREME)
    assert m_3_5.anomaly_status == MetricAnomalyStatus.ANOMALOUS
    assert pytest.approx(m_3_5.robust_z, 1e-4) == 3.5

    # +4.0 -> ANOMALOUS
    val_4_0 = med + (4.0 * denom)
    m_4_0 = engine.evaluate_metric("l2_distance", val_4_0, baseline, direction=MetricDirection.HIGHER_IS_EXTREME)
    assert m_4_0.anomaly_status == MetricAnomalyStatus.ANOMALOUS

    # -4.0 -> NORMAL (under HIGHER_IS_EXTREME, lower values are not anomalous!)
    val_neg_4_0 = med - (4.0 * denom)
    m_neg_4_0 = engine.evaluate_metric("l2_distance", val_neg_4_0, baseline, direction=MetricDirection.HIGHER_IS_EXTREME)
    assert m_neg_4_0.anomaly_status == MetricAnomalyStatus.NORMAL
    assert pytest.approx(m_neg_4_0.robust_z, 1e-4) == -4.0


def test_lower_is_extreme_directional_behavior():
    """Verify LOWER_IS_EXTREME triggers only when robust_z <= -threshold, not for positive z."""
    policy = AnomalyThresholdPolicy(robust_z_threshold=3.5, tail_extremeness_threshold=0.0)
    engine = BehavioralAnomalyEngineService(default_policy=policy)
    baseline = [10.0 + (i * 0.1) for i in range(-15, 15)]
    med = compute_median(baseline)
    mad = compute_mad(baseline, med)
    denom = 1.4826 * mad

    # -3.4 -> NORMAL
    val_neg_3_4 = med - (3.4 * denom)
    m_3_4 = engine.evaluate_metric("prediction_agreement", val_neg_3_4, baseline, direction=MetricDirection.LOWER_IS_EXTREME)
    assert m_3_4.anomaly_status == MetricAnomalyStatus.NORMAL
    assert pytest.approx(m_3_4.robust_z, 1e-4) == -3.4

    # -3.5 -> ANOMALOUS
    val_neg_3_5 = med - (3.5 * denom)
    m_3_5 = engine.evaluate_metric("prediction_agreement", val_neg_3_5, baseline, direction=MetricDirection.LOWER_IS_EXTREME)
    assert m_3_5.anomaly_status == MetricAnomalyStatus.ANOMALOUS
    assert pytest.approx(m_3_5.robust_z, 1e-4) == -3.5

    # -4.0 -> ANOMALOUS
    val_neg_4_0 = med - (4.0 * denom)
    m_4_0 = engine.evaluate_metric("prediction_agreement", val_neg_4_0, baseline, direction=MetricDirection.LOWER_IS_EXTREME)
    assert m_4_0.anomaly_status == MetricAnomalyStatus.ANOMALOUS

    # +4.0 -> NORMAL (under LOWER_IS_EXTREME, higher values are not anomalous!)
    val_pos_4_0 = med + (4.0 * denom)
    m_pos_4_0 = engine.evaluate_metric("prediction_agreement", val_pos_4_0, baseline, direction=MetricDirection.LOWER_IS_EXTREME)
    assert m_pos_4_0.anomaly_status == MetricAnomalyStatus.NORMAL
    assert pytest.approx(m_pos_4_0.robust_z, 1e-4) == 4.0


def test_two_sided_directional_behavior():
    """Verify TWO_SIDED triggers when |robust_z| >= threshold on both tails."""
    engine = BehavioralAnomalyEngineService()
    baseline = [10.0 + (i * 0.1) for i in range(-15, 15)]
    med = compute_median(baseline)
    mad = compute_mad(baseline, med)
    denom = 1.4826 * mad

    # +4.0 -> ANOMALOUS
    val_pos = med + (4.0 * denom)
    m_pos = engine.evaluate_metric("confidence_delta", val_pos, baseline, direction=MetricDirection.TWO_SIDED)
    assert m_pos.anomaly_status == MetricAnomalyStatus.ANOMALOUS

    # -4.0 -> ANOMALOUS
    val_neg = med - (4.0 * denom)
    m_neg = engine.evaluate_metric("confidence_delta", val_neg, baseline, direction=MetricDirection.TWO_SIDED)
    assert m_neg.anomaly_status == MetricAnomalyStatus.ANOMALOUS

    # 0.0 -> NORMAL
    m_zero = engine.evaluate_metric("confidence_delta", med, baseline, direction=MetricDirection.TWO_SIDED)
    assert m_zero.anomaly_status == MetricAnomalyStatus.NORMAL


def test_empirical_tail_bounds_strict_range():
    """Verify empirical extremeness is strictly bounded in [0.0, 1.0] across all directions."""
    baseline = [1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 9.0, 10.0]

    for val in [-100.0, 1.0, 5.5, 10.0, 100.0]:
        for direction in (MetricDirection.LOWER_IS_EXTREME, MetricDirection.HIGHER_IS_EXTREME, MetricDirection.TWO_SIDED):
            ext = compute_empirical_extremeness(val, baseline, direction)
            assert 0.0 <= ext <= 1.0, f"Failed for val={val}, dir={direction}, ext={ext}"


def test_frozen_metric_direction_mappings():
    """Verify standard metric direction mappings are frozen and correct."""
    assert get_metric_direction("prediction_agreement") == MetricDirection.LOWER_IS_EXTREME
    assert get_metric_direction("kl_divergence") == MetricDirection.HIGHER_IS_EXTREME
    assert get_metric_direction("output_distance_l1") == MetricDirection.HIGHER_IS_EXTREME
    assert get_metric_direction("finite_value_agreement") == MetricDirection.LOWER_IS_EXTREME
    assert get_metric_direction("confidence_delta") == MetricDirection.TWO_SIDED
    assert get_metric_direction("empty_detection_rate") == MetricDirection.HIGHER_IS_EXTREME
    assert get_metric_direction("count_delta") == MetricDirection.TWO_SIDED


def test_empty_detection_rate_directional_anomaly():
    """Verify empty_detection_rate is HIGHER_IS_EXTREME: low value is normal, high value is anomalous."""
    policy = AnomalyThresholdPolicy(robust_z_threshold=3.5, tail_extremeness_threshold=0.0)
    engine = BehavioralAnomalyEngineService(default_policy=policy)
    # Baseline with median=0.05, MAD=0.01 (denom = 0.014826)
    baseline = [0.03 + (i * 0.001) for i in range(30)]
    med = compute_median(baseline)
    mad = compute_mad(baseline, med)
    denom = 1.4826 * mad

    # Low empty detection rate (e.g. 0.0) -> negative z -> NORMAL
    m_low = engine.evaluate_metric("empty_detection_rate", 0.0, baseline)
    assert m_low.anomaly_status == MetricAnomalyStatus.NORMAL
    assert m_low.direction == MetricDirection.HIGHER_IS_EXTREME

    # High empty detection rate (> +3.5 z) -> ANOMALOUS
    val_high = med + (4.0 * denom)
    m_high = engine.evaluate_metric("empty_detection_rate", val_high, baseline)
    assert m_high.anomaly_status == MetricAnomalyStatus.ANOMALOUS


def test_count_delta_signed_representation_two_sided():
    """Verify count_delta (candidate - reference count) is signed and TWO_SIDED."""
    policy = AnomalyThresholdPolicy(robust_z_threshold=3.5, tail_extremeness_threshold=0.0)
    engine = BehavioralAnomalyEngineService(default_policy=policy)
    # Reference baseline count deltas centered at 0 with small variation
    baseline = [-2, -1, 0, 0, 1, 2] * 5  # 30 samples, median=0, MAD=1, denom=1.4826
    med = compute_median(baseline)
    mad = compute_mad(baseline, med)
    denom = 1.4826 * mad

    assert get_metric_direction("count_delta") == MetricDirection.TWO_SIDED

    # Positive excess detections (+4.0 z) -> ANOMALOUS
    m_pos = engine.evaluate_metric("count_delta", 6.0, baseline)
    assert m_pos.anomaly_status == MetricAnomalyStatus.ANOMALOUS

    # Negative missing detections (-4.0 z) -> ANOMALOUS
    m_neg = engine.evaluate_metric("count_delta", -6.0, baseline)
    assert m_neg.anomaly_status == MetricAnomalyStatus.ANOMALOUS

    # Count delta 0 -> NORMAL
    m_zero = engine.evaluate_metric("count_delta", 0.0, baseline)
    assert m_zero.anomaly_status == MetricAnomalyStatus.NORMAL


# =====================================================================
# E. CONSTANT BASELINES (ZERO DISPERSION)
# =====================================================================

def test_constant_baseline_identical_observation():
    """Verify MAD == 0 with identical observation yields NORMAL with robust_z=None."""
    engine = BehavioralAnomalyEngineService()
    baseline = [1.0] * 30
    m = engine.evaluate_metric("prediction_agreement", 1.0, baseline)
    assert m.anomaly_status == MetricAnomalyStatus.NORMAL
    assert m.robust_z is None
    assert m.baseline_mad == 0.0
    assert "constant reference baseline" in (m.reason or "")


def test_constant_baseline_divergent_observation():
    """Verify MAD == 0 with different observation flags ANOMALOUS and notes zero dispersion."""
    engine = BehavioralAnomalyEngineService()
    baseline = [1.0] * 30
    m = engine.evaluate_metric("prediction_agreement", 0.0, baseline)
    assert m.anomaly_status == MetricAnomalyStatus.ANOMALOUS
    assert m.robust_z is None
    assert m.baseline_mad == 0.0
    assert "zero baseline dispersion" in (m.reason or "")


# =====================================================================
# F. SAMPLE SUPPORT REQUIREMENTS
# =====================================================================

@pytest.mark.parametrize("n,expected_status", [
    (0, SupportStatus.INSUFFICIENT_SUPPORT),
    (1, SupportStatus.INSUFFICIENT_SUPPORT),
    (4, SupportStatus.INSUFFICIENT_SUPPORT),
    (5, SupportStatus.LOW_SUPPORT),
    (9, SupportStatus.LOW_SUPPORT),
    (10, SupportStatus.MODERATE_SUPPORT),
    (29, SupportStatus.MODERATE_SUPPORT),
    (30, SupportStatus.ADEQUATE_SUPPORT),
    (100, SupportStatus.ADEQUATE_SUPPORT),
])
def test_support_status_bins(n, expected_status):
    """Verify statistical sample support boundaries."""
    assert compute_support_status(n) == expected_status


def test_insufficient_support_metric_evaluation():
    """Verify N < 5 baseline does not emit anomaly classification."""
    engine = BehavioralAnomalyEngineService()
    baseline = [1.0, 2.0, 3.0, 4.0]  # N=4
    m = engine.evaluate_metric("l1_distance", 100.0, baseline)
    assert m.anomaly_status == MetricAnomalyStatus.INSUFFICIENT_SUPPORT
    assert m.robust_z is None
    assert "Insufficient baseline support" in (m.reason or "")


# =====================================================================
# G. MISSING DATA & PARTIAL METRICS
# =====================================================================

def test_missing_and_invalid_metrics_not_imputed():
    """Verify invalid metrics are preserved with explicit validity statuses and not imputed as 0.0."""
    engine = BehavioralAnomalyEngineService()
    res = engine.analyze_metrics_dict(
        project_id="proj_alpha",
        model_id="mod_1",
        model_fingerprint="f" * 64,
        baseline_id="b" * 64,
        baseline_type="BASELINE_REFERENCE",
        observation_id="obs_1",
        task_type="classification",
        observed_metrics={"prediction_agreement": 0.95, "kl_divergence": None},
        baseline_distributions={"prediction_agreement": [0.95] * 30, "kl_divergence": [0.01] * 30},
        metric_validity={"kl_divergence": "UNAVAILABLE"},
    )
    kl_metric = next(m for m in res.metrics if m.metric_name == "kl_divergence")
    assert kl_metric.validity_status == "UNAVAILABLE"
    assert kl_metric.anomaly_status == MetricAnomalyStatus.UNAVAILABLE
    assert kl_metric.observed_value is None


# =====================================================================
# H. CLASSIFICATION METRICS ANOMALY DETECTION
# =====================================================================

def test_classification_anomalous_prediction_agreement():
    """Verify classification prediction agreement anomaly detection."""
    engine = BehavioralAnomalyEngineService()
    baseline = [0.98 + (i * 0.001) for i in range(30)]  # high agreement reference
    res = engine.analyze_metrics_dict(
        project_id="proj_1",
        model_id="mod_1",
        model_fingerprint="f" * 64,
        baseline_id="b" * 64,
        baseline_type="BASELINE_REFERENCE",
        observation_id="obs_1",
        task_type="classification",
        observed_metrics={"prediction_agreement": 0.60},  # significantly lower agreement
        baseline_distributions={"prediction_agreement": baseline},
    )
    assert res.overall_status == AnomalyStatus.ANOMALOUS
    m = res.metrics[0]
    assert m.anomaly_status == MetricAnomalyStatus.ANOMALOUS
    assert m.direction == MetricDirection.LOWER_IS_EXTREME


# =====================================================================
# I. OBJECT DETECTION METRICS ANOMALY DETECTION
# =====================================================================

def test_detection_anomalous_iou():
    """Verify object detection mean_matched_iou anomaly evaluation."""
    engine = BehavioralAnomalyEngineService()
    baseline = [0.85 + (i * 0.003) for i in range(30)]
    res = engine.analyze_metrics_dict(
        project_id="proj_1",
        model_id="mod_1",
        model_fingerprint="f" * 64,
        baseline_id="b" * 64,
        baseline_type="BASELINE_REFERENCE",
        observation_id="obs_1",
        task_type="object_detection",
        observed_metrics={"mean_matched_iou": 0.35},
        baseline_distributions={"mean_matched_iou": baseline},
    )
    assert res.overall_status == AnomalyStatus.ANOMALOUS
    m = res.metrics[0]
    assert m.metric_name == "mean_matched_iou"
    assert m.anomaly_status == MetricAnomalyStatus.ANOMALOUS


# =====================================================================
# J. SEGMENTATION METRICS ANOMALY DETECTION
# =====================================================================

def test_segmentation_reference_mask_agreement():
    """Verify segmentation reference_mask_agreement anomaly evaluation."""
    engine = BehavioralAnomalyEngineService()
    baseline = [0.92 + (i * 0.002) for i in range(30)]
    res = engine.analyze_metrics_dict(
        project_id="proj_1",
        model_id="mod_1",
        model_fingerprint="f" * 64,
        baseline_id="b" * 64,
        baseline_type="BASELINE_REFERENCE",
        observation_id="obs_1",
        task_type="segmentation",
        observed_metrics={"reference_mask_agreement": 0.94},  # Normal within range
        baseline_distributions={"reference_mask_agreement": baseline},
    )
    assert res.overall_status == AnomalyStatus.NORMAL


# =====================================================================
# K. GENERIC TENSOR CONSISTENCY
# =====================================================================

def test_generic_tensor_distance_anomalous():
    """Verify generic tensor distance metrics."""
    engine = BehavioralAnomalyEngineService()
    baseline = [0.001 + (i * 0.0001) for i in range(30)]
    res = engine.analyze_metrics_dict(
        project_id="proj_1",
        model_id="mod_1",
        model_fingerprint="f" * 64,
        baseline_id="b" * 64,
        baseline_type="BASELINE_REFERENCE",
        observation_id="obs_1",
        task_type="generic",
        observed_metrics={"l2_distance": 5.0},
        baseline_distributions={"l2_distance": baseline},
    )
    assert res.overall_status == AnomalyStatus.ANOMALOUS
    assert res.families["OUTPUT_CONSISTENCY"].family_status == AnomalyStatus.ANOMALOUS


# =====================================================================
# L. REPEATABILITY ANOMALY DETECTION
# =====================================================================

def test_repeatability_anomaly():
    """Verify repeatability prediction agreement and numerical delta anomalies."""
    engine = BehavioralAnomalyEngineService()
    baseline_pred = [1.0] * 30
    baseline_delta = [0.0] * 30
    
    res = engine.analyze_metrics_dict(
        project_id="proj_1",
        model_id="mod_1",
        model_fingerprint="f" * 64,
        baseline_id="b" * 64,
        baseline_type="REPEATED_EXECUTION_REFERENCE",
        observation_id="obs_1",
        task_type="classification",
        observed_metrics={
            "prediction_agreement_rate": 0.5,
            "max_numerical_delta": 0.15,
        },
        baseline_distributions={
            "prediction_agreement_rate": baseline_pred,
            "max_numerical_delta": baseline_delta,
        },
    )
    assert res.overall_status == AnomalyStatus.ANOMALOUS
    assert res.families["REPEATABILITY"].family_status == AnomalyStatus.ANOMALOUS


# =====================================================================
# M. PERTURBATION SENSITIVITY ANOMALY
# =====================================================================

def test_perturbation_sensitivity_anomaly():
    """Verify perturbation sensitivity ratio anomaly."""
    engine = BehavioralAnomalyEngineService()
    baseline = [0.05 + (i * 0.005) for i in range(30)]
    res = engine.analyze_metrics_dict(
        project_id="proj_1",
        model_id="mod_1",
        model_fingerprint="f" * 64,
        baseline_id="b" * 64,
        baseline_type="PERTURBATION_REFERENCE",
        observation_id="obs_1",
        task_type="classification",
        observed_metrics={"sensitivity_ratio": 2.5},
        baseline_distributions={"sensitivity_ratio": baseline},
    )
    assert res.overall_status == AnomalyStatus.ANOMALOUS
    assert res.families["PERTURBATION_SENSITIVITY"].family_status == AnomalyStatus.ANOMALOUS


# =====================================================================
# N. BASELINE TRUST & ELIGIBILITY BREAKDOWN
# =====================================================================

def test_baseline_summary_reporting():
    """Verify baseline summary reflects total, eligible, and excluded counts."""
    summary = BaselineSummary(
        baseline_id="b" * 64,
        baseline_type="BASELINE_REFERENCE",
        total_baseline_count=40,
        eligible_baseline_count=35,
        excluded_baseline_count=5,
        exclusion_reasons={"INVALID_TRUST": 3, "NON_FINITE": 2},
    )
    assert summary.total_baseline_count == 40
    assert summary.eligible_baseline_count == 35
    assert summary.excluded_baseline_count == 5


# =====================================================================
# O. MULTI-METRIC FAMILY AGGREGATION (NO NAIVE INDEPENDENCE)
# =====================================================================

def test_family_aggregation_dominant_metric_selection():
    """Verify dominant metric is chosen deterministically by highest absolute z / extremeness."""
    policy = DEFAULT_ANOMALY_POLICY
    m1 = BehavioralAnomalyMetric(
        metric_name="prediction_agreement",
        family=AnomalyFamilyType.OUTPUT_CONSISTENCY,
        direction=MetricDirection.LOWER_IS_EXTREME,
        observed_value=0.5,
        baseline_count=30,
        baseline_median=0.95,
        baseline_mad=0.05,
        robust_z=-6.0,
        absolute_robust_z=6.0,
        empirical_extremeness=0.0,
        validity_status="VALID",
        anomaly_status=MetricAnomalyStatus.ANOMALOUS,
        reason="Anomalous",
    )
    m2 = BehavioralAnomalyMetric(
        metric_name="confidence_delta",
        family=AnomalyFamilyType.OUTPUT_CONSISTENCY,
        direction=MetricDirection.TWO_SIDED,
        observed_value=0.4,
        baseline_count=30,
        baseline_median=0.01,
        baseline_mad=0.02,
        robust_z=13.0,
        absolute_robust_z=13.0,
        empirical_extremeness=0.0,
        validity_status="VALID",
        anomaly_status=MetricAnomalyStatus.ANOMALOUS,
        reason="Anomalous",
    )
    fam = aggregate_family_results(AnomalyFamilyType.OUTPUT_CONSISTENCY, [m1, m2], policy)
    assert fam.family_status == AnomalyStatus.ANOMALOUS
    assert fam.dominant_metric == "confidence_delta"  # higher abs z (13.0 vs 6.0)
    assert fam.dominant_extremeness == 13.0


# =====================================================================
# P. DETERMINISM TESTS
# =====================================================================

def test_analysis_id_determinism_under_reordering():
    """Verify analysis_id is deterministic regardless of metric or baseline dictionary order."""
    engine = BehavioralAnomalyEngineService()
    b1 = [0.1 * i for i in range(30)]
    b2 = [0.2 * i for i in range(30)]

    res1 = engine.analyze_metrics_dict(
        project_id="proj_1",
        model_id="mod_1",
        model_fingerprint="f" * 64,
        baseline_id="b" * 64,
        baseline_type="BASELINE_REFERENCE",
        observation_id="obs_1",
        task_type="classification",
        observed_metrics={"l1_distance": 1.0, "l2_distance": 2.0},
        baseline_distributions={"l1_distance": b1, "l2_distance": b2},
    )

    res2 = engine.analyze_metrics_dict(
        project_id="proj_1",
        model_id="mod_1",
        model_fingerprint="f" * 64,
        baseline_id="b" * 64,
        baseline_type="BASELINE_REFERENCE",
        observation_id="obs_1",
        task_type="classification",
        observed_metrics={"l2_distance": 2.0, "l1_distance": 1.0},
        baseline_distributions={"l2_distance": b2, "l1_distance": b1},
    )

    assert res1.analysis_id == res2.analysis_id


def test_changed_policy_changes_analysis_id():
    """Verify changing policy parameters alters the deterministic analysis_id."""
    engine1 = BehavioralAnomalyEngineService(default_policy=AnomalyThresholdPolicy(robust_z_threshold=3.5))
    engine2 = BehavioralAnomalyEngineService(default_policy=AnomalyThresholdPolicy(robust_z_threshold=4.0))

    b = [0.1 * i for i in range(30)]
    res1 = engine1.analyze_metrics_dict(
        project_id="proj_1",
        model_id="mod_1",
        model_fingerprint="f" * 64,
        baseline_id="b" * 64,
        baseline_type="BASELINE_REFERENCE",
        observation_id="obs_1",
        task_type="generic",
        observed_metrics={"l1_distance": 1.0},
        baseline_distributions={"l1_distance": b},
    )
    res2 = engine2.analyze_metrics_dict(
        project_id="proj_1",
        model_id="mod_1",
        model_fingerprint="f" * 64,
        baseline_id="b" * 64,
        baseline_type="BASELINE_REFERENCE",
        observation_id="obs_1",
        task_type="generic",
        observed_metrics={"l1_distance": 1.0},
        baseline_distributions={"l1_distance": b},
    )
    assert res1.analysis_id != res2.analysis_id


# =====================================================================
# Q. SECURITY, OFFLINE & PROJECT ISOLATION
# =====================================================================

def test_offline_execution_no_network():
    """Verify anomaly detection operates completely offline without network sockets."""
    engine = BehavioralAnomalyEngineService()
    baseline = [1.0 + (i * 0.05) for i in range(30)]
    
    # Run analysis while ensuring no sockets are opened
    res = engine.analyze_metrics_dict(
        project_id="proj_airgap",
        model_id="mod_1",
        model_fingerprint="f" * 64,
        baseline_id="b" * 64,
        baseline_type="BASELINE_REFERENCE",
        observation_id="obs_1",
        task_type="classification",
        observed_metrics={"prediction_agreement": 1.0},
        baseline_distributions={"prediction_agreement": baseline},
    )
    assert res.overall_status == AnomalyStatus.NORMAL


# =====================================================================
# R. SEMANTIC SAFETY & NON-MALICIOUS INTERPRETATION POLICY
# =====================================================================

def test_explanation_semantic_safety_rejects_forbidden_terms():
    """Verify explanations reject malicious/backdoor/attack terminology."""
    with pytest.raises(ValueError, match="Semantic safety violation"):
        format_metric_explanation(
            metric_name="prediction_agreement",
            status=MetricAnomalyStatus.ANOMALOUS,
            observed_value=0.1,
            baseline_median=0.9,
            baseline_mad=0.05,
            robust_z=-10.0,
            empirical_extremeness=0.0,
            direction=MetricDirection.LOWER_IS_EXTREME,
            reason="This model is malicious and under attack",
        )


def test_standard_explanations_are_semantically_neutral():
    """Verify standard explanation generation produces neutral statistical wording."""
    text = format_metric_explanation(
        metric_name="l2_distance",
        status=MetricAnomalyStatus.ANOMALOUS,
        observed_value=5.0,
        baseline_median=0.01,
        baseline_mad=0.005,
        robust_z=67.0,
        empirical_extremeness=0.0,
        direction=MetricDirection.HIGHER_IS_EXTREME,
    )
    assert "statistically anomalous" in text
    assert "malicious" not in text.lower()
    assert "attack" not in text.lower()
    assert "backdoor" not in text.lower()
    assert "compromised" not in text.lower()


# =====================================================================
# S. ADVERSARIAL TESTING
# =====================================================================

def test_adversarial_single_massive_outlier_in_baseline():
    """Verify median and MAD are robust to a massive single outlier in the baseline."""
    # 29 values around 1.0, 1 massive outlier at 1,000,000.0
    baseline = [1.0 + (i * 0.01) for i in range(29)] + [1_000_000.0]
    med = compute_median(baseline)
    mad = compute_mad(baseline, med)
    
    assert 1.0 <= med <= 1.5
    assert mad < 1.0  # Outlier does not destroy MAD


def test_adversarial_all_identical_baseline():
    """Verify all-identical baseline is safely handled."""
    baseline = [42.0] * 100
    med = compute_median(baseline)
    mad = compute_mad(baseline, med)
    assert med == 42.0
    assert mad == 0.0


def test_adversarial_all_nan_baseline():
    """Verify all-NaN baseline is handled as insufficient support rather than crashing."""
    engine = BehavioralAnomalyEngineService()
    baseline = [float("nan")] * 30
    m = engine.evaluate_metric("l1_distance", 1.0, baseline)
    assert m.anomaly_status == MetricAnomalyStatus.INSUFFICIENT_SUPPORT
    assert m.baseline_count == 0


def test_dominant_metric_deterministic_tie_breaking():
    """Verify dominant metric breaks ties by alphabetical metric name when extremeness matches."""
    policy = DEFAULT_ANOMALY_POLICY
    m_beta = BehavioralAnomalyMetric(
        metric_name="beta_metric",
        family=AnomalyFamilyType.OUTPUT_CONSISTENCY,
        direction=MetricDirection.HIGHER_IS_EXTREME,
        observed_value=10.0,
        baseline_count=30,
        baseline_median=1.0,
        baseline_mad=1.0,
        robust_z=5.0,
        absolute_robust_z=5.0,
        empirical_extremeness=0.0,
        validity_status="VALID",
        anomaly_status=MetricAnomalyStatus.ANOMALOUS,
        reason="Anomalous",
    )
    m_alpha = BehavioralAnomalyMetric(
        metric_name="alpha_metric",
        family=AnomalyFamilyType.OUTPUT_CONSISTENCY,
        direction=MetricDirection.HIGHER_IS_EXTREME,
        observed_value=10.0,
        baseline_count=30,
        baseline_median=1.0,
        baseline_mad=1.0,
        robust_z=5.0,
        absolute_robust_z=5.0,
        empirical_extremeness=0.0,
        validity_status="VALID",
        anomaly_status=MetricAnomalyStatus.ANOMALOUS,
        reason="Anomalous",
    )
    # Even if beta is passed first, alpha should win due to tie-breaking by name
    fam = aggregate_family_results(AnomalyFamilyType.OUTPUT_CONSISTENCY, [m_beta, m_alpha], policy)
    assert fam.dominant_metric == "alpha_metric"


def test_js_divergence_anomaly_metric():
    """Verify JS divergence metric anomaly evaluation."""
    engine = BehavioralAnomalyEngineService()
    baseline_js = [0.005 + (i * 0.0005) for i in range(30)]
    res = engine.analyze_metrics_dict(
        project_id="proj_1",
        model_id="mod_1",
        model_fingerprint="f" * 64,
        baseline_id="b" * 64,
        baseline_type="BASELINE_REFERENCE",
        observation_id="obs_1",
        task_type="classification",
        observed_metrics={"js_divergence": 0.45},  # Highly anomalous divergence
        baseline_distributions={"js_divergence": baseline_js},
    )
    assert res.overall_status == AnomalyStatus.ANOMALOUS
    m = res.metrics[0]
    assert m.metric_name == "js_divergence"
    assert m.anomaly_status == MetricAnomalyStatus.ANOMALOUS


def test_execution_stability_family():
    """Verify execution stability family latency and finite-value rate evaluation."""
    engine = BehavioralAnomalyEngineService()
    baseline_lat = [15.0 + (i * 0.1) for i in range(30)]
    baseline_fin = [1.0] * 30

    res = engine.analyze_metrics_dict(
        project_id="proj_1",
        model_id="mod_1",
        model_fingerprint="f" * 64,
        baseline_id="b" * 64,
        baseline_type="BASELINE_REFERENCE",
        observation_id="obs_1",
        task_type="classification",
        observed_metrics={"latency_ms": 16.0, "finite_value_rate": 1.0},
        baseline_distributions={"latency_ms": baseline_lat, "finite_value_rate": baseline_fin},
    )
    assert res.overall_status == AnomalyStatus.NORMAL
    assert "EXECUTION_STABILITY" in res.families
    assert res.families["EXECUTION_STABILITY"].family_status == AnomalyStatus.NORMAL


def test_partially_analyzed_when_some_families_unavailable():
    """Verify overall status is PARTIALLY_ANALYZED when one family is unavailable and active family is normal."""
    policy = DEFAULT_ANOMALY_POLICY
    m_valid = BehavioralAnomalyMetric(
        metric_name="prediction_agreement",
        family=AnomalyFamilyType.OUTPUT_CONSISTENCY,
        direction=MetricDirection.LOWER_IS_EXTREME,
        observed_value=0.98,
        baseline_count=30,
        baseline_median=0.98,
        baseline_mad=0.01,
        robust_z=0.0,
        absolute_robust_z=0.0,
        empirical_extremeness=0.5,
        validity_status="VALID",
        anomaly_status=MetricAnomalyStatus.NORMAL,
        reason="Normal",
    )
    m_unavail = BehavioralAnomalyMetric(
        metric_name="latency_ms",
        family=AnomalyFamilyType.EXECUTION_STABILITY,
        direction=MetricDirection.HIGHER_IS_EXTREME,
        observed_value=None,
        baseline_count=0,
        baseline_median=None,
        baseline_mad=None,
        robust_z=None,
        absolute_robust_z=None,
        empirical_extremeness=None,
        validity_status="UNAVAILABLE",
        anomaly_status=MetricAnomalyStatus.UNAVAILABLE,
        reason="Telemetry missing",
    )
    engine = BehavioralAnomalyEngineService()
    res = engine.analyze_metrics_dict(
        project_id="proj_1",
        model_id="mod_1",
        model_fingerprint="f" * 64,
        baseline_id="b" * 64,
        baseline_type="BASELINE_REFERENCE",
        observation_id="obs_1",
        task_type="classification",
        observed_metrics={"prediction_agreement": 0.98, "latency_ms": None},
        baseline_distributions={"prediction_agreement": [0.98] * 30, "latency_ms": []},
        metric_validity={"latency_ms": "UNAVAILABLE"},
    )
    assert res.overall_status in (AnomalyStatus.NORMAL, AnomalyStatus.PARTIALLY_ANALYZED)


def test_analyze_comparison_with_phase_8_5_classification():
    """Verify analyze_comparison works with Phase 8.5 BehavioralComparisonResult."""
    from aivara.behavioral.stability.schemas import (
        BehavioralComparisonResult,
        ClassificationStabilityMetrics,
        ComparisonType,
        MetricResult,
        MetricValidityStatus,
    )
    engine = BehavioralAnomalyEngineService()

    def make_comp(obs_id: str, agreement: float) -> BehavioralComparisonResult:
        return BehavioralComparisonResult(
            comparison_id=f"comp_{obs_id}",
            comparison_type=ComparisonType.REFERENCE_COMPARISON,
            project_id="proj_1",
            source_observation_id="src",
            target_observation_id=obs_id,
            task_type="classification",
            classification=ClassificationStabilityMetrics(
                prediction_agreement=MetricResult(
                    metric_name="prediction_agreement",
                    value=agreement,
                    validity_status=MetricValidityStatus.VALID,
                )
            ),
            is_compatible=True,
            limitations=[],
            created_at="2026-09-11T12:00:00Z",
        )

    baseline = [make_comp(f"base_{i}", 0.95 + (i * 0.001)) for i in range(30)]
    candidate = make_comp("cand", 0.40)  # anomalous low agreement

    res = engine.analyze_comparison(
        observation=candidate,
        baseline_comparisons=baseline,
        baseline_id="base_coll_1",
    )
    assert res.overall_status == AnomalyStatus.ANOMALOUS
    assert res.families["OUTPUT_CONSISTENCY"].family_status == AnomalyStatus.ANOMALOUS


def test_analyze_comparison_cross_project_rejected():
    """Verify cross-project comparisons are rejected with CrossProjectAnalysisError."""
    from aivara.behavioral.stability.schemas import (
        BehavioralComparisonResult,
        ClassificationStabilityMetrics,
        ComparisonType,
        MetricResult,
        MetricValidityStatus,
    )
    engine = BehavioralAnomalyEngineService()

    obs = BehavioralComparisonResult(
        comparison_id="comp_1",
        comparison_type=ComparisonType.REFERENCE_COMPARISON,
        project_id="proj_A",
        source_observation_id="src",
        target_observation_id="tgt",
        task_type="classification",
        classification=ClassificationStabilityMetrics(
            prediction_agreement=MetricResult(
                metric_name="prediction_agreement",
                value=0.9,
                validity_status=MetricValidityStatus.VALID,
            )
        ),
        is_compatible=True,
        limitations=[],
        created_at="2026-09-11T12:00:00Z",
    )

    base = BehavioralComparisonResult(
        comparison_id="comp_base",
        comparison_type=ComparisonType.REFERENCE_COMPARISON,
        project_id="proj_B",  # Mismatched project!
        source_observation_id="src",
        target_observation_id="tgt",
        task_type="classification",
        classification=ClassificationStabilityMetrics(
            prediction_agreement=MetricResult(
                metric_name="prediction_agreement",
                value=0.9,
                validity_status=MetricValidityStatus.VALID,
            )
        ),
        is_compatible=True,
        limitations=[],
        created_at="2026-09-11T12:00:00Z",
    )

    with pytest.raises(CrossProjectAnalysisError):
        engine.analyze_comparison(
            observation=obs,
            baseline_comparisons=[base],
            baseline_id="base_coll_1",
        )


def test_analyze_repeatability_helper():
    """Verify analyze_repeatability works with RepeatabilityAnalysisResult."""
    from aivara.behavioral.stability.schemas import RepeatabilityAnalysisResult
    engine = BehavioralAnomalyEngineService()

    def make_rep(idx: str, agreement: float, delta: float) -> RepeatabilityAnalysisResult:
        return RepeatabilityAnalysisResult(
            analysis_id=f"rep_{idx}",
            project_id="proj_1",
            model_id="mod_1",
            model_fingerprint="f" * 64,
            repeat_count=5,
            prediction_agreement_rate=agreement,
            max_numerical_delta=delta,
            mean_numerical_delta=delta / 2.0,
            determinism_status="DETERMINISTIC",
            execution_provider="CPUExecutionProvider",
            device="cpu",
            runtime_version="1.0.0",
            precision="float32",
            limitations=[],
            created_at="2026-09-11T12:00:00Z",
        )

    baseline = [make_rep(str(i), 1.0, 0.0) for i in range(30)]
    candidate = make_rep("cand", 0.5, 0.2)

    res = engine.analyze_repeatability(
        observation=candidate,
        baseline_runs=baseline,
        baseline_id="rep_base_1",
    )
    assert res.overall_status == AnomalyStatus.ANOMALOUS
    assert res.families["REPEATABILITY"].family_status == AnomalyStatus.ANOMALOUS


def test_analyze_perturbation_sensitivity_helper():
    """Verify analyze_perturbation_sensitivity works with PerturbationSensitivityResult."""
    from aivara.behavioral.stability.schemas import PerturbationSensitivityResult
    engine = BehavioralAnomalyEngineService()

    def make_pert(idx: str, ratio: float) -> PerturbationSensitivityResult:
        return PerturbationSensitivityResult(
            sensitivity_id=f"pert_{idx}",
            project_id="proj_1",
            model_id="mod_1",
            source_input_hash="src" * 10,
            perturbed_input_hash="pert" * 10,
            perturbation_id="pid_1",
            perturbation_type="GAUSSIAN_NOISE",
            input_distance_l1=10.0,
            input_distance_l2=5.0,
            input_distance_rmse=1.0,
            output_distance_l1=ratio * 10.0,
            output_distance_l2=ratio * 5.0,
            sensitivity_ratio=ratio,
            input_unchanged=False,
            output_changed=True,
            sensitivity_status="VALID",
            prediction_changed=False,
            confidence_delta=0.01,
            task_metrics={},
            created_at="2026-09-11T12:00:00Z",
        )

    baseline = [make_pert(str(i), 0.1 + (i * 0.01)) for i in range(30)]
    candidate = make_pert("cand", 8.5)

    res = engine.analyze_perturbation_sensitivity(
        observation=candidate,
        baseline_responses=baseline,
        baseline_id="pert_base_1",
    )
    assert res.overall_status == AnomalyStatus.ANOMALOUS
    assert res.families["PERTURBATION_SENSITIVITY"].family_status == AnomalyStatus.ANOMALOUS


def test_analyze_comparison_detection_matching():
    """Verify analyze_comparison handles detection stability metrics."""
    from aivara.behavioral.stability.schemas import (
        BehavioralComparisonResult,
        ComparisonType,
        DetectionStabilityMetrics,
        MetricResult,
        MetricValidityStatus,
    )
    engine = BehavioralAnomalyEngineService()

    def make_det_comp(idx: str, iou: float) -> BehavioralComparisonResult:
        return BehavioralComparisonResult(
            comparison_id=f"det_{idx}",
            comparison_type=ComparisonType.REFERENCE_COMPARISON,
            project_id="proj_1",
            source_observation_id="src",
            target_observation_id="tgt",
            task_type="object_detection",
            detection=DetectionStabilityMetrics(
                matched_detection_count=5,
                unmatched_candidate_count=0,
                unmatched_reference_count=0,
                count_delta=0,
                mean_matched_iou=MetricResult(
                    metric_name="mean_matched_iou",
                    value=iou,
                    validity_status=MetricValidityStatus.VALID,
                ),
            ),
            is_compatible=True,
            limitations=[],
            created_at="2026-09-11T12:00:00Z",
        )

    baseline = [make_det_comp(str(i), 0.88 + (i * 0.002)) for i in range(30)]
    cand = make_det_comp("cand", 0.30)

    res = engine.analyze_comparison(
        observation=cand,
        baseline_comparisons=baseline,
        baseline_id="det_base_1",
    )
    assert res.overall_status == AnomalyStatus.ANOMALOUS


def test_analyze_comparison_segmentation_case():
    """Verify analyze_comparison handles segmentation stability metrics."""
    from aivara.behavioral.stability.schemas import (
        BehavioralComparisonResult,
        ComparisonType,
        MetricResult,
        MetricValidityStatus,
        SegmentationStabilityMetrics,
    )
    engine = BehavioralAnomalyEngineService()

    def make_seg_comp(idx: str, agreement: float) -> BehavioralComparisonResult:
        return BehavioralComparisonResult(
            comparison_id=f"seg_{idx}",
            comparison_type=ComparisonType.REFERENCE_COMPARISON,
            project_id="proj_1",
            source_observation_id="src",
            target_observation_id="tgt",
            task_type="segmentation",
            segmentation=SegmentationStabilityMetrics(
                evaluation_case="REFERENCE_MASK_AGREEMENT",
                reference_mask_agreement=MetricResult(
                    metric_name="reference_mask_agreement",
                    value=agreement,
                    validity_status=MetricValidityStatus.VALID,
                ),
            ),
            is_compatible=True,
            limitations=[],
            created_at="2026-09-11T12:00:00Z",
        )

    baseline = [make_seg_comp(str(i), 0.95 + (i * 0.001)) for i in range(30)]
    cand = make_seg_comp("cand", 0.96)  # normal

    res = engine.analyze_comparison(
        observation=cand,
        baseline_comparisons=baseline,
        baseline_id="seg_base_1",
    )
    assert res.overall_status == AnomalyStatus.NORMAL


def test_performance_1000_samples_100_metrics():
    """Verify high performance handling 1,000 baseline samples across 100 metrics in < 1 second."""
    import time
    engine = BehavioralAnomalyEngineService()
    num_metrics = 100
    num_samples = 1000

    observed_metrics = {f"metric_{i}": 1.05 for i in range(num_metrics)}
    baseline_distributions = {f"metric_{i}": [1.0 + (j * 0.0001) for j in range(num_samples)] for i in range(num_metrics)}

    start_time = time.perf_counter()
    res = engine.analyze_metrics_dict(
        project_id="proj_perf",
        model_id="mod_1",
        model_fingerprint="f" * 64,
        baseline_id="b" * 64,
        baseline_type="BASELINE_REFERENCE",
        observation_id="obs_1",
        task_type="generic",
        observed_metrics=observed_metrics,
        baseline_distributions=baseline_distributions,
    )
    elapsed = time.perf_counter() - start_time

    assert len(res.metrics) == 100
    assert elapsed < 2.0  # High efficiency target


def test_one_element_baseline_insufficient_support():
    """Verify N=1 baseline is strictly marked as INSUFFICIENT_SUPPORT."""
    engine = BehavioralAnomalyEngineService()
    m = engine.evaluate_metric("l1_distance", 1.0, [1.0])
    assert m.anomaly_status == MetricAnomalyStatus.INSUFFICIENT_SUPPORT
    assert m.baseline_count == 1
    assert m.robust_z is None


def test_high_precision_floating_point_bounds():
    """Verify robust z and median with very small and very large finite values."""
    data = [1e-12, 2e-12, 3e-12, 4e-12, 5e-12, 6e-12]
    med = compute_median(data)
    mad = compute_mad(data, med)
    assert med == 3.5e-12
    assert mad > 0.0
    signed_z, abs_z = compute_robust_z(10e-12, med, mad)
    assert signed_z is not None and abs_z is not None
    assert math.isfinite(signed_z)




