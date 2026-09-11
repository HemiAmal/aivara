"""Phase 8.6 — Behavioral Anomaly Detection Subsystem for AIVARA."""

from __future__ import annotations

from aivara.behavioral.anomaly.enums import (
    AnomalyBaselineType,
    AnomalyFamilyType,
    AnomalyStatus,
    MetricAnomalyStatus,
    MetricDirection,
    SupportStatus,
)
from aivara.behavioral.anomaly.exceptions import (
    BehavioralAnomalyError,
    CrossProjectAnalysisError,
    IncompatibleAnalysisContextError,
    InsufficientSupportError,
    InvalidMetricDataError,
)
from aivara.behavioral.anomaly.empirical import (
    compute_empirical_extremeness,
    compute_percentile_rank,
    compute_support_status,
)
from aivara.behavioral.anomaly.explanations import (
    format_family_explanation,
    format_metric_explanation,
    format_overall_explanation,
)
from aivara.behavioral.anomaly.families import (
    METRIC_DIRECTIONS,
    METRIC_FAMILY_MAP,
    aggregate_family_results,
    get_metric_direction,
    get_metric_family,
)
from aivara.behavioral.anomaly.identity import compute_anomaly_analysis_id
from aivara.behavioral.anomaly.policy import (
    AnomalyThresholdPolicy,
    DEFAULT_ANOMALY_POLICY,
)
from aivara.behavioral.anomaly.schemas import (
    BaselineSummary,
    BehavioralAnomalyAnalysis,
    BehavioralAnomalyFamily,
    BehavioralAnomalyMetric,
)
from aivara.behavioral.anomaly.statistics import (
    compute_mad,
    compute_median,
    compute_robust_z,
    filter_finite_values,
)
from aivara.behavioral.anomaly.engine import BehavioralAnomalyEngineService

__all__ = [
    "AnomalyBaselineType",
    "AnomalyFamilyType",
    "AnomalyStatus",
    "MetricAnomalyStatus",
    "MetricDirection",
    "SupportStatus",
    "BehavioralAnomalyError",
    "CrossProjectAnalysisError",
    "IncompatibleAnalysisContextError",
    "InsufficientSupportError",
    "InvalidMetricDataError",
    "AnomalyThresholdPolicy",
    "DEFAULT_ANOMALY_POLICY",
    "compute_median",
    "compute_mad",
    "compute_robust_z",
    "filter_finite_values",
    "compute_empirical_extremeness",
    "compute_percentile_rank",
    "compute_support_status",
    "format_metric_explanation",
    "format_family_explanation",
    "format_overall_explanation",
    "METRIC_DIRECTIONS",
    "METRIC_FAMILY_MAP",
    "get_metric_direction",
    "get_metric_family",
    "aggregate_family_results",
    "compute_anomaly_analysis_id",
    "BaselineSummary",
    "BehavioralAnomalyMetric",
    "BehavioralAnomalyFamily",
    "BehavioralAnomalyAnalysis",
    "BehavioralAnomalyEngineService",
]
