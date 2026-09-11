"""Deterministic, semantically safe human-readable explanation generation for Behavioral Anomaly Detection."""

from __future__ import annotations

from typing import List, Optional
from aivara.behavioral.anomaly.enums import (
    AnomalyFamilyType,
    AnomalyStatus,
    MetricAnomalyStatus,
    MetricDirection,
    SupportStatus,
)


import re

FORBIDDEN_PATTERNS = [
    re.compile(r"\bmalicious\b", re.IGNORECASE),
    re.compile(r"\battack\b", re.IGNORECASE),
    re.compile(r"\battacks\b", re.IGNORECASE),
    re.compile(r"\bcompromise\b", re.IGNORECASE),
    re.compile(r"\bcompromised\b", re.IGNORECASE),
    re.compile(r"\bbackdoor\b", re.IGNORECASE),
    re.compile(r"\bbackdoors\b", re.IGNORECASE),
    re.compile(r"\btrojan\b", re.IGNORECASE),
    re.compile(r"\badversary\b", re.IGNORECASE),
    re.compile(r"\bculpability\b", re.IGNORECASE),
]


def _sanitize(text: str) -> str:
    """Ensure that no forbidden security or culpability terms appear in explanations."""
    for pattern in FORBIDDEN_PATTERNS:
        if pattern.search(text):
            match = pattern.search(text).group(0)
            raise ValueError(f"Semantic safety violation: explanation contains forbidden term '{match}'.")
    return text


def format_metric_explanation(
    metric_name: str,
    status: MetricAnomalyStatus,
    observed_value: Optional[float],
    baseline_median: Optional[float],
    baseline_mad: Optional[float],
    robust_z: Optional[float],
    empirical_extremeness: Optional[float],
    direction: MetricDirection,
    zero_dispersion: bool = False,
    reason: Optional[str] = None,
) -> str:
    """Generate a deterministic, semantically safe explanation for an individual metric result."""
    if reason:
        _sanitize(reason)

    if status == MetricAnomalyStatus.INSUFFICIENT_SUPPORT:
        return _sanitize(
            f"Metric '{metric_name}' statistical anomaly evaluation was not performed due to insufficient "
            f"reference sample support."
        )

    if status in (MetricAnomalyStatus.UNAVAILABLE, MetricAnomalyStatus.UNVERIFIABLE, MetricAnomalyStatus.INCOMPATIBLE):
        detail = f" ({reason})" if reason else ""
        return _sanitize(f"Metric '{metric_name}' is {status.value}{detail}.")

    if zero_dispersion:
        if status == MetricAnomalyStatus.ANOMALOUS:
            return _sanitize(
                f"Metric '{metric_name}' observed value {observed_value} differs from reference baseline "
                f"value {baseline_median} with zero baseline dispersion (MAD=0.0, empirical extremeness={empirical_extremeness:.4f})."
            )
        else:
            return _sanitize(
                f"Metric '{metric_name}' observed value {observed_value} matches the constant reference baseline "
                f"(median={baseline_median}, MAD=0.0)."
            )

    if status == MetricAnomalyStatus.ANOMALOUS:
        direction_str = "lower" if direction == MetricDirection.LOWER_IS_EXTREME else (
            "higher" if direction == MetricDirection.HIGHER_IS_EXTREME else "deviates from"
        )
        z_str = f"robust_z={robust_z:+.2f}" if robust_z is not None else "robust_z=N/A"
        ext_str = f"empirical extremeness={empirical_extremeness:.4f}" if empirical_extremeness is not None else ""
        crit_str = f" Decision criterion: {reason}." if reason else ""
        return _sanitize(
            f"Metric '{metric_name}' is statistically anomalous ({direction_str} than reference population). "
            f"Observed={observed_value:.4f}, baseline median={baseline_median:.4f}, MAD={baseline_mad:.4f}, "
            f"{z_str}, {ext_str}.{crit_str}"
        )

    # NORMAL
    return _sanitize(
        f"Metric '{metric_name}' is within the declared reference behavioral range. "
        f"Observed={observed_value:.4f}, baseline median={baseline_median:.4f}."
    )


def format_family_explanation(
    family_name: AnomalyFamilyType,
    status: AnomalyStatus,
    support_status: SupportStatus,
    anomalous_count: int,
    valid_count: int,
    dominant_metric: Optional[str] = None,
    dominant_extremeness: Optional[float] = None,
) -> str:
    """Generate a deterministic, semantically safe explanation for a behavioral family."""
    if status == AnomalyStatus.INSUFFICIENT_SUPPORT:
        return _sanitize(
            f"Behavioral family '{family_name.value}' evaluation withheld due to insufficient reference sample support."
        )

    if status == AnomalyStatus.UNAVAILABLE:
        return _sanitize(f"Behavioral family '{family_name.value}' measurements are unavailable.")

    if status == AnomalyStatus.ANOMALOUS:
        dominant_str = f", dominant metric: '{dominant_metric}'" if dominant_metric else ""
        return _sanitize(
            f"Behavioral family '{family_name.value}' contains {anomalous_count}/{valid_count} statistically "
            f"anomalous metrics{dominant_str} under the declared statistical threshold policy."
        )

    if status == AnomalyStatus.NORMAL:
        return _sanitize(
            f"Behavioral family '{family_name.value}' exhibits expected behavioral consistency across all "
            f"{valid_count} valid metrics."
        )

    return _sanitize(f"Behavioral family '{family_name.value}' status is {status.value}.")


def format_overall_explanation(
    overall_status: AnomalyStatus,
    support_status: SupportStatus,
    anomalous_families: List[str],
    total_metrics_evaluated: int,
    anomalous_metrics_count: int,
    policy_version: str,
) -> str:
    """Generate an overall deterministic explanation of the anomaly analysis result."""
    if overall_status == AnomalyStatus.INSUFFICIENT_SUPPORT:
        return _sanitize(
            "Overall behavioral anomaly classification was not performed because the reference baseline "
            "population contains fewer than the required minimum number of comparable observations."
        )

    if overall_status == AnomalyStatus.INCOMPARABLE:
        return _sanitize(
            "Observations and baseline reference population possess incompatible execution contexts or model identities."
        )

    if overall_status == AnomalyStatus.UNAVAILABLE:
        return _sanitize("Required behavioral observations or comparison metrics are unavailable.")

    if overall_status == AnomalyStatus.ANOMALOUS:
        fams = ", ".join(sorted(anomalous_families))
        return _sanitize(
            f"Observed model behavior is statistically anomalous relative to reference baseline under policy "
            f"v{policy_version}. {anomalous_metrics_count}/{total_metrics_evaluated} metrics across families "
            f"[{fams}] crossed the statistical anomaly threshold."
        )

    if overall_status == AnomalyStatus.NORMAL:
        return _sanitize(
            f"Observed model behavior is statistically consistent with the reference behavioral population across "
            f"all {total_metrics_evaluated} evaluated metrics under policy v{policy_version}."
        )

    return _sanitize(f"Behavioral analysis completed with overall status {overall_status.value}.")
