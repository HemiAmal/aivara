"""Deterministic empirical ranking and extremeness calculations for Behavioral Anomaly Detection."""

from __future__ import annotations

import math
from typing import Sequence
from aivara.behavioral.anomaly.enums import MetricDirection, SupportStatus
from aivara.behavioral.anomaly.statistics import filter_finite_values


def compute_support_status(
    count: int,
    min_support: int = 5,
    low_support: int = 10,
    adequate_support: int = 30,
) -> SupportStatus:
    """Classify sample size into standardized statistical support states."""
    if count < min_support:
        return SupportStatus.INSUFFICIENT_SUPPORT
    if count < low_support:
        return SupportStatus.LOW_SUPPORT
    if count < adequate_support:
        return SupportStatus.MODERATE_SUPPORT
    return SupportStatus.ADEQUATE_SUPPORT


def compute_empirical_extremeness(
    value: float,
    baseline_values: Sequence[float],
    direction: MetricDirection = MetricDirection.TWO_SIDED,
) -> float:
    """Compute deterministic empirical tail extremeness of an observed value against a baseline population.

    Returns a float in [0.0, 1.0] representing empirical tail probability under the declared direction:
    - LOWER_IS_EXTREME: Proportion of baseline values <= observed value.
    - HIGHER_IS_EXTREME: Proportion of baseline values >= observed value.
    - TWO_SIDED: 2 * min(Proportion <= value, Proportion >= value), clamped in [0.0, 1.0].
    """
    finite_baseline = filter_finite_values(baseline_values)
    if not finite_baseline:
        return 1.0
    if not math.isfinite(value):
        return 0.0

    n = len(finite_baseline)
    le_count = sum(1 for b in finite_baseline if b <= value)
    ge_count = sum(1 for b in finite_baseline if b >= value)

    p_le = le_count / n
    p_ge = ge_count / n

    if direction == MetricDirection.LOWER_IS_EXTREME:
        return float(min(1.0, max(0.0, p_le)))
    elif direction == MetricDirection.HIGHER_IS_EXTREME:
        return float(min(1.0, max(0.0, p_ge)))
    else:  # TWO_SIDED
        two_sided = 2.0 * min(p_le, p_ge)
        return float(min(1.0, max(0.0, two_sided)))


def compute_percentile_rank(
    value: float,
    baseline_values: Sequence[float],
) -> float:
    """Compute deterministic percentile rank in [0.0, 100.0] of a value within a baseline."""
    finite_baseline = filter_finite_values(baseline_values)
    if not finite_baseline or not math.isfinite(value):
        return 50.0
    n = len(finite_baseline)
    strictly_less = sum(1 for b in finite_baseline if b < value)
    equal = sum(1 for b in finite_baseline if b == value)
    # Mid-rank convention for ties
    percentile = (strictly_less + 0.5 * equal) / n * 100.0
    return float(min(100.0, max(0.0, percentile)))
