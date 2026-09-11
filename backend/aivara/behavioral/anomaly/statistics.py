"""Robust, distribution-aware statistical calculations for Behavioral Anomaly Detection."""

from __future__ import annotations

import math
from typing import List, Optional, Sequence, Tuple
import numpy as np


def filter_finite_values(values: Sequence[float]) -> List[float]:
    """Filter out NaN, +Inf, -Inf, returning a list of valid finite float numbers."""
    return [float(x) for x in values if isinstance(x, (int, float)) and math.isfinite(x)]


def compute_median(values: Sequence[float]) -> float:
    """Compute the deterministic median of a non-empty sequence of finite floats.

    Uses standard exact middle element for odd length and arithmetic mean of two middle
    elements for even length, sorting deterministically.
    """
    finite_vals = filter_finite_values(values)
    if not finite_vals:
        raise ValueError("Cannot compute median on empty or entirely non-finite sequence.")
    sorted_vals = sorted(finite_vals)
    n = len(sorted_vals)
    mid = n // 2
    if n % 2 == 1:
        return float(sorted_vals[mid])
    else:
        return float((sorted_vals[mid - 1] + sorted_vals[mid]) / 2.0)


def compute_mad(values: Sequence[float], median_val: Optional[float] = None) -> float:
    """Compute the Median Absolute Deviation (MAD) of a non-empty sequence of finite floats.

    MAD = median(|x_i - median(X)|).
    """
    finite_vals = filter_finite_values(values)
    if not finite_vals:
        raise ValueError("Cannot compute MAD on empty or entirely non-finite sequence.")
    if median_val is None:
        median_val = compute_median(finite_vals)
    deviations = [abs(x - median_val) for x in finite_vals]
    return compute_median(deviations)


def compute_robust_z(
    value: float,
    median_val: float,
    mad_val: float,
) -> Tuple[Optional[float], Optional[float]]:
    """Compute signed robust z-score and absolute robust z-score.

    Formula: robust_z = (value - median) / (1.4826 * MAD).

    Returns:
        (robust_z, absolute_robust_z) tuple.
        Returns (None, None) if MAD == 0.0 or if value/median/mad is not finite.
    """
    if not (math.isfinite(value) and math.isfinite(median_val) and math.isfinite(mad_val)):
        return None, None
    if mad_val <= 0.0:
        return None, None

    denom = 1.4826 * mad_val
    z = (value - median_val) / denom
    if not math.isfinite(z):
        return None, None
    return float(z), float(abs(z))
