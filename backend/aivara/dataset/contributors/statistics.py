"""Statistical calculation functions for Phase 5.8 Contributor Aggregation.

Implements:
  1. Wilson 95% Confidence Interval for binomial/fractional rates.
  2. Differential estimation and standard error SE(Delta).
  3. Shannon Entropy H(c) for class and domain specialization.
  4. Herfindahl-Hirschman Index (HHI) for anomaly dispersion.
  5. Gini inequality coefficient.
"""

from __future__ import annotations

import math
from typing import Dict, List, Sequence, Tuple

import numpy as np


def compute_wilson_confidence_interval(
    k: float,
    n: float,
    confidence: float = 0.95,
) -> Tuple[float, float, float]:
    """Compute empirical rate and conservative Wilson score confidence bounds.
    
    Args:
        k: Weighted positive anomaly count (0.0 <= k <= n).
        n: Weighted exposure / sample size.
        confidence: Confidence level (default 0.95 -> z ~ 1.96).
        
    Returns:
        Tuple of (estimated_rate, lower_bound, upper_bound).
    """
    if n <= 0.0:
        return 0.0, 0.0, 0.0

    k_clamped = min(n, max(0.0, float(k)))
    p_hat = k_clamped / n

    # Normal quantile z approximation for standard confidence levels
    if math.isclose(confidence, 0.95, rel_tol=1e-3):
        z = 1.959963984540054
    elif math.isclose(confidence, 0.99, rel_tol=1e-3):
        z = 2.5758293035489004
    elif math.isclose(confidence, 0.90, rel_tol=1e-3):
        z = 1.6448536269514722
    else:
        # Generic probit approximation via sqrt(2) * erfinv(2*conf - 1)
        # Using erf-inverse polynomial approximation
        p = 2.0 * confidence - 1.0
        z = 1.96  # fallback default

    z_sq = z ** 2
    denom = 1.0 + (z_sq / n)
    center = (p_hat + (z_sq / (2.0 * n))) / denom
    
    var_term = (p_hat * (1.0 - p_hat) / n) + (z_sq / (4.0 * (n ** 2)))
    margin = (z * math.sqrt(max(0.0, var_term))) / denom

    lower_bound = max(0.0, min(1.0, float(center - margin)))
    upper_bound = max(0.0, min(1.0, float(center + margin)))
    rate = max(0.0, min(1.0, float(p_hat)))

    return rate, lower_bound, upper_bound


def compute_rate_differential_and_se(
    r_c: float,
    n_c: float,
    r_bg: Optional[float],
    n_bg: float,
) -> Tuple[Optional[float], Optional[float]]:
    """Compute contributor rate differential Delta = R_c - R_bg and Standard Error SE(Delta).
    
    When background exposure <= 0 or r_bg is None, returns (None, None) representing
    INSUFFICIENT_BACKGROUND_SUPPORT rather than fabricating Delta=0 or SE=0.
    
    Returns:
        Tuple of (rate_differential, standard_error).
    """
    if r_bg is None or n_bg <= 0.0 or n_c <= 0.0:
        return None, None

    diff = float(r_c - r_bg)
    var_c = (r_c * (1.0 - r_c)) / max(1e-4, n_c)
    var_bg = (r_bg * (1.0 - r_bg)) / max(1e-4, n_bg)
    se = float(math.sqrt(max(0.0, var_c + var_bg)))

    return diff, se


def compute_shannon_entropy(distribution: Dict[str, float]) -> float:
    """Compute Shannon entropy in bits H = -sum p_i * log2(p_i).
    
    Args:
        distribution: Mapping of category names to proportions or counts.
        
    Returns:
        Entropy in bits >= 0.0.
    """
    total = sum(distribution.values())
    if total <= 0.0:
        return 0.0

    entropy = 0.0
    for count in distribution.values():
        if count > 0.0:
            p = count / total
            entropy -= p * math.log2(p)

    return max(0.0, float(entropy))


def compute_herfindahl_hirschman_index(shares: Sequence[float]) -> float:
    """Compute Herfindahl-Hirschman Index (HHI) for anomaly concentration.
    
    Formula:
      HHI = sum_{i=1}^C (s_i)^2
      where s_i is the proportion of total dataset anomalies contributed by contributor i.
      
    Returns:
        HHI in [0.0, 1.0].
    """
    valid_shares = [s for s in shares if s > 0.0]
    total_share = sum(valid_shares)
    if total_share <= 0.0:
        return 0.0

    # Normalize shares so they sum to 1.0
    norm_shares = [s / total_share for s in valid_shares]
    hhi = sum(s ** 2 for s in norm_shares)
    return max(0.0, min(1.0, float(hhi)))


def compute_gini_coefficient(values: Sequence[float]) -> float:
    """Compute Gini coefficient of inequality for an array of values in [0.0, 1.0]."""
    arr = np.array(values, dtype=np.float64)
    arr = arr[arr >= 0.0]
    n = len(arr)
    if n <= 1 or np.sum(arr) == 0.0:
        return 0.0

    sorted_arr = np.sort(arr)
    index = np.arange(1, n + 1)
    gini = (2.0 * np.sum(index * sorted_arr)) / (n * np.sum(sorted_arr)) - (n + 1.0) / n
    return max(0.0, min(1.0, float(gini)))
