"""Pure NumPy implementation of categorical distribution shift methods.

Provides:
- Total Variation Distance (TVD)
- Jensen-Shannon Divergence (JSD)
- Chi-Square Goodness-of-Fit test with degrees of freedom and asymptotic p-value
- Class presence/absence detection (unseen vs missing classes)
"""

from __future__ import annotations

import math
from typing import Any, Dict, List, Tuple
import numpy as np


def compute_total_variation_distance(
    ref_probs: Dict[str, float],
    target_probs: Dict[str, float],
) -> float:
    """Compute Total Variation Distance between two discrete probability distributions.
    
    TVD = 0.5 * sum_{c} |p(c) - q(c)| in [0, 1]
    """
    all_classes = set(ref_probs.keys()) | set(target_probs.keys())
    if not all_classes:
        return 0.0
        
    tvd_sum = 0.0
    for c in all_classes:
        p = ref_probs.get(c, 0.0)
        q = target_probs.get(c, 0.0)
        tvd_sum += abs(p - q)
        
    return max(0.0, min(1.0, float(0.5 * tvd_sum)))


def compute_jensen_shannon_divergence(
    ref_probs: Dict[str, float],
    target_probs: Dict[str, float],
    base: float = 2.0,
) -> float:
    """Compute Jensen-Shannon Divergence (JSD) in base-2 (bounded in [0, 1]).
    
    JSD(P || Q) = 0.5 * KL(P || M) + 0.5 * KL(Q || M), where M = 0.5 * (P + Q)
    """
    all_classes = set(ref_probs.keys()) | set(target_probs.keys())
    if not all_classes:
        return 0.0
        
    log_func = math.log2 if base == 2.0 else math.log
    
    kl_pm = 0.0
    kl_qm = 0.0
    
    for c in all_classes:
        p = ref_probs.get(c, 0.0)
        q = target_probs.get(c, 0.0)
        m = 0.5 * (p + q)
        
        if m <= 0.0:
            continue
            
        if p > 0.0:
            kl_pm += p * log_func(p / m)
        if q > 0.0:
            kl_qm += q * log_func(q / m)
            
    jsd = 0.5 * (kl_pm + kl_qm)
    return max(0.0, min(1.0, float(jsd)))


def _gammp_series(a: float, x: float) -> float:
    """Compute regularized lower incomplete gamma function P(a, x) via power series."""
    if x <= 0.0:
        return 0.0
    gln = math.lgamma(a)
    ap = a
    sum_val = 1.0 / a
    del_val = sum_val
    for _ in range(1, 200):
        ap += 1.0
        del_val *= x / ap
        sum_val += del_val
        if abs(del_val) < abs(sum_val) * 1e-15:
            break
    return sum_val * math.exp(-x + a * math.log(x) - gln)


def _gammq_cf(a: float, x: float) -> float:
    """Compute regularized upper incomplete gamma function Q(a, x) via Legendre's continued fraction."""
    gln = math.lgamma(a)
    b = x + 1.0 - a
    c = 1.0 / 1e-30
    d = 1.0 / b
    h = d
    for i in range(1, 200):
        an = -i * (i - a)
        b += 2.0
        d = an * d + b
        if abs(d) < 1e-30:
            d = 1e-30
        c = b + an / c
        if abs(c) < 1e-30:
            c = 1e-30
        d = 1.0 / d
        del_val = d * c
        h *= del_val
        if abs(del_val - 1.0) < 1e-15:
            break
    return math.exp(-x + a * math.log(x) - gln) * h


def chi2_survival_function(chi2_stat: float, df: int) -> float:
    """Compute survival function (1 - CDF) for Chi-Square distribution with df degrees of freedom."""
    if chi2_stat <= 0.0 or df <= 0:
        return 1.0
    a = 0.5 * df
    x = 0.5 * chi2_stat
    if x < (a + 1.0):
        return max(0.0, min(1.0, 1.0 - _gammp_series(a, x)))
    else:
        return max(0.0, min(1.0, _gammq_cf(a, x)))


def compute_chi_square_test(
    ref_counts: Dict[str, int],
    target_counts: Dict[str, int],
    epsilon: float = 1e-6,
) -> Tuple[float, float, int, List[str], List[str]]:
    """Compute Chi-Square goodness-of-fit test statistic, p-value, and degrees of freedom.
    
    Returns: (chi2_statistic, p_value, df, unseen_classes, missing_classes)
    """
    all_classes = sorted(list(set(ref_counts.keys()) | set(target_counts.keys())))
    if len(all_classes) <= 1:
        # Trivial single category
        return 0.0, 1.0, 1, [], []
        
    n_ref = sum(ref_counts.values())
    n_target = sum(target_counts.values())
    
    if n_ref == 0 or n_target == 0:
        raise ValueError("Cannot perform chi-square test with 0 total counts.")
        
    unseen_classes = [c for c in all_classes if ref_counts.get(c, 0) == 0 and target_counts.get(c, 0) > 0]
    missing_classes = [c for c in all_classes if ref_counts.get(c, 0) > 0 and target_counts.get(c, 0) == 0]
    
    num_classes = len(all_classes)
    df = num_classes - 1
    
    # Expected target frequencies based on reference proportions with additive smoothing
    smoothed_ref_total = n_ref + num_classes * epsilon
    
    chi2_stat = 0.0
    for c in all_classes:
        o_c = float(target_counts.get(c, 0))
        ref_prob = (float(ref_counts.get(c, 0)) + epsilon) / smoothed_ref_total
        e_c = n_target * ref_prob
        chi2_stat += ((o_c - e_c) ** 2) / e_c
        
    p_val = chi2_survival_function(chi2_stat, df)
    
    return float(chi2_stat), float(p_val), df, unseen_classes, missing_classes
