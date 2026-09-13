"""Multiple hypothesis testing error control algorithms.

Provides:
- Benjamini-Hochberg (BH) False Discovery Rate (FDR) control
- Holm-Bonferroni Family-Wise Error Rate (FWER) step-down control
- Standard Bonferroni single-step correction
"""

from __future__ import annotations

from typing import Any, Dict, List, Tuple
from aivara.drift.enums import MultipleTestingCorrectionMethod


def apply_benjamini_hochberg(
    p_values: Dict[str, float],
    q_star: float = 0.05,
) -> Dict[str, Dict[str, Any]]:
    """Apply Benjamini-Hochberg procedure controlling FDR at q_star.
    
    q_(i) = min_{j >= i} (min(1.0, (K / j) * p_(j)))
    Returns a dict mapping feature_name -> {
        "raw_p_value": float,
        "adjusted_p_value": float,
        "is_significant": bool,
        "rank": int,
        "critical_value": float
    }
    """
    if not p_values:
        return {}
        
    k = len(p_values)
    # Sort items by raw p-value ascending
    sorted_items = sorted(p_values.items(), key=lambda item: item[1])
    
    # Calculate unadjusted step-up values: p_(i) * (K / i)
    unadjusted_q: List[Tuple[str, float, int, float]] = []
    for rank_idx, (name, p_val) in enumerate(sorted_items, start=1):
        p_clamped = max(0.0, min(1.0, float(p_val)))
        q_raw = p_clamped * (k / rank_idx)
        crit_val = (rank_idx / k) * q_star
        unadjusted_q.append((name, p_clamped, rank_idx, q_raw))
        
    # Enforce monotonicity backwards: q_(i) = min(q_(i+1), unadjusted_q_(i))
    adjusted_results: Dict[str, Dict[str, Any]] = {}
    running_min = 1.0
    for name, p_clamped, rank_idx, q_raw in reversed(unadjusted_q):
        running_min = min(running_min, q_raw)
        q_val = max(0.0, min(1.0, float(running_min)))
        is_sig = q_val <= q_star
        crit_val = (rank_idx / k) * q_star
        
        adjusted_results[name] = {
            "raw_p_value": p_clamped,
            "adjusted_p_value": q_val,
            "is_significant": is_sig,
            "rank": rank_idx,
            "critical_value": crit_val,
        }
        
    return adjusted_results


def apply_holm_bonferroni(
    p_values: Dict[str, float],
    alpha: float = 0.05,
) -> Dict[str, Dict[str, Any]]:
    """Apply Holm-Bonferroni step-down procedure controlling FWER at alpha.
    
    p_tilde_(i) = min(1.0, max_{j <= i} ((K - j + 1) * p_(j)))
    """
    if not p_values:
        return {}
        
    k = len(p_values)
    sorted_items = sorted(p_values.items(), key=lambda item: item[1])
    
    adjusted_results: Dict[str, Dict[str, Any]] = {}
    running_max = 0.0
    
    for rank_idx, (name, p_val) in enumerate(sorted_items, start=1):
        p_clamped = max(0.0, min(1.0, float(p_val)))
        multiplier = k - rank_idx + 1
        adj_p = min(1.0, p_clamped * multiplier)
        running_max = max(running_max, adj_p)
        p_tilde = max(0.0, min(1.0, float(running_max)))
        is_sig = p_tilde <= alpha
        
        adjusted_results[name] = {
            "raw_p_value": p_clamped,
            "adjusted_p_value": p_tilde,
            "is_significant": is_sig,
            "rank": rank_idx,
            "critical_value": alpha / multiplier,
        }
        
    return adjusted_results


def apply_multiple_testing_correction(
    p_values: Dict[str, float],
    method: MultipleTestingCorrectionMethod,
    threshold: float = 0.05,
) -> Dict[str, Dict[str, Any]]:
    """Dispatch to the specified multiple testing error control procedure."""
    if method == MultipleTestingCorrectionMethod.BENJAMINI_HOCHBERG_FDR:
        return apply_benjamini_hochberg(p_values, q_star=threshold)
    elif method == MultipleTestingCorrectionMethod.HOLM_BONFERRONI_FWER:
        return apply_holm_bonferroni(p_values, alpha=threshold)
    elif method == MultipleTestingCorrectionMethod.BONFERRONI:
        k = len(p_values)
        return {
            name: {
                "raw_p_value": p,
                "adjusted_p_value": min(1.0, p * k),
                "is_significant": min(1.0, p * k) <= threshold,
                "rank": 1,
                "critical_value": threshold / max(1, k),
            }
            for name, p in p_values.items()
        }
    else:
        # NONE
        return {
            name: {
                "raw_p_value": p,
                "adjusted_p_value": p,
                "is_significant": p <= threshold,
                "rank": 1,
                "critical_value": threshold,
            }
            for name, p in p_values.items()
        }
