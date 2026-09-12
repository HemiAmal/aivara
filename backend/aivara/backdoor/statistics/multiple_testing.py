"""Multiplicity Corrections: Benjamini-Hochberg FDR & Holm-Bonferroni Step-Down (ADR-090).

Implements deterministic multiple testing adjustments for candidate screening
and spatial grid localization hypotheses.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple
import numpy as np

from aivara.backdoor.statistics.exceptions import MultiplicityAdjustmentError


def benjamini_hochberg_fdr(
    p_values: List[Optional[float]],
    candidate_keys: Optional[List[str]] = None,
    alpha: float = 0.05,
) -> List[Dict[str, Any]]:
    """Apply Benjamini-Hochberg (BH-FDR) procedure across candidate hypothesis tests.
    
    Args:
        p_values: List of raw p-values. None entries indicate unevaluated candidates.
        candidate_keys: Optional list of deterministic identifiers for deterministic tie-breaking.
        alpha: False Discovery Rate target level (default 0.05).
        
    Returns:
        List of dicts with raw_p, adjusted_p, rank, and is_significant flags aligned to input order.
    """
    m_total = len(p_values)
    if candidate_keys is not None and len(candidate_keys) != m_total:
        raise MultiplicityAdjustmentError("Length of candidate_keys must match length of p_values.")
    if alpha <= 0.0 or alpha >= 1.0:
        raise MultiplicityAdjustmentError(f"Alpha must be in (0, 1), got {alpha}")

    keys = candidate_keys if candidate_keys is not None else [str(i) for i in range(m_total)]

    # Filter evaluable entries
    evaluable_indices = [i for i, p in enumerate(p_values) if p is not None and not np.isnan(p)]
    m = len(evaluable_indices)

    # Initialize results array matching original shape
    results: List[Dict[str, Any]] = [
        {
            "raw_p_value": p_values[i],
            "adjusted_p_value": None,
            "rank": None,
            "is_significant": False,
            "method": "BENJAMINI_HOCHBERG",
            "alpha": alpha,
        }
        for i in range(m_total)
    ]

    if m == 0:
        return results

    # Sort evaluable entries: primary by p-value asc, secondary by key asc (deterministic tie-break)
    indexed_p = [(evaluable_indices[idx], p_values[evaluable_indices[idx]], keys[evaluable_indices[idx]]) for idx in range(m)]
    indexed_p.sort(key=lambda x: (x[1], x[2]))

    # Compute raw Benjamini-Hochberg adjusted values: q_(i) = (m / i) * p_(i) for 1-based rank i
    raw_adjusted = []
    for rank_1b, (orig_idx, p_val, key) in enumerate(indexed_p, start=1):
        q = min(1.0, max(0.0, (m / rank_1b) * p_val))
        raw_adjusted.append(q)

    # Enforce monotonicity backwards (step-up): adj_(i) = min_{j >= i} q_(j)
    final_adjusted = [0.0] * m
    cum_min = 1.0
    for i in reversed(range(m)):
        cum_min = min(cum_min, raw_adjusted[i])
        final_adjusted[i] = cum_min

    # Populate results
    for rank_1b, ((orig_idx, p_val, key), adj_p) in enumerate(zip(indexed_p, final_adjusted), start=1):
        is_sig = (adj_p < alpha)
        results[orig_idx] = {
            "raw_p_value": float(p_val),
            "adjusted_p_value": float(adj_p),
            "rank": rank_1b,
            "is_significant": is_sig,
            "method": "BENJAMINI_HOCHBERG",
            "alpha": alpha,
        }

    return results


def holm_bonferroni_step_down(
    p_values: List[Optional[float]],
    item_keys: Optional[List[str]] = None,
    alpha: float = 0.05,
) -> List[Dict[str, Any]]:
    """Apply Holm-Bonferroni step-down procedure across family-wise hypotheses (e.g. spatial grid cells).
    
    Args:
        p_values: List of raw p-values.
        item_keys: Optional deterministic identifiers for deterministic tie-breaking.
        alpha: FWER target level (default 0.05).
        
    Returns:
        List of dicts with raw_p, adjusted_p, rank, and is_significant flags aligned to input order.
    """
    m_total = len(p_values)
    if item_keys is not None and len(item_keys) != m_total:
        raise MultiplicityAdjustmentError("Length of item_keys must match length of p_values.")
    if alpha <= 0.0 or alpha >= 1.0:
        raise MultiplicityAdjustmentError(f"Alpha must be in (0, 1), got {alpha}")

    keys = item_keys if item_keys is not None else [str(i) for i in range(m_total)]

    evaluable_indices = [i for i, p in enumerate(p_values) if p is not None and not np.isnan(p)]
    m = len(evaluable_indices)

    results: List[Dict[str, Any]] = [
        {
            "raw_p_value": p_values[i],
            "adjusted_p_value": None,
            "rank": None,
            "is_significant": False,
            "method": "HOLM_BONFERRONI",
            "alpha": alpha,
        }
        for i in range(m_total)
    ]

    if m == 0:
        return results

    # Sort evaluable entries: primary by p-value asc, secondary by key asc
    indexed_p = [(evaluable_indices[idx], p_values[evaluable_indices[idx]], keys[evaluable_indices[idx]]) for idx in range(m)]
    indexed_p.sort(key=lambda x: (x[1], x[2]))

    # Compute step-down multipliers: (m - i + 1) * p_(i) for 1-based rank i
    raw_adjusted = []
    for rank_1b, (orig_idx, p_val, key) in enumerate(indexed_p, start=1):
        multiplier = m - rank_1b + 1
        q = min(1.0, max(0.0, multiplier * p_val))
        raw_adjusted.append(q)

    # Enforce monotonicity forwards (step-down): adj_(i) = max_{j <= i} q_(j)
    final_adjusted = [0.0] * m
    cum_max = 0.0
    for i in range(m):
        cum_max = max(cum_max, raw_adjusted[i])
        final_adjusted[i] = min(1.0, cum_max)

    # Populate results
    for rank_1b, ((orig_idx, p_val, key), adj_p) in enumerate(zip(indexed_p, final_adjusted), start=1):
        is_sig = (adj_p < alpha)
        results[orig_idx] = {
            "raw_p_value": float(p_val),
            "adjusted_p_value": float(adj_p),
            "rank": rank_1b,
            "is_significant": is_sig,
            "method": "HOLM_BONFERRONI",
            "alpha": alpha,
        }

    return results
