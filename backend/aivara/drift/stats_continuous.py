"""Pure NumPy implementation of 1D continuous statistical methods.

Provides:
- Two-sample Kolmogorov-Smirnov (KS) test with asymptotic p-value
- 1D Wasserstein distance (Earth Mover's Distance)
- Population Stability Index (PSI) with quantile binning and Laplace smoothing
- Robust input sanitization for non-finite values (NaN, Inf)
"""

from __future__ import annotations

import math
from typing import Any, Dict, Tuple
import numpy as np


def sanitize_1d_array(arr: Any) -> np.ndarray:
    """Validate and sanitize a 1D numeric array, rejecting non-finite values if invalid."""
    if arr is None:
        raise ValueError("Input array cannot be None.")
    
    np_arr = np.asarray(arr, dtype=np.float64).ravel()
    if np_arr.size == 0:
        raise ValueError("Input array cannot be empty.")
    
    if not np.all(np.isfinite(np_arr)):
        has_nan = np.isnan(np_arr).any()
        has_inf = np.isinf(np_arr).any()
        err_msg = "Array contains non-finite values: "
        if has_nan and has_inf:
            err_msg += "both NaN and Infinity found."
        elif has_nan:
            err_msg += "NaN found."
        else:
            err_msg += "Infinity found."
        raise ValueError(err_msg)
    
    return np_arr


def compute_two_sample_ks(ref: np.ndarray, target: np.ndarray) -> Tuple[float, float]:
    """Compute the two-sample Kolmogorov-Smirnov statistic D and asymptotic p-value.
    
    D = sup_x |F_ref(x) - F_target(x)|
    """
    ref_arr = sanitize_1d_array(ref)
    target_arr = sanitize_1d_array(target)
    
    n1 = len(ref_arr)
    n2 = len(target_arr)
    
    if n1 == 0 or n2 == 0:
        raise ValueError("Cannot perform KS test with empty sample.")
        
    # Check for identical constant populations
    ref_min, ref_max = np.min(ref_arr), np.max(ref_arr)
    target_min, target_max = np.min(target_arr), np.max(target_arr)
    if ref_min == ref_max and target_min == target_max:
        if ref_min == target_min:
            return 0.0, 1.0
        else:
            return 1.0, 0.0

    # Sort arrays
    ref_sorted = np.sort(ref_arr)
    target_sorted = np.sort(target_arr)
    
    # Unified evaluated points
    all_vals = np.concatenate([ref_sorted, target_sorted])
    all_vals.sort()
    
    # Compute empirical CDFs via searchsorted (right-side evaluation)
    cdf_ref = np.searchsorted(ref_sorted, all_vals, side="right") / n1
    cdf_target = np.searchsorted(target_sorted, all_vals, side="right") / n2
    
    d_stat = float(np.max(np.abs(cdf_ref - cdf_target)))
    d_stat = max(0.0, min(1.0, d_stat))
    
    # Asymptotic p-value calculation via Kolmogorov limiting distribution
    # Effective sample size: n_e = (n1 * n2) / (n1 + n2)
    n_e = (n1 * n2) / (n1 + n2)
    sqrt_ne = math.sqrt(n_e)
    
    # Stephens (1970) modified Kolmogorov statistic for two-sample test
    lambda_val = max(0.0, (sqrt_ne + 0.12 + 0.11 / sqrt_ne) * d_stat)
    
    if lambda_val <= 1e-8:
        p_val = 1.0
    elif lambda_val > 5.0:
        p_val = 0.0
    else:
        # Sum Kolmogorov series: p = 2 * sum_{k=1}^inf (-1)^{k-1} * exp(-2 * k^2 * lambda^2)
        p_val = 0.0
        term_prev = 0.0
        for k in range(1, 101):
            term = math.exp(-2.0 * (k ** 2) * (lambda_val ** 2))
            if k % 2 == 1:
                p_val += 2.0 * term
            else:
                p_val -= 2.0 * term
            if abs(term) < 1e-15 or abs(term - term_prev) < 1e-15:
                break
            term_prev = term
            
        p_val = max(0.0, min(1.0, p_val))
        
    return d_stat, float(p_val)


def compute_wasserstein_1d(ref: np.ndarray, target: np.ndarray, num_quantiles: int = 2000) -> float:
    """Compute 1D Wasserstein distance (Earth Mover's Distance) W1.
    
    W1 = int_0^1 |F_ref^{-1}(t) - F_target^{-1}(t)| dt
    """
    ref_arr = sanitize_1d_array(ref)
    target_arr = sanitize_1d_array(target)
    
    n1 = len(ref_arr)
    n2 = len(target_arr)
    
    if n1 == n2:
        # Exact calculation on sorted samples of identical length
        ref_sorted = np.sort(ref_arr)
        target_sorted = np.sort(target_arr)
        w1 = float(np.mean(np.abs(ref_sorted - target_sorted)))
    else:
        # Quantile interpolation over fine uniform grid
        grid = np.linspace(0.0, 1.0, max(num_quantiles, max(n1, n2)))
        ref_quantiles = np.quantile(ref_arr, grid)
        target_quantiles = np.quantile(target_arr, grid)
        w1 = float(np.mean(np.abs(ref_quantiles - target_quantiles)))
        
    return max(0.0, float(w1))


def compute_psi(
    ref: np.ndarray,
    target: np.ndarray,
    num_bins: int = 10,
    epsilon: float = 1e-6,
) -> Tuple[float, Dict[str, Any]]:
    """Compute Population Stability Index (PSI) using reference-derived quantile bins.
    
    Includes Laplace additive smoothing to avoid division by zero or ln(0).
    """
    ref_arr = sanitize_1d_array(ref)
    target_arr = sanitize_1d_array(target)
    
    n_ref = len(ref_arr)
    n_target = len(target_arr)
    
    # Quantile bin edges based on reference distribution
    percentiles = np.linspace(0.0, 100.0, num_bins + 1)
    raw_edges = np.percentile(ref_arr, percentiles)
    
    # Deduplicate edges (handles repeated/constant values)
    unique_edges = np.unique(raw_edges)
    
    if len(unique_edges) < 2:
        # Entire reference population is a single constant value
        target_matches = np.isclose(target_arr, unique_edges[0])
        if np.all(target_matches):
            return 0.0, {"bin_count": 1, "is_constant": True}
        else:
            # Different constant or varying target
            return 1.0, {"bin_count": 1, "is_constant": True}
            
    # Set outer boundaries to -inf and +inf for robust bin assignment
    bin_edges = unique_edges.copy()
    bin_edges[0] = -np.inf
    bin_edges[-1] = np.inf
    
    # Histogram bin counts
    ref_counts, _ = np.histogram(ref_arr, bins=bin_edges)
    target_counts, _ = np.histogram(target_arr, bins=bin_edges)
    
    actual_bins = len(ref_counts)
    
    # Proportions with Laplace smoothing
    ref_probs = (ref_counts + epsilon) / (n_ref + actual_bins * epsilon)
    target_probs = (target_counts + epsilon) / (n_target + actual_bins * epsilon)
    
    # PSI sum = sum (p - q) * ln(p / q)
    psi_terms = (target_probs - ref_probs) * np.log(target_probs / ref_probs)
    psi_value = float(np.sum(psi_terms))
    
    psi_value = max(0.0, float(psi_value))
    
    details = {
        "bin_count": actual_bins,
        "ref_bin_proportions": ref_probs.tolist(),
        "target_bin_proportions": target_probs.tolist(),
    }
    
    return psi_value, details
