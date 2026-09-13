"""Pure NumPy implementation of multivariate distribution shift methods.

Provides:
- Kernel Maximum Mean Discrepancy (MMD) with Gaussian RBF and median heuristic
- Energy Distance (Euclidean metric space)
- Deterministic Permutation Null Hypothesis Testing for empirical p-values
"""

from __future__ import annotations

import math
from typing import Any, Callable, Dict, List, Optional, Tuple
import numpy as np


def sanitize_2d_array(arr: Any) -> np.ndarray:
    """Validate and sanitize a 2D numeric matrix, rejecting non-finite values."""
    if arr is None:
        raise ValueError("Input array cannot be None.")
        
    np_arr = np.asarray(arr, dtype=np.float64)
    if np_arr.ndim == 1:
        np_arr = np_arr[:, np.newaxis]
    elif np_arr.ndim != 2:
        raise ValueError(f"Array must be 1D or 2D, got shape {np_arr.shape}.")
        
    if np_arr.size == 0 or np_arr.shape[0] == 0:
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


def compute_pairwise_sq_distances(X: np.ndarray, Y: np.ndarray) -> np.ndarray:
    """Compute pairwise squared Euclidean distances ||x_i - y_j||^2."""
    x_sq = np.sum(X ** 2, axis=1, keepdims=True)
    y_sq = np.sum(Y ** 2, axis=1, keepdims=True).T
    dists_sq = x_sq + y_sq - 2.0 * np.dot(X, Y.T)
    return np.maximum(dists_sq, 0.0)


def compute_median_heuristic_gamma(X: np.ndarray, Y: np.ndarray) -> float:
    """Estimate RBF kernel bandwidth gamma = 1 / (2 * sigma^2) via the median heuristic."""
    n = min(len(X), 500)
    m = min(len(Y), 500)
    pooled = np.vstack([X[:n], Y[:m]])
    dists_sq = compute_pairwise_sq_distances(pooled, pooled)
    triu_dists_sq = dists_sq[np.triu_indices_from(dists_sq, k=1)]
    
    positive_dists_sq = triu_dists_sq[triu_dists_sq > 1e-12]
    if len(positive_dists_sq) == 0:
        return 1.0
        
    median_sq = float(np.median(positive_dists_sq))
    if median_sq <= 1e-12:
        return 1.0
        
    gamma = 1.0 / (2.0 * median_sq)
    return max(1e-6, min(1e6, float(gamma)))


def compute_kernel_mmd(
    X: np.ndarray,
    Y: np.ndarray,
    gamma: Optional[float] = None,
) -> Tuple[float, float]:
    """Compute empirical Maximum Mean Discrepancy squared (MMD^2) using Gaussian RBF kernel.
    
    MMD^2 = E[k(x,x')] + E[k(y,y')] - 2*E[k(x,y)]
    Returns: (mmd_squared, gamma_used)
    """
    x_arr = sanitize_2d_array(X)
    y_arr = sanitize_2d_array(Y)
    
    if x_arr.shape[1] != y_arr.shape[1]:
        raise ValueError(f"Dimension mismatch: X has {x_arr.shape[1]} features, Y has {y_arr.shape[1]}.")
        
    if gamma is None:
        gamma = compute_median_heuristic_gamma(x_arr, y_arr)
        
    k_xx = np.exp(-gamma * compute_pairwise_sq_distances(x_arr, x_arr))
    k_yy = np.exp(-gamma * compute_pairwise_sq_distances(y_arr, y_arr))
    k_xy = np.exp(-gamma * compute_pairwise_sq_distances(x_arr, y_arr))
    
    mmd_sq = float(np.mean(k_xx) + np.mean(k_yy) - 2.0 * np.mean(k_xy))
    return max(0.0, mmd_sq), float(gamma)


def compute_energy_distance(X: np.ndarray, Y: np.ndarray) -> float:
    """Compute empirical Energy Distance between two multivariate samples.
    
    E(X, Y) = 2*E||X - Y|| - E||X - X'|| - E||Y - Y'||
    """
    x_arr = sanitize_2d_array(X)
    y_arr = sanitize_2d_array(Y)
    
    if x_arr.shape[1] != y_arr.shape[1]:
        raise ValueError(f"Dimension mismatch: X has {x_arr.shape[1]} features, Y has {y_arr.shape[1]}.")
        
    d_xy = np.sqrt(compute_pairwise_sq_distances(x_arr, y_arr))
    d_xx = np.sqrt(compute_pairwise_sq_distances(x_arr, x_arr))
    d_yy = np.sqrt(compute_pairwise_sq_distances(y_arr, y_arr))
    
    energy_dist = float(2.0 * np.mean(d_xy) - np.mean(d_xx) - np.mean(d_yy))
    return max(0.0, energy_dist)


def compute_permutation_p_value(
    X: np.ndarray,
    Y: np.ndarray,
    stat_fn: Callable[[np.ndarray, np.ndarray], float],
    num_permutations: int = 100,
    seed: int = 42,
) -> Tuple[float, float, List[float]]:
    """Compute non-parametric p-value via deterministic sample relabeling permutation test.
    
    p = (1 + sum(T_perm >= T_obs)) / (1 + B)
    Returns: (observed_statistic, empirical_p_value, permutation_statistics)
    """
    x_arr = sanitize_2d_array(X)
    y_arr = sanitize_2d_array(Y)
    
    n1 = len(x_arr)
    n2 = len(y_arr)
    
    obs_stat = stat_fn(x_arr, y_arr)
    
    pooled = np.vstack([x_arr, y_arr])
    total_n = len(pooled)
    
    rng = np.random.RandomState(seed)
    
    perm_stats: List[float] = []
    count_ge = 0
    
    for _ in range(num_permutations):
        perm_idx = rng.permutation(total_n)
        perm_x = pooled[perm_idx[:n1]]
        perm_y = pooled[perm_idx[n1:]]
        
        t_b = stat_fn(perm_x, perm_y)
        perm_stats.append(t_b)
        if t_b >= obs_stat - 1e-12:
            count_ge += 1
            
    p_val = (1.0 + count_ge) / (1.0 + num_permutations)
    return float(obs_stat), max(0.0, min(1.0, float(p_val))), perm_stats
