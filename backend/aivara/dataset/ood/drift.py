"""Dataset-level statistical distribution shift & operational drift engine.

Computes Maximum Mean Discrepancy (MMD) and Energy Distance using deterministic
kernel formulations and permutation testing.
"""

from __future__ import annotations

import math
from typing import Dict, List, Optional, Tuple

import numpy as np

from aivara.dataset.ood.schemas import DistributionShiftEvidence


def compute_rbf_kernel_matrix(
    X: np.ndarray,
    Y: np.ndarray,
    gamma: Optional[float] = None,
) -> np.ndarray:
    """Compute Gaussian RBF kernel matrix K(X, Y) = exp(-gamma * ||x - y||^2)."""
    # Squared Euclidean distances: ||x - y||^2 = ||x||^2 + ||y||^2 - 2 x y^T
    x_sq = np.sum(X ** 2, axis=1, keepdims=True)
    y_sq = np.sum(Y ** 2, axis=1, keepdims=True)
    dists_sq = np.maximum(0.0, x_sq + y_sq.T - 2.0 * np.dot(X, Y.T))

    if gamma is None:
        # Median heuristic
        median_dist = float(np.median(dists_sq))
        gamma = 1.0 / (2.0 * max(1e-4, median_dist))

    return np.exp(-gamma * dists_sq)


def compute_mmd(
    X: np.ndarray,
    Y: np.ndarray,
    gamma: Optional[float] = None,
) -> float:
    """Compute empirical Maximum Mean Discrepancy (MMD) between distributions X and Y."""
    n = len(X)
    m = len(Y)
    if n == 0 or m == 0:
        return 0.0

    k_xx = compute_rbf_kernel_matrix(X, X, gamma=gamma)
    k_yy = compute_rbf_kernel_matrix(Y, Y, gamma=gamma)
    k_xy = compute_rbf_kernel_matrix(X, Y, gamma=gamma)

    mmd_sq = float(np.mean(k_xx) + np.mean(k_yy) - 2.0 * np.mean(k_xy))
    return float(math.sqrt(max(0.0, mmd_sq)))


def compute_energy_distance(X: np.ndarray, Y: np.ndarray) -> float:
    """Compute non-parametric Energy Distance between distributions X and Y."""
    n = len(X)
    m = len(Y)
    if n == 0 or m == 0:
        return 0.0

    # Euclidean distance matrices
    def _pairwise_dists(A: np.ndarray, B: np.ndarray) -> np.ndarray:
        a_sq = np.sum(A ** 2, axis=1, keepdims=True)
        b_sq = np.sum(B ** 2, axis=1, keepdims=True)
        sq = np.maximum(0.0, a_sq + b_sq.T - 2.0 * np.dot(A, B.T))
        return np.sqrt(sq)

    d_xy = _pairwise_dists(X, Y)
    d_xx = _pairwise_dists(X, X)
    d_yy = _pairwise_dists(Y, Y)

    energy_stat = float(2.0 * np.mean(d_xy) - np.mean(d_xx) - np.mean(d_yy))
    return float(math.sqrt(max(0.0, energy_stat)))


def evaluate_distribution_shift(
    query_features: np.ndarray,
    ref_features: np.ndarray,
    seed: int = 42,
    max_subsample: int = 1000,
    n_permutations: int = 50,
    contributor_ids: Optional[Tuple[str, ...]] = None,
) -> DistributionShiftEvidence:
    """Evaluate dataset-level distribution shift with non-parametric permutation testing.
    
    Args:
        query_features: [N, D] array of query dataset features.
        ref_features: [M, D] array of reference dataset features.
        seed: Deterministic integer seed.
        max_subsample: Maximum samples to evaluate for kernel complexity budget.
        n_permutations: Number of permutations for null hypothesis significance testing.
        contributor_ids: Optional contributor associations per query sample.
        
    Returns:
        DistributionShiftEvidence immutable instance.
    """
    rng = np.random.RandomState(seed)

    n_q = len(query_features)
    n_r = len(ref_features)

    # Deterministic subsampling if large
    if n_q > max_subsample:
        idx_q = rng.choice(n_q, size=max_subsample, replace=False)
        x_eval = query_features[idx_q]
    else:
        x_eval = query_features

    if n_r > max_subsample:
        idx_r = rng.choice(n_r, size=max_subsample, replace=False)
        y_eval = ref_features[idx_r]
    else:
        y_eval = ref_features

    mmd_stat = compute_mmd(x_eval, y_eval)
    energy_stat = compute_energy_distance(x_eval, y_eval)

    # Permutation test for empirical p-value calibration
    pooled = np.vstack([x_eval, y_eval])
    total_len = len(pooled)
    n_x = len(x_eval)

    perm_mmds = []
    for _ in range(n_permutations):
        perm_idx = rng.permutation(total_len)
        perm_x = pooled[perm_idx[:n_x]]
        perm_y = pooled[perm_idx[n_x:]]
        perm_mmds.append(compute_mmd(perm_x, perm_y))

    perm_mmds_arr = np.array(perm_mmds)
    # p-value = fraction of permutation stats >= observed stat
    p_val = float(np.mean(perm_mmds_arr >= mmd_stat))
    is_shift = bool((p_val < 0.05 and mmd_stat > 0.02) or (energy_stat > 1.0 and mmd_stat > 0.02))

    # Check shift factors
    shift_factors: List[str] = []
    mean_diff = np.abs(np.mean(x_eval, axis=0) - np.mean(y_eval, axis=0))
    if len(mean_diff) >= 128:
        # RGB vs HSV components
        rgb_diff = float(np.mean(mean_diff[:96]))
        hsv_diff = float(np.mean(mean_diff[96:128]))
        if rgb_diff > 0.02:
            shift_factors.append("color_luminance_distribution")
        if hsv_diff > 0.02:
            shift_factors.append("saturation_value_distribution")
    else:
        if float(np.mean(mean_diff)) > 0.05:
            shift_factors.append("feature_space_divergence")

    # Contributor concentration check (is_targeted)
    is_targeted = False
    if contributor_ids and len(contributor_ids) == n_q and is_shift:
        unique_c, counts_c = np.unique(contributor_ids, return_counts=True)
        if len(unique_c) > 1:
            max_c_ratio = float(np.max(counts_c) / n_q)
            if max_c_ratio > 0.80:
                is_targeted = True

    return DistributionShiftEvidence(
        mmd_statistic=mmd_stat,
        energy_distance=energy_stat,
        is_shift_detected=is_shift,
        p_value_estimate=p_val,
        affected_sample_count=n_q if is_shift else 0,
        is_targeted=is_targeted,
        primary_shift_factors=tuple(shift_factors),
    )
