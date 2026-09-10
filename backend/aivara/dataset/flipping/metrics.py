"""Mathematical formulation and metrics for Label-Flipping Detection Engine (Phase 5.6).

Implements:
1. Transition count matrix N_{i, j}
2. Row-normalized conditional transition rate matrix T_{i -> j}
3. Directional Asymmetry Index Asym(i, j)
4. Noise Concentration Index NCI_{i -> j}
5. Asymptotic Support Discount function
6. Targeted Flipping Score TFS_{i -> j}
7. Wilson Score Interval Lower Bound w^-(p, n)
8. Contributor Transition Differentials Delta T_{i -> j}^{(c)}
"""

from __future__ import annotations

import math
from typing import Dict, List, Optional, Sequence, Tuple
import numpy as np


def compute_transition_count_matrix(
    observed_labels: Sequence[int],
    latent_labels: Sequence[int],
    num_classes: int,
) -> np.ndarray:
    """Compute K x K unnormalized integer transition count matrix N_{i, j}.

    N_{i, j} = |{ n : y_tilde_n = i and y_star_hat_n = j }|

    Args:
        observed_labels: Sequence of observed class labels y_tilde.
        latent_labels: Sequence of estimated latent class labels y_star_hat.
        num_classes: Total number of classes K.

    Returns:
        (K, K) numpy array of integer counts.
    """
    counts = np.zeros((num_classes, num_classes), dtype=np.int64)
    for obs, lat in zip(observed_labels, latent_labels):
        if 0 <= obs < num_classes and 0 <= lat < num_classes:
            counts[obs, lat] += 1
    return counts


def compute_row_normalized_transition_rates(
    count_matrix: np.ndarray,
) -> List[List[float]]:
    """Compute K x K row-normalized transition rate matrix T_{i -> j} = N_{i, j} / sum_k N_{i, k}.

    Args:
        count_matrix: (K, K) integer count matrix.

    Returns:
        K x K list of floats where each row sums to 1.0.
    """
    num_classes = count_matrix.shape[0]
    row_sums = np.sum(count_matrix, axis=1).astype(np.float64)
    rates = np.zeros((num_classes, num_classes), dtype=np.float64)

    for i in range(num_classes):
        if row_sums[i] > 0:
            rates[i, :] = count_matrix[i, :] / row_sums[i]
        else:
            # Fallback for unobserved source class: diagonal is 1.0
            rates[i, i] = 1.0

    return [[float(val) for val in row] for row in rates]


def compute_directional_asymmetry(
    count_i_to_j: int,
    count_j_to_i: int,
    eps: float = 1e-12,
) -> float:
    """Compute Directional Asymmetry Index between class i and class j.

    Asym(i, j) = (N_{i, j} - N_{j, i}) / (N_{i, j} + N_{j, i} + eps)

    Returns:
        Float in [-1.0, 1.0].
    """
    total = count_i_to_j + count_j_to_i
    if total == 0:
        return 0.0
    asym = float(count_i_to_j - count_j_to_i) / float(total)
    return max(-1.0, min(1.0, asym))


def compute_noise_concentration_index(
    count_matrix: np.ndarray,
    source_class: int,
    target_class: int,
    eps: float = 1e-12,
) -> float:
    """Compute Noise Concentration Index NCI_{i -> j}.

    NCI_{i -> j} = N_{i, j} / (sum_{k != i} N_{i, k} + eps)

    Measures proportion of total noise from class i captured specifically by class j.
    """
    n_ij = float(count_matrix[source_class, target_class])
    # Sum over all off-diagonal entries in row source_class
    total_noise = float(np.sum(count_matrix[source_class, :]) - count_matrix[source_class, source_class])

    if total_noise <= 0.0:
        return 0.0

    nci = n_ij / total_noise
    return max(0.0, min(1.0, nci))



def compute_support_discount(
    n: int,
    target_n: float = 6.0,
    min_n: int = 3,
) -> float:
    """Compute asymptotic sigmoid support multiplier.

    SupportDiscount(n) = 1 / (1 + exp(-0.5 * (n - target_n))) for n >= min_n, else 0.0.
    """
    if n < min_n:
        return 0.0
    val = 1.0 / (1.0 + math.exp(-0.5 * (float(n) - target_n)))
    return max(0.0, min(1.0, val))


def compute_wilson_lower_bound(
    p: float,
    n: int,
    z: float = 1.96,
) -> float:
    """Compute lower bound of Wilson Score Interval for binomial proportion at 95% CI.

    w^-(p, n) = (p + z^2/(2n) - z * sqrt(p(1-p)/n + z^2/(4n^2))) / (1 + z^2/n)
    """
    if n <= 0 or p <= 0.0:
        return 0.0
    p = min(1.0, max(0.0, p))
    z2 = z * z
    denom = 1.0 + (z2 / n)
    center = p + (z2 / (2.0 * n))
    radicand = (p * (1.0 - p) / n) + (z2 / (4.0 * n * n))
    radicand = max(0.0, radicand)
    margin = z * math.sqrt(radicand)
    lower = (center - margin) / denom
    return max(0.0, min(1.0, lower))


def compute_targeted_flip_score(
    transition_rate: float,
    asymmetry: float,
    noise_concentration: float,
    transition_count: int,
    target_n: float = 6.0,
) -> Tuple[float, float]:
    """Compute composite Targeted Flipping Score TFS_{i -> j} and its support discount.

    TFS = SupportDiscount(N_{i, j}) * T_{i -> j} * max(0.0, Asym(i, j)) * NCI_{i -> j}

    Returns:
        Tuple of (TFS, support_discount).
    """
    discount = compute_support_discount(transition_count, target_n=target_n)
    asym_factor = max(0.0, asymmetry)
    tfs = discount * transition_rate * asym_factor * noise_concentration
    return max(0.0, min(1.0, tfs)), discount
