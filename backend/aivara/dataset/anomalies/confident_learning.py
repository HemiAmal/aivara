"""Confident Learning mathematical core for Phase 5.5.

Implements:
1. Class-specific empirical confident thresholds (t_j).
2. Confident count matrix (C_{i, j}).
3. Normalized joint distribution estimation (Q_{i, j}).
4. Margin computation and sigmoid anomaly scoring (S_n).
5. Systematic reciprocal class confusion detection.
6. Calibrated statistical confidence with sample size scaling and guardrail discounts.
"""

from __future__ import annotations

import math
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple
import numpy as np


def compute_class_thresholds(
    observed_labels: Sequence[int],
    predicted_probs: np.ndarray,
    num_classes: int,
) -> Dict[int, float]:
    """Compute empirical confident threshold t_j for each class j.

    t_j = (1 / |X_{y_tilde=j}|) * sum_{x in X_{y_tilde=j}} P_hat(y = j | x)

    Args:
        observed_labels: Observed integer labels y_tilde of length N.
        predicted_probs: (N, K) array of out-of-fold predicted class probabilities.
        num_classes: Total number of classes K.

    Returns:
        Dictionary mapping class integer ID to its empirical threshold t_j in [0.0, 1.0].
    """
    y = np.asarray(observed_labels, dtype=np.int64)
    thresholds: Dict[int, float] = {}

    for j in range(num_classes):
        mask = y == j
        class_count = int(np.sum(mask))
        if class_count > 0:
            avg_prob = float(np.mean(predicted_probs[mask, j]))
            # Bound within [0.0, 1.0]
            thresholds[j] = max(0.0, min(1.0, avg_prob))
        else:
            # Fallback for unobserved class in evaluation set
            thresholds[j] = 1.0 / max(1, num_classes)

    return thresholds


def compute_confident_count_matrix(
    observed_labels: Sequence[int],
    predicted_probs: np.ndarray,
    thresholds: Dict[int, float],
    num_classes: int,
) -> np.ndarray:
    """Compute K x K unnormalized integer confident count matrix C_{i, j}.

    A sample x_n with observed label y_tilde=i is assigned to latent class y*=j if:
    1. P_hat(y = j | x_n) >= t_j
    2. j = argmax_k (P_hat(y = k | x_n) - t_k)

    Args:
        observed_labels: Observed integer labels of length N.
        predicted_probs: (N, K) array of class probabilities.
        thresholds: Class-specific thresholds dictionary.
        num_classes: Total number of classes K.

    Returns:
        (K, K) numpy array of integer confident counts where row i is observed label and col j is latent label.
    """
    n_samples = len(observed_labels)
    y = np.asarray(observed_labels, dtype=np.int64)
    t_vec = np.array([thresholds.get(k, 1.0 / num_classes) for k in range(num_classes)], dtype=np.float64)

    counts = np.zeros((num_classes, num_classes), dtype=np.int64)
    # Threshold-adjusted margins: P_hat(y = k | x_n) - t_k
    adjusted_probs = predicted_probs - t_vec

    for n in range(n_samples):
        i = int(y[n])
        if i < 0 or i >= num_classes:
            continue
        
        # Find class maximizing threshold-adjusted probability
        j_candidate = int(np.argmax(adjusted_probs[n]))
        
        # Check if probability for candidate meets threshold
        if predicted_probs[n, j_candidate] >= t_vec[j_candidate]:
            counts[i, j_candidate] += 1
        else:
            # If no threshold is met, default to observed label count
            counts[i, i] += 1

    return counts


def compute_joint_distribution_matrix(
    confident_counts: np.ndarray,
    observed_labels: Sequence[int],
    num_classes: int,
) -> List[List[float]]:
    """Compute K x K normalized joint noise distribution matrix Q_{i, j}.

    Q_{i, j} = ( (C_{i, j} / sum_{i'} C_{i', j}) * |X_{y_tilde=j}| ) / N

    Normalized so sum_{i, j} Q_{i, j} == 1.0.

    Args:
        confident_counts: (K, K) integer count matrix.
        observed_labels: Observed labels of length N.
        num_classes: Number of classes K.

    Returns:
        K x K list of floats representing joint probability matrix Q.
    """
    n_samples = len(observed_labels)
    if n_samples == 0:
        return [[0.0] * num_classes for _ in range(num_classes)]

    y = np.asarray(observed_labels, dtype=np.int64)
    class_counts = np.array([np.sum(y == j) for j in range(num_classes)], dtype=np.float64)

    # Column sums of C: total samples estimated to belong to latent class j
    col_sums = np.sum(confident_counts, axis=0).astype(np.float64)
    
    q_matrix = np.zeros((num_classes, num_classes), dtype=np.float64)
    eps = 1e-12

    for j in range(num_classes):
        denom = col_sums[j] if col_sums[j] > 0 else eps
        for i in range(num_classes):
            q_matrix[i, j] = (confident_counts[i, j] / denom) * (class_counts[j] / n_samples)

    # Normalize matrix to sum to 1.0
    total_sum = np.sum(q_matrix)
    if total_sum > 0:
        q_matrix = q_matrix / total_sum
    else:
        # Uniform fallback if all zeros
        q_matrix = np.full((num_classes, num_classes), fill_value=1.0 / (num_classes * num_classes))

    return [[float(val) for val in row] for row in q_matrix]


def compute_sample_anomaly_metrics(
    observed_label: int,
    probabilities: Sequence[float],
    thresholds: Dict[int, float],
    class_counts: Dict[int, int],
    num_classes: int,
) -> Tuple[int, float, float, float, float, float]:
    """Compute margin, anomaly score, and confidence metrics for a single sample.

    Args:
        observed_label: Observed class index i (y_tilde).
        probabilities: Probability distribution P_hat(y | x) over all K classes.
        thresholds: Class-specific thresholds.
        class_counts: Map from class index to observed sample count in dataset.
        num_classes: Total number of classes K.

    Returns:
        Tuple of:
        - j_star (top alternative class index)
        - observed_prob (P_hat(y = i | x))
        - latent_prob (P_hat(y = j_star | x))
        - margin (threshold-adjusted margin)
        - anomaly_score (sigmoid score in [0.0, 1.0])
        - raw_confidence (sample size & certainty scaled confidence in [0.0, 1.0])
    """
    probs = np.asarray(probabilities, dtype=np.float64)
    i = int(observed_label)
    observed_prob = float(probs[i]) if 0 <= i < len(probs) else 0.0
    t_i = thresholds.get(i, 1.0 / num_classes)

    # Find highest probability alternative class j != i
    alt_classes = [c for c in range(num_classes) if c != i]
    if not alt_classes:
        # Singleton class / binary edge case where only 1 class exists in ontology
        return i, observed_prob, observed_prob, 0.0, 0.5, 0.0

    alt_probs = [probs[c] for c in alt_classes]
    best_alt_idx = int(np.argmax(alt_probs))
    j_star = alt_classes[best_alt_idx]
    latent_prob = float(probs[j_star])
    t_j_star = thresholds.get(j_star, 1.0 / num_classes)

    # Margin = (P_hat(y=j* | x) - t_j*) - (P_hat(y=i | x) - t_i)
    margin = float((latent_prob - t_j_star) - (observed_prob - t_i))

    # Anomaly Score = 1 / (1 + exp(-5 * margin))
    # Clip margin to prevent float overflow in exp
    clipped_margin = max(-50.0, min(50.0, margin))
    anomaly_score = float(1.0 / (1.0 + math.exp(-5.0 * clipped_margin)))

    # Confidence scaling: min(1.0, |X_i| / 20) * P_hat(y=j* | x)
    observed_class_size = class_counts.get(i, 0)
    sample_size_factor = min(1.0, observed_class_size / 20.0)
    raw_confidence = float(sample_size_factor * latent_prob)
    raw_confidence = max(0.0, min(1.0, raw_confidence))

    return j_star, observed_prob, latent_prob, margin, anomaly_score, raw_confidence


def identify_systematic_anomalies(
    observed_labels: Sequence[int],
    predicted_top_alts: Sequence[int],
    margins: Sequence[float],
    class_counts: Dict[int, int],
    systematic_ratio_threshold: float = 0.15,
) -> Set[Tuple[int, int]]:
    """Identify pairs of classes (i, j) exhibiting systematic label confusion.

    A systematic anomaly exists between observed class i and alternative class j
    if the number of samples in class i with positive margin towards class j
    exceeds systematic_ratio_threshold * count(i).

    Args:
        observed_labels: Sequence of observed class labels.
        predicted_top_alts: Sequence of top alternative classes for each sample.
        margins: Sequence of margins for each sample.
        class_counts: Total sample counts per class.
        systematic_ratio_threshold: Ratio threshold (default 0.15).

    Returns:
        Set of (observed_class_id, alternative_class_id) tuples exhibiting systematic confusion.
    """
    confusion_counts: Dict[Tuple[int, int], int] = {}

    for i, j, margin in zip(observed_labels, predicted_top_alts, margins):
        if margin > 0.0 and i != j:
            pair = (i, j)
            confusion_counts[pair] = confusion_counts.get(pair, 0) + 1

    systematic_pairs: Set[Tuple[int, int]] = set()
    for (i, j), count in confusion_counts.items():
        total_in_class = class_counts.get(i, 0)
        if total_in_class > 0:
            ratio = count / total_in_class
            if ratio >= systematic_ratio_threshold:
                systematic_pairs.add((i, j))

    return systematic_pairs
