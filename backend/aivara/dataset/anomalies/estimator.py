"""Detector-side temporary estimators for out-of-fold probability generation (Phase 5.5).

MANDATORY INVARIANT: NO BASELINE RETRAINING
- Customer production models and submitted baseline models are never modified or retrained.
- This module provides temporary, detector-side analytical estimators fitted strictly on
  frozen offline feature embeddings across stratified cross-validation folds.
- All preprocessing (scaling, normalization) is fitted strictly per-fold on training partitions
  to ensure zero data leakage.
"""

from __future__ import annotations

import hashlib
from typing import Dict, List, Optional, Sequence, Tuple
import numpy as np

from aivara.dataset.anomalies.exceptions import (
    InsufficientDataError,
    InvalidFoldSplitError,
)
from aivara.dataset.anomalies.folds import deterministic_stratified_kfold_split


class DetectorSideCentroidEstimator:
    """Lightweight, deterministic nearest-centroid classifier with softmax probability calibration.

    Fits class centroids exclusively on training data and computes calibrated softmax probabilities
    based on negative squared Euclidean distance / cosine similarity with temperature scaling.
    """

    def __init__(self, temperature: float = 1.0, metric: str = "cosine") -> None:
        self.temperature = max(1e-4, temperature)
        self.metric = metric
        self.centroids: Dict[int, np.ndarray] = {}
        self.num_classes: int = 0
        self.mean_: Optional[np.ndarray] = None
        self.std_: Optional[np.ndarray] = None

    def fit(self, X: np.ndarray, y: np.ndarray, num_classes: int) -> "DetectorSideCentroidEstimator":
        """Fit class centroids and feature normalizers strictly on training partition."""
        self.num_classes = num_classes
        X_train = np.asarray(X, dtype=np.float64)
        y_train = np.asarray(y, dtype=np.int64)

        # Standardize features per-fold
        self.mean_ = np.mean(X_train, axis=0)
        self.std_ = np.std(X_train, axis=0)
        # Avoid zero division
        self.std_[self.std_ < 1e-8] = 1.0
        X_norm = (X_train - self.mean_) / self.std_

        if self.metric == "cosine":
            # L2 normalize rows
            norms = np.linalg.norm(X_norm, axis=1, keepdims=True)
            norms[norms < 1e-8] = 1.0
            X_norm = X_norm / norms

        self.centroids = {}
        for c in range(num_classes):
            mask = y_train == c
            if np.sum(mask) > 0:
                centroid = np.mean(X_norm[mask], axis=0)
                if self.metric == "cosine":
                    c_norm = np.linalg.norm(centroid)
                    if c_norm > 1e-8:
                        centroid = centroid / c_norm
                self.centroids[c] = centroid
            else:
                # If a class is missing in training partition, fallback to zero vector
                self.centroids[c] = np.zeros(X_train.shape[1], dtype=np.float64)

        return self

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        """Predict calibrated class probabilities for held-out samples."""
        if self.mean_ is None or self.std_ is None:
            raise RuntimeError("Estimator has not been fitted.")

        X_eval = np.asarray(X, dtype=np.float64)
        X_norm = (X_eval - self.mean_) / self.std_

        if self.metric == "cosine":
            norms = np.linalg.norm(X_norm, axis=1, keepdims=True)
            norms[norms < 1e-8] = 1.0
            X_norm = X_norm / norms

        n_eval = X_norm.shape[0]
        logits = np.zeros((n_eval, self.num_classes), dtype=np.float64)

        for c in range(self.num_classes):
            centroid = self.centroids.get(c, np.zeros(X_norm.shape[1]))
            if self.metric == "cosine":
                # Cosine similarity
                sim = np.dot(X_norm, centroid)
                logits[:, c] = sim / self.temperature
            else:
                # Negative Euclidean distance
                dist = np.linalg.norm(X_norm - centroid, axis=1)
                logits[:, c] = -dist / self.temperature

        # Softmax with numerical stability
        max_logits = np.max(logits, axis=1, keepdims=True)
        exp_logits = np.exp(logits - max_logits)
        sum_exp = np.sum(exp_logits, axis=1, keepdims=True)
        sum_exp[sum_exp < 1e-12] = 1.0
        probs = exp_logits / sum_exp
        return probs


def compute_out_of_fold_probabilities(
    features: np.ndarray,
    labels: Sequence[int],
    num_classes: int,
    sample_ids: Optional[Sequence[str]] = None,
    k_folds: int = 5,
    random_seed: int = 42,
    dataset_fingerprint: Optional[str] = None,
) -> np.ndarray:
    """Compute strictly out-of-fold class probability matrix (N, K) over frozen feature vectors.

    Zero Data Leakage Guarantee:
    - Splits dataset into K stratified folds.
    - Fits detector-side estimator and normalizer exclusively on fold training partition.
    - Generates predictions strictly for held-out test partition.
    - Concatenates predictions in original sample order.

    Args:
        features: (N, D) array of fixed visual feature embeddings.
        labels: Sequence of integer class labels y_tilde of length N.
        num_classes: Total number of classes K.
        sample_ids: Optional sequence of sample IDs for deterministic splitting.
        k_folds: Number of folds (>= 2).
        random_seed: Deterministic random seed.
        dataset_fingerprint: Optional cryptographic dataset hash.

    Returns:
        (N, K) numpy array of out-of-fold probability vectors where rows sum to 1.0.
    """
    X = np.asarray(features, dtype=np.float64)
    y = np.asarray(labels, dtype=np.int64)
    n_samples = len(y)

    if X.shape[0] != n_samples:
        raise InsufficientDataError(
            f"Feature count ({X.shape[0]}) does not match label count ({n_samples})"
        )

    if n_samples < k_folds:
        raise InvalidFoldSplitError(
            f"Dataset size ({n_samples}) is smaller than k_folds ({k_folds})"
        )

    splits = deterministic_stratified_kfold_split(
        labels=labels,
        sample_ids=sample_ids,
        k_folds=k_folds,
        random_seed=random_seed,
        dataset_fingerprint=dataset_fingerprint,
    )

    oof_probs = np.zeros((n_samples, num_classes), dtype=np.float64)

    for train_idx, test_idx in splits:
        X_train, y_train = X[train_idx], y[train_idx]
        X_test = X[test_idx]

        # Fit lightweight detector-side estimator exclusively on training fold
        estimator = DetectorSideCentroidEstimator()
        estimator.fit(X_train, y_train, num_classes=num_classes)

        # Predict out-of-fold probabilities for held-out test fold
        fold_probs = estimator.predict_proba(X_test)
        oof_probs[test_idx] = fold_probs

    return oof_probs
