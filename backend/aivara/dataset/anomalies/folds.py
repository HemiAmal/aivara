"""Deterministic stratified K-fold cross-validation partitioner for Phase 5.5.

Guarantees:
1. Complete data leakage prevention: training and test fold indices are strictly disjoint.
2. Deterministic reproducibility: fold assignments are derived from dataset identity,
   sample identifiers, and a fixed configuration seed.
3. Class stratification: class proportions are preserved across folds as closely as mathematically possible.
4. Handling of small/rare classes: classes with count < k_folds are assigned safely without dropping.
"""

from __future__ import annotations

import hashlib
import math
from typing import Dict, List, Optional, Sequence, Tuple
import numpy as np

from aivara.dataset.anomalies.exceptions import InvalidFoldSplitError


def generate_deterministic_seed(
    base_seed: int,
    dataset_fingerprint: Optional[str] = None,
    salt: str = "aivara_stratified_kfold",
) -> int:
    """Generate a deterministic 32-bit unsigned integer seed from base seed and dataset identity."""
    content = f"{base_seed}:{dataset_fingerprint or 'default'}:{salt}".encode("utf-8")
    digest = hashlib.sha256(content).digest()
    return int.from_bytes(digest[:4], byteorder="big")


def deterministic_stratified_kfold_split(
    labels: Sequence[int],
    sample_ids: Optional[Sequence[str]] = None,
    k_folds: int = 5,
    random_seed: int = 42,
    dataset_fingerprint: Optional[str] = None,
) -> List[Tuple[np.ndarray, np.ndarray]]:
    """Partition sample indices into K stratified folds deterministically without data leakage.

    Args:
        labels: Sequence of integer class labels y_tilde for all N samples.
        sample_ids: Optional sequence of unique sample IDs for deterministic tie-breaking.
        k_folds: Number of cross-validation partitions (must be >= 2).
        random_seed: Deterministic integer seed.
        dataset_fingerprint: Optional cryptographic hash of the dataset for seed derivation.

    Returns:
        List of (train_indices, test_indices) tuples of numpy arrays for each fold.

    Raises:
        InvalidFoldSplitError: If parameters are invalid or total sample count < k_folds.
    """
    n_samples = len(labels)
    if k_folds < 2:
        raise InvalidFoldSplitError(f"k_folds must be >= 2, got {k_folds}")
    if n_samples < k_folds:
        raise InvalidFoldSplitError(
            f"Dataset has {n_samples} samples, which is less than k_folds={k_folds}"
        )

    # Convert labels to numpy array
    y = np.asarray(labels, dtype=np.int64)
    if sample_ids is None:
        sample_ids = [f"sample_{i}" for i in range(n_samples)]
    elif len(sample_ids) != n_samples:
        raise InvalidFoldSplitError(
            f"Length of sample_ids ({len(sample_ids)}) does not match labels ({n_samples})"
        )

    # Derive deterministic RNG
    effective_seed = generate_deterministic_seed(
        random_seed, dataset_fingerprint=dataset_fingerprint
    )
    rng = np.random.RandomState(effective_seed)

    # Group sample indices by class
    unique_classes, class_counts = np.unique(y, return_counts=True)
    
    # Initialize fold assignments array
    fold_assignments = np.full(n_samples, fill_value=-1, dtype=np.int64)

    # Stratified round-robin assignment per class
    for cls in unique_classes:
        cls_indices = np.where(y == cls)[0]
        
        # Deterministic shuffle within class using sample_id cryptographic ordering + RNG permutation
        # Create reproducible sorting keys
        hashes = [
            hashlib.sha256(f"{sample_ids[idx]}:{effective_seed}".encode("utf-8")).hexdigest()
            for idx in cls_indices
        ]
        # Sort indices primarily by SHA-256 hash
        sorted_order = np.argsort(hashes)
        cls_indices_sorted = cls_indices[sorted_order]
        
        # Permute deterministically with class-seeded RNG
        perm = rng.permutation(len(cls_indices_sorted))
        shuffled_cls_indices = cls_indices_sorted[perm]

        # Assign folds round-robin
        for i, sample_idx in enumerate(shuffled_cls_indices):
            fold_assignments[sample_idx] = i % k_folds

    # Build train/test index splits for each fold
    splits: List[Tuple[np.ndarray, np.ndarray]] = []
    all_indices = np.arange(n_samples, dtype=np.int64)

    for fold in range(k_folds):
        test_mask = fold_assignments == fold
        test_indices = all_indices[test_mask]
        train_indices = all_indices[~test_mask]

        # Safety assertions
        if len(test_indices) == 0:
            raise InvalidFoldSplitError(f"Fold {fold} received 0 test samples.")
        
        # Verify strict disjointness (no data leakage)
        intersection = np.intersect1d(train_indices, test_indices)
        if len(intersection) > 0:
            raise InvalidFoldSplitError(
                f"Data leakage detected in fold {fold}: {len(intersection)} overlapping indices"
            )

        splits.append((train_indices, test_indices))

    return splits
