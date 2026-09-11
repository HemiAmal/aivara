"""Weight Merkle root comparison and tensor-level drift attribution (Phase 7.5).

Compares Tier 4 weight Merkle digests and performs deterministic, tensor-level
change classification across shape, dtype, content hashes, and leaf representations.
"""

from __future__ import annotations

from typing import Dict, List, Optional, Tuple

from aivara.model_integrity.comparison.schemas import (
    TensorChangeRecord,
    TensorChangeType,
    WeightComparisonStatus,
)
from aivara.model_integrity.fingerprinting.schemas import TensorLeafDescriptor


def compare_weight_roots(
    reference_root: Optional[str],
    candidate_root: Optional[str],
) -> WeightComparisonStatus:
    """Compare Tier 4 Weight Merkle roots (H_weight_merkle).

    Args:
        reference_root: 64-char lowercase hex Merkle root of reference model.
        candidate_root: 64-char lowercase hex Merkle root of candidate model.

    Returns:
        WeightComparisonStatus (WEIGHT_MERKLE_MATCH, WEIGHT_DRIFT, or WEIGHT_COMPARISON_UNAVAILABLE).
    """
    if not reference_root or not candidate_root:
        return WeightComparisonStatus.WEIGHT_COMPARISON_UNAVAILABLE

    if reference_root.strip().lower() == candidate_root.strip().lower():
        return WeightComparisonStatus.WEIGHT_MERKLE_MATCH

    return WeightComparisonStatus.WEIGHT_DRIFT


def attribute_tensor_changes(
    reference_leaves: Optional[List[TensorLeafDescriptor]],
    candidate_leaves: Optional[List[TensorLeafDescriptor]],
) -> Tuple[List[TensorChangeRecord], Dict[str, int]]:
    """Perform granular tensor-level change attribution using safe tensor leaf descriptors.

    Args:
        reference_leaves: Deterministically ordered reference model tensor leaves.
        candidate_leaves: Deterministically ordered candidate model tensor leaves.

    Returns:
        Tuple of (List[TensorChangeRecord] sorted by name, summary_counts_dict).
    """
    summary = {
        "total_unique_tensors": 0,
        "unchanged": 0,
        "added": 0,
        "removed": 0,
        "content_changed": 0,
        "metadata_changed": 0,
        "content_and_metadata_changed": 0,
    }

    if reference_leaves is None or candidate_leaves is None:
        return [], summary

    ref_map = {leaf.name: leaf for leaf in reference_leaves}
    cand_map = {leaf.name: leaf for leaf in candidate_leaves}

    all_names = sorted(set(ref_map.keys()).union(cand_map.keys()))
    summary["total_unique_tensors"] = len(all_names)

    change_records: List[TensorChangeRecord] = []

    for name in all_names:
        r_leaf = ref_map.get(name)
        c_leaf = cand_map.get(name)

        if r_leaf is None and c_leaf is not None:
            change_type = TensorChangeType.ADDED
            summary["added"] += 1
            record = TensorChangeRecord(
                tensor_name=name,
                change_type=change_type,
                reference_shape=None,
                candidate_shape=c_leaf.shape,
                reference_dtype=None,
                candidate_dtype=c_leaf.dtype,
                reference_content_hash=None,
                candidate_content_hash=c_leaf.content_hash,
                reference_leaf_hash=None,
                candidate_leaf_hash=c_leaf.leaf_hash,
                inclusion_proof=None,
            )
        elif c_leaf is None and r_leaf is not None:
            change_type = TensorChangeType.REMOVED
            summary["removed"] += 1
            record = TensorChangeRecord(
                tensor_name=name,
                change_type=change_type,
                reference_shape=r_leaf.shape,
                candidate_shape=None,
                reference_dtype=r_leaf.dtype,
                candidate_dtype=None,
                reference_content_hash=r_leaf.content_hash,
                candidate_content_hash=None,
                reference_leaf_hash=r_leaf.leaf_hash,
                candidate_leaf_hash=None,
                inclusion_proof=None,
            )
        else:
            # Both present
            assert r_leaf is not None and c_leaf is not None
            shape_diff = r_leaf.shape != c_leaf.shape
            dtype_diff = r_leaf.dtype.upper() != c_leaf.dtype.upper()
            bytes_diff = r_leaf.byte_length != c_leaf.byte_length
            meta_changed = shape_diff or dtype_diff or bytes_diff

            content_changed = r_leaf.content_hash.lower() != c_leaf.content_hash.lower()

            if meta_changed and content_changed:
                change_type = TensorChangeType.CONTENT_AND_METADATA_CHANGED
                summary["content_and_metadata_changed"] += 1
            elif content_changed:
                change_type = TensorChangeType.CONTENT_CHANGED
                summary["content_changed"] += 1
            elif meta_changed:
                change_type = TensorChangeType.METADATA_CHANGED
                summary["metadata_changed"] += 1
            else:
                change_type = TensorChangeType.UNCHANGED
                summary["unchanged"] += 1

            record = TensorChangeRecord(
                tensor_name=name,
                change_type=change_type,
                reference_shape=r_leaf.shape,
                candidate_shape=c_leaf.shape,
                reference_dtype=r_leaf.dtype,
                candidate_dtype=c_leaf.dtype,
                reference_content_hash=r_leaf.content_hash,
                candidate_content_hash=c_leaf.content_hash,
                reference_leaf_hash=r_leaf.leaf_hash,
                candidate_leaf_hash=c_leaf.leaf_hash,
                inclusion_proof=None,
            )

        change_records.append(record)

    # Sort strictly by tensor name
    return sorted(change_records, key=lambda r: r.tensor_name), summary
