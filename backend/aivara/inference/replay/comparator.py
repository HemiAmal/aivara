"""Structural and numerical output comparator for Phase 10.9 Replay & Consistency."""

import hmac
import math
from typing import Any, Dict, List, Optional, Sequence, Tuple, Union

import numpy as np

from aivara.inference.execution.models import RawOutputTensor
from aivara.inference.replay.enums import ComparisonStatus
from aivara.inference.replay.models import ReplayComparisonResult, ReplayPolicy


def _extract_array_and_metadata(
    item: Union[RawOutputTensor, np.ndarray, Dict[str, Any]]
) -> Tuple[np.ndarray, str, List[int], str]:
    """Extract (numpy_array, name, shape, dtype) from various tensor representations."""
    if isinstance(item, np.ndarray):
        return item, "output", list(item.shape), str(item.dtype)
    elif isinstance(item, RawOutputTensor):
        # RawOutputTensor might not contain underlying array in observational model
        return np.array([]), item.name, item.shape, item.dtype
    elif isinstance(item, dict):
        arr = item.get("array")
        if arr is None:
            arr = np.array([])
        name = item.get("name", "output")
        shape = item.get("shape", list(arr.shape) if hasattr(arr, "shape") else [])
        dtype = str(item.get("dtype", getattr(arr, "dtype", "float32")))
        return np.asarray(arr), name, shape, dtype
    else:
        arr = np.asarray(item)
        return arr, "output", list(arr.shape), str(arr.dtype)


def compare_raw_outputs(
    *,
    recorded_raw_hash: str,
    replay_raw_hash: str,
    recorded_tensors: Sequence[Any],
    replay_tensors: Sequence[Any],
    policy: ReplayPolicy,
    recorded_arrays: Optional[Sequence[np.ndarray]] = None,
    replay_arrays: Optional[Sequence[np.ndarray]] = None,
) -> ReplayComparisonResult:
    """Compare recorded baseline outputs against newly computed replay outputs.

    Applies:
      1. Exact byte-level hash comparison (SHA-256)
      2. Structural comparison (tensor count, tensor names, rank, shape, dtype)
      3. Numerical pointwise tolerance comparison: |a - b| <= atol + rtol * |a|
      4. Finite value (NaN, Inf) sanity evaluation
    """
    exact_hash_match = hmac.compare_digest(recorded_raw_hash, replay_raw_hash)

    # If hashes match exactly and no arrays are provided for fine-grained diffing, return exact match
    if exact_hash_match and (recorded_arrays is None or replay_arrays is None):
        return ReplayComparisonResult(
            recorded_raw_output_hash=recorded_raw_hash,
            replay_raw_output_hash=replay_raw_hash,
            exact_hash_match=True,
            structural_match=True,
            numerical_match=True,
            max_absolute_error=0.0,
            max_relative_error=0.0,
            mismatch_count=0,
            total_elements=0,
            comparison_status=ComparisonStatus.EXACT_MATCH,
            details={"exact_match_reason": "Identical canonical raw output hashes"},
        )

    # 1. Structural Comparison: Tensor Count
    if len(recorded_tensors) != len(replay_tensors):
        return ReplayComparisonResult(
            recorded_raw_output_hash=recorded_raw_hash,
            replay_raw_output_hash=replay_raw_hash,
            exact_hash_match=False,
            structural_match=False,
            numerical_match=False,
            max_absolute_error=0.0,
            max_relative_error=0.0,
            mismatch_count=0,
            total_elements=0,
            comparison_status=ComparisonStatus.COUNT_MISMATCH,
            details={
                "error": "Tensor count mismatch",
                "recorded_count": len(recorded_tensors),
                "replay_count": len(replay_tensors),
            },
        )

    # 2. Structural & Numerical Element Comparison per Tensor
    total_elements = 0
    total_mismatches = 0
    max_abs_err = 0.0
    max_rel_err = 0.0
    structural_match = True
    comp_status = ComparisonStatus.EXACT_MATCH if exact_hash_match else ComparisonStatus.TOLERANT_MATCH
    details: Dict[str, Any] = {}

    for i in range(len(recorded_tensors)):
        rec_item = recorded_tensors[i]
        rep_item = replay_tensors[i]

        _, rec_name, rec_shape, rec_dtype = _extract_array_and_metadata(rec_item)
        _, rep_name, rep_shape, rep_dtype = _extract_array_and_metadata(rep_item)

        # Name check
        if rec_name and rep_name and rec_name != rep_name:
            return ReplayComparisonResult(
                recorded_raw_output_hash=recorded_raw_hash,
                replay_raw_output_hash=replay_raw_hash,
                exact_hash_match=False,
                structural_match=False,
                numerical_match=False,
                max_absolute_error=0.0,
                max_relative_error=0.0,
                mismatch_count=0,
                total_elements=0,
                comparison_status=ComparisonStatus.NAME_MISMATCH,
                details={
                    "tensor_index": i,
                    "recorded_name": rec_name,
                    "replay_name": rep_name,
                },
            )

        # Rank check
        if len(rec_shape) != len(rep_shape):
            return ReplayComparisonResult(
                recorded_raw_output_hash=recorded_raw_hash,
                replay_raw_output_hash=replay_raw_hash,
                exact_hash_match=False,
                structural_match=False,
                numerical_match=False,
                max_absolute_error=0.0,
                max_relative_error=0.0,
                mismatch_count=0,
                total_elements=0,
                comparison_status=ComparisonStatus.RANK_MISMATCH,
                details={
                    "tensor_index": i,
                    "recorded_shape": rec_shape,
                    "replay_shape": rep_shape,
                },
            )

        # Shape check
        if rec_shape != rep_shape:
            return ReplayComparisonResult(
                recorded_raw_output_hash=recorded_raw_hash,
                replay_raw_output_hash=replay_raw_hash,
                exact_hash_match=False,
                structural_match=False,
                numerical_match=False,
                max_absolute_error=0.0,
                max_relative_error=0.0,
                mismatch_count=0,
                total_elements=0,
                comparison_status=ComparisonStatus.SHAPE_MISMATCH,
                details={
                    "tensor_index": i,
                    "recorded_shape": rec_shape,
                    "replay_shape": rep_shape,
                },
            )

        # Dtype check
        if rec_dtype != rep_dtype and not policy.allow_dtype_variance:
            return ReplayComparisonResult(
                recorded_raw_output_hash=recorded_raw_hash,
                replay_raw_output_hash=replay_raw_hash,
                exact_hash_match=False,
                structural_match=False,
                numerical_match=False,
                max_absolute_error=0.0,
                max_relative_error=0.0,
                mismatch_count=0,
                total_elements=0,
                comparison_status=ComparisonStatus.DTYPE_MISMATCH,
                details={
                    "tensor_index": i,
                    "recorded_dtype": rec_dtype,
                    "replay_dtype": rep_dtype,
                },
            )

        # Numerical diff if arrays provided
        if recorded_arrays is not None and replay_arrays is not None:
            # Reference: Authoritative recorded output baseline from Phase 10.8 record
            ref = np.asarray(recorded_arrays[i])
            # Candidate: Newly recomputed output from replay execution
            cand = np.asarray(replay_arrays[i])

            num_elems = ref.size
            total_elements += num_elems

            # Check finite sanity
            ref_finite = np.isfinite(ref)
            cand_finite = np.isfinite(cand)

            if not np.all(cand_finite):
                if not (policy.allow_nonfinite_if_recorded and np.array_equal(ref_finite, cand_finite)):
                    total_mismatches += int(np.sum(~cand_finite))
                    comp_status = ComparisonStatus.NUMERICAL_MISMATCH

            # Pointwise error evaluation against authoritative recorded baseline
            # Formula: |candidate - reference| <= atol + rtol * |reference|
            with np.errstate(invalid="ignore"):
                diff = np.abs(cand - ref)
                allowable = policy.atol + (policy.rtol * np.abs(ref))
                mismatches = (diff > allowable) | (~cand_finite & ref_finite)

                # Pointwise relative error with epsilon protecting against division-by-zero on zero-reference:
                # relative_error = |candidate - reference| / (|reference| + 1e-12)
                rel_err = diff / (np.abs(ref) + 1e-12)

                finite_diff = diff[np.isfinite(diff)]
                if finite_diff.size > 0:
                    curr_max_abs = float(np.max(finite_diff))
                    if curr_max_abs > max_abs_err:
                        max_abs_err = curr_max_abs

                finite_rel = rel_err[np.isfinite(rel_err)]
                if finite_rel.size > 0:
                    curr_max_rel = float(np.max(finite_rel))
                    if curr_max_rel > max_rel_err:
                        max_rel_err = curr_max_rel

                mismatch_count_tensor = int(np.sum(mismatches))
                total_mismatches += mismatch_count_tensor

    numerical_match = (total_mismatches == 0)
    if not numerical_match:
        comp_status = ComparisonStatus.NUMERICAL_MISMATCH
    elif exact_hash_match:
        comp_status = ComparisonStatus.EXACT_MATCH
    else:
        comp_status = ComparisonStatus.TOLERANT_MATCH

    return ReplayComparisonResult(
        recorded_raw_output_hash=recorded_raw_hash,
        replay_raw_output_hash=replay_raw_hash,
        exact_hash_match=exact_hash_match,
        structural_match=structural_match,
        numerical_match=numerical_match,
        max_absolute_error=max_abs_err,
        max_relative_error=max_rel_err,
        mismatch_count=total_mismatches,
        total_elements=total_elements,
        comparison_status=comp_status,
        details=details,
    )
