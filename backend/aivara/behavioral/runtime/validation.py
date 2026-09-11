"""Input and output tensor validation and deterministic output hashing (Phase 8.2)."""

from __future__ import annotations

import hashlib
import json
from typing import Any, Dict, List, Tuple
import numpy as np

from aivara.behavioral.exceptions import (
    InvalidInputTensorError,
    InvalidOutputTensorError,
    ResourceLimitExceededError,
)
from aivara.behavioral.limits import ExecutionLimits
from aivara.behavioral.schemas import OutputMetadata
from aivara.crypto.canonical import canonicalize
from aivara.crypto.hashing import sha256_bytes, sha256_text


def validate_input_tensors(
    inputs: Dict[str, Any],
    limits: ExecutionLimits,
    allow_nan: bool = False,
) -> Dict[str, np.ndarray]:
    """Validate and convert input tensors according to strict dimensionality, finite-value, and resource rules."""
    if not isinstance(inputs, dict) or len(inputs) == 0:
        raise InvalidInputTensorError("Execution inputs must be a non-empty dictionary mapping input names to tensors.")

    validated_inputs: Dict[str, np.ndarray] = {}
    total_elements = 0

    for name, value in sorted(inputs.items()):
        if not isinstance(name, str) or len(name.strip()) == 0:
            raise InvalidInputTensorError(f"Invalid input tensor name '{name}'.")

        # Convert to numpy array
        if isinstance(value, np.ndarray):
            arr = value
        elif isinstance(value, (list, tuple)):
            arr = np.array(value)
        elif isinstance(value, (int, float, bool)):
            arr = np.array([value])
        else:
            raise InvalidInputTensorError(
                f"Unsupported input data type '{type(value).__name__}' for tensor '{name}'. Expected numpy array or list.",
                details={"tensor_name": name, "type": type(value).__name__},
            )

        # 1. Dimension / Rank Validation
        rank = arr.ndim
        if rank < 1:
            raise InvalidInputTensorError(
                f"Input tensor '{name}' has rank 0 (scalar). Rank must be >= 1.",
                details={"tensor_name": name, "shape": list(arr.shape)},
            )
        if rank > limits.max_input_dimensions:
            raise ResourceLimitExceededError(
                f"Input tensor '{name}' rank {rank} exceeds maximum allowed rank {limits.max_input_dimensions}.",
                details={"tensor_name": name, "rank": rank, "max_rank": limits.max_input_dimensions},
            )

        # 2. Batch Size Validation (Dimension 0)
        batch_size = arr.shape[0]
        if batch_size > limits.max_batch_size:
            raise ResourceLimitExceededError(
                f"Input tensor '{name}' batch size {batch_size} exceeds maximum allowed batch size {limits.max_batch_size}.",
                details={"tensor_name": name, "batch_size": batch_size, "max_batch_size": limits.max_batch_size},
            )
        if any(d <= 0 for d in arr.shape):
            raise InvalidInputTensorError(
                f"Input tensor '{name}' contains non-positive dimension in shape {list(arr.shape)}.",
                details={"tensor_name": name, "shape": list(arr.shape)},
            )

        # 3. Element Count Validation
        num_elements = arr.size
        total_elements += num_elements
        if num_elements > limits.max_tensor_elements:
            raise ResourceLimitExceededError(
                f"Input tensor '{name}' element count {num_elements} exceeds limit of {limits.max_tensor_elements}.",
                details={"tensor_name": name, "element_count": num_elements, "max_elements": limits.max_tensor_elements},
            )

        # 4. Finite Value Validation
        if np.issubdtype(arr.dtype, np.floating) and not allow_nan:
            if not np.all(np.isfinite(arr)):
                raise InvalidInputTensorError(
                    f"Input tensor '{name}' contains non-finite values (NaN or Inf).",
                    details={"tensor_name": name, "dtype": str(arr.dtype)},
                )

        validated_inputs[name] = arr

    if total_elements > limits.max_tensor_elements:
        raise ResourceLimitExceededError(
            f"Total input elements ({total_elements}) across all tensors exceeds limit of {limits.max_tensor_elements}.",
            details={"total_elements": total_elements, "max_elements": limits.max_tensor_elements},
        )

    return validated_inputs


def validate_output_tensors(
    outputs: Dict[str, np.ndarray],
    limits: ExecutionLimits,
    require_finite: bool = True,
) -> Tuple[OutputMetadata, int]:
    """Validate model inference outputs against size, dimension, finite-value, and memory limits."""
    if not isinstance(outputs, dict) or len(outputs) == 0:
        raise InvalidOutputTensorError("Model execution returned empty or invalid output dictionary.")

    output_names = sorted(outputs.keys())
    output_shapes: Dict[str, List[int]] = {}
    output_dtypes: Dict[str, str] = {}
    element_counts: Dict[str, int] = {}
    summary_stats: Dict[str, Dict[str, float]] = {}
    total_output_bytes = 0
    total_elements = 0
    all_finite = True

    for name in output_names:
        arr = outputs[name]
        if not isinstance(arr, np.ndarray):
            raise InvalidOutputTensorError(
                f"Output tensor '{name}' is of type '{type(arr).__name__}', expected numpy.ndarray.",
                details={"output_name": name},
            )

        output_shapes[name] = list(arr.shape)
        output_dtypes[name] = str(arr.dtype)
        elem_count = arr.size
        element_counts[name] = elem_count
        total_elements += elem_count

        byte_size = arr.nbytes
        total_output_bytes += byte_size

        if elem_count > limits.max_tensor_elements:
            raise ResourceLimitExceededError(
                f"Output tensor '{name}' element count {elem_count} exceeds maximum limit of {limits.max_tensor_elements}.",
                details={"output_name": name, "element_count": elem_count},
            )

        if total_output_bytes > limits.max_output_bytes:
            raise ResourceLimitExceededError(
                f"Total output size {total_output_bytes} bytes exceeds maximum allowed output bytes {limits.max_output_bytes}.",
                details={"total_bytes": total_output_bytes, "max_bytes": limits.max_output_bytes},
            )

        # Finite Value Check
        if np.issubdtype(arr.dtype, np.floating):
            is_arr_finite = bool(np.all(np.isfinite(arr)))
            if not is_arr_finite:
                all_finite = False
                if require_finite:
                    raise InvalidOutputTensorError(
                        f"Output tensor '{name}' contains non-finite values (NaN or Inf).",
                        details={"output_name": name, "dtype": str(arr.dtype)},
                    )
            # Compute basic statistics if finite and non-empty
            if is_arr_finite and elem_count > 0:
                summary_stats[name] = {
                    "min": float(np.min(arr)),
                    "max": float(np.max(arr)),
                    "mean": float(np.mean(arr)),
                    "std": float(np.std(arr)),
                }

    meta = OutputMetadata(
        output_names=output_names,
        output_shapes=output_shapes,
        output_dtypes=output_dtypes,
        element_counts=element_counts,
        is_finite=all_finite,
        summary_stats=summary_stats,
    )

    return meta, total_elements


def compute_canonical_output_hash(outputs: Dict[str, np.ndarray]) -> str:
    """Compute a deterministic SHA-256 digest over the canonical representation of output tensors.

    Binds:
    - Sorted tensor names
    - Tensor shapes & dtypes
    - Canonical byte representation of contiguous array data
    """
    descriptor_list: List[Dict[str, Any]] = []

    for name in sorted(outputs.keys()):
        arr = outputs[name]
        # Ensure contiguous memory layout for deterministic byte hashing
        c_arr = np.ascontiguousarray(arr)
        tensor_bytes = c_arr.tobytes()
        content_hash = hashlib.sha256(tensor_bytes).hexdigest().lower()

        descriptor_list.append({
            "name": name,
            "shape": list(arr.shape),
            "dtype": str(arr.dtype),
            "element_count": int(arr.size),
            "content_hash": content_hash,
        })

    payload = {
        "schema_version": "1.0",
        "tensors": descriptor_list,
    }

    canonical_bytes = canonicalize(payload)
    return sha256_bytes(canonical_bytes)
