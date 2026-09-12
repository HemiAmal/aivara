"""Tensor validation, layout inspection, and canonical hashing engine."""

from __future__ import annotations

import hashlib
import math
from typing import Any, Dict, List, Optional, Tuple, Union

import numpy as np

from aivara.crypto.canonical import canonicalize
from aivara.inference.config import DEFAULT_INFERENCE_LIMITS, InferenceInputLimits
from aivara.inference.enums import (
    InferenceIntegrityStatus,
    InputKind,
    InputLayout,
    ValueRangeKind,
)
from aivara.inference.exceptions import (
    AmbiguousLayoutError,
    MalformedInputError,
    NonFiniteValueError,
    ResourceLimitExceededError,
    UnsupportedDtypeError,
    ValueRangeMismatchError,
)
from aivara.inference.input.models import InputFinding, TensorMetadata


def resolve_tensor_layout(
    shape: Tuple[int, ...],
    declared_layout: Optional[Union[str, InputLayout]] = None,
) -> InputLayout:
    """Resolve and validate tensor layout against shape dimensions.

    Raises:
        AmbiguousLayoutError: If layout is ambiguous or declared layout is incompatible.
    """
    if declared_layout is not None:
        if isinstance(declared_layout, str):
            try:
                target_layout = InputLayout(declared_layout)
            except ValueError as err:
                raise AmbiguousLayoutError(
                    f"Unknown declared layout '{declared_layout}'.",
                    details={"declared_layout": declared_layout},
                ) from err
        else:
            target_layout = declared_layout

        # Validate declared layout compatibility
        rank = len(shape)
        if target_layout == InputLayout.GRAYSCALE_2D and rank != 2:
            raise AmbiguousLayoutError(
                f"Declared layout GRAYSCALE_2D requires rank 2, got shape {shape}.",
                details={"shape": list(shape), "layout": target_layout.value},
            )
        elif target_layout == InputLayout.HWC:
            if rank != 3 or shape[2] not in (1, 3, 4):
                raise AmbiguousLayoutError(
                    f"Declared layout HWC requires rank 3 with trailing channel in (1,3,4), got {shape}.",
                    details={"shape": list(shape), "layout": target_layout.value},
                )
        elif target_layout == InputLayout.CHW:
            if rank != 3 or shape[0] not in (1, 3, 4):
                raise AmbiguousLayoutError(
                    f"Declared layout CHW requires rank 3 with leading channel in (1,3,4), got {shape}.",
                    details={"shape": list(shape), "layout": target_layout.value},
                )
        elif target_layout == InputLayout.NHWC:
            if rank != 4 or shape[3] not in (1, 3, 4):
                raise AmbiguousLayoutError(
                    f"Declared layout NHWC requires rank 4 with trailing channel in (1,3,4), got {shape}.",
                    details={"shape": list(shape), "layout": target_layout.value},
                )
        elif target_layout == InputLayout.NCHW:
            if rank != 4 or shape[1] not in (1, 3, 4):
                raise AmbiguousLayoutError(
                    f"Declared layout NCHW requires rank 4 with channel in dim 1 in (1,3,4), got {shape}.",
                    details={"shape": list(shape), "layout": target_layout.value},
                )
        elif target_layout == InputLayout.VECTOR_1D and rank != 1:
            raise AmbiguousLayoutError(
                f"Declared layout VECTOR_1D requires rank 1, got shape {shape}.",
                details={"shape": list(shape), "layout": target_layout.value},
            )
        elif target_layout == InputLayout.BATCH_VECTOR_2D and rank != 2:
            raise AmbiguousLayoutError(
                f"Declared layout BATCH_VECTOR_2D requires rank 2, got shape {shape}.",
                details={"shape": list(shape), "layout": target_layout.value},
            )
        return target_layout

    # Automatic Layout Inference
    rank = len(shape)
    if rank == 1:
        return InputLayout.VECTOR_1D
    elif rank == 2:
        return InputLayout.GRAYSCALE_2D
    elif rank == 3:
        # Check channels
        c_first = shape[0] in (1, 3, 4)
        c_last = shape[2] in (1, 3, 4)
        if c_last and not c_first:
            return InputLayout.HWC
        elif c_first and not c_last:
            return InputLayout.CHW
        elif c_first and c_last and shape[0] == shape[2]:
            # e.g. (3, 224, 3) -> ambiguous!
            raise AmbiguousLayoutError(
                f"Ambiguous 3D tensor layout with matching boundary channels: {shape}.",
                details={"shape": list(shape)},
            )
        return InputLayout.TENSOR_ND
    elif rank == 4:
        c_first = shape[1] in (1, 3, 4)
        c_last = shape[3] in (1, 3, 4)
        if c_last and not c_first:
            return InputLayout.NHWC
        elif c_first and not c_last:
            return InputLayout.NCHW
        elif c_first and c_last and shape[1] == shape[3]:
            raise AmbiguousLayoutError(
                f"Ambiguous 4D tensor layout with matching boundary channels: {shape}.",
                details={"shape": list(shape)},
            )
        return InputLayout.TENSOR_ND
    return InputLayout.TENSOR_ND


def classify_value_range(
    min_val: float,
    max_val: float,
    dtype_str: str,
) -> ValueRangeKind:
    """Classify numerical value range into categorical domain."""
    if dtype_str.startswith("uint8") or dtype_str.startswith("int8") or dtype_str.startswith("int16") or dtype_str.startswith("int32") or dtype_str.startswith("int64"):
        if min_val >= 0 and max_val <= 255 and dtype_str.startswith("uint8"):
            return ValueRangeKind.BYTE_INTEGER
        return ValueRangeKind.UNBOUNDED_FLOAT

    if min_val >= 0.0 and max_val <= 1.0:
        return ValueRangeKind.UNIT_FLOAT
    elif min_val >= -1.0 and max_val <= 1.0:
        return ValueRangeKind.ZERO_CENTERED
    return ValueRangeKind.UNBOUNDED_FLOAT


def validate_tensor_input(
    tensor: Any,
    declared_layout: Optional[Union[str, InputLayout]] = None,
    declared_range: Optional[Union[str, ValueRangeKind]] = None,
    limits: Optional[InferenceInputLimits] = None,
) -> Tuple[TensorMetadata, str]:
    """Validate a tensor input safely without in-place mutation.

    Args:
        tensor: Numpy ndarray or array-like numeric object.
        declared_layout: Optional expected layout.
        declared_range: Optional expected value range.
        limits: Resource limits envelope.

    Returns:
        Tuple of (TensorMetadata, canonical_hash).

    Raises:
        MalformedInputError: If tensor is not an array or has non-positive dimensions.
        UnsupportedDtypeError: If dtype is object, string, complex, or unapproved.
        ResourceLimitExceededError: If rank, elements, or memory limits are exceeded.
        NonFiniteValueError: If tensor contains NaN, +Inf, or -Inf.
        AmbiguousLayoutError: If layout is invalid or conflicting.
        ValueRangeMismatchError: If values contradict declared_range.
    """
    active_limits = limits or DEFAULT_INFERENCE_LIMITS

    if tensor is None:
        raise MalformedInputError("Tensor input cannot be None.")

    if not isinstance(tensor, np.ndarray):
        try:
            # Check if object list without converting arbitrary Python objects
            if isinstance(tensor, (list, tuple)):
                tensor = np.asarray(tensor)
            else:
                raise MalformedInputError(
                    f"Expected numpy.ndarray, got '{type(tensor).__name__}'.",
                    details={"type": type(tensor).__name__},
                )
        except Exception as err:
            raise MalformedInputError(
                f"Failed to interpret input as numpy ndarray: {err}",
                details={"type": type(tensor).__name__},
            ) from err

    # 1. Reject object dtypes, string dtypes, complex dtypes
    dtype_str = str(tensor.dtype).lower()
    if tensor.dtype == object or dtype_str.startswith(("object", "<u", ">u", "str", "complex", "datetime")):
        raise UnsupportedDtypeError(
            f"Unsupported tensor dtype '{tensor.dtype}'. Only safe numeric types are permitted.",
            details={"dtype": str(tensor.dtype)},
        )

    # Normalize dtype string to match allowed list
    canonical_dtype = dtype_str
    if canonical_dtype not in active_limits.allowed_tensor_dtypes:
        raise UnsupportedDtypeError(
            f"Dtype '{canonical_dtype}' is not in allowed list {active_limits.allowed_tensor_dtypes}.",
            details={"dtype": canonical_dtype},
        )

    # 2. Check Rank and Shape
    shape = tuple(int(s) for s in tensor.shape)
    rank = len(shape)
    if rank == 0:
        raise MalformedInputError("0-D scalar arrays are not supported as inference tensor inputs.")

    if rank > active_limits.max_tensor_rank:
        raise ResourceLimitExceededError(
            f"Tensor rank {rank} exceeds maximum allowed rank {active_limits.max_tensor_rank}.",
            details={"rank": rank, "max_rank": active_limits.max_tensor_rank},
        )

    for dim in shape:
        if dim <= 0:
            raise MalformedInputError(
                f"Tensor dimension must be strictly positive, got shape {shape}.",
                details={"shape": list(shape)},
            )

    # 3. Check Batch Size if batched
    if rank >= 2 and shape[0] > active_limits.max_batch_size and declared_layout in (InputLayout.NHWC, InputLayout.NCHW, InputLayout.BATCH_VECTOR_2D):
        raise ResourceLimitExceededError(
            f"Batch size {shape[0]} exceeds maximum allowed batch size {active_limits.max_batch_size}.",
            details={"batch_size": shape[0], "max_batch_size": active_limits.max_batch_size},
        )

    # 4. Resource Allocation Pre-calculation
    element_count = int(np.prod(shape))
    if element_count > active_limits.max_tensor_elements:
        raise ResourceLimitExceededError(
            f"Tensor element count {element_count} exceeds maximum {active_limits.max_tensor_elements}.",
            details={"element_count": element_count, "max_elements": active_limits.max_tensor_elements},
        )

    byte_size = element_count * tensor.itemsize
    if byte_size > active_limits.max_tensor_memory_bytes:
        raise ResourceLimitExceededError(
            f"Tensor byte size {byte_size} bytes exceeds maximum memory limit {active_limits.max_tensor_memory_bytes} bytes.",
            details={"byte_size": byte_size, "max_memory_bytes": active_limits.max_tensor_memory_bytes},
        )

    # 5. Finite-Value Validation
    if np.issubdtype(tensor.dtype, np.floating):
        if not np.isfinite(tensor).all():
            raise NonFiniteValueError(
                "Tensor contains non-finite numerical values (NaN, +Inf, or -Inf).",
                details={"shape": list(shape), "dtype": canonical_dtype},
            )
        min_val = float(np.min(tensor))
        max_val = float(np.max(tensor))
    elif np.issubdtype(tensor.dtype, np.integer) or tensor.dtype == bool:
        min_val = float(np.min(tensor))
        max_val = float(np.max(tensor))
    else:
        min_val = None
        max_val = None

    # 6. Value Range Classification and Validation
    if min_val is not None and max_val is not None:
        value_range = classify_value_range(min_val, max_val, canonical_dtype)
    else:
        value_range = ValueRangeKind.UNKNOWN

    if declared_range is not None:
        if isinstance(declared_range, str):
            try:
                target_range = ValueRangeKind(declared_range)
            except ValueError as err:
                raise ValueRangeMismatchError(
                    f"Unknown declared value range '{declared_range}'.",
                    details={"declared_range": declared_range},
                ) from err
        else:
            target_range = declared_range

        if target_range == ValueRangeKind.UNIT_FLOAT:
            if min_val is not None and (min_val < 0.0 or max_val > 1.0):
                raise ValueRangeMismatchError(
                    f"Values [{min_val}, {max_val}] exceed declared UNIT_FLOAT range [0.0, 1.0].",
                    details={"min": min_val, "max": max_val, "expected": "UNIT_FLOAT"},
                )
        elif target_range == ValueRangeKind.ZERO_CENTERED:
            if min_val is not None and (min_val < -1.0 or max_val > 1.0):
                raise ValueRangeMismatchError(
                    f"Values [{min_val}, {max_val}] exceed declared ZERO_CENTERED range [-1.0, 1.0].",
                    details={"min": min_val, "max": max_val, "expected": "ZERO_CENTERED"},
                )
        elif target_range == ValueRangeKind.BYTE_INTEGER:
            if min_val is not None and (min_val < 0 or max_val > 255):
                raise ValueRangeMismatchError(
                    f"Values [{min_val}, {max_val}] exceed declared BYTE_INTEGER range [0, 255].",
                    details={"min": min_val, "max": max_val, "expected": "BYTE_INTEGER"},
                )

    # 7. Resolve Layout
    layout = resolve_tensor_layout(shape, declared_layout)

    # 8. Deterministic Canonical Bytes & Hash (without mutating caller's tensor)
    if tensor.flags.c_contiguous:
        c_bytes = tensor.tobytes()
    else:
        # Create contiguous copy for byte hashing only
        c_bytes = np.ascontiguousarray(tensor).tobytes()

    c_byte_hash = hashlib.sha256(c_bytes).hexdigest()

    # Form canonical descriptor
    canonical_descriptor = {
        "byte_hash": c_byte_hash,
        "dtype": canonical_dtype,
        "element_count": element_count,
        "layout": layout.value,
        "rank": rank,
        "schema_version": "1.0",
        "shape": list(shape),
    }

    canonical_json_bytes = canonicalize(canonical_descriptor)
    canonical_hash = hashlib.sha256(canonical_json_bytes).hexdigest()

    metadata = TensorMetadata(
        rank=rank,
        shape=shape,
        dtype=canonical_dtype,
        layout=layout,
        element_count=element_count,
        byte_size=byte_size,
        finite=True,
        min_value=min_val,
        max_value=max_val,
        value_range=value_range,
        c_contiguous_byte_hash=c_byte_hash,
    )

    return metadata, canonical_hash
