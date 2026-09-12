"""Input Array and Layout Validation for Trigger Transformation (Phase 9.3)."""

from __future__ import annotations

from typing import Any, Optional, Tuple, Union
import numpy as np

from aivara.backdoor.candidates.models import InputConstraints, TriggerCandidateSpec
from aivara.backdoor.transformation.enums import InputLayoutEnum
from aivara.backdoor.transformation.exceptions import (
    CandidateInputMismatchError,
    InvalidInputError,
    NonFiniteInputError,
    TransformationBudgetExceededError,
    UnsupportedDtypeError,
    UnsupportedInputShapeError,
)

# Safe memory and dimension bounds
MAX_SPATIAL_DIM: int = 4096
MIN_SPATIAL_DIM: int = 16
MAX_BATCH_SIZE: int = 16
MAX_ELEMENTS_PER_ARRAY: int = 4096 * 4096 * 4 * 16  # ~1GB float32 ceiling

SUPPORTED_DTYPES = (
    np.float32,
    np.float64,
    np.uint8,
    np.int32,
    np.int64,
)

SUPPORTED_CHANNELS = (1, 3, 4)


def validate_input_array(
    arr: Any,
    candidate_spec: TriggerCandidateSpec,
    declared_layout: Optional[Union[InputLayoutEnum, str]] = None,
) -> Tuple[InputLayoutEnum, Tuple[int, int], int, Optional[int]]:
    """Validate input array against Phase 8/9 tensor contracts, candidate constraints, and resolve explicit layout.

    Returns:
      (resolved_layout, (H, W), C, N_batch_or_None)
    """
    if not isinstance(arr, np.ndarray):
        raise InvalidInputError(f"Expected numpy.ndarray input, got '{type(arr).__name__}'.")

    if arr.size == 0:
        raise InvalidInputError("Input array is empty (size 0).")

    if arr.size > MAX_ELEMENTS_PER_ARRAY:
        raise TransformationBudgetExceededError(
            f"Input array size ({arr.size} elements) exceeds maximum safe element limit ({MAX_ELEMENTS_PER_ARRAY})."
        )

    # Validate dtype
    if arr.dtype.type not in SUPPORTED_DTYPES and arr.dtype not in (np.float32, np.float64, np.uint8, np.int32, np.int64):
        raise UnsupportedDtypeError(
            f"Unsupported array dtype '{arr.dtype}'. Supported dtypes: {[dt.__name__ for dt in SUPPORTED_DTYPES]}."
        )

    # Validate finite values (no NaN, no Inf)
    if np.issubdtype(arr.dtype, np.floating):
        if not np.all(np.isfinite(arr)):
            raise NonFiniteInputError("Input array contains non-finite values (NaN or Inf).")

    rank = arr.ndim
    constraints = candidate_spec.input_constraints

    if rank not in constraints.supported_ranks:
        raise UnsupportedInputShapeError(
            f"Input rank {rank} is not supported by candidate constraints {constraints.supported_ranks}."
        )

    # Resolve layout enum if string provided
    layout_enum: Optional[InputLayoutEnum] = None
    if declared_layout is not None:
        if isinstance(declared_layout, InputLayoutEnum):
            layout_enum = declared_layout
        elif isinstance(declared_layout, str):
            try:
                layout_enum = InputLayoutEnum(declared_layout.upper())
            except ValueError:
                raise UnsupportedInputShapeError(
                    f"Unsupported layout string '{declared_layout}'. Supported layouts: {[e.value for e in InputLayoutEnum]}."
                )
        else:
            raise UnsupportedInputShapeError(f"Invalid layout specification type: {type(declared_layout).__name__}.")

    # 1. Rank 2: GRAYSCALE_2D
    if rank == 2:
        if layout_enum is not None and layout_enum != InputLayoutEnum.GRAYSCALE_2D:
            raise UnsupportedInputShapeError(f"Rank 2 array is incompatible with declared layout '{layout_enum.value}'.")
        resolved_layout = InputLayoutEnum.GRAYSCALE_2D
        H, W = arr.shape
        C = 1
        N = None

    # 2. Rank 3: HWC or CHW
    elif rank == 3:
        if layout_enum is not None:
            if layout_enum == InputLayoutEnum.HWC:
                H, W, C = arr.shape
                if C not in SUPPORTED_CHANNELS:
                    raise UnsupportedInputShapeError(f"HWC channel dimension (axis 2) must be in {SUPPORTED_CHANNELS}, got {C}.")
                resolved_layout = InputLayoutEnum.HWC
            elif layout_enum == InputLayoutEnum.CHW:
                C, H, W = arr.shape
                if C not in SUPPORTED_CHANNELS:
                    raise UnsupportedInputShapeError(f"CHW channel dimension (axis 0) must be in {SUPPORTED_CHANNELS}, got {C}.")
                resolved_layout = InputLayoutEnum.CHW
            else:
                raise UnsupportedInputShapeError(f"Rank 3 array is incompatible with declared layout '{layout_enum.value}'.")
            N = None
        else:
            # Layout inference
            axis0_is_ch = arr.shape[0] in SUPPORTED_CHANNELS
            axis2_is_ch = arr.shape[2] in SUPPORTED_CHANNELS
            if axis2_is_ch and not axis0_is_ch and arr.shape[0] >= MIN_SPATIAL_DIM and arr.shape[1] >= MIN_SPATIAL_DIM:
                H, W, C = arr.shape
                resolved_layout = InputLayoutEnum.HWC
            elif axis0_is_ch and not axis2_is_ch and arr.shape[1] >= MIN_SPATIAL_DIM and arr.shape[2] >= MIN_SPATIAL_DIM:
                C, H, W = arr.shape
                resolved_layout = InputLayoutEnum.CHW
            elif axis0_is_ch and axis2_is_ch:
                raise UnsupportedInputShapeError(
                    f"Ambiguous rank 3 array shape {arr.shape}: both axis 0 and axis 2 match channel counts. "
                    "Explicit input_layout (HWC or CHW) is required (ADR-087)."
                )
            else:
                raise UnsupportedInputShapeError(
                    f"Cannot infer channel layout for rank 3 array shape {arr.shape}. Explicit input_layout is required."
                )
            N = None

    # 3. Rank 4: NHWC or NCHW
    elif rank == 4:
        N = arr.shape[0]
        if N > MAX_BATCH_SIZE:
            raise TransformationBudgetExceededError(
                f"Batch size {N} exceeds maximum allowed batch ceiling ({MAX_BATCH_SIZE})."
            )
        if N < 1:
            raise UnsupportedInputShapeError(f"Batch dimension must be >= 1, got {N}.")

        if layout_enum is not None:
            if layout_enum == InputLayoutEnum.NHWC:
                _, H, W, C = arr.shape
                if C not in SUPPORTED_CHANNELS:
                    raise UnsupportedInputShapeError(f"NHWC channel dimension (axis 3) must be in {SUPPORTED_CHANNELS}, got {C}.")
                resolved_layout = InputLayoutEnum.NHWC
            elif layout_enum == InputLayoutEnum.NCHW:
                _, C, H, W = arr.shape
                if C not in SUPPORTED_CHANNELS:
                    raise UnsupportedInputShapeError(f"NCHW channel dimension (axis 1) must be in {SUPPORTED_CHANNELS}, got {C}.")
                resolved_layout = InputLayoutEnum.NCHW
            else:
                raise UnsupportedInputShapeError(f"Rank 4 array is incompatible with declared layout '{layout_enum.value}'.")
        else:
            # Layout inference
            axis1_is_ch = arr.shape[1] in SUPPORTED_CHANNELS
            axis3_is_ch = arr.shape[3] in SUPPORTED_CHANNELS
            if axis3_is_ch and not axis1_is_ch and arr.shape[1] >= MIN_SPATIAL_DIM and arr.shape[2] >= MIN_SPATIAL_DIM:
                _, H, W, C = arr.shape
                resolved_layout = InputLayoutEnum.NHWC
            elif axis1_is_ch and not axis3_is_ch and arr.shape[2] >= MIN_SPATIAL_DIM and arr.shape[3] >= MIN_SPATIAL_DIM:
                _, C, H, W = arr.shape
                resolved_layout = InputLayoutEnum.NCHW
            elif axis1_is_ch and axis3_is_ch:
                raise UnsupportedInputShapeError(
                    f"Ambiguous rank 4 array shape {arr.shape}: both axis 1 and axis 3 match channel counts. "
                    "Explicit input_layout (NHWC or NCHW) is required (ADR-087)."
                )
            else:
                raise UnsupportedInputShapeError(
                    f"Cannot infer channel layout for rank 4 array shape {arr.shape}. Explicit input_layout is required."
                )
    else:
        raise UnsupportedInputShapeError(f"Unsupported array rank {rank}. Only ranks 2, 3, 4 are supported.")

    # Spatial shape bounds check
    min_h, min_w = constraints.min_spatial_shape
    max_h, max_w = constraints.max_spatial_shape
    if H < min_h or H > max_h or W < min_w or W > max_w:
        raise UnsupportedInputShapeError(
            f"Input spatial dimensions ({H}, {W}) violate bounds [({min_h}, {min_w}), ({max_h}, {max_w})]."
        )

    return resolved_layout, (H, W), C, N
