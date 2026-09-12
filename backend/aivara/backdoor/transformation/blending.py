"""Deterministic Mathematical Blending and Clipping for Trigger Transformation (Phase 9.3)."""

from __future__ import annotations

from typing import Tuple
import numpy as np

from aivara.backdoor.candidates.enums import BlendModeEnum, ValueRangeEnum
from aivara.backdoor.transformation.exceptions import TransformationNumericalError


def apply_blend_and_clip(
    source_slice: np.ndarray,  # (H, W, C) float32
    pattern_slice: np.ndarray,  # (H, W, C) float32
    mask_slice: np.ndarray,  # (H, W) float32
    blend_mode: BlendModeEnum,
    alpha: float,
    value_range: ValueRangeEnum = ValueRangeEnum.UNIT_FLOAT,
    is_multiplicative: bool = False,
) -> Tuple[np.ndarray, bool]:
    """Apply mathematical blending equations and deterministic clipping.

    Equations:
      - REPLACE:
          Output = Pattern * Mask + Source * (1 - Mask)
      - ALPHA_BLEND:
          Eff_Alpha = Alpha * Mask
          Output = (1 - Eff_Alpha) * Source + Eff_Alpha * Pattern
      - ADDITIVE_BLEND:
          Output = Source + Alpha * Mask * Pattern
      - MULTIPLICATIVE:
          Output = Source * Pattern * Mask + Source * (1 - Mask)

    Returns:
      (blended_and_clipped_array, clipping_occurred)
    """
    mask_3d = mask_slice[:, :, np.newaxis]  # (H, W, 1)

    if is_multiplicative:
        # Multiplicative scaling in active region
        blended = source_slice * pattern_slice * (mask_3d > 0) + source_slice * (1.0 - (mask_3d > 0))
    elif blend_mode == BlendModeEnum.REPLACE:
        binary_mask = (mask_3d > 0).astype(np.float32)
        blended = pattern_slice * binary_mask + source_slice * (1.0 - binary_mask)
    elif blend_mode == BlendModeEnum.ALPHA_BLEND:
        # mask_3d contains the alpha value in the active region
        eff_alpha = mask_3d
        blended = (1.0 - eff_alpha) * source_slice + eff_alpha * pattern_slice
    elif blend_mode in (BlendModeEnum.ADDITIVE, "ADDITIVE", "ADDITIVE_BLEND"):
        blended = source_slice + (mask_3d * pattern_slice)
    else:
        blended = pattern_slice * (mask_3d > 0) + source_slice * (1.0 - (mask_3d > 0))

    if not np.all(np.isfinite(blended)):
        raise TransformationNumericalError("Transformation produced non-finite values (NaN or Inf).")

    # Clipping Policy
    clipping_occurred = False
    if value_range == ValueRangeEnum.UNIT_FLOAT:
        min_bound, max_bound = 0.0, 1.0
        if np.any(blended < min_bound) or np.any(blended > max_bound):
            clipping_occurred = True
            blended = np.clip(blended, min_bound, max_bound)
    elif value_range in (ValueRangeEnum.BYTE_INTEGER, "BYTE_INTEGER", "BYTE_INT"):
        min_bound, max_bound = 0.0, 255.0
        if np.any(blended < min_bound) or np.any(blended > max_bound):
            clipping_occurred = True
            blended = np.clip(blended, min_bound, max_bound)
    elif value_range == ValueRangeEnum.ZERO_CENTERED:
        min_bound, max_bound = -1.0, 1.0
        if np.any(blended < min_bound) or np.any(blended > max_bound):
            clipping_occurred = True
            blended = np.clip(blended, min_bound, max_bound)

    return blended.astype(np.float32), clipping_occurred
