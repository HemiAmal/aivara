"""Deterministic Pattern Synthesis for Trigger Candidates (Phase 9.2)."""

from __future__ import annotations

import math
from typing import Any, Dict, Optional, Tuple
import numpy as np

from aivara.backdoor.candidates.enums import (
    BlendModeEnum,
    ColorSpaceEnum,
    CornerLocationEnum,
    PatchShapeEnum,
    PerturbationModeEnum,
    PlacementModeEnum,
    TexturePrimitiveEnum,
    TriggerFamilyEnum,
)
from aivara.backdoor.candidates.exceptions import (
    CandidateOutOfBoundsError,
    InvalidCandidateParameterError,
)
from aivara.backdoor.candidates.models import (
    ColorPatternPatchParameters,
    LocalizedPerturbationParameters,
    PlacementSpec,
    SpatialPatchParameters,
    TextureGridParameters,
    TriggerCandidateSpec,
)


def compute_bounding_box(
    target_shape: Tuple[int, int, int],  # (H, W, C)
    rel_width: float,
    rel_height: float,
    placement: PlacementSpec,
) -> Tuple[int, int, int, int]:  # (top, left, height, width)
    """Compute exact pixel coordinates (top, left, height, width) for candidate on canvas."""
    H, W, _ = target_shape
    h_px = max(1, min(H, int(round(rel_height * H))))
    w_px = max(1, min(W, int(round(rel_width * W))))

    if placement.mode == PlacementModeEnum.FIXED_CORNER:
        corner = placement.corner or CornerLocationEnum.BOTTOM_RIGHT
        if corner == CornerLocationEnum.TOP_LEFT:
            top, left = 0, 0
        elif corner == CornerLocationEnum.TOP_RIGHT:
            top, left = 0, max(0, W - w_px)
        elif corner == CornerLocationEnum.BOTTOM_LEFT:
            top, left = max(0, H - h_px), 0
        elif corner == CornerLocationEnum.BOTTOM_RIGHT:
            top, left = max(0, H - h_px), max(0, W - w_px)
        elif corner == CornerLocationEnum.CENTER:
            top = max(0, (H - h_px) // 2)
            left = max(0, (W - w_px) // 2)
        else:
            top, left = max(0, H - h_px), max(0, W - w_px)

    elif placement.mode == PlacementModeEnum.NORMALIZED_POSITION:
        nx = placement.normalized_x if placement.normalized_x is not None else 0.8
        ny = placement.normalized_y if placement.normalized_y is not None else 0.8
        left = int(round(nx * (W - w_px)))
        top = int(round(ny * (H - h_px)))
        top = max(0, min(H - h_px, top))
        left = max(0, min(W - w_px, left))

    elif placement.mode == PlacementModeEnum.GRID_CELL:
        row = placement.grid_row if placement.grid_row is not None else 7
        col = placement.grid_col if placement.grid_col is not None else 7
        grid_rows, grid_cols = 8, 8
        cell_h = H / grid_rows
        cell_w = W / grid_cols
        center_y = (row + 0.5) * cell_h
        center_x = (col + 0.5) * cell_w
        top = int(round(center_y - h_px / 2.0))
        left = int(round(center_x - w_px / 2.0))
        top = max(0, min(H - h_px, top))
        left = max(0, min(W - w_px, left))
    else:
        top, left = max(0, H - h_px), max(0, W - w_px)

    return top, left, h_px, w_px


def generate_spatial_patch_pattern(
    params: SpatialPatchParameters,
    placement: PlacementSpec,
    target_shape: Tuple[int, int, int],  # (H, W, C)
) -> Tuple[np.ndarray, np.ndarray]:
    """Synthesize pattern and alpha mask for SPATIAL_PATCH."""
    H, W, C = target_shape
    pattern = np.zeros((H, W, C), dtype=np.float32)
    mask = np.zeros((H, W), dtype=np.float32)

    top, left, h_px, w_px = compute_bounding_box(
        target_shape, params.relative_width, params.relative_height, placement
    )

    color = np.array(params.fill_color[:C], dtype=np.float32)
    if len(color) < C:
        color = np.pad(color, (0, C - len(color)), mode="edge")

    alpha_val = float(params.alpha)

    if params.shape in (PatchShapeEnum.RECTANGLE, PatchShapeEnum.SQUARE):
        pattern[top : top + h_px, left : left + w_px, :] = color
        mask[top : top + h_px, left : left + w_px] = alpha_val

    elif params.shape == PatchShapeEnum.CIRCLE:
        cy = top + h_px / 2.0
        cx = left + w_px / 2.0
        radius = min(h_px, w_px) / 2.0
        
        y_indices, x_indices = np.ogrid[:H, :W]
        dist_sq = (y_indices - cy) ** 2 + (x_indices - cx) ** 2
        circle_mask = (dist_sq <= radius ** 2)
        
        pattern[circle_mask, :] = color
        mask[circle_mask] = alpha_val

    return pattern, mask


def generate_color_pattern_patch(
    params: ColorPatternPatchParameters,
    placement: PlacementSpec,
    target_shape: Tuple[int, int, int],
) -> Tuple[np.ndarray, np.ndarray]:
    """Synthesize pattern and alpha mask for COLOR_PATTERN_PATCH."""
    H, W, C = target_shape
    pattern = np.zeros((H, W, C), dtype=np.float32)
    mask = np.zeros((H, W), dtype=np.float32)

    top, left, h_px, w_px = compute_bounding_box(
        target_shape, params.relative_width, params.relative_height, placement
    )

    deltas = np.array(params.channel_deltas[:C], dtype=np.float32)
    if len(deltas) < C:
        deltas = np.pad(deltas, (0, C - len(deltas)), mode="edge")

    pattern[top : top + h_px, left : left + w_px, :] = deltas
    mask[top : top + h_px, left : left + w_px] = float(params.alpha)

    return pattern, mask


def generate_texture_grid_pattern(
    params: TextureGridParameters,
    target_shape: Tuple[int, int, int],
) -> Tuple[np.ndarray, np.ndarray]:
    """Synthesize full-frame periodic pattern and mask for TEXTURE_GRID."""
    H, W, C = target_shape
    pattern = np.zeros((H, W, C), dtype=np.float32)
    mask = np.zeros((H, W), dtype=np.float32)

    stride = max(2, params.stride_pixels)
    line_w = max(1, min(stride // 2, params.line_width_pixels))
    phase = int(round(params.phase_offset * stride))
    amp = float(params.amplitude)
    alpha_val = float(params.alpha)

    y_coords = (np.arange(H) + phase) % stride
    x_coords = (np.arange(W) + phase) % stride

    if params.primitive == TexturePrimitiveEnum.CHECKER:
        y_grid = (y_coords < (stride // 2))[:, None]
        x_grid = (x_coords < (stride // 2))[None, :]
        active = (y_grid ^ x_grid)

    elif params.primitive == TexturePrimitiveEnum.GRID:
        y_lines = (y_coords < line_w)[:, None]
        x_lines = (x_coords < line_w)[None, :]
        active = (y_lines | x_lines)

    elif params.primitive == TexturePrimitiveEnum.STRIPE_HORIZONTAL:
        active = (y_coords < line_w)[:, None]
        active = np.broadcast_to(active, (H, W))

    elif params.primitive == TexturePrimitiveEnum.STRIPE_VERTICAL:
        active = (x_coords < line_w)[None, :]
        active = np.broadcast_to(active, (H, W))

    elif params.primitive == TexturePrimitiveEnum.DOT_GRID:
        y_dots = (y_coords < line_w)[:, None]
        x_dots = (x_coords < line_w)[None, :]
        active = (y_dots & x_dots)

    else:
        active = np.zeros((H, W), dtype=bool)

    color = np.array(params.color_channels[:C], dtype=np.float32) * amp
    if len(color) < C:
        color = np.pad(color, (0, C - len(color)), mode="edge")

    pattern[active, :] = color
    mask[active] = alpha_val

    return pattern, mask


def generate_localized_perturbation_pattern(
    params: LocalizedPerturbationParameters,
    placement: PlacementSpec,
    target_shape: Tuple[int, int, int],
    seed: int,
) -> Tuple[np.ndarray, np.ndarray]:
    """Synthesize pattern and mask for LOCALIZED_PERTURBATION using PCG64 random state."""
    H, W, C = target_shape
    pattern = np.zeros((H, W, C), dtype=np.float32)
    mask = np.zeros((H, W), dtype=np.float32)

    top, left, h_px, w_px = compute_bounding_box(
        target_shape, params.relative_width, params.relative_height, placement
    )

    # Initialize deterministic PCG64 generator
    rng = np.random.Generator(np.random.PCG64(seed))

    amp = float(params.amplitude)
    std = float(params.noise_std)

    if params.mode == PerturbationModeEnum.ADDITIVE_GAUSSIAN:
        noise = rng.normal(loc=0.0, scale=std, size=(h_px, w_px, C)).astype(np.float32)
        noise = np.clip(noise, -amp, amp)
    elif params.mode == PerturbationModeEnum.ADDITIVE_UNIFORM:
        noise = rng.uniform(low=-amp, high=amp, size=(h_px, w_px, C)).astype(np.float32)
    elif params.mode == PerturbationModeEnum.MULTIPLICATIVE_UNIFORM:
        noise = rng.uniform(low=1.0 - amp, high=1.0 + amp, size=(h_px, w_px, C)).astype(np.float32)
    else:
        noise = np.zeros((h_px, w_px, C), dtype=np.float32)

    pattern[top : top + h_px, left : left + w_px, :] = noise
    mask[top : top + h_px, left : left + w_px] = 1.0

    return pattern, mask
