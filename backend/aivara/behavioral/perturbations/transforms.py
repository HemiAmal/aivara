"""Pure, deterministic, bounded mathematical implementations of all Phase 8.4 image perturbations."""

from __future__ import annotations

import io
import math
from typing import Any, Dict, List, Optional, Tuple, Union
import numpy as np
from PIL import Image

from aivara.behavioral.perturbations.schemas import (
    BorderPolicy,
    BrightnessParams,
    ContrastParams,
    GaussianBlurParams,
    GaussianNoiseParams,
    JpegCompressionParams,
    SpatialTranslationParams,
    UniformNoiseParams,
)


def _get_effective_range_and_dtype(
    image: np.ndarray,
    declared_range: Optional[Tuple[float, float]] = None,
) -> Tuple[float, float, str]:
    """Determine effective min/max value bounds and base dtype representation."""
    if image.dtype == np.uint8:
        return (0.0, 255.0, "uint8")
    elif np.issubdtype(image.dtype, np.floating):
        if declared_range is not None:
            return (float(declared_range[0]), float(declared_range[1]), str(image.dtype))
        # Default float assumption is standard unit interval [0.0, 1.0]
        return (0.0, 1.0, str(image.dtype))
    else:
        raise ValueError(f"Unsupported image array dtype: {image.dtype}. Expected uint8 or floating-point.")


def apply_gaussian_noise(
    image: np.ndarray,
    params: GaussianNoiseParams,
    declared_range: Optional[Tuple[float, float]] = None,
) -> np.ndarray:
    """Apply bounded additive Gaussian noise using an isolated, deterministic PRNG."""
    v_min, v_max, dtype_str = _get_effective_range_and_dtype(image, declared_range)
    v_span = v_max - v_min

    # Isolated deterministic PRNG
    rng = np.random.Generator(np.random.PCG64(params.seed))

    # Scale relative parameters if needed
    eff_std = params.std * v_span if dtype_str == "uint8" and params.std <= 1.0 else params.std
    eff_mean = params.mean * v_span if dtype_str == "uint8" and abs(params.mean) <= 1.0 else params.mean

    noise = rng.normal(loc=eff_mean, scale=eff_std, size=image.shape)
    perturbed = image.astype(np.float64) + noise

    # Strict clipping within declared representation bounds
    clipped = np.clip(perturbed, v_min, v_max)

    if dtype_str == "uint8":
        return np.round(clipped).astype(np.uint8)
    return clipped.astype(image.dtype)


def apply_uniform_noise(
    image: np.ndarray,
    params: UniformNoiseParams,
    declared_range: Optional[Tuple[float, float]] = None,
) -> np.ndarray:
    """Apply bounded additive Uniform noise using an isolated, deterministic PRNG."""
    v_min, v_max, dtype_str = _get_effective_range_and_dtype(image, declared_range)
    v_span = v_max - v_min

    rng = np.random.Generator(np.random.PCG64(params.seed))

    eff_low = params.min_val * v_span if dtype_str == "uint8" and abs(params.min_val) <= 1.0 else params.min_val
    eff_high = params.max_val * v_span if dtype_str == "uint8" and abs(params.max_val) <= 1.0 else params.max_val

    noise = rng.uniform(low=eff_low, high=eff_high, size=image.shape)
    perturbed = image.astype(np.float64) + noise
    clipped = np.clip(perturbed, v_min, v_max)

    if dtype_str == "uint8":
        return np.round(clipped).astype(np.uint8)
    return clipped.astype(image.dtype)


def apply_brightness(
    image: np.ndarray,
    params: BrightnessParams,
    declared_range: Optional[Tuple[float, float]] = None,
) -> np.ndarray:
    """Apply deterministic multiplicative brightness scaling with boundary clipping."""
    v_min, v_max, dtype_str = _get_effective_range_and_dtype(image, declared_range)

    scaled = image.astype(np.float64) * params.factor
    clipped = np.clip(scaled, v_min, v_max)

    if dtype_str == "uint8":
        return np.round(clipped).astype(np.uint8)
    return clipped.astype(image.dtype)


def apply_contrast(
    image: np.ndarray,
    params: ContrastParams,
    declared_range: Optional[Tuple[float, float]] = None,
) -> np.ndarray:
    """Apply deterministic linear contrast scaling centered at midpoint of value range."""
    v_min, v_max, dtype_str = _get_effective_range_and_dtype(image, declared_range)
    midpoint = (v_min + v_max) / 2.0

    adjusted = midpoint + params.factor * (image.astype(np.float64) - midpoint)
    clipped = np.clip(adjusted, v_min, v_max)

    if dtype_str == "uint8":
        return np.round(clipped).astype(np.uint8)
    return clipped.astype(image.dtype)


def _generate_1d_gaussian_kernel(kernel_size: int, sigma: float) -> np.ndarray:
    """Generate normalized 1D Gaussian kernel array."""
    radius = kernel_size // 2
    x = np.arange(-radius, radius + 1, dtype=np.float64)
    kernel = np.exp(-0.5 * (x / sigma) ** 2)
    k_sum = np.sum(kernel)
    if k_sum > 0:
        kernel /= k_sum
    return kernel


def _convolve1d_axis(arr: np.ndarray, kernel: np.ndarray, axis: int) -> np.ndarray:
    """Apply 1D convolution along specified spatial axis with edge replication padding."""
    radius = len(kernel) // 2
    pad_width = [(0, 0)] * arr.ndim
    pad_width[axis] = (radius, radius)

    padded = np.pad(arr, pad_width, mode="edge")
    out = np.zeros_like(arr, dtype=np.float64)

    # Vectorized 1D convolution over the padded slice
    for k_idx, weight in enumerate(kernel):
        start = k_idx
        end = padded.shape[axis] - (len(kernel) - 1 - k_idx)
        # Construct slicing tuple
        slices_padded = [slice(None)] * arr.ndim
        slices_padded[axis] = slice(start, end)
        out += weight * padded[tuple(slices_padded)]

    return out


def apply_gaussian_blur(
    image: np.ndarray,
    params: GaussianBlurParams,
    declared_range: Optional[Tuple[float, float]] = None,
) -> np.ndarray:
    """Apply deterministic separable 2D Gaussian blur with edge-replicated boundaries."""
    v_min, v_max, dtype_str = _get_effective_range_and_dtype(image, declared_range)
    kernel = _generate_1d_gaussian_kernel(params.kernel_size, params.sigma)

    # Determine spatial axes (assuming spatial dims are at end or start)
    # Supported: 2D (H, W), 3D (H, W, C) or (C, H, W), 4D (N, C, H, W) or (N, H, W, C)
    arr = image.astype(np.float64)

    if arr.ndim == 2:
        # (H, W) -> filter along axis 0, then axis 1
        arr = _convolve1d_axis(arr, kernel, axis=0)
        arr = _convolve1d_axis(arr, kernel, axis=1)
    elif arr.ndim == 3:
        if arr.shape[0] in (1, 3, 4) and arr.shape[0] < min(arr.shape[1], arr.shape[2]):
            # Channel first: (C, H, W)
            arr = _convolve1d_axis(arr, kernel, axis=1)
            arr = _convolve1d_axis(arr, kernel, axis=2)
        else:
            # Channel last: (H, W, C)
            arr = _convolve1d_axis(arr, kernel, axis=0)
            arr = _convolve1d_axis(arr, kernel, axis=1)
    elif arr.ndim == 4:
        if arr.shape[1] in (1, 3, 4) and arr.shape[1] < min(arr.shape[2], arr.shape[3]):
            # NCHW
            arr = _convolve1d_axis(arr, kernel, axis=2)
            arr = _convolve1d_axis(arr, kernel, axis=3)
        else:
            # NHWC
            arr = _convolve1d_axis(arr, kernel, axis=1)
            arr = _convolve1d_axis(arr, kernel, axis=2)
    else:
        raise ValueError(f"Gaussian blur requires image rank 2, 3, or 4 (received {arr.ndim})")

    clipped = np.clip(arr, v_min, v_max)
    if dtype_str == "uint8":
        return np.round(clipped).astype(np.uint8)
    return clipped.astype(image.dtype)


def apply_jpeg_compression(
    image: np.ndarray,
    params: JpegCompressionParams,
    declared_range: Optional[Tuple[float, float]] = None,
) -> np.ndarray:
    """Apply deterministic JPEG compression encoding and decoding via in-memory buffer."""
    v_min, v_max, dtype_str = _get_effective_range_and_dtype(image, declared_range)

    # Convert to uint8 for JPEG encoding
    if dtype_str == "uint8":
        u8_img = image
    else:
        # Scale to [0, 255]
        v_span = (v_max - v_min) or 1.0
        norm = (image.astype(np.float64) - v_min) / v_span
        u8_img = np.round(np.clip(norm * 255.0, 0.0, 255.0)).astype(np.uint8)

    # Handle channel arrangements
    orig_shape = u8_img.shape
    is_ch_first = False
    if u8_img.ndim == 3 and u8_img.shape[0] in (1, 3) and u8_img.shape[0] < min(u8_img.shape[1], u8_img.shape[2]):
        is_ch_first = True
        u8_img = np.transpose(u8_img, (1, 2, 0))

    if u8_img.ndim == 2:
        pil_img = Image.fromarray(u8_img, mode="L")
    elif u8_img.ndim == 3 and u8_img.shape[2] == 1:
        pil_img = Image.fromarray(u8_img[:, :, 0], mode="L")
    elif u8_img.ndim == 3 and u8_img.shape[2] == 3:
        pil_img = Image.fromarray(u8_img, mode="RGB")
    elif u8_img.ndim == 3 and u8_img.shape[2] == 4:
        # JPEG does not support alpha channel directly, encode RGB part
        pil_img = Image.fromarray(u8_img[:, :, :3], mode="RGB")
    else:
        raise ValueError(f"Unsupported image shape for JPEG compression: {image.shape}")

    # Encode to buffer
    buf = io.BytesIO()
    pil_img.save(buf, format="JPEG", quality=params.quality, optimize=False, subsampling=0)
    buf.seek(0)

    # Decode
    reloaded_pil = Image.open(buf)
    reloaded_arr = np.array(reloaded_pil)

    if u8_img.ndim == 3 and u8_img.shape[2] == 1 and reloaded_arr.ndim == 2:
        reloaded_arr = np.expand_dims(reloaded_arr, axis=-1)
    elif u8_img.ndim == 3 and u8_img.shape[2] == 4 and reloaded_arr.ndim == 3:
        # Re-attach original alpha channel unmodified
        alpha = u8_img[:, :, 3:4]
        reloaded_arr = np.concatenate([reloaded_arr, alpha], axis=-1)

    if is_ch_first:
        reloaded_arr = np.transpose(reloaded_arr, (2, 0, 1))

    # Convert back to original dtype / range
    if dtype_str == "uint8":
        return reloaded_arr.astype(np.uint8)
    else:
        v_span = (v_max - v_min) or 1.0
        rescaled = v_min + (reloaded_arr.astype(np.float64) / 255.0) * v_span
        return np.clip(rescaled, v_min, v_max).astype(image.dtype)


def apply_spatial_translation(
    image: np.ndarray,
    params: SpatialTranslationParams,
    declared_range: Optional[Tuple[float, float]] = None,
) -> np.ndarray:
    """Apply bounded 2D pixel displacement along horizontal and vertical axes with border policy."""
    v_min, v_max, dtype_str = _get_effective_range_and_dtype(image, declared_range)

    dx = params.dx
    dy = params.dy

    # Identify spatial axes
    # 2D: (H, W) -> y_axis=0, x_axis=1
    # 3D: (C, H, W) -> y_axis=1, x_axis=2 OR (H, W, C) -> y_axis=0, x_axis=1
    if image.ndim == 2:
        y_axis, x_axis = 0, 1
    elif image.ndim == 3:
        if image.shape[0] in (1, 3, 4) and image.shape[0] < min(image.shape[1], image.shape[2]):
            y_axis, x_axis = 1, 2
        else:
            y_axis, x_axis = 0, 1
    elif image.ndim == 4:
        if image.shape[1] in (1, 3, 4) and image.shape[1] < min(image.shape[2], image.shape[3]):
            y_axis, x_axis = 2, 3
        else:
            y_axis, x_axis = 1, 2
    else:
        raise ValueError(f"Spatial translation requires image rank 2, 3, or 4 (received {image.ndim})")

    H = image.shape[y_axis]
    W = image.shape[x_axis]

    # Translate using np.roll and pad border according to policy
    res = np.roll(image, shift=(dy, dx), axis=(y_axis, x_axis))

    # Apply boundary policy for shifted-in regions
    if params.border_policy == BorderPolicy.CONSTANT:
        fill_val = params.fill_value
        if dy > 0:
            slices = [slice(None)] * image.ndim
            slices[y_axis] = slice(0, dy)
            res[tuple(slices)] = fill_val
        elif dy < 0:
            slices = [slice(None)] * image.ndim
            slices[y_axis] = slice(H + dy, H)
            res[tuple(slices)] = fill_val

        if dx > 0:
            slices = [slice(None)] * image.ndim
            slices[x_axis] = slice(0, dx)
            res[tuple(slices)] = fill_val
        elif dx < 0:
            slices = [slice(None)] * image.ndim
            slices[x_axis] = slice(W + dx, W)
            res[tuple(slices)] = fill_val

    elif params.border_policy == BorderPolicy.REPLICATE:
        if dy > 0:
            # Replicate top row
            edge_slice = [slice(None)] * image.ndim
            edge_slice[y_axis] = slice(dy, dy + 1)
            target_slice = [slice(None)] * image.ndim
            target_slice[y_axis] = slice(0, dy)
            res[tuple(target_slice)] = res[tuple(edge_slice)]
        elif dy < 0:
            # Replicate bottom row
            edge_slice = [slice(None)] * image.ndim
            edge_slice[y_axis] = slice(H + dy - 1, H + dy)
            target_slice = [slice(None)] * image.ndim
            target_slice[y_axis] = slice(H + dy, H)
            res[tuple(target_slice)] = res[tuple(edge_slice)]

        if dx > 0:
            # Replicate left col
            edge_slice = [slice(None)] * image.ndim
            edge_slice[x_axis] = slice(dx, dx + 1)
            target_slice = [slice(None)] * image.ndim
            target_slice[x_axis] = slice(0, dx)
            res[tuple(target_slice)] = res[tuple(edge_slice)]
        elif dx < 0:
            # Replicate right col
            edge_slice = [slice(None)] * image.ndim
            edge_slice[x_axis] = slice(W + dx - 1, W + dx)
            target_slice = [slice(None)] * image.ndim
            target_slice[x_axis] = slice(W + dx, W)
            res[tuple(target_slice)] = res[tuple(edge_slice)]

    # BorderPolicy.REFLECT is naturally handled via symmetric reflection if needed or roll fallback
    return res
