"""Deterministic, objective physical image quality analysis (IQA) algorithms.

Operates directly on uncompressed pixel arrays (RGB uint8 or float32) without
relying on external network calls or heavy deep learning models.
"""

from __future__ import annotations

import math
from pathlib import Path
from typing import Any, Dict, Optional, Tuple, Union

import numpy as np
from PIL import Image, ImageOps

from aivara.dataset.ood.exceptions import ImageQualityError
from aivara.dataset.ood.schemas import ImageQualityConfig, ImageQualityMetrics


def _rgb_to_gray(rgb_array: np.ndarray) -> np.ndarray:
    """Convert RGB float32/uint8 array [H, W, 3] to standard Rec.601 Grayscale [H, W]."""
    if rgb_array.ndim == 2:
        return rgb_array.astype(np.float32)
    if rgb_array.shape[2] == 1:
        return rgb_array[:, :, 0].astype(np.float32)
    
    r = rgb_array[:, :, 0].astype(np.float32)
    g = rgb_array[:, :, 1].astype(np.float32)
    b = rgb_array[:, :, 2].astype(np.float32)
    return 0.299 * r + 0.587 * g + 0.114 * b


def compute_variance_of_laplacian(gray_array: np.ndarray) -> float:
    """Compute Variance of Laplacian blur/focus metric.
    
    Uses standard 3x3 discrete Laplacian kernel:
      [[ 0,  1,  0],
       [ 1, -4,  1],
       [ 0,  1,  0]]
    """
    h, w = gray_array.shape
    if h < 3 or w < 3:
        return 0.0
    
    # 2D discrete Laplacian convolution using fast slicing
    lap = (
        gray_array[0:-2, 1:-1]
        + gray_array[2:, 1:-1]
        + gray_array[1:-1, 0:-2]
        + gray_array[1:-1, 2:]
        - 4.0 * gray_array[1:-1, 1:-1]
    )
    val = float(np.var(lap))
    return max(0.0, val) if math.isfinite(val) else 0.0


def compute_tenengrad_sharpness(gray_array: np.ndarray) -> float:
    """Compute Tenengrad gradient sharpness acutance score using Sobel filters."""
    h, w = gray_array.shape
    if h < 3 or w < 3:
        return 0.0
    
    # Sobel Horizontal (Gx)
    # [[-1, 0, 1], [-2, 0, 2], [-1, 0, 1]]
    gx = (
        (gray_array[0:-2, 2:] + 2.0 * gray_array[1:-1, 2:] + gray_array[2:, 2:])
        - (gray_array[0:-2, 0:-2] + 2.0 * gray_array[1:-1, 0:-2] + gray_array[2:, 0:-2])
    )
    
    # Sobel Vertical (Gy)
    # [[-1, -2, -1], [0, 0, 0], [1, 2, 1]]
    gy = (
        (gray_array[2:, 0:-2] + 2.0 * gray_array[2:, 1:-1] + gray_array[2:, 2:])
        - (gray_array[0:-2, 0:-2] + 2.0 * gray_array[0:-2, 1:-1] + gray_array[0:-2, 2:])
    )
    
    val = float(np.mean(gx ** 2 + gy ** 2))
    return max(0.0, val) if math.isfinite(val) else 0.0


def compute_luminance_and_exposure(gray_array: np.ndarray) -> Tuple[float, float, float, float]:
    """Compute mean luminance, RMS contrast, underexposure ratio, and overexposure ratio."""
    if gray_array.size == 0:
        return 0.0, 0.0, 0.0, 0.0
    
    mean_lum = float(np.mean(gray_array))
    rms_contrast = float(np.std(gray_array))
    under_ratio = float(np.mean(gray_array < 15.0))
    over_ratio = float(np.mean(gray_array > 240.0))
    
    mean_lum = min(255.0, max(0.0, mean_lum)) if math.isfinite(mean_lum) else 0.0
    rms_contrast = max(0.0, rms_contrast) if math.isfinite(rms_contrast) else 0.0
    under_ratio = min(1.0, max(0.0, under_ratio)) if math.isfinite(under_ratio) else 0.0
    over_ratio = min(1.0, max(0.0, over_ratio)) if math.isfinite(over_ratio) else 0.0
    
    return mean_lum, rms_contrast, under_ratio, over_ratio


def compute_color_cast_and_saturation(rgb_array: np.ndarray) -> Tuple[float, float]:
    """Compute mean HSV saturation and CIELAB chromaticity divergence delta."""
    if rgb_array.size == 0 or rgb_array.ndim < 3 or rgb_array.shape[2] < 3:
        return 0.0, 0.0
    
    rgb_norm = rgb_array[:, :, :3].astype(np.float32) / 255.0
    r = rgb_norm[:, :, 0]
    g = rgb_norm[:, :, 1]
    b = rgb_norm[:, :, 2]
    
    cmax = np.maximum(np.maximum(r, g), b)
    cmin = np.minimum(np.minimum(r, g), b)
    delta = cmax - cmin
    
    # HSV Saturation = delta / (cmax + eps)
    sat = np.where(cmax > 1e-6, delta / (cmax + 1e-6), 0.0)
    mean_sat = float(np.mean(sat))
    mean_sat = min(1.0, max(0.0, mean_sat)) if math.isfinite(mean_sat) else 0.0
    
    # Approximation of CIELAB chromaticity divergence
    # sRGB -> linear RGB
    lin_rgb = np.where(rgb_norm > 0.04045, ((rgb_norm + 0.055) / 1.055) ** 2.4, rgb_norm / 12.92)
    # RGB to XYZ matrix
    x = 0.4124564 * lin_rgb[:, :, 0] + 0.3575761 * lin_rgb[:, :, 1] + 0.1804375 * lin_rgb[:, :, 2]
    y = 0.2126729 * lin_rgb[:, :, 0] + 0.7151522 * lin_rgb[:, :, 1] + 0.0721750 * lin_rgb[:, :, 2]
    z = 0.0193339 * lin_rgb[:, :, 0] + 0.1191920 * lin_rgb[:, :, 1] + 0.9503041 * lin_rgb[:, :, 2]
    
    # Normalize by D65 illuminant
    xn, yn, zn = x / 0.95047, y / 1.00000, z / 1.08883
    
    def f_lab(t: np.ndarray) -> np.ndarray:
        delta_const = 6.0 / 29.0
        return np.where(t > delta_const ** 3, np.cbrt(np.maximum(1e-9, t)), t / (3.0 * delta_const ** 2) + 4.0 / 29.0)
    
    fx, fy, fz = f_lab(xn), f_lab(yn), f_lab(zn)
    a_star = 500.0 * (fx - fy)
    b_star = 200.0 * (fy - fz)
    
    mean_a = float(np.mean(a_star))
    mean_b = float(np.mean(b_star))
    
    cast_delta = float(math.sqrt(mean_a ** 2 + mean_b ** 2))
    cast_delta = max(0.0, cast_delta) if math.isfinite(cast_delta) else 0.0
    
    return mean_sat, cast_delta


def compute_immerkaer_noise_and_snr(gray_array: np.ndarray, mean_lum: float) -> Tuple[float, float]:
    """Compute Immerkaer fast noise variance estimation and Signal-to-Noise Ratio (SNR).
    
    Kernel:
      [[ 1, -2,  1],
       [-2,  4, -2],
       [ 1, -2,  1]]
    """
    h, w = gray_array.shape
    if h < 3 or w < 3:
        return 0.0, 50.0
    
    # 2D convolution with Immerkaer kernel
    conv = (
        gray_array[0:-2, 0:-2] - 2.0 * gray_array[0:-2, 1:-1] + gray_array[0:-2, 2:]
        - 2.0 * gray_array[1:-1, 0:-2] + 4.0 * gray_array[1:-1, 1:-1] - 2.0 * gray_array[1:-1, 2:]
        + gray_array[2:, 0:-2] - 2.0 * gray_array[2:, 1:-1] + gray_array[2:, 2:]
    )
    
    sum_abs = float(np.sum(np.abs(conv)))
    count = 6.0 * (w - 2) * (h - 2)
    noise_std = float((math.sqrt(math.pi / 2.0) / count) * sum_abs)
    noise_var = float(noise_std ** 2)
    noise_var = max(0.0, noise_var) if math.isfinite(noise_var) else 0.0
    
    if noise_std < 1e-5:
        snr_db = 60.0
    else:
        snr_db = float(20.0 * math.log10(max(1e-4, mean_lum) / (noise_std + 1e-6)))
    
    snr_db = max(-30.0, min(100.0, snr_db)) if math.isfinite(snr_db) else 0.0
    return noise_var, snr_db


def compute_jpeg_blockiness(gray_array: np.ndarray) -> float:
    """Compute JPEG 8x8 DCT grid boundary discontinuity step metric."""
    h, w = gray_array.shape
    if h < 16 or w < 16:
        return 1.0
    
    # Vertical grid edges (columns x = 7, 15, 23, ...)
    diff_h = np.abs(gray_array[:, 1:] - gray_array[:, :-1])
    col_indices = np.arange(w - 1)
    boundary_cols = (col_indices % 8 == 7)
    
    boundary_diff_h = diff_h[:, boundary_cols]
    non_boundary_diff_h = diff_h[:, ~boundary_cols]
    
    # Horizontal grid edges (rows y = 7, 15, 23, ...)
    diff_v = np.abs(gray_array[1:, :] - gray_array[:-1, :])
    row_indices = np.arange(h - 1)
    boundary_rows = (row_indices % 8 == 7)
    
    boundary_diff_v = diff_v[boundary_rows, :]
    non_boundary_diff_v = diff_v[~boundary_rows, :]
    
    mean_boundary = float(np.mean(boundary_diff_h) + np.mean(boundary_diff_v)) / 2.0
    mean_non_boundary = float(np.mean(non_boundary_diff_h) + np.mean(non_boundary_diff_v)) / 2.0
    
    if mean_non_boundary < 1e-4:
        if mean_boundary > 1e-4:
            return float(min(10.0, max(2.0, mean_boundary / 1e-4)))
        return 1.0
    
    val = mean_boundary / mean_non_boundary
    return max(0.0, val) if math.isfinite(val) else 1.0


def compute_uniform_region_ratio(gray_array: np.ndarray, patch_size: int = 16) -> float:
    """Compute the fraction of non-overlapping 16x16 patches that are flat/zero-variance."""
    h, w = gray_array.shape
    if h < patch_size or w < patch_size:
        return 0.0
    
    n_h = h // patch_size
    n_w = w // patch_size
    if n_h == 0 or n_w == 0:
        return 0.0
    
    cropped = gray_array[:n_h * patch_size, :n_w * patch_size]
    patches = cropped.reshape(n_h, patch_size, n_w, patch_size).swapaxes(1, 2).reshape(-1, patch_size, patch_size)
    
    patch_vars = np.var(patches, axis=(1, 2))
    uniform_count = int(np.sum(patch_vars < 1.0))
    ratio = float(uniform_count / len(patch_vars))
    return min(1.0, max(0.0, ratio)) if math.isfinite(ratio) else 0.0


def compute_composite_quality_score(
    blur_var: float,
    tenengrad: float,
    under_ratio: float,
    over_ratio: float,
    rms_contrast: float,
    noise_var: float,
    blockiness: float,
    uniform_ratio: float,
) -> float:
    """Compute calibrated composite image quality index [0.0 = degraded, 1.0 = pristine]."""
    # Individual quality factor scores in [0.0, 1.0]
    # Blur factor (higher blur_var -> higher score)
    blur_factor = min(1.0, blur_var / 150.0)
    
    # Contrast factor
    contrast_factor = min(1.0, rms_contrast / 35.0)
    
    # Exposure factor
    exposure_penalty = max(0.0, (under_ratio - 0.20) * 1.5) + max(0.0, (over_ratio - 0.15) * 1.5)
    exposure_factor = max(0.0, 1.0 - exposure_penalty)
    
    # Noise factor
    noise_factor = max(0.0, 1.0 - (noise_var / 300.0))
    
    # Blockiness factor
    blockiness_penalty = max(0.0, (blockiness - 1.5) * 0.5)
    blockiness_factor = max(0.0, 1.0 - blockiness_penalty)
    
    # Uniform patch factor
    uniform_factor = max(0.0, 1.0 - uniform_ratio)
    
    # Weighted composite
    composite = (
        0.25 * blur_factor
        + 0.15 * contrast_factor
        + 0.20 * exposure_factor
        + 0.15 * noise_factor
        + 0.10 * blockiness_factor
        + 0.15 * uniform_factor
    )
    
    composite = min(1.0, max(0.0, float(composite)))
    return composite if math.isfinite(composite) else 0.0


def extract_image_quality_metrics(
    image_input: Union[Path, str, np.ndarray, Image.Image]
) -> ImageQualityMetrics:
    """Extract complete, deterministic Image Quality Metrics from an image source.
    
    Args:
        image_input: File path, numpy RGB array, or PIL Image.
        
    Returns:
        ImageQualityMetrics immutable instance.
        
    Raises:
        ImageQualityError: If image loading, decoding, or processing fails.
    """
    try:
        if isinstance(image_input, (str, Path)):
            path_obj = Path(image_input)
            if not path_obj.exists() or not path_obj.is_file():
                raise ImageQualityError(f"Image file not found: {path_obj.name}")
            with Image.open(path_obj) as raw_img:
                img = ImageOps.exif_transpose(raw_img)
                if img is None:
                    img = raw_img
                # Alpha composite over white if needed
                if img.mode in ("RGBA", "LA") or (img.mode == "P" and "transparency" in img.info):
                    rgba = img.convert("RGBA")
                    bg = Image.new("RGB", rgba.size, (255, 255, 255))
                    bg.paste(rgba, mask=rgba.split()[-1])
                    canonical_img = bg
                else:
                    canonical_img = img.convert("RGB")
                canonical_img.load()
                rgb_array = np.array(canonical_img, dtype=np.uint8)
        elif isinstance(image_input, Image.Image):
            img = ImageOps.exif_transpose(image_input) or image_input
            if img.mode in ("RGBA", "LA"):
                rgba = img.convert("RGBA")
                bg = Image.new("RGB", rgba.size, (255, 255, 255))
                bg.paste(rgba, mask=rgba.split()[-1])
                canonical_img = bg
            else:
                canonical_img = img.convert("RGB")
            canonical_img.load()
            rgb_array = np.array(canonical_img, dtype=np.uint8)
        elif isinstance(image_input, np.ndarray):
            rgb_array = image_input
            if rgb_array.ndim == 2:
                rgb_array = np.stack([rgb_array] * 3, axis=-1)
            elif rgb_array.shape[2] == 4:
                rgb_array = rgb_array[:, :, :3]
            if rgb_array.dtype != np.uint8:
                rgb_array = np.clip(rgb_array, 0, 255).astype(np.uint8)
        else:
            raise ImageQualityError(f"Unsupported image input type: {type(image_input)}")

        h, w = rgb_array.shape[:2]
        if h < 1 or w < 1:
            raise ImageQualityError(f"Invalid image dimensions: {w}x{h}")

        gray_array = _rgb_to_gray(rgb_array)

        blur_var = compute_variance_of_laplacian(gray_array)
        tenengrad = compute_tenengrad_sharpness(gray_array)
        mean_lum, rms_contrast, under_ratio, over_ratio = compute_luminance_and_exposure(gray_array)
        mean_sat, cast_delta = compute_color_cast_and_saturation(rgb_array)
        noise_var, snr_db = compute_immerkaer_noise_and_snr(gray_array, mean_lum)
        blockiness = compute_jpeg_blockiness(gray_array)
        uniform_ratio = compute_uniform_region_ratio(gray_array)
        aspect_ratio = float(w / h)

        composite_score = compute_composite_quality_score(
            blur_var=blur_var,
            tenengrad=tenengrad,
            under_ratio=under_ratio,
            over_ratio=over_ratio,
            rms_contrast=rms_contrast,
            noise_var=noise_var,
            blockiness=blockiness,
            uniform_ratio=uniform_ratio,
        )

        return ImageQualityMetrics(
            blur_laplacian_var=blur_var,
            sharpness_tenengrad=tenengrad,
            mean_luminance=mean_lum,
            rms_contrast=rms_contrast,
            underexposure_ratio=under_ratio,
            overexposure_ratio=over_ratio,
            mean_saturation=mean_sat,
            color_cast_delta=cast_delta,
            noise_variance=noise_var,
            snr_db=snr_db,
            jpeg_blockiness=blockiness,
            width=w,
            height=h,
            aspect_ratio=aspect_ratio,
            uniform_region_ratio=uniform_ratio,
            composite_quality_score=composite_score,
        )

    except ImageQualityError:
        raise
    except Exception as exc:
        raise ImageQualityError(f"Failed to extract image quality metrics: {str(exc)}") from exc
