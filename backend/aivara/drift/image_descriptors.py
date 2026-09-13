"""Safe, deterministic image descriptor extraction for Phase 11.5 Image Distribution Shift Analysis.

Computes physical structural dimensions, photometric statistics, channel distributions,
format metadata, and physical image quality descriptors without neural networks or cloud dependencies.
"""

from __future__ import annotations

import io
import math
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

import numpy as np
from PIL import Image, ImageOps

# Maximum safety limits to prevent decompression bombs and resource exhaustion
MAX_IMAGE_PIXELS: int = 25_000_000  # 25 Megapixels (e.g., 5000x5000)
MAX_IMAGE_DIMENSION: int = 10_000
MAX_IMAGE_BYTES: int = 50 * 1024 * 1024  # 50 MB
MAX_POPULATION_IMAGES: int = 5000

# Supported image formats
SUPPORTED_FORMATS = {"JPEG", "JPG", "PNG", "WEBP", "BMP", "TIFF", "GIF"}


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


def _compute_shannon_entropy(gray_array: np.ndarray) -> float:
    """Compute Shannon entropy of 8-bit grayscale intensity distribution in bits [0..8]."""
    if gray_array.size == 0:
        return 0.0
    # Discretize to 256 bins
    flat_uint8 = np.clip(gray_array, 0, 255).astype(np.uint8).ravel()
    counts = np.bincount(flat_uint8, minlength=256)
    probs = counts[counts > 0] / flat_uint8.size
    entropy = -np.sum(probs * np.log2(probs))
    return float(max(0.0, entropy)) if math.isfinite(entropy) else 0.0


def _compute_variance_of_laplacian(gray_array: np.ndarray) -> float:
    """Compute Variance of Laplacian blur/focus metric using standard 3x3 discrete kernel."""
    h, w = gray_array.shape
    if h < 3 or w < 3:
        return 0.0

    lap = (
        gray_array[0:-2, 1:-1]
        + gray_array[2:, 1:-1]
        + gray_array[1:-1, 0:-2]
        + gray_array[1:-1, 2:]
        - 4.0 * gray_array[1:-1, 1:-1]
    )
    val = float(np.var(lap))
    return max(0.0, val) if math.isfinite(val) else 0.0


def _compute_saturation(rgb_array: np.ndarray) -> float:
    """Compute mean HSV saturation [0..1]."""
    if rgb_array.ndim < 3 or rgb_array.shape[2] < 3 or rgb_array.size == 0:
        return 0.0
    rgb_norm = rgb_array[:, :, :3].astype(np.float32) / 255.0
    r = rgb_norm[:, :, 0]
    g = rgb_norm[:, :, 1]
    b = rgb_norm[:, :, 2]
    cmax = np.maximum(np.maximum(r, g), b)
    cmin = np.minimum(np.minimum(r, g), b)
    delta = cmax - cmin
    sat = np.where(cmax > 1e-6, delta / (cmax + 1e-6), 0.0)
    mean_sat = float(np.mean(sat))
    return min(1.0, max(0.0, mean_sat)) if math.isfinite(mean_sat) else 0.0


def extract_single_image_descriptors(
    image_input: Union[Path, str, bytes, np.ndarray, Image.Image, Dict[str, Any]],
    max_pixels: int = MAX_IMAGE_PIXELS,
    max_dimension: int = MAX_IMAGE_DIMENSION,
) -> Tuple[str, Optional[Dict[str, Any]], Optional[str]]:
    """Extract deterministic descriptors from a single image input safely.

    Returns:
        Tuple of (status, descriptor_dict_or_None, error_message_or_None)
        status is one of: "VALID", "MISSING", "CORRUPT", "UNSUPPORTED"
    """
    file_size_bytes = 0
    img_format = "UNKNOWN"

    try:
        # 1. Resolve path/bytes/array/image
        if isinstance(image_input, dict):
            # Check for standard dict keys
            if "path" in image_input:
                image_input = image_input["path"]
            elif "data" in image_input:
                image_input = image_input["data"]
            elif "image" in image_input:
                image_input = image_input["image"]
            elif "array" in image_input:
                image_input = image_input["array"]
            else:
                return "UNSUPPORTED", None, f"Unsupported dict input structure: {list(image_input.keys())}"

        if isinstance(image_input, (str, Path)):
            path_obj = Path(image_input)
            if not path_obj.exists() or not path_obj.is_file():
                return "MISSING", None, f"Image file not found: {path_obj.name}"

            file_size_bytes = path_obj.stat().st_size
            if file_size_bytes > MAX_IMAGE_BYTES:
                return "UNSUPPORTED", None, f"Image file exceeds size limit ({file_size_bytes} > {MAX_IMAGE_BYTES})"

            with Image.open(path_obj) as raw_img:
                img_format = (raw_img.format or path_obj.suffix.lstrip(".").upper() or "UNKNOWN").upper()
                if img_format == "JPG":
                    img_format = "JPEG"
                raw_w, raw_h = raw_img.size
                if raw_w * raw_h > max_pixels or raw_w > max_dimension or raw_h > max_dimension:
                    return "UNSUPPORTED", None, f"Dimensions exceed limit: {raw_w}x{raw_h}"

                img = ImageOps.exif_transpose(raw_img) or raw_img
                channels = len(img.getbands())
                if img.mode in ("RGBA", "LA") or (img.mode == "P" and "transparency" in img.info):
                    rgba = img.convert("RGBA")
                    bg = Image.new("RGB", rgba.size, (255, 255, 255))
                    bg.paste(rgba, mask=rgba.split()[-1])
                    canonical = bg
                else:
                    canonical = img.convert("RGB")
                canonical.load()
                rgb_array = np.array(canonical, dtype=np.uint8)

        elif isinstance(image_input, bytes):
            file_size_bytes = len(image_input)
            if file_size_bytes > MAX_IMAGE_BYTES:
                return "UNSUPPORTED", None, f"Image bytes exceed size limit ({file_size_bytes} > {MAX_IMAGE_BYTES})"

            with Image.open(io.BytesIO(image_input)) as raw_img:
                img_format = (raw_img.format or "UNKNOWN").upper()
                if img_format == "JPG":
                    img_format = "JPEG"
                raw_w, raw_h = raw_img.size
                if raw_w * raw_h > max_pixels or raw_w > max_dimension or raw_h > max_dimension:
                    return "UNSUPPORTED", None, f"Dimensions exceed limit: {raw_w}x{raw_h}"

                img = ImageOps.exif_transpose(raw_img) or raw_img
                channels = len(img.getbands())
                if img.mode in ("RGBA", "LA"):
                    rgba = img.convert("RGBA")
                    bg = Image.new("RGB", rgba.size, (255, 255, 255))
                    bg.paste(rgba, mask=rgba.split()[-1])
                    canonical = bg
                else:
                    canonical = img.convert("RGB")
                canonical.load()
                rgb_array = np.array(canonical, dtype=np.uint8)

        elif isinstance(image_input, Image.Image):
            raw_w, raw_h = image_input.size
            if raw_w * raw_h > max_pixels or raw_w > max_dimension or raw_h > max_dimension:
                return "UNSUPPORTED", None, f"Dimensions exceed limit: {raw_w}x{raw_h}"

            img_format = (image_input.format or "UNKNOWN").upper()
            if img_format == "JPG":
                img_format = "JPEG"
            channels = len(image_input.getbands())
            img = ImageOps.exif_transpose(image_input) or image_input
            if img.mode in ("RGBA", "LA"):
                rgba = img.convert("RGBA")
                bg = Image.new("RGB", rgba.size, (255, 255, 255))
                bg.paste(rgba, mask=rgba.split()[-1])
                canonical = bg
            else:
                canonical = img.convert("RGB")
            canonical.load()
            rgb_array = np.array(canonical, dtype=np.uint8)

        elif isinstance(image_input, np.ndarray):
            rgb_array = image_input
            if rgb_array.ndim == 2:
                h, w = rgb_array.shape
                channels = 1
                rgb_array = np.stack([rgb_array] * 3, axis=-1)
            elif rgb_array.ndim == 3:
                h, w, c = rgb_array.shape
                channels = c
                if c == 1:
                    rgb_array = np.concatenate([rgb_array] * 3, axis=-1)
                elif c == 4:
                    rgb_array = rgb_array[:, :, :3]
            else:
                return "UNSUPPORTED", None, f"Invalid array dimensions: {rgb_array.ndim}D"

            if h * w > max_pixels or w > max_dimension or h > max_dimension:
                return "UNSUPPORTED", None, f"Dimensions exceed limit: {w}x{h}"

            if rgb_array.dtype != np.uint8:
                rgb_array = np.clip(rgb_array, 0, 255).astype(np.uint8)

        else:
            return "UNSUPPORTED", None, f"Unsupported input type: {type(image_input)}"

        h, w = rgb_array.shape[:2]
        if h < 1 or w < 1:
            return "CORRUPT", None, f"Invalid empty image dimensions: {w}x{h}"

        # 2. Extract structural descriptors
        aspect_ratio = float(w / h)

        # 3. Extract photometric / color descriptors
        gray_array = _rgb_to_gray(rgb_array)
        mean_intensity = float(np.mean(gray_array))
        std_intensity = float(np.std(gray_array))
        brightness = mean_intensity
        rms_contrast = std_intensity

        r_channel = rgb_array[:, :, 0].astype(np.float32)
        g_channel = rgb_array[:, :, 1].astype(np.float32)
        b_channel = rgb_array[:, :, 2].astype(np.float32)

        r_mean = float(np.mean(r_channel))
        g_mean = float(np.mean(g_channel))
        b_mean = float(np.mean(b_channel))

        r_std = float(np.std(r_channel))
        g_std = float(np.std(g_channel))
        b_std = float(np.std(b_channel))

        # 4. Extract quality / spatial frequency descriptors
        entropy = _compute_shannon_entropy(gray_array)
        sharpness_laplacian_var = _compute_variance_of_laplacian(gray_array)
        clipping_ratio = float(np.mean((gray_array <= 0.0) | (gray_array >= 255.0)))
        mean_saturation = _compute_saturation(rgb_array)

        descriptors = {
            # Structural
            "width": int(w),
            "height": int(h),
            "aspect_ratio": float(aspect_ratio),
            "channels": int(channels),
            "file_size_bytes": int(file_size_bytes),
            "format": str(img_format),
            # Photometric / Pixel
            "mean_intensity": float(mean_intensity),
            "std_intensity": float(std_intensity),
            "brightness": float(brightness),
            "rms_contrast": float(rms_contrast),
            "r_mean": float(r_mean),
            "g_mean": float(g_mean),
            "b_mean": float(b_mean),
            "r_std": float(r_std),
            "g_std": float(g_std),
            "b_std": float(b_std),
            # Quality
            "entropy": float(entropy),
            "sharpness_laplacian_var": float(sharpness_laplacian_var),
            "clipping_ratio": float(clipping_ratio),
            "mean_saturation": float(mean_saturation),
        }

        return "VALID", descriptors, None

    except (Image.DecompressionBombError, MemoryError) as exc:
        return "UNSUPPORTED", None, f"Decompression or memory limit exceeded: {str(exc)}"
    except (Image.UnidentifiedImageError, ValueError, IOError, OSError) as exc:
        return "CORRUPT", None, f"Image decoding/corruption failure: {str(exc)}"
    except Exception as exc:
        return "CORRUPT", None, f"Unexpected image processing failure: {str(exc)}"


def extract_population_descriptors(
    image_items: List[Any],
    max_images: int = MAX_POPULATION_IMAGES,
    max_pixels: int = MAX_IMAGE_PIXELS,
) -> Tuple[Dict[str, List[Any]], Dict[str, int]]:
    """Extract batch descriptors for an image population and track sample accounting.

    Returns:
        Tuple of (descriptor_column_dict, accounting_counts_dict)
        where descriptor_column_dict maps feature names to list of extracted values
        and accounting_counts_dict contains:
          {"total": int, "analyzable": int, "corrupt": int, "unsupported": int, "missing": int}
    """
    total = len(image_items)
    analyzable = 0
    corrupt = 0
    unsupported = 0
    missing = 0

    numerical_columns: Dict[str, List[float]] = {
        "width": [],
        "height": [],
        "aspect_ratio": [],
        "channels": [],
        "file_size_bytes": [],
        "mean_intensity": [],
        "std_intensity": [],
        "brightness": [],
        "rms_contrast": [],
        "r_mean": [],
        "g_mean": [],
        "b_mean": [],
        "r_std": [],
        "g_std": [],
        "b_std": [],
        "entropy": [],
        "sharpness_laplacian_var": [],
        "clipping_ratio": [],
        "mean_saturation": [],
    }
    format_column: List[str] = []

    # Enforce population bounds
    items_to_process = image_items[:max_images]

    for item in items_to_process:
        status, descs, _err = extract_single_image_descriptors(item, max_pixels=max_pixels)
        if status == "VALID" and descs is not None:
            analyzable += 1
            for k in numerical_columns:
                numerical_columns[k].append(float(descs[k]))
            format_column.append(str(descs["format"]))
        elif status == "CORRUPT":
            corrupt += 1
        elif status == "UNSUPPORTED":
            unsupported += 1
        elif status == "MISSING":
            missing += 1
        else:
            unsupported += 1

    accounting = {
        "total": total,
        "analyzable": analyzable,
        "corrupt": corrupt,
        "unsupported": unsupported,
        "missing": missing,
    }

    result_columns: Dict[str, List[Any]] = {**numerical_columns, "format": format_column}
    return result_columns, accounting
