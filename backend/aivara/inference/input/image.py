"""Image file validation, sandboxed header parsing, and dual-identity hashing."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Optional, Tuple, Union

from PIL import Image, ImageOps

from aivara.crypto.canonical import canonicalize
from aivara.inference.config import DEFAULT_INFERENCE_LIMITS, InferenceInputLimits
from aivara.inference.exceptions import (
    ImageDecodingError,
    ResourceLimitExceededError,
    UnsupportedImageFormatError,
)
from aivara.inference.input.models import ImageFileMetadata
from aivara.inference.input.path_security import validate_safe_input_path

PIXEL_DOMAIN_PREFIX: str = "aivara-pixels-v1"


def compute_raw_file_sha256(path: Path) -> str:
    """Compute deterministic SHA-256 digest of raw file on disk via streaming chunks."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


def compute_canonical_pixel_sha256(path: Path) -> Tuple[str, int, int, int, str, str]:
    """Decode image and compute canonical sRGB pixel buffer hash.

    Returns:
        Tuple of (canonical_pixel_hash, width, height, channels, color_space, format_name).
    """
    try:
        with Image.open(path) as raw_img:
            format_name = (raw_img.format or "UNKNOWN").upper()

            # Apply EXIF transpose if present
            img = ImageOps.exif_transpose(raw_img)
            if img is None:
                img = raw_img

            # Handle alpha channel / transparency
            if img.mode in ("RGBA", "LA") or (img.mode == "P" and "transparency" in img.info):
                rgba_img = img.convert("RGBA")
                bg = Image.new("RGB", rgba_img.size, (255, 255, 255))
                bg.paste(rgba_img, mask=rgba_img.split()[-1])
                canonical_img = bg
            elif img.mode == "RGB":
                canonical_img = img
            elif img.mode in ("L", "1", "CMYK", "P"):
                canonical_img = img.convert("RGB")
            else:
                try:
                    canonical_img = img.convert("RGB")
                except Exception as ce:
                    raise ImageDecodingError(
                        f"Unsupported image mode '{img.mode}' in file {path.name}: {ce}",
                        details={"mode": img.mode, "file_name": path.name},
                    ) from ce

            width, height = canonical_img.size
            channels = 3
            color_space = "RGB"

            canonical_img.load()
            raw_pixel_bytes = canonical_img.tobytes()

            prefix = f"{PIXEL_DOMAIN_PREFIX}:{width}:{height}:{channels}:".encode("utf-8")
            pixel_hash = hashlib.sha256(prefix + raw_pixel_bytes).hexdigest()

            return pixel_hash, width, height, channels, color_space, format_name

    except (ImageDecodingError, UnsupportedImageFormatError):
        raise
    except Exception as err:
        raise ImageDecodingError(
            f"Failed to decode image file '{path.name}': {err}",
            details={"file_name": path.name, "error": str(err)},
        ) from err


def validate_image_file_input(
    file_path: Union[str, Path],
    limits: Optional[InferenceInputLimits] = None,
    root_dir: Optional[Union[str, Path]] = None,
) -> Tuple[ImageFileMetadata, str]:
    """Safely validate image file, check resource bounds, and compute dual hashes.

    Args:
        file_path: Relative or absolute path to image file.
        limits: Configured resource bounds.
        root_dir: Optional sandboxing root directory.

    Returns:
        Tuple of (ImageFileMetadata, input_id).
    """
    active_limits = limits or DEFAULT_INFERENCE_LIMITS

    # 1. Path Sandboxing & Security Check
    resolved_path = validate_safe_input_path(
        path_input=file_path,
        root_boundary=root_dir,
        must_exist=True,
    )

    # 2. Extension Check
    ext = resolved_path.suffix.lower()
    if ext not in active_limits.allowed_image_extensions:
        raise UnsupportedImageFormatError(
            f"Image file extension '{ext}' is not in allowed extensions {active_limits.allowed_image_extensions}.",
            details={"extension": ext, "path": str(resolved_path)},
        )

    # 3. File Size Check
    file_size = resolved_path.stat().st_size
    if file_size <= 0:
        raise ImageDecodingError(
            f"Image file '{resolved_path.name}' is empty (0 bytes).",
            details={"path": str(resolved_path)},
        )
    if file_size > active_limits.max_file_size_bytes:
        raise ResourceLimitExceededError(
            f"Image file size {file_size} bytes exceeds maximum allowed {active_limits.max_file_size_bytes} bytes.",
            details={"file_size": file_size, "max_file_size": active_limits.max_file_size_bytes},
        )

    # 4. Raw File SHA-256
    raw_file_hash = compute_raw_file_sha256(resolved_path)

    # 5. Canonical Decoded Pixel Hash & Metadata
    (
        pixel_hash,
        width,
        height,
        channels,
        color_space,
        format_name,
    ) = compute_canonical_pixel_sha256(resolved_path)

    # 6. Dimension and Pixel Resource Bounds Check
    if width <= 0 or height <= 0:
        raise ImageDecodingError(
            f"Invalid image dimensions: {width}x{height}",
            details={"width": width, "height": height},
        )
    if width > active_limits.max_image_width or height > active_limits.max_image_height:
        raise ResourceLimitExceededError(
            f"Image dimensions {width}x{height} exceed limits ({active_limits.max_image_width}x{active_limits.max_image_height}).",
            details={"width": width, "height": height},
        )
    total_pixels = width * height
    if total_pixels > active_limits.max_image_pixels:
        raise ResourceLimitExceededError(
            f"Total image pixels {total_pixels} exceeds limit {active_limits.max_image_pixels}.",
            details={"total_pixels": total_pixels},
        )

    # 7. Form Canonical Input Identity (Envelope Hash)
    canonical_descriptor = {
        "canonical_pixel_hash": pixel_hash,
        "channels": channels,
        "color_space": color_space,
        "file_size_bytes": file_size,
        "format": format_name,
        "height": height,
        "raw_file_hash": raw_file_hash,
        "schema_version": "1.0",
        "width": width,
    }

    canonical_json_bytes = canonicalize(canonical_descriptor)
    input_id = hashlib.sha256(canonical_json_bytes).hexdigest()

    metadata = ImageFileMetadata(
        file_path=str(resolved_path),
        file_size_bytes=file_size,
        width=width,
        height=height,
        channels=channels,
        color_space=color_space,
        format_name=format_name,
        raw_file_hash=raw_file_hash,
        canonical_pixel_hash=pixel_hash,
    )

    return metadata, input_id
