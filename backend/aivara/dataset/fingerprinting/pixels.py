"""Level 1: Decoded RGB Pixel Buffer Digest Engine (Phase 5.3).

Computes deterministic SHA-256 digests over uncompressed, canonical sRGB 8-bit
pixel buffers. Invariant across lossless container resaves, metadata stripping,
EXIF rotations, and compression artifact changes that preserve pixel values.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Union

from PIL import Image, ImageOps

from aivara.dataset.fingerprinting.exceptions import (
    InvalidImageDecodingError,
    MissingFileError,
    UnreadableFileError,
    UnsupportedImageEncodingError,
)

PIXEL_DOMAIN_PREFIX: str = "aivara-pixels-v1"


def compute_decoded_rgb_sha256(file_path: Union[str, Path]) -> str:
    """Compute deterministic SHA-256 digest over the decoded, uncompressed sRGB 8-bit pixel grid.

    Normalization Pipeline:
      1. Decode image using local PIL reader.
      2. Apply EXIF orientation transposition if present.
      3. Handle alpha transparency by compositing over standard opaque white (255, 255, 255).
      4. Convert grayscale (L) or palette images to 3-channel sRGB 8-bit (RGB).
      5. Extract row-major raw bytes (W * H * 3 bytes).
      6. Form canonical prefix: "aivara-pixels-v1:W:H:C:".
      7. Return SHA-256 digest over prefix + raw RGB bytes.

    Args:
        file_path: Local filesystem path to the target image file.

    Returns:
        64-character lowercase hexadecimal SHA-256 digest.

    Raises:
        MissingFileError: If the file does not exist.
        UnreadableFileError: If the file cannot be accessed.
        InvalidImageDecodingError: If the image data is corrupted or cannot be decoded.
        UnsupportedImageEncodingError: If the image format/mode is unsupported.
    """
    path_obj = Path(file_path)
    if not path_obj.exists() or not path_obj.is_file():
        raise MissingFileError(
            f"Image file not found on disk: {path_obj.name}",
            details={"file_name": path_obj.name},
        )

    try:
        with Image.open(path_obj) as raw_img:
            # Apply EXIF orientation
            img = ImageOps.exif_transpose(raw_img)
            if img is None:
                img = raw_img

            # Handle alpha channel / transparency
            if img.mode in ("RGBA", "LA") or (img.mode == "P" and "transparency" in img.info):
                rgba_img = img.convert("RGBA")
                # Create opaque solid white background
                bg = Image.new("RGB", rgba_img.size, (255, 255, 255))
                # Alpha composite
                bg.paste(rgba_img, mask=rgba_img.split()[-1])
                canonical_img = bg
            elif img.mode == "RGB":
                canonical_img = img
            elif img.mode in ("L", "1"):
                canonical_img = img.convert("RGB")
            elif img.mode == "CMYK":
                canonical_img = img.convert("RGB")
            elif img.mode == "P":
                canonical_img = img.convert("RGB")
            else:
                # Attempt general RGB conversion
                try:
                    canonical_img = img.convert("RGB")
                except Exception as ce:
                    raise UnsupportedImageEncodingError(
                        f"Unsupported image mode '{img.mode}' in file {path_obj.name}",
                        details={"mode": img.mode, "file_name": path_obj.name, "error": str(ce)},
                    ) from ce

            width, height = canonical_img.size
            channels = 3  # Normalized RGB

            # Ensure image is fully loaded into memory before extracting bytes
            canonical_img.load()
            pixel_bytes = canonical_img.tobytes()

    except (MissingFileError, UnreadableFileError, UnsupportedImageEncodingError):
        raise
    except PermissionError as pe:
        raise UnreadableFileError(
            f"Permission denied accessing image file: {path_obj.name}",
            details={"file_name": path_obj.name, "error": str(pe)},
        ) from pe
    except OSError as oe:
        raise InvalidImageDecodingError(
            f"Corrupted or invalid image stream: {path_obj.name}",
            details={"file_name": path_obj.name, "error": str(oe)},
        ) from oe
    except Exception as exc:
        raise InvalidImageDecodingError(
            f"Failed to decode image pixels for: {path_obj.name}",
            details={"file_name": path_obj.name, "error": str(exc)},
        ) from exc

    # Prefix: aivara-pixels-v1:W:H:C:
    header = f"{PIXEL_DOMAIN_PREFIX}:{width}:{height}:{channels}:".encode("utf-8")

    hasher = hashlib.sha256()
    hasher.update(header)
    hasher.update(pixel_bytes)

    return hasher.hexdigest().lower()
