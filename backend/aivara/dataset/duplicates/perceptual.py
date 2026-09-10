"""Perceptual hashing algorithms: 64-bit pHash (DCT) and 64-bit dHash (Gradient) (Phase 5.4).

Provides deterministic, pure-Python perceptual hash extraction invariant to minor
JPEG recompression, metadata changes, container format conversions, and subtle scaling.
"""

from __future__ import annotations

import math
from pathlib import Path
from statistics import median
from typing import List, Tuple, Union

from PIL import Image, ImageOps

from aivara.dataset.duplicates.distance import uint64_to_hex
from aivara.dataset.fingerprinting.exceptions import (
    InvalidImageDecodingError,
    MissingFileError,
    UnreadableFileError,
)

# Precomputed 8x32 DCT-II Transformation Matrix
# T[u, x] = sqrt(1/32) * cos((2x+1)*u*pi / 64) for u=0
# T[u, x] = sqrt(2/32) * cos((2x+1)*u*pi / 64) for u>0
_DCT_MATRIX_8x32: Tuple[Tuple[float, ...], ...] = tuple(
    tuple(
        (1.0 / math.sqrt(32.0) if u == 0 else math.sqrt(2.0 / 32.0))
        * math.cos((2.0 * x + 1.0) * u * math.pi / 64.0)
        for x in range(32)
    )
    for u in range(8)
)


def _load_and_normalize_image(image_or_path: Union[str, Path, Image.Image]) -> Image.Image:
    """Load image from path or object and normalize orientation and transparency."""
    if isinstance(image_or_path, (str, Path)):
        path_obj = Path(image_or_path)
        if not path_obj.exists() or not path_obj.is_file():
            raise MissingFileError(
                f"Image file not found on disk: {path_obj.name}",
                details={"file_name": path_obj.name},
            )
        try:
            with Image.open(path_obj) as raw_img:
                img = ImageOps.exif_transpose(raw_img)
                if img is None:
                    img = raw_img.copy()
                else:
                    img = img.copy()
        except PermissionError as pe:
            raise UnreadableFileError(
                f"Permission denied accessing image file: {path_obj.name}",
                details={"file_name": path_obj.name, "error": str(pe)},
            ) from pe
        except Exception as exc:
            raise InvalidImageDecodingError(
                f"Failed to decode image file for perceptual hashing: {path_obj.name}",
                details={"file_name": path_obj.name, "error": str(exc)},
            ) from exc
    elif isinstance(image_or_path, Image.Image):
        img = ImageOps.exif_transpose(image_or_path)
        if img is None:
            img = image_or_path.copy()
        else:
            img = img.copy()
    else:
        raise InvalidImageDecodingError(
            f"Expected filesystem path or PIL Image, got '{type(image_or_path).__name__}'."
        )

    # Handle alpha flattening
    if img.mode in ("RGBA", "LA") or (img.mode == "P" and "transparency" in img.info):
        rgba = img.convert("RGBA")
        bg = Image.new("RGB", rgba.size, (255, 255, 255))
        bg.paste(rgba, mask=rgba.split()[-1])
        img = bg

    return img.convert("L")  # Canonical 8-bit grayscale


def compute_phash_uint64(image_or_path: Union[str, Path, Image.Image]) -> int:
    """Compute 64-bit pHash (Perceptual Hash) using 2D Discrete Cosine Transform.

    Algorithm:
      1. Preprocess: grayscale conversion + EXIF transposition + alpha flattening.
      2. Resize to 32x32 using Bilinear resampling.
      3. Compute 2D DCT-II to extract top-left 8x8 low-frequency block.
      4. Compute median of the 63 AC coefficients (excluding DC component).
      5. Bit is 1 if coefficient > median else 0.
      6. Pack 64 bits into a 64-bit unsigned integer.

    Args:
        image_or_path: Local path or PIL Image.

    Returns:
        64-bit unsigned integer representing the pHash.
    """
    gray_img = _load_and_normalize_image(image_or_path)
    resized_32x32 = gray_img.resize((32, 32), Image.Resampling.BILINEAR)

    # Extract 32x32 pixel intensity matrix F
    pixels_flat = list(resized_32x32.tobytes())
    F = [pixels_flat[i * 32 : (i + 1) * 32] for i in range(32)]

    # Matrix multiplication: Temp = T (8x32) * F (32x32) -> Temp (8x32)
    # Temp[u, y] = sum_x(T[u, x] * F[y][x])
    Temp = [[0.0] * 32 for _ in range(8)]
    for u in range(8):
        T_u = _DCT_MATRIX_8x32[u]
        for y in range(32):
            s = 0.0
            row_y = F[y]
            for x in range(32):
                s += T_u[x] * row_y[x]
            Temp[u][y] = s

    # Matrix multiplication: D = Temp (8x32) * T^T (32x8) -> D (8x8)
    # D[u, v] = sum_y(Temp[u, y] * T[v, y])
    D: List[float] = []
    for u in range(8):
        Temp_u = Temp[u]
        for v in range(8):
            T_v = _DCT_MATRIX_8x32[v]
            s = 0.0
            for y in range(32):
                s += Temp_u[y] * T_v[y]
            D.append(s)

    # Compute median over the AC coefficients (excluding DC at D[0])
    # to avoid threshold skew from average brightness
    med = median(D[1:]) if len(D) > 1 else D[0]

    # Thresholding: 1 if D[i] > median else 0
    hash_val = 0
    for val in D:
        hash_val = (hash_val << 1) | (1 if val > med else 0)

    return hash_val


def compute_phash(image_or_path: Union[str, Path, Image.Image]) -> str:
    """Compute 64-bit pHash as a 16-character lowercase hexadecimal string."""
    return uint64_to_hex(compute_phash_uint64(image_or_path))


def compute_dhash_uint64(image_or_path: Union[str, Path, Image.Image]) -> int:
    """Compute 64-bit dHash (Difference Hash) using horizontal pixel gradients.

    Algorithm:
      1. Preprocess: grayscale conversion + EXIF transposition + alpha flattening.
      2. Resize to 9x8 (9 columns, 8 rows) using Bilinear resampling.
      3. For each row y in [0..7], compare adjacent columns x and x+1.
      4. Bit is 1 if pixel(x+1, y) > pixel(x, y) else 0.
      5. Pack 64 bits into a 64-bit unsigned integer.

    Args:
        image_or_path: Local path or PIL Image.

    Returns:
        64-bit unsigned integer representing the dHash.
    """
    gray_img = _load_and_normalize_image(image_or_path)
    resized_9x8 = gray_img.resize((9, 8), Image.Resampling.BILINEAR)

    pixels = list(resized_9x8.tobytes())  # 72 values (8 rows * 9 cols)

    hash_val = 0
    for y in range(8):
        row_offset = y * 9
        for x in range(8):
            p_left = pixels[row_offset + x]
            p_right = pixels[row_offset + x + 1]
            hash_val = (hash_val << 1) | (1 if p_right > p_left else 0)

    return hash_val


def compute_dhash(image_or_path: Union[str, Path, Image.Image]) -> str:
    """Compute 64-bit dHash as a 16-character lowercase hexadecimal string."""
    return uint64_to_hex(compute_dhash_uint64(image_or_path))
