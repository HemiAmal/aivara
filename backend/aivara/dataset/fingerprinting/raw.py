"""Level 0: Raw Image File Digest Engine (Phase 5.3).

Computes deterministic SHA-256 digests over exact filesystem image bytes using
bounded 64 KiB chunked streaming to prevent unbounded RAM usage.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Union

from aivara.dataset.fingerprinting.exceptions import (
    MissingFileError,
    UnreadableFileError,
)

# 64 KiB buffer size for streaming disk reads
RAW_CHUNK_SIZE: int = 65536


def compute_raw_image_sha256(file_path: Union[str, Path]) -> str:
    """Compute deterministic SHA-256 digest over exact raw bytes of an image file on disk.

    Guarantees:
      - Bit-exact filesystem integrity tracking (FIPS 180-4 SHA-256).
      - Fixed O(1) memory consumption via 64 KiB chunked streaming.
      - Lowercase 64-character hexadecimal format.
      - Safe exception handling for missing or unreadable files.

    Args:
        file_path: Local filesystem path to the target image file.

    Returns:
        64-character lowercase hexadecimal SHA-256 digest.

    Raises:
        MissingFileError: If the file does not exist.
        UnreadableFileError: If the file cannot be read due to permissions or I/O errors.
    """
    path_obj = Path(file_path)
    if not path_obj.exists() or not path_obj.is_file():
        raise MissingFileError(
            f"Image file not found on disk: {path_obj.name}",
            details={"file_name": path_obj.name},
        )

    hasher = hashlib.sha256()
    try:
        with open(path_obj, "rb") as f:
            while chunk := f.read(RAW_CHUNK_SIZE):
                hasher.update(chunk)
    except PermissionError as pe:
        raise UnreadableFileError(
            f"Permission denied reading image file: {path_obj.name}",
            details={"file_name": path_obj.name, "error": str(pe)},
        ) from pe
    except OSError as oe:
        raise UnreadableFileError(
            f"I/O error reading image file: {path_obj.name}",
            details={"file_name": path_obj.name, "error": str(oe)},
        ) from oe

    return hasher.hexdigest().lower()
