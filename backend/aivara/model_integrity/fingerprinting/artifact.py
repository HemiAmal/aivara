"""Tier 1: Artifact Identity Cryptographic Engine (H_artifact).

Computes deterministic streaming SHA-256 over exact raw artifact bytes on disk.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from aivara.model_integrity.security import compute_streaming_sha256


def compute_artifact_hash(
    file_path: Path,
    chunk_size: int = 65_536,
    max_bytes: Optional[int] = None,
) -> str:
    """Compute the 64-character lowercase hex SHA-256 digest of the exact artifact file bytes.

    Args:
        file_path: Validated Path to model file on disk.
        chunk_size: Streaming chunk size (default 64 KB).
        max_bytes: Optional maximum allowed file size.

    Returns:
        64-character lowercase hexadecimal SHA-256 digest.
    """
    return compute_streaming_sha256(
        file_path=file_path,
        chunk_size=chunk_size,
        max_bytes=max_bytes,
    )
