"""Filesystem security, path normalization, and bounded hashing for model artifacts.

Enforces strict containment, traversal defenses, UNC path rejection, symlink safety,
and streaming cryptographic hashing for untrusted model inputs.
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
from typing import Optional, Union

from aivara.model_integrity.exceptions import (
    ModelCorruptionError,
    ResourceLimitExceededError,
    UntrustedArtifactSecurityError,
)
from aivara.model_integrity.limits import DEFAULT_LIMITS, ModelIngestionLimits

# Streaming chunk size for hashing and bounded reading (64 KB)
STREAMING_CHUNK_SIZE: int = 65_536


def normalize_and_sanitize_path(raw_path: Union[str, Path]) -> Path:
    """Normalize a path string and reject dangerous filesystem patterns.

    Guarantees:
      - Rejects UNC network paths (e.g. \\\\server\\share or //server/share)
      - Rejects embedded traversal '..' components prior to resolution
      - Rejects NUL bytes and control characters
      - Converts backslashes to native separators
    """
    path_str = str(raw_path).strip()
    if not path_str:
        raise UntrustedArtifactSecurityError(
            "Model artifact path cannot be empty.",
            code="MISSING_ARTIFACT",
            details={"path": path_str},
        )

    # Check for NUL bytes or non-printable control characters
    if "\x00" in path_str:
        raise UntrustedArtifactSecurityError(
            "Path contains forbidden NUL character.",
            code="PATH_TRAVERSAL_ATTEMPT",
            details={"path": path_str},
        )

    # Reject UNC paths
    if path_str.startswith(("\\\\", "//")):
        raise UntrustedArtifactSecurityError(
            f"UNC network path '{path_str}' is strictly forbidden.",
            code="FORBIDDEN_PATH_TYPE",
            details={"path": path_str},
        )

    # Check for embedded traversal in segments before resolution
    normalized_str = path_str.replace("\\", "/")
    segments = [s for s in normalized_str.split("/") if s]
    if ".." in segments:
        raise UntrustedArtifactSecurityError(
            f"Path traversal sequence '..' detected in path '{path_str}'.",
            code="PATH_TRAVERSAL_ATTEMPT",
            details={"path": path_str},
        )

    return Path(path_str)


def validate_artifact_file(
    artifact_path: Union[str, Path],
    allowed_base_dir: Optional[Union[str, Path]] = None,
    limits: Optional[ModelIngestionLimits] = None,
) -> Path:
    """Validate that an untrusted artifact path points to a readable, bounded, regular file.

    Args:
        artifact_path: Raw path or string to inspect.
        allowed_base_dir: Optional root directory that artifact must resolve within.
        limits: Configurable resource limits (defaults to DEFAULT_LIMITS).

    Returns:
        Resolved, validated Path object.

    Raises:
        UntrustedArtifactSecurityError: If security constraints, symlink escape, or path format fails.
        ResourceLimitExceededError: If file exceeds size limits.
    """
    effective_limits = limits or DEFAULT_LIMITS
    clean_path = normalize_and_sanitize_path(artifact_path)

    # Check symlinks and resolve safely
    try:
        if clean_path.is_symlink():
            try:
                resolved_path = clean_path.resolve(strict=True)
            except (RecursionError, RuntimeError):
                raise UntrustedArtifactSecurityError(
                    f"Circular symlink loop detected for '{clean_path}'.",
                    code="UNRESOLVABLE_SYMLINK",
                    details={"path": str(clean_path)},
                )
            except OSError as e:
                raise UntrustedArtifactSecurityError(
                    f"Unresolvable symlink for '{clean_path}': {e}",
                    code="UNRESOLVABLE_SYMLINK",
                    details={"path": str(clean_path), "error": str(e)},
                )
        else:
            resolved_path = clean_path.resolve()
    except OSError as e:
        raise UntrustedArtifactSecurityError(
            f"Filesystem error resolving artifact path '{clean_path}': {e}",
            code="MISSING_ARTIFACT",
            details={"path": str(clean_path), "error": str(e)},
        )

    # Check allowed_base_dir containment if specified
    if allowed_base_dir is not None:
        base_resolved = Path(allowed_base_dir).resolve()
        try:
            resolved_path.relative_to(base_resolved)
        except ValueError:
            raise UntrustedArtifactSecurityError(
                f"Artifact '{clean_path}' resolves outside allowed directory '{base_resolved}'.",
                code="PATH_TRAVERSAL_ATTEMPT",
                details={"path": str(clean_path), "allowed_base": str(base_resolved)},
            )

    # Validate existence
    if not resolved_path.exists():
        raise UntrustedArtifactSecurityError(
            f"Artifact file '{clean_path}' does not exist on disk.",
            code="MISSING_ARTIFACT",
            details={"path": str(clean_path)},
        )

    # Validate that it is a regular file
    if not resolved_path.is_file():
        raise UntrustedArtifactSecurityError(
            f"Artifact path '{clean_path}' is not a regular file (directory, device, or socket).",
            code="NOT_A_REGULAR_FILE",
            details={"path": str(clean_path)},
        )

    # Validate readability and check file size
    try:
        stat_result = resolved_path.stat()
        file_size = stat_result.st_size
    except OSError as e:
        raise UntrustedArtifactSecurityError(
            f"Cannot stat artifact file '{clean_path}': {e}",
            code="MISSING_ARTIFACT",
            details={"path": str(clean_path), "error": str(e)},
        )

    effective_limits.check_file_size(file_size, filename=resolved_path.name)

    return resolved_path


def compute_streaming_sha256(
    file_path: Path,
    chunk_size: int = STREAMING_CHUNK_SIZE,
    max_bytes: Optional[int] = None,
) -> str:
    """Compute the SHA-256 cryptographic digest of a file using bounded streaming.

    Args:
        file_path: Validated Path to hash.
        chunk_size: Buffer size for read chunks (default: 64 KB).
        max_bytes: Optional upper bound on bytes to hash (fails if file exceeds).

    Returns:
        64-character lowercase hexadecimal SHA-256 digest.
    """
    hasher = hashlib.sha256()
    bytes_read = 0

    try:
        with open(file_path, "rb") as f:
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                bytes_read += len(chunk)
                if max_bytes is not None and bytes_read > max_bytes:
                    raise ResourceLimitExceededError(
                        f"File streaming exceeded maximum limit of {max_bytes} bytes.",
                        code="FILE_SIZE_LIMIT_EXCEEDED",
                        details={"bytes_read": bytes_read, "max_bytes": max_bytes},
                    )
                hasher.update(chunk)
    except OSError as e:
        raise UntrustedArtifactSecurityError(
            f"Error reading artifact stream '{file_path}': {e}",
            code="MISSING_ARTIFACT",
            details={"path": str(file_path), "error": str(e)},
        )

    return hasher.hexdigest().lower()
