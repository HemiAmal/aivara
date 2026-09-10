"""Filesystem security and path normalization utilities for dataset sandboxing."""

import os
from pathlib import Path
from typing import Union

from aivara.dataset.exceptions import (
    PathTraversalError,
    SymlinkEscapeError,
    MissingImageError,
)


def normalize_relative_path(path_str: Union[str, Path]) -> str:
    """Normalize a path to a clean, dataset-relative string using forward slashes.

    Rules:
      - Convert all backslashes '\\' to forward slashes '/'.
      - Strip leading and trailing whitespace and slashes.
      - Remove redundant './' segments and empty components.
      - Reject embedded '..' traversal segments.
      - Reject drive letter prefixes (e.g. 'C:', 'D:') and UNC network prefixes ('//', '\\\\').
    """
    raw = str(path_str).strip()

    # Reject UNC paths
    if raw.startswith(("\\\\", "//")):
        raise PathTraversalError(
            f"UNC network path '{raw}' is forbidden.",
            details={"path": raw},
        )

    # Convert Windows backslashes to forward slashes
    normalized = raw.replace("\\", "/")

    # Reject Windows drive letters (e.g. C:/path, D:/path)
    if len(normalized) >= 2 and normalized[1] == ":" and normalized[0].isalpha():
        raise PathTraversalError(
            f"Absolute drive-letter path '{raw}' is forbidden.",
            details={"path": raw},
        )

    # Strip leading slashes to prevent absolute root escapes
    while normalized.startswith("/"):
        normalized = normalized[1:]

    # Remove './' prefixes
    while normalized.startswith("./"):
        normalized = normalized[2:]

    # Split into components and check for traversal
    parts = [p for p in normalized.split("/") if p and p != "."]

    for part in parts:
        if part == "..":
            raise PathTraversalError(
                f"Directory traversal component '..' detected in path '{raw}'.",
                details={"path": raw},
            )

    if not parts:
        raise PathTraversalError("Relative path cannot be empty.", details={"path": raw})

    return "/".join(parts)


def resolve_safe_path(
    dataset_root: Path,
    relative_path: Union[str, Path],
    require_exists: bool = False,
) -> Path:
    """Resolve a relative path safely within the dataset root boundary.

    Guarantees:
      - The resulting Path resolves strictly inside dataset_root.
      - Traversal attempts via '..' or symlinks escaping dataset_root are rejected.
      - Circular symlink chains are detected and rejected.
    """
    root_resolved = dataset_root.resolve()
    if not root_resolved.is_dir():
        raise PathTraversalError(
            f"Dataset root '{dataset_root}' is not a valid directory.",
            details={"root": str(dataset_root)},
        )

    norm_rel = normalize_relative_path(relative_path)
    candidate = (root_resolved / norm_rel)

    # Check symlink escapes on existing components
    try:
        # Check if candidate or any existing parent is a symlink pointing outside root
        curr = candidate
        while curr != root_resolved and curr != curr.parent:
            if curr.is_symlink():
                target = curr.resolve()
                try:
                    target.relative_to(root_resolved)
                except ValueError:
                    raise SymlinkEscapeError(
                        f"Symlink at '{curr.name}' resolves outside dataset root boundary.",
                        details={"symlink": str(curr.name)},
                    )
            curr = curr.parent

        resolved_candidate = candidate.resolve()
    except RecursionError:
        raise SymlinkEscapeError(
            "Circular symlink loop detected.",
            details={"path": norm_rel},
        )
    except OSError as e:
        raise PathTraversalError(
            f"Filesystem error resolving path '{norm_rel}': {e}",
            details={"path": norm_rel},
        )

    # Verify candidate is strictly a child of root_resolved
    try:
        resolved_candidate.relative_to(root_resolved)
    except ValueError:
        raise PathTraversalError(
            f"Path '{norm_rel}' resolves outside dataset root.",
            details={"path": norm_rel},
        )

    if require_exists and not resolved_candidate.exists():
        raise MissingImageError(
            f"Referenced image file '{norm_rel}' does not exist on disk.",
            details={"relative_path": norm_rel},
        )

    return resolved_candidate
