"""Path security and sandboxing utilities for inference input files."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Optional, Union

from aivara.inference.exceptions import (
    InferencePathSecurityError,
    InputFileNotFoundError,
    InputFileUnreadableError,
)

_WINDOWS_RESERVED_NAMES = frozenset({
    "CON", "PRN", "AUX", "NUL",
    "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
    "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
})

_FORBIDDEN_URL_SCHEMES = ("http://", "https://", "ftp://", "file://", "smb://")


def validate_safe_input_path(
    path_input: Union[str, Path],
    root_boundary: Optional[Union[str, Path]] = None,
    must_exist: bool = True,
) -> Path:
    """Validate and resolve an inference input file path safely.

    Guarantees:
      - Rejects UNC paths (\\\\ or //)
      - Rejects URL schemes (http://, file://, etc.)
      - Rejects directory traversal (..)
      - Rejects Windows special device names (CON, NUL, AUX, etc.)
      - If root_boundary is provided, guarantees path resolves strictly within root.
      - If must_exist is True, verifies path exists and is a regular file.
      - Rejects symlink boundary escapes.

    Returns:
        Resolved absolute Path.
    """
    raw_str = str(path_input).strip()
    if not raw_str:
        raise InferencePathSecurityError(
            "Input file path cannot be empty.",
            details={"path": raw_str},
        )

    # Check forbidden URL schemes
    lower_raw = raw_str.lower()
    for scheme in _FORBIDDEN_URL_SCHEMES:
        if lower_raw.startswith(scheme):
            raise InferencePathSecurityError(
                f"URL schemes '{scheme}' are prohibited in inference input.",
                details={"path": raw_str},
            )

    # Check UNC network prefixes
    if raw_str.startswith(("\\\\", "//")):
        raise InferencePathSecurityError(
            f"UNC network path '{raw_str}' is forbidden.",
            details={"path": raw_str},
        )

    # Convert to Path object
    try:
        path_obj = Path(raw_str)
    except Exception as err:
        raise InferencePathSecurityError(
            f"Malformed file path syntax: {err}",
            details={"path": raw_str},
        ) from err

    # Check for reserved device names on Windows
    for part in path_obj.parts:
        stem = Path(part).stem.upper()
        if stem in _WINDOWS_RESERVED_NAMES:
            raise InferencePathSecurityError(
                f"Reserved Windows device name '{stem}' is prohibited.",
                details={"path": raw_str, "reserved_name": stem},
            )

    # Check for embedded '..' components in un-resolved parts
    norm_parts = path_obj.parts
    for part in norm_parts:
        if part == "..":
            if root_boundary is not None or not path_obj.is_absolute():
                raise InferencePathSecurityError(
                    f"Directory traversal component '..' detected in path '{raw_str}'.",
                    details={"path": raw_str},
                )

    if root_boundary is not None:
        root_path = Path(root_boundary).resolve()
        if not root_path.is_dir():
            raise InferencePathSecurityError(
                f"Specified root boundary '{root_boundary}' is not a valid directory.",
                details={"root": str(root_boundary)},
            )
        resolved = (root_path / path_obj).resolve() if not path_obj.is_absolute() else path_obj.resolve()

        try:
            resolved.relative_to(root_path)
        except ValueError:
            raise InferencePathSecurityError(
                f"Path '{raw_str}' resolves outside authorized root boundary '{root_path}'.",
                details={"path": raw_str, "root": str(root_path)},
            )
    else:
        resolved = path_obj.resolve()

    if must_exist:
        if not resolved.exists():
            raise InputFileNotFoundError(
                f"Inference input file not found: {resolved.name}",
                details={"file_name": resolved.name, "resolved_path": str(resolved)},
            )
        if not resolved.is_file():
            raise InferencePathSecurityError(
                f"Input path '{resolved.name}' is not a regular file (directory or special file).",
                details={"path": str(resolved)},
            )
        if not os.access(resolved, os.R_OK):
            raise InputFileUnreadableError(
                f"Inference input file is not readable: {resolved.name}",
                details={"path": str(resolved)},
            )

    return resolved
