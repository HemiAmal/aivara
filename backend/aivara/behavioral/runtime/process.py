"""Controlled Execution Environment, process containment, and path isolation (Phase 8.2)."""

from __future__ import annotations

import os
import shutil
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import Generator, List, Optional, Set

from aivara.behavioral.exceptions import SecuritySandboxViolationError


# Sensitive environment key prefixes and substrings that must never leak into worker environments
SENSITIVE_ENV_PREFIXES = (
    "AWS_",
    "AZURE_",
    "GCP_",
    "GOOGLE_",
    "OPENAI_",
    "ANTHROPIC_",
    "HF_",
    "HUGGINGFACE_",
    "API_KEY",
    "SECRET",
    "TOKEN",
    "PASSWORD",
    "PASSWD",
    "PRIVATE_KEY",
    "DATABASE_",
    "DB_PASS",
    "GITHUB_",
    "GIT_",
)


def is_sensitive_env_var(key: str) -> bool:
    """Check whether an environment variable key matches sensitive credential patterns."""
    k_upper = key.upper()
    return any(k_upper.startswith(prefix) or prefix in k_upper for prefix in SENSITIVE_ENV_PREFIXES)


def sanitize_environment(base_env: Optional[dict] = None) -> dict:
    """Create a sanitized minimal environment dictionary with credentials stripped."""
    source_env = base_env if base_env is not None else os.environ
    sanitized: dict = {}

    allowed_standard_keys = {
        "PATH",
        "SYSTEMROOT",
        "SYSTEMDRIVE",
        "TEMP",
        "TMP",
        "HOMEDRIVE",
        "HOMEPATH",
        "USERPROFILE",
        "USERNAME",
        "LANG",
        "LC_ALL",
        "PYTHONPATH",
        "PYTHONHOME",
        "ONNX_LOG_LEVEL",
        "OMP_NUM_THREADS",
        "MKL_NUM_THREADS",
        "NUMEXPR_NUM_THREADS",
        "CUDA_VISIBLE_DEVICES",
    }

    for k, v in source_env.items():
        # Strip all sensitive keys
        if is_sensitive_env_var(k):
            continue
        # Include if recognized or non-sensitive
        if k in allowed_standard_keys or not k.startswith("_"):
            sanitized[k] = v

    return sanitized


def validate_secure_model_path(
    model_path: str | Path,
    allowed_base_dir: Optional[Path] = None,
    forbidden_paths: Optional[List[Path]] = None,
) -> Path:
    """Validate that a model file path is safe, regular, and does not violate filesystem boundaries."""
    raw_str = str(model_path).strip()
    if not raw_str:
        raise SecuritySandboxViolationError("Model path cannot be empty.")

    # 1. Reject UNC paths (\\server\share or //server/share)
    if raw_str.startswith(("\\\\", "//")):
        raise SecuritySandboxViolationError(
            f"UNC paths are forbidden: '{raw_str}'",
            details={"path": raw_str},
        )

    # 2. Check path traversal patterns
    if ".." in raw_str.replace("\\", "/").split("/"):
        raise SecuritySandboxViolationError(
            f"Path traversal detected in model path: '{raw_str}'",
            details={"path": raw_str},
        )

    try:
        resolved = Path(raw_str).resolve()
    except Exception as err:
        raise SecuritySandboxViolationError(
            f"Failed to resolve model path '{raw_str}': {err}",
            details={"path": raw_str, "error": str(err)},
        ) from err

    # 3. Check for existence and regular file
    if not resolved.exists():
        raise SecuritySandboxViolationError(
            f"Model artifact does not exist: '{resolved}'",
            details={"resolved_path": str(resolved)},
        )
    if not resolved.is_file():
        raise SecuritySandboxViolationError(
            f"Model artifact is not a regular file: '{resolved}'",
            details={"resolved_path": str(resolved)},
        )

    # 4. Check against forbidden paths (e.g., .git, keys, database)
    resolved_str = str(resolved).lower()
    forbidden_indicators = [
        "\\.git\\",
        "/.git/",
        "\\.git",
        "/.git",
        "\\keys\\",
        "/keys/",
        "aivara.db",
        "id_ed25519",
        "id_rsa",
    ]
    for ind in forbidden_indicators:
        if ind in resolved_str:
            raise SecuritySandboxViolationError(
                f"Model path violates boundary: access to sensitive asset '{ind}' is forbidden.",
                details={"resolved_path": str(resolved), "matched_indicator": ind},
            )

    # 5. Check allowed base directory if provided
    if allowed_base_dir is not None:
        try:
            base_resolved = Path(allowed_base_dir).resolve()
            resolved.relative_to(base_resolved)
        except ValueError as err:
            raise SecuritySandboxViolationError(
                f"Model path '{resolved}' escapes allowed base directory '{allowed_base_dir}'.",
                details={"resolved_path": str(resolved), "allowed_base": str(allowed_base_dir)},
            ) from err

    return resolved


class ControlledExecutionEnvironment:
    """Manages an isolated temporary workspace and sanitized environment for a model execution."""

    def __init__(
        self,
        execution_id: str,
        custom_temp_root: Optional[Path] = None,
    ) -> None:
        self.execution_id = execution_id
        self.custom_temp_root = custom_temp_root
        self._temp_dir: Optional[tempfile.TemporaryDirectory] = None
        self.workspace_path: Optional[Path] = None

    def __enter__(self) -> ControlledExecutionEnvironment:
        prefix = f"aivara_exec_{self.execution_id[:8]}_"
        root_dir = str(self.custom_temp_root) if self.custom_temp_root else None
        self._temp_dir = tempfile.TemporaryDirectory(prefix=prefix, dir=root_dir)
        self.workspace_path = Path(self._temp_dir.name).resolve()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.cleanup()

    def cleanup(self) -> None:
        """Ensure thorough cleanup of the temporary execution workspace."""
        if self._temp_dir is not None:
            try:
                self._temp_dir.cleanup()
            except Exception:
                # Fallback manual removal if Windows file handle delay occurs
                if self.workspace_path and self.workspace_path.exists():
                    shutil.rmtree(self.workspace_path, ignore_errors=True)
            finally:
                self._temp_dir = None
                self.workspace_path = None
