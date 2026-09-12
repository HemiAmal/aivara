"""Security and Numerical Bounding Validators for Trigger Candidates (Phase 9.2)."""

from __future__ import annotations

import math
import re
from typing import Any, Dict, List, Optional, Union

from aivara.backdoor.candidates.exceptions import (
    CandidateOutOfBoundsError,
    InvalidCandidateParameterError,
    InvalidSeedError,
    InvalidValueRangeError,
    SecurityValidationError,
)

# Forbidden execution/injection keywords in string parameters
_DANGEROUS_PATTERNS = re.compile(
    r"(__import__|eval\s*\(|exec\s*\(|os\.system|\bsubprocess\b|\bimportlib\b|\bshutil\b|\bpopen\b|\bsh\b|\bbash\b|\bcmd\.exe\b|\bcmd\b|\bpowershell\b|"
    r"javascript:|data:|http://|https://|ftp://|file://|\\\\\w+|\.\./|\.\.\\)",
    re.IGNORECASE,
)

# Seed range constants
MIN_SEED: int = 0
MAX_SEED: int = 2**32 - 1

# Maximum spatial relative dimensions (cannot exceed 50% width or 50% height = max 25% area)
MAX_RELATIVE_WIDTH: float = 0.50
MAX_RELATIVE_HEIGHT: float = 0.50
MAX_RELATIVE_RADIUS: float = 0.25
MIN_RELATIVE_DIMENSION: float = 0.01


def validate_seed(seed: Any) -> int:
    """Validate that seed is a valid non-negative integer within [0, 2^32 - 1]."""
    if not isinstance(seed, int) or isinstance(seed, bool):
        raise InvalidSeedError(f"Seed must be an integer, got '{type(seed).__name__}'.")
    if not (MIN_SEED <= seed <= MAX_SEED):
        raise InvalidSeedError(f"Seed {seed} out of bounds [{MIN_SEED}, {MAX_SEED}].")
    return seed


def validate_finite_number(val: Any, name: str, min_val: Optional[float] = None, max_val: Optional[float] = None) -> float:
    """Validate that a float/int value is finite (not NaN, not Inf) and within bounds."""
    if not isinstance(val, (int, float)) or isinstance(val, bool):
        raise InvalidCandidateParameterError(f"Parameter '{name}' must be numeric, got '{type(val).__name__}'.")
    
    float_val = float(val)
    if not math.isfinite(float_val):
        raise InvalidCandidateParameterError(f"Parameter '{name}' contains non-finite value '{val}'.")
    
    if min_val is not None and float_val < min_val:
        raise InvalidCandidateParameterError(
            f"Parameter '{name}' value {float_val} is below minimum allowed {min_val}."
        )
    if max_val is not None and float_val > max_val:
        raise InvalidCandidateParameterError(
            f"Parameter '{name}' value {float_val} exceeds maximum allowed {max_val}."
        )
    return float_val


def validate_security_string(val: str, name: str) -> str:
    """Validate that a string value does not contain code injection, path traversal, or command patterns."""
    if not isinstance(val, str):
        raise InvalidCandidateParameterError(f"Parameter '{name}' must be a string, got '{type(val).__name__}'.")
    
    if len(val) > 256:
        raise SecurityValidationError(f"Parameter '{name}' exceeds maximum allowed string length (256).")
    
    if _DANGEROUS_PATTERNS.search(val):
        raise SecurityValidationError(
            f"Parameter '{name}' contains prohibited command, script, path traversal, or network pattern."
        )
    return val


def validate_security_dict(params: Dict[str, Any], path: str = "parameters") -> None:
    """Recursively validate a parameter dictionary against dangerous injection patterns."""
    for k, v in params.items():
        validate_security_string(k, f"{path}.key")
        if isinstance(v, str):
            validate_security_string(v, f"{path}.{k}")
        elif isinstance(v, dict):
            validate_security_dict(v, f"{path}.{k}")
        elif isinstance(v, list):
            for i, item in enumerate(v):
                if isinstance(item, str):
                    validate_security_string(item, f"{path}.{k}[{i}]")
                elif isinstance(item, (int, float)):
                    validate_finite_number(item, f"{path}.{k}[{i}]")
                elif isinstance(item, dict):
                    validate_security_dict(item, f"{path}.{k}[{i}]")
        elif isinstance(v, (int, float)):
            validate_finite_number(v, f"{path}.{k}")


def validate_patch_dimensions(
    relative_width: float,
    relative_height: float,
) -> Tuple[float, float]:
    """Validate that relative patch dimensions are strictly bounded within (0.01, 0.50]."""
    rw = validate_finite_number(relative_width, "relative_width", min_val=MIN_RELATIVE_DIMENSION, max_val=MAX_RELATIVE_WIDTH)
    rh = validate_finite_number(relative_height, "relative_height", min_val=MIN_RELATIVE_DIMENSION, max_val=MAX_RELATIVE_HEIGHT)
    return rw, rh


def validate_normalized_coordinates(x: float, y: float) -> Tuple[float, float]:
    """Validate that normalized coordinates lie strictly in [0.0, 1.0]."""
    nx = validate_finite_number(x, "normalized_x", min_val=0.0, max_val=1.0)
    ny = validate_finite_number(y, "normalized_y", min_val=0.0, max_val=1.0)
    return nx, ny
