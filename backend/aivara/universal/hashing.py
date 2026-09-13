"""Deterministic Cryptographic Hashing and Serialization for Universal Evidence (Phase 12.2).

Guarantees:
- RFC 8785 JSON Canonicalization Scheme (JCS) compliance.
- SHA-256 content addressing across payloads, ancestry paths, and envelopes.
- Rejection of non-finite floats (NaN, +Inf, -Inf).
"""

from __future__ import annotations

import hashlib
import math
from typing import Any, Dict, List, Optional, Union

from aivara.crypto.canonical import canonicalize
from aivara.universal.exceptions import InvalidEvidenceError


def validate_finite_numerical_data(data: Any, path: str = "") -> None:
    """Recursively validate that all float values in a nested structure are finite real numbers."""
    if isinstance(data, float):
        if math.isnan(data) or math.isinf(data):
            field_str = f" at '{path}'" if path else ""
            raise InvalidEvidenceError(
                f"Non-finite float value encountered{field_str}: {data}"
            )
    elif isinstance(data, dict):
        for k, v in data.items():
            curr_path = f"{path}.{k}" if path else str(k)
            validate_finite_numerical_data(v, curr_path)
    elif isinstance(data, (list, tuple)):
        for idx, item in enumerate(data):
            curr_path = f"{path}[{idx}]"
            validate_finite_numerical_data(item, curr_path)


def compute_canonical_jcs_bytes(data: Dict[str, Any]) -> bytes:
    """Serialize a dictionary to RFC 8785 canonical bytes after finite float validation."""
    validate_finite_numerical_data(data)
    try:
        return canonicalize(data)
    except Exception as exc:
        raise InvalidEvidenceError(
            f"RFC 8785 canonicalization failed: {exc}",
            details={"error": str(exc)},
        ) from exc


def compute_sha256_digest(data_bytes: bytes) -> str:
    """Compute 64-character lowercase hex SHA-256 digest."""
    return hashlib.sha256(data_bytes).hexdigest()


def compute_payload_hash(payload: Dict[str, Any]) -> str:
    """Compute deterministic SHA-256 digest of a canonical evidence payload."""
    raw_bytes = compute_canonical_jcs_bytes(payload)
    return compute_sha256_digest(raw_bytes)


def compute_envelope_hash(envelope_dict: Dict[str, Any]) -> str:
    """Compute deterministic SHA-256 digest of a canonical universal evidence envelope."""
    raw_bytes = compute_canonical_jcs_bytes(envelope_dict)
    return compute_sha256_digest(raw_bytes)
