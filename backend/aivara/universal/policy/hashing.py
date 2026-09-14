"""Cryptographic hashing and canonicalization for Universal Policy & Decision (Phase 12.7).

Uses RFC 8785 JSON Canonicalization Scheme (JCS) and SHA-256 for deterministic
content addressing of policies and decision audit trails.
"""

from __future__ import annotations

from typing import Any, Dict

from aivara.universal.hashing import (
    compute_canonical_jcs_bytes,
    compute_sha256_digest,
    validate_finite_numerical_data,
)


def compute_policy_hash(canonical_dict: Dict[str, Any]) -> str:
    """Compute deterministic SHA-256 digest of a canonical policy descriptor."""
    validate_finite_numerical_data(canonical_dict)
    canonical_bytes = compute_canonical_jcs_bytes(canonical_dict)
    return compute_sha256_digest(canonical_bytes)


def compute_decision_hash(canonical_dict: Dict[str, Any]) -> str:
    """Compute deterministic SHA-256 digest of a canonical decision descriptor."""
    validate_finite_numerical_data(canonical_dict)
    canonical_bytes = compute_canonical_jcs_bytes(canonical_dict)
    return compute_sha256_digest(canonical_bytes)
