"""Cryptographic hashing and canonicalization for Universal Proof Integration (Phase 12.8).

Uses RFC 8785 JSON Canonicalization Scheme (JCS) and SHA-256 for deterministic
content addressing of proof verification results and aggregated proof assessments.
"""

from __future__ import annotations

from typing import Any, Dict

from aivara.universal.hashing import (
    compute_canonical_jcs_bytes,
    compute_sha256_digest,
    validate_finite_numerical_data,
)


def compute_proof_result_hash(canonical_dict: Dict[str, Any]) -> str:
    """Compute deterministic SHA-256 digest of a canonical proof verification result descriptor."""
    validate_finite_numerical_data(canonical_dict)
    canonical_bytes = compute_canonical_jcs_bytes(canonical_dict)
    return compute_sha256_digest(canonical_bytes)


def compute_proof_assessment_hash(canonical_dict: Dict[str, Any]) -> str:
    """Compute deterministic SHA-256 digest of a canonical universal proof assessment descriptor."""
    validate_finite_numerical_data(canonical_dict)
    canonical_bytes = compute_canonical_jcs_bytes(canonical_dict)
    return compute_sha256_digest(canonical_bytes)
