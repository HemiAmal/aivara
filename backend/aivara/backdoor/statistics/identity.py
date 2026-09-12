"""Deterministic Identity and Random Seed Derivation for Phase 9.5 Statistical Trigger Analysis."""

from __future__ import annotations

import struct
from typing import Any, Dict, Optional, Union

from aivara.crypto.canonical import canonicalize
from aivara.crypto.hashing import hash_canonical_data, sha256_bytes

STATISTICAL_SCHEMA_VERSION: str = "1.0.0"
STATISTICAL_ANALYSIS_VERSION: str = "1.0.0"


def compute_statistical_analysis_id(
    project_id: str,
    candidate_hash: str,
    sample_set_hash: str,
    trigger_assessment_id: str,
    target_class: Optional[Union[int, str]] = None,
    permutation_count: int = 1000,
    rng_algorithm: str = "PCG64",
    alpha: float = 0.05,
    confidence_level: float = 0.95,
    multiple_comparison_method: str = "BENJAMINI_HOCHBERG",
    policy_version: str = "1.0.0",
    schema_version: str = STATISTICAL_SCHEMA_VERSION,
) -> str:
    """Compute deterministic RFC 8785 JCS SHA-256 statistical analysis identity hash (ADR-089)."""
    canonical_dict = {
        "alpha": float(alpha),
        "candidate_hash": str(candidate_hash),
        "confidence_level": float(confidence_level),
        "multiple_comparison_method": str(multiple_comparison_method),
        "permutation_count": int(permutation_count),
        "policy_version": str(policy_version),
        "project_id": str(project_id),
        "rng_algorithm": str(rng_algorithm),
        "sample_set_hash": str(sample_set_hash),
        "schema_version": str(schema_version),
        "statistical_analysis_version": STATISTICAL_ANALYSIS_VERSION,
        "target_class": target_class if target_class is None else str(target_class),
        "trigger_assessment_id": str(trigger_assessment_id),
    }
    return hash_canonical_data(canonical_dict)


def derive_pcg64_seed(
    statistical_analysis_id: str,
    experiment_tag: str = "paired_permutation",
    candidate_hash: Optional[str] = None,
) -> int:
    """Derive a deterministic 32-bit unsigned integer seed from canonical identity for PCG64."""
    canonical_dict = {
        "candidate_hash": str(candidate_hash) if candidate_hash else "",
        "experiment_tag": str(experiment_tag),
        "statistical_analysis_id": str(statistical_analysis_id),
    }
    digest_hex = sha256_bytes(canonicalize(canonical_dict))
    digest_bytes = bytes.fromhex(digest_hex)
    # Extract first 4 bytes as big-endian unsigned 32-bit integer
    seed_uint32 = struct.unpack(">I", digest_bytes[:4])[0]
    return seed_uint32

