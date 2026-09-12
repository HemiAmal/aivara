"""Deterministic Identity and Hashing for Trigger Candidates (Phase 9.2)."""

from __future__ import annotations

from typing import Any, Dict
from aivara.crypto.canonical import canonicalize
from aivara.crypto.hashing import hash_canonical_data, is_valid_sha256, sha256_bytes


def compute_candidate_identity_hash(candidate_data: Dict[str, Any]) -> str:
    """Compute deterministic RFC 8785 JCS SHA-256 identity hash for a trigger candidate.

    Includes all semantic identity-bearing fields:
      - schema_version
      - candidate_family
      - parameters
      - placement
      - input_constraints
      - random_seed
      - transformation_version

    Excludes non-deterministic or derived fields (e.g. candidate_id, candidate_hash, timestamps).
    """
    canonical_dict = {
        "schema_version": candidate_data.get("schema_version", "1.0.0"),
        "candidate_family": (
            candidate_data["candidate_family"].value
            if hasattr(candidate_data["candidate_family"], "value")
            else str(candidate_data["candidate_family"])
        ),
        "parameters": candidate_data.get("parameters", {}),
        "placement": (
            candidate_data["placement"].model_dump()
            if hasattr(candidate_data.get("placement"), "model_dump")
            else candidate_data.get("placement", {})
        ),
        "input_constraints": (
            candidate_data["input_constraints"].model_dump()
            if hasattr(candidate_data.get("input_constraints"), "model_dump")
            else candidate_data.get("input_constraints", {})
        ),
        "random_seed": int(candidate_data.get("random_seed", 42)),
        "transformation_version": candidate_data.get("transformation_version", "1.0.0"),
    }

    return hash_canonical_data(canonical_dict)
