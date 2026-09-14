"""Deterministic Content Addressing and Hashing for Multi-Asset Aggregation (Phase 12.9)."""

from __future__ import annotations

from typing import Any, Dict

from aivara.crypto.hashing import hash_canonical_data


def compute_aggregation_hash(canonical_dict: Dict[str, Any]) -> str:
    """Compute deterministic SHA-256 digest of RFC 8785 canonicalized dictionary."""
    return hash_canonical_data(canonical_dict)
