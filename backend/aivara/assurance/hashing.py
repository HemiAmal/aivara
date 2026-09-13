"""Cryptographic hashing routines for Multi-Modal Risk Integration Engine (Phase 11.9).

Implements deterministic RFC 8785 Canonical JSON Serialization (JCS) + SHA-256 digests.
"""

from __future__ import annotations

import hashlib
from typing import Any, Dict, Sequence

from aivara.crypto.canonical import canonicalize


def compute_evidence_set_hash(evidence_hashes: Sequence[str]) -> str:
    """Compute deterministic SHA-256 digest over sorted evidence digests."""
    canonical_list = sorted(list(evidence_hashes))
    canonical_bytes = canonicalize(canonical_list)
    return hashlib.sha256(canonical_bytes).hexdigest()


def compute_risk_policy_hash(canonical_dict: Dict[str, Any]) -> str:
    """Compute deterministic SHA-256 digest over canonical RiskPolicy descriptor."""
    canonical_bytes = canonicalize(canonical_dict)
    return hashlib.sha256(canonical_bytes).hexdigest()


def compute_decision_policy_hash(canonical_dict: Dict[str, Any]) -> str:
    """Compute deterministic SHA-256 digest over canonical DecisionPolicy descriptor."""
    canonical_bytes = canonicalize(canonical_dict)
    return hashlib.sha256(canonical_bytes).hexdigest()


def compute_integrated_profile_hash(canonical_dict: Dict[str, Any]) -> str:
    """Compute deterministic SHA-256 digest over canonical IntegratedAssuranceProfile descriptor."""
    canonical_bytes = canonicalize(canonical_dict)
    return hashlib.sha256(canonical_bytes).hexdigest()
