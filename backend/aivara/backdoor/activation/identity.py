"""Deterministic Identity and Control Seed Derivation for Phase 9.4."""

from __future__ import annotations

from typing import Any, Dict, Optional, Union

from aivara.backdoor.transformation.enums import InputLayoutEnum
from aivara.crypto.canonical import canonicalize
from aivara.crypto.hashing import hash_canonical_data, sha256_bytes

EXPERIMENT_SCHEMA_VERSION: str = "1.0.0"
SEED_POLICY_VERSION: str = "1.0.0"


def compute_experiment_identity(
    project_id: str,
    source_input_id: str,
    source_input_hash: str,
    candidate_hash: str,
    input_layout: Union[InputLayoutEnum, str],
    condition_policy_version: str = "1.0.0",
    transformation_version: str = "1.0.0",
    execution_policy_version: str = "1.0.0",
    seed_version: str = SEED_POLICY_VERSION,
    schema_version: str = EXPERIMENT_SCHEMA_VERSION,
) -> str:
    """Compute deterministic RFC 8785 JCS SHA-256 experiment identity hash."""
    layout_str = input_layout.value if hasattr(input_layout, "value") else str(input_layout)
    canonical_dict = {
        "candidate_hash": candidate_hash,
        "condition_policy_version": condition_policy_version,
        "execution_policy_version": execution_policy_version,
        "input_layout": layout_str,
        "project_id": project_id,
        "schema_version": schema_version,
        "seed_version": seed_version,
        "source_input_hash": source_input_hash,
        "source_input_id": source_input_id,
        "transformation_version": transformation_version,
    }
    return hash_canonical_data(canonical_dict)


def derive_control_seed(
    project_id: str,
    source_input_id: str,
    source_input_hash: str,
    candidate_hash: str,
    condition_type: str,
    experiment_id: str,
    sample_index: int = 0,
    seed_version: str = SEED_POLICY_VERSION,
) -> int:
    """Derive a deterministic integer seed in [0, 2^32 - 1] for stochastic control operations."""
    canonical_dict = {
        "candidate_hash": candidate_hash,
        "condition_type": str(condition_type),
        "experiment_id": experiment_id,
        "project_id": project_id,
        "sample_index": int(sample_index),
        "seed_version": seed_version,
        "source_input_hash": source_input_hash,
        "source_input_id": source_input_id,
    }
    digest = hash_canonical_data(canonical_dict)
    # Take first 8 hex characters (32 bits)
    return int(digest[:8], 16)
