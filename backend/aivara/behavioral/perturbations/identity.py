"""Deterministic cryptographic hashing and identity generation for Phase 8.4 Perturbation Engine."""

from __future__ import annotations

import hashlib
from typing import Any, Dict, Optional, Tuple
import numpy as np

from aivara.crypto.canonical import canonicalize
from aivara.crypto.hashing import sha256_bytes


def compute_input_array_hash(arr: np.ndarray) -> str:
    """Compute a deterministic 64-char SHA-256 digest over an input numpy ndarray.

    Incorporates array dtype, shape, and canonical contiguous C-order bytes.
    """
    c_arr = np.ascontiguousarray(arr)
    header = f"{c_arr.dtype.str}:{list(c_arr.shape)}:".encode("utf-8")
    data_bytes = c_arr.tobytes()
    return sha256_bytes(header + data_bytes)


def compute_perturbation_id(
    source_input_hash: str,
    perturbation_type: str,
    parameters: Dict[str, Any],
    seed: Optional[int] = None,
    implementation_version: str = "1.0.0",
) -> str:
    """Compute a deterministic 64-char lowercase SHA-256 JCS digest of the perturbation identity."""
    payload = {
        "implementation_version": implementation_version,
        "parameters": parameters,
        "perturbation_type": str(perturbation_type),
        "seed": seed,
        "source_input_hash": source_input_hash,
    }
    canonical_bytes = canonicalize(payload)
    return sha256_bytes(canonical_bytes)


def compute_experiment_id(
    project_id: str,
    source_input_id: str,
    source_input_hash: str,
    perturbation_id: str,
    model_id: Optional[str] = None,
) -> str:
    """Compute a deterministic 64-char lowercase SHA-256 JCS digest of the experiment identity."""
    payload = {
        "model_id": model_id,
        "perturbation_id": perturbation_id,
        "project_id": project_id,
        "source_input_hash": source_input_hash,
        "source_input_id": source_input_id,
    }
    canonical_bytes = canonicalize(payload)
    return sha256_bytes(canonical_bytes)
