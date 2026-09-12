"""Deterministic Identity and Hashing for Phase 9.3 Trigger Transformation Engine."""

from __future__ import annotations

from typing import Any, Dict, Optional, Tuple, Union
import numpy as np

from aivara.backdoor.transformation.enums import InputLayoutEnum
from aivara.crypto.canonical import canonicalize
from aivara.crypto.hashing import hash_canonical_data, sha256_bytes


def compute_input_array_hash(arr: np.ndarray) -> str:
    """Compute deterministic 64-char lowercase SHA-256 digest over an in-memory numpy ndarray.

    Incorporates array dtype, shape, and contiguous C-order bytes.
    """
    c_arr = np.ascontiguousarray(arr)
    header = f"{c_arr.dtype.str}:{list(c_arr.shape)}:".encode("utf-8")
    data_bytes = c_arr.tobytes()
    return sha256_bytes(header + data_bytes)


def compute_transformation_id(
    source_input_hash: str,
    candidate_hash: str,
    placement: Dict[str, Any],
    input_layout: Union[InputLayoutEnum, str],
    transformation_version: str = "1.0.0",
    schema_version: str = "1.0.0",
) -> str:
    """Compute deterministic RFC 8785 JCS SHA-256 identity digest for a trigger transformation.

    Includes:
      - schema_version
      - source_input_hash
      - candidate_hash
      - placement
      - input_layout (ADR-087)
      - transformation_version

    Excludes wall-clock timestamps, memory addresses, and transient execution IDs.
    """
    layout_str = input_layout.value if hasattr(input_layout, "value") else str(input_layout)
    canonical_dict = {
        "candidate_hash": candidate_hash,
        "input_layout": layout_str,
        "placement": placement,
        "schema_version": schema_version,
        "source_input_hash": source_input_hash,
        "transformation_version": transformation_version,
    }
    return hash_canonical_data(canonical_dict)
