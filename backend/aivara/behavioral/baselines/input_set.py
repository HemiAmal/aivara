"""Deterministic Input Set Identity and descriptor generation (Phase 8.3)."""

from __future__ import annotations

import hashlib
from typing import Any, Dict, List, Optional, Tuple
import numpy as np

from aivara.behavioral.baselines.schemas import InputItemDescriptor, InputSetDescriptor
from aivara.crypto.canonical import canonicalize
from aivara.crypto.hashing import sha256_bytes


def compute_sample_input_hash(sample_inputs: Dict[str, np.ndarray]) -> str:
    """Compute a deterministic SHA-256 digest for a single multi-tensor input sample."""
    tensor_digests: List[Dict[str, Any]] = []

    for name in sorted(sample_inputs.keys()):
        arr = np.ascontiguousarray(sample_inputs[name])
        tensor_bytes = arr.tobytes()
        t_hash = hashlib.sha256(tensor_bytes).hexdigest().lower()

        tensor_digests.append({
            "name": name,
            "shape": list(arr.shape),
            "dtype": str(arr.dtype),
            "content_hash": t_hash,
        })

    payload = {
        "schema_version": "1.0",
        "tensors": tensor_digests,
    }
    canonical_bytes = canonicalize(payload)
    return sha256_bytes(canonical_bytes)


def build_input_set_descriptor(
    samples: List[Tuple[str, Dict[str, np.ndarray], Optional[Dict[str, Any]]]],
) -> InputSetDescriptor:
    """Build a deterministic, canonically ordered InputSetDescriptor from a collection of samples.

    Args:
        samples: List of tuples (input_id, sample_inputs_dict, optional_metadata).

    Returns:
        InputSetDescriptor with deterministic input_set_id digest.
    """
    items: List[InputItemDescriptor] = []
    input_names_set: set[str] = set()
    input_shapes_map: Dict[str, List[int]] = {}

    for input_id, sample_inputs, metadata in samples:
        sample_hash = compute_sample_input_hash(sample_inputs)
        items.append(
            InputItemDescriptor(
                input_id=str(input_id),
                input_hash=sample_hash,
                metadata=metadata or {},
            )
        )
        for name, arr in sample_inputs.items():
            input_names_set.add(name)
            if name not in input_shapes_map:
                input_shapes_map[name] = list(arr.shape)

    # Sort items deterministically by input_id
    sorted_items = sorted(items, key=lambda x: x.input_id)
    sorted_input_names = sorted(input_names_set)

    # Compute overall input_set_id
    set_payload = {
        "schema_version": "1.0",
        "sample_count": len(sorted_items),
        "input_names": sorted_input_names,
        "inputs": [{"input_id": item.input_id, "input_hash": item.input_hash} for item in sorted_items],
    }
    canonical_set_bytes = canonicalize(set_payload)
    input_set_id = sha256_bytes(canonical_set_bytes)

    return InputSetDescriptor(
        input_set_id=input_set_id,
        sample_count=len(sorted_items),
        input_names=sorted_input_names,
        input_shapes=input_shapes_map,
        inputs=sorted_items,
    )
