"""Tier 2: Structural Identity Cryptographic Engine (H_structural).

Canonicalizes format, architecture, graph operator topology, and tensor schema
via RFC 8785 JCS, then computes the deterministic SHA-256 structural hash.
"""

from __future__ import annotations

from typing import Any, Dict, List

from aivara.crypto.canonical import canonicalize
from aivara.crypto.hashing import sha256_bytes
from aivara.model_integrity.fingerprinting.schemas import StructuralRepresentation
from aivara.model_integrity.schemas import NormalizedModelMetadata


def build_structural_representation(
    metadata: NormalizedModelMetadata,
) -> StructuralRepresentation:
    """Build a deterministic, canonically ordered StructuralRepresentation from normalized metadata."""
    sorted_tensors: List[Dict[str, Any]] = [
        {
            "byte_size": t.byte_size,
            "dtype": t.dtype,
            "element_count": t.element_count,
            "name": t.name,
            "shape": t.shape,
        }
        for t in sorted(metadata.tensors, key=lambda x: x.name)
    ]

    sorted_operators: List[Dict[str, Any]] = [
        {
            "count": op.count,
            "domain": op.domain,
            "op_type": op.op_type,
        }
        for op in sorted(metadata.operators, key=lambda x: (x.op_type, x.domain))
    ]

    # Filter out any non-deterministic metadata properties
    clean_props = {
        k: metadata.metadata_props[k]
        for k in sorted(metadata.metadata_props.keys())
        if k not in ("file_path", "timestamp", "ingested_at", "artifact_path")
    }

    arch = clean_props.get("model_arch") or clean_props.get("architecture") or ""

    return StructuralRepresentation(
        schema_version="1.0",
        format=metadata.format.value,
        architecture=arch,
        tensor_count=len(sorted_tensors),
        parameter_count=metadata.parameter_count,
        tensors=sorted_tensors,
        operators=sorted_operators,
        metadata_props=clean_props,
    )


def compute_structural_hash(
    structural_rep: StructuralRepresentation,
) -> str:
    """Compute 64-char lowercase hex SHA-256 of JCS-canonicalized structural payload."""
    canonical_bytes = canonicalize(structural_rep.model_dump())
    return sha256_bytes(canonical_bytes)
