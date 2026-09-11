"""Tier 3: Operational Contract Identity Cryptographic Engine (H_contract).

Canonicalizes input/output contracts, shapes, dtypes, and activation schemas via
RFC 8785 JCS, then computes the deterministic SHA-256 contract hash.
"""

from __future__ import annotations

from typing import Any, Dict, List

from aivara.crypto.canonical import canonicalize
from aivara.crypto.hashing import sha256_bytes
from aivara.model_integrity.fingerprinting.schemas import ContractRepresentation
from aivara.model_integrity.schemas import NormalizedModelMetadata


def build_contract_representation(
    metadata: NormalizedModelMetadata,
) -> ContractRepresentation:
    """Build a deterministic, canonically ordered ContractRepresentation from normalized metadata."""
    sorted_inputs: List[Dict[str, Any]] = [
        {
            "channel_order": inp.channel_order or "",
            "dtype": inp.dtype,
            "is_dynamic": inp.is_dynamic,
            "name": inp.name,
            "shape": inp.shape,
        }
        for inp in sorted(metadata.inputs, key=lambda x: x.name)
    ]

    sorted_outputs: List[Dict[str, Any]] = [
        {
            "activation_type": out.activation_type or "",
            "dtype": out.dtype,
            "name": out.name,
            "shape": out.shape,
        }
        for out in sorted(metadata.outputs, key=lambda x: x.name)
    ]

    return ContractRepresentation(
        schema_version="1.0",
        inputs=sorted_inputs,
        outputs=sorted_outputs,
    )


def compute_contract_hash(
    contract_rep: ContractRepresentation,
) -> str:
    """Compute 64-char lowercase hex SHA-256 of JCS-canonicalized contract payload."""
    canonical_bytes = canonicalize(contract_rep.model_dump())
    return sha256_bytes(canonical_bytes)
