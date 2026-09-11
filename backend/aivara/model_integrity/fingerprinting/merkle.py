"""Deterministic Merkle Tree Engine for Model Parameter Weights.

Constructs RFC 6962-balanced binary Merkle trees over canonical tensor leaves
with explicit RFC 8785 JCS domain separation.
"""

from __future__ import annotations

from typing import Dict, List, Optional, Sequence, Tuple

from aivara.crypto.canonical import canonicalize
from aivara.crypto.hashing import sha256_bytes
from aivara.model_integrity.fingerprinting.exceptions import (
    DuplicateTensorLeafError,
    FingerprintingError,
)
from aivara.model_integrity.fingerprinting.schemas import (
    TensorLeafDescriptor,
    WeightMerkleResult,
)
from aivara.model_integrity.schemas import ReasonCode

NODE_DOMAIN_TAG: str = "aivara:model-weight-node:v1"
EMPTY_DOMAIN_TAG: str = "aivara:model-weight-empty:v1"

# Deterministic constant for empty model weight tree
EMPTY_WEIGHT_ROOT_HEX: str = sha256_bytes(
    canonicalize({"domain": EMPTY_DOMAIN_TAG, "schema_version": "1.0"})
)


def compute_internal_node_hash(left_hex: str, right_hex: str) -> str:
    """Compute 64-char lowercase hex SHA-256 of JCS-canonicalized internal Merkle node."""
    node_payload = {
        "domain": NODE_DOMAIN_TAG,
        "left": left_hex.lower(),
        "right": right_hex.lower(),
        "schema_version": "1.0",
    }
    return sha256_bytes(canonicalize(node_payload))


def _largest_power_of_two_less_than(n: int) -> int:
    """Calculate the largest power of 2 strictly less than n (for n > 1)."""
    if n <= 1:
        raise ValueError(f"n must be > 1, got {n}")
    return 1 << ((n - 1).bit_length() - 1)


def compute_weight_merkle_root(leaf_hashes: Sequence[str]) -> str:
    """Recursively compute RFC 6962-balanced binary Merkle root over 64-char leaf hex digests.

    Algorithm:
      1. If N == 0: return EMPTY_WEIGHT_ROOT_HEX.
      2. If N == 1: return leaf_hashes[0].
      3. If N > 1:
         k = largest power of 2 strictly less than N.
         left_root = compute_weight_merkle_root(leaf_hashes[:k])
         right_root = compute_weight_merkle_root(leaf_hashes[k:])
         return compute_internal_node_hash(left_root, right_root)
    """
    n = len(leaf_hashes)
    if n == 0:
        return EMPTY_WEIGHT_ROOT_HEX
    if n == 1:
        return leaf_hashes[0].lower()

    k = _largest_power_of_two_less_than(n)
    left_root = compute_weight_merkle_root(leaf_hashes[:k])
    right_root = compute_weight_merkle_root(leaf_hashes[k:])
    return compute_internal_node_hash(left_root, right_root)


class WeightMerkleTree:
    """Immutable Merkle tree representation for model parameter weights."""

    def __init__(self, leaves: Sequence[TensorLeafDescriptor]) -> None:
        # Enforce strict name uniqueness and collation
        seen_names = set()
        for leaf in leaves:
            if leaf.name in seen_names:
                raise DuplicateTensorLeafError(f"Duplicate tensor leaf name '{leaf.name}'.")
            seen_names.add(leaf.name)

        # Sort strictly by tensor name
        self._leaves: Tuple[TensorLeafDescriptor, ...] = tuple(
            sorted(leaves, key=lambda l: l.name)
        )
        self._leaf_hashes: Tuple[str, ...] = tuple(l.leaf_hash for l in self._leaves)
        self._root_hex: str = compute_weight_merkle_root(self._leaf_hashes)
        self._name_to_index: Dict[str, int] = {
            l.name: idx for idx, l in enumerate(self._leaves)
        }

    @property
    def leaves(self) -> Tuple[TensorLeafDescriptor, ...]:
        return self._leaves

    @property
    def leaf_hashes(self) -> Tuple[str, ...]:
        return self._leaf_hashes

    @property
    def total_leaves(self) -> int:
        return len(self._leaves)

    @property
    def root_hex(self) -> str:
        return self._root_hex

    def get_leaf_by_index(self, index: int) -> TensorLeafDescriptor:
        if index < 0 or index >= len(self._leaves):
            raise IndexError(f"Leaf index {index} out of bounds.")
        return self._leaves[index]

    def get_leaf_by_name(self, name: str) -> Optional[TensorLeafDescriptor]:
        idx = self._name_to_index.get(name)
        if idx is not None:
            return self._leaves[idx]
        return None

    def to_result(self) -> WeightMerkleResult:
        """Convert tree to sealed WeightMerkleResult."""
        total_elements = sum(
            (l.byte_length // 4) if l.dtype == "F32" else l.byte_length
            for l in self._leaves
        )
        total_bytes = sum(l.byte_length for l in self._leaves)
        status = "empty" if self.total_leaves == 0 else "verified"

        return WeightMerkleResult(
            schema_version="1.0",
            status=status,
            tensor_count=self.total_leaves,
            total_parameter_count=total_elements,
            total_tensor_bytes=total_bytes,
            merkle_root=self.root_hex,
            leaves=list(self._leaves),
            reason_codes=[ReasonCode.SAFE_INSPECTION_PASSED],
        )
