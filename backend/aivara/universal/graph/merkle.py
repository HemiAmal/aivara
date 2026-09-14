"""Deterministic Binary Merkle Tree Computation for Universal Evidence Graph (Phase 12.3)."""

from __future__ import annotations

import hashlib
from typing import List, Sequence

from aivara.universal.hashing import compute_sha256_digest


def compute_graph_merkle_root(leaf_hashes: Sequence[str]) -> str:
    """Compute deterministic binary SHA-256 Merkle root over a sequence of leaf hashes.
    
    Rules:
    - Leaves are deterministically sorted lexicographically.
    - If leaf sequence is empty: return SHA-256(b"aivara:empty_merkle_tree").
    - Odd leaf handling: duplicate last leaf at each reduction level.
    - Intermediate node hash: SHA-256(left_hex.encode() + right_hex.encode()).
    - Returns: 64-character lowercase hexadecimal SHA-256 root digest.
    """
    if not leaf_hashes:
        return compute_sha256_digest(b"aivara:empty_merkle_tree")

    # Sort leaves deterministically
    current_level = sorted(list(leaf_hashes))

    while len(current_level) > 1:
        next_level: List[str] = []
        # If odd number of elements, duplicate last element
        if len(current_level) % 2 != 0:
            current_level.append(current_level[-1])

        for i in range(0, len(current_level), 2):
            left = current_level[i]
            right = current_level[i + 1]
            combined = hashlib.sha256(left.encode("utf-8") + right.encode("utf-8")).hexdigest()
            next_level.append(combined)

        current_level = next_level

    return current_level[0]
