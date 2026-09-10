"""Multi-Index Hashing (MIH) candidate retrieval engine for 64-bit perceptual hashes (Phase 5.4).

Implements partition-based inverted indexing.
For a 64-bit hash partitioned into m blocks of 16 bits each:
By the Pigeonhole Principle, if d_H(Q, P) <= r, then in at least one block i:
    d_H(Q_i, P_i) <= floor(r / m)
"""

from __future__ import annotations

from typing import Any, Dict, List, NamedTuple, Optional, Set, Tuple

from aivara.dataset.duplicates.distance import hamming_distance_uint64
from aivara.dataset.duplicates.exceptions import InvalidThresholdError, MultiIndexHashError


class MIHItem(NamedTuple):
    """Entry stored in Multi-Index Hash tables."""
    sample_id: str
    relative_path: str
    hash_val: int
    data: Any


class MultiIndexHash:
    """Multi-Index Hash table for fast candidate lookup on 64-bit perceptual hashes."""

    def __init__(self, num_blocks: int = 4) -> None:
        """Initialize Multi-Index Hash with specified number of equal-sized blocks.

        For 64-bit hashes, num_blocks=4 yields 16-bit sub-blocks.

        Args:
            num_blocks: Number of disjoint partitions (must divide 64 evenly: 2, 4, 8, 16).
        """
        if 64 % num_blocks != 0:
            raise MultiIndexHashError(f"num_blocks ({num_blocks}) must divide 64 evenly.")

        self.num_blocks: int = num_blocks
        self.block_width: int = 64 // num_blocks
        self.mask: int = (1 << self.block_width) - 1

        # Inverted index tables: one dictionary per partition block
        self.tables: List[Dict[int, List[MIHItem]]] = [{} for _ in range(num_blocks)]
        self._total_items: int = 0

    @property
    def total_items(self) -> int:
        """Total number of items indexed."""
        return self._total_items

    def _extract_block(self, hash_val: int, block_idx: int) -> int:
        """Extract the integer value of the block_idx-th partition."""
        shift = (self.num_blocks - 1 - block_idx) * self.block_width
        return (hash_val >> shift) & self.mask

    def insert(
        self,
        hash_val: int,
        sample_id: str,
        relative_path: str,
        data: Any = None,
    ) -> None:
        """Insert a sample hash into all partition tables."""
        item = MIHItem(sample_id=sample_id, relative_path=relative_path, hash_val=hash_val, data=data)
        self._total_items += 1

        for b_idx in range(self.num_blocks):
            sub_val = self._extract_block(hash_val, b_idx)
            if sub_val not in self.tables[b_idx]:
                self.tables[b_idx][sub_val] = []
            self.tables[b_idx][sub_val].append(item)

    def query(
        self,
        query_hash: int,
        max_distance: int,
    ) -> List[Tuple[MIHItem, int]]:
        """Retrieve candidate matches within max_distance using Multi-Index sub-block lookups.

        Args:
            query_hash: 64-bit unsigned integer query hash.
            max_distance: Maximum allowable Hamming distance.

        Returns:
            List of (MIHItem, exact_distance) pairs satisfying exact_distance <= max_distance.
        """
        if max_distance < 0 or max_distance > 64:
            raise InvalidThresholdError(f"max_distance must be in [0, 64], got {max_distance}.")

        # Collect candidate items from partition tables
        candidate_set: Set[str] = set()
        candidates: List[MIHItem] = []

        for b_idx in range(self.num_blocks):
            sub_val = self._extract_block(query_hash, b_idx)
            bucket = self.tables[b_idx].get(sub_val)
            if bucket:
                for item in bucket:
                    if item.sample_id not in candidate_set:
                        candidate_set.add(item.sample_id)
                        candidates.append(item)

        # Exact distance verification
        results: List[Tuple[MIHItem, int]] = []
        for item in candidates:
            dist = hamming_distance_uint64(query_hash, item.hash_val)
            if dist <= max_distance:
                results.append((item, dist))

        return results
