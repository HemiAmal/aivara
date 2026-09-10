"""BK-Tree (Burkhard-Keller Tree) metric space index for 64-bit perceptual hashes (Phase 5.4).

Enables sub-quadratic radius queries over Hamming distance metric spaces by exploiting
the triangle inequality property:
    |d(Q, P) - d(P, C)| <= d(Q, C) <= d(Q, P) + d(P, C)
Pruning rule:
    Search child at edge distance k only if: d(Q, P) - radius <= k <= d(Q, P) + radius
"""

from __future__ import annotations

from typing import Any, Dict, List, NamedTuple, Optional, Sequence, Tuple

from aivara.dataset.duplicates.distance import (
    hamming_distance_uint64,
    hex_to_uint64,
)
from aivara.dataset.duplicates.exceptions import BKTreeError, InvalidThresholdError


class BKTreeItem(NamedTuple):
    """Entry stored in a BK-Tree node."""
    sample_id: str
    relative_path: str
    data: Any


class BKTreeNode:
    """Internal node in the BK-Tree."""

    def __init__(self, hash_val: int, item: BKTreeItem) -> None:
        self.hash_val: int = hash_val
        self.items: List[BKTreeItem] = [item]
        self.children: Dict[int, BKTreeNode] = {}

    def add_item(self, item: BKTreeItem) -> None:
        """Add an item sharing the exact same hash value."""
        self.items.append(item)


class BKTree:
    """Metric space index for efficient nearest-neighbor and radius search over Hamming distance."""

    def __init__(self) -> None:
        self._root: Optional[BKTreeNode] = None
        self._total_items: int = 0
        self._unique_hashes: int = 0

    @property
    def total_items(self) -> int:
        """Total number of sample items indexed."""
        return self._total_items

    @property
    def unique_hashes(self) -> int:
        """Total number of unique hash nodes in the tree."""
        return self._unique_hashes

    def insert(
        self,
        hash_val: int,
        sample_id: str,
        relative_path: str,
        data: Any = None,
    ) -> None:
        """Insert a sample item into the BK-Tree.

        Args:
            hash_val: 64-bit unsigned integer perceptual hash.
            sample_id: Canonical sample identifier.
            relative_path: Normalized relative path.
            data: Optional extra payload (e.g. dHash or contributor info).
        """
        item = BKTreeItem(sample_id=sample_id, relative_path=relative_path, data=data)
        self._total_items += 1

        if self._root is None:
            self._root = BKTreeNode(hash_val, item)
            self._unique_hashes += 1
            return

        current = self._root
        while True:
            dist = hamming_distance_uint64(hash_val, current.hash_val)
            if dist == 0:
                # Exact perceptual hash collision: append item to existing node
                current.add_item(item)
                return

            if dist not in current.children:
                # Create new child at edge distance `dist`
                current.children[dist] = BKTreeNode(hash_val, item)
                self._unique_hashes += 1
                return

            current = current.children[dist]

    def search(
        self,
        query_hash: int,
        max_distance: int,
    ) -> List[Tuple[BKTreeItem, int]]:
        """Search all indexed items within a maximum Hamming distance of query_hash.

        Args:
            query_hash: 64-bit unsigned integer query hash.
            max_distance: Maximum allowable Hamming distance (radius) in [0, 64].

        Returns:
            List of (BKTreeItem, distance) pairs satisfying distance <= max_distance.

        Raises:
            InvalidThresholdError: If max_distance is outside [0, 64].
        """
        if max_distance < 0 or max_distance > 64:
            raise InvalidThresholdError(f"max_distance must be in [0, 64], got {max_distance}.")

        if self._root is None:
            return []

        results: List[Tuple[BKTreeItem, int]] = []
        stack = [self._root]

        while stack:
            node = stack.pop()
            d = hamming_distance_uint64(query_hash, node.hash_val)

            if d <= max_distance:
                for item in node.items:
                    results.append((item, d))

            min_dist = max(0, d - max_distance)
            max_dist = min(64, d + max_distance)

            for dist_edge, child_node in node.children.items():
                if min_dist <= dist_edge <= max_dist:
                    stack.append(child_node)

        return results
