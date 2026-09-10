"""Level 4: RFC 6962-Compliant Binary Merkle Tree Integrity Engine (Phase 5.3).

Provides deterministic binary Merkle tree construction with 1-byte domain separation
(0x00 leaf prefix, 0x01 internal node prefix), balanced power-of-2 splitting
(avoiding CVE-2012-2459 node duplication attacks), deterministic UTF-8 path-ordered
leaf collation, and root digest generation.
"""

from __future__ import annotations

import hashlib
from typing import Dict, List, NamedTuple, Optional, Sequence, Tuple

from aivara.crypto.hashing import secure_compare_hashes, sha256_bytes, sha256_text
from aivara.dataset.fingerprinting.exceptions import (
    DuplicateSampleIdError,
    DuplicateSamplePathError,
    InvalidCanonicalInputError,
    InvalidHashFormatError,
    MalformedMerkleTreeError,
)
from aivara.dataset.schemas import CanonicalSample

LEAF_PREFIX: bytes = b"\x00"
INTERNAL_PREFIX: bytes = b"\x01"

# Deterministic constant for empty dataset Merkle root
EMPTY_MERKLE_ROOT_HEX: str = sha256_text("aivara-empty-tree-v1")
EMPTY_MERKLE_ROOT_BYTES: bytes = bytes.fromhex(EMPTY_MERKLE_ROOT_HEX)


class MerkleLeaf(NamedTuple):
    """Leaf node descriptor in the dataset Merkle tree."""
    index: int
    sample_id: str
    relative_path: str
    sample_fingerprint: str
    leaf_hash_bytes: bytes

    @property
    def leaf_hash_hex(self) -> str:
        """64-character lowercase hex representation of leaf digest."""
        return self.leaf_hash_bytes.hex().lower()


def compute_leaf_hash(sample_fingerprint_hex: str) -> bytes:
    """Compute 32-byte binary leaf digest using RFC 6962 0x00 prefix.

    LeafDigest = SHA-256(0x00 || raw_32_byte_sample_fingerprint)

    Args:
        sample_fingerprint_hex: 64-character lowercase hex sample fingerprint.

    Returns:
        32 raw bytes of SHA-256 digest.

    Raises:
        InvalidHashFormatError: If fingerprint format is invalid.
    """
    if not isinstance(sample_fingerprint_hex, str) or len(sample_fingerprint_hex) != 64:
        raise InvalidHashFormatError(
            f"Expected 64-character hex sample fingerprint, got '{sample_fingerprint_hex}'."
        )
    try:
        raw_fingerprint = bytes.fromhex(sample_fingerprint_hex)
    except ValueError as ve:
        raise InvalidHashFormatError(
            f"Invalid hex characters in sample fingerprint '{sample_fingerprint_hex}': {ve}"
        ) from ve

    hasher = hashlib.sha256()
    hasher.update(LEAF_PREFIX)
    hasher.update(raw_fingerprint)
    return hasher.digest()


def compute_internal_hash(left_32_bytes: bytes, right_32_bytes: bytes) -> bytes:
    """Compute 32-byte binary internal node digest using RFC 6962 0x01 prefix.

    InternalDigest = SHA-256(0x01 || left_32_bytes || right_32_bytes)

    Args:
        left_32_bytes: 32 raw bytes of left child digest.
        right_32_bytes: 32 raw bytes of right child digest.

    Returns:
        32 raw bytes of SHA-256 digest.
    """
    if len(left_32_bytes) != 32 or len(right_32_bytes) != 32:
        raise MalformedMerkleTreeError("Internal node children must each be exactly 32 bytes.")

    hasher = hashlib.sha256()
    hasher.update(INTERNAL_PREFIX)
    hasher.update(left_32_bytes)
    hasher.update(right_32_bytes)
    return hasher.digest()


def _largest_power_of_two_less_than(n: int) -> int:
    """Calculate the largest power of 2 strictly less than n (for n > 1)."""
    if n <= 1:
        raise ValueError(f"n must be > 1, got {n}")
    # Equivalent to 2^(floor(log2(n - 1)))
    return 1 << ((n - 1).bit_length() - 1)


def compute_rfc6962_merkle_root(leaf_hashes: Sequence[bytes]) -> bytes:
    """Recursively compute RFC 6962 binary Merkle root over a sequence of 32-byte leaf digests.

    Algorithm:
      1. If N == 0: return EMPTY_MERKLE_ROOT_BYTES.
      2. If N == 1: return leaf_hashes[0].
      3. If N > 1:
         k = largest power of 2 strictly less than N.
         left_root = compute_rfc6962_merkle_root(leaf_hashes[:k])
         right_root = compute_rfc6962_merkle_root(leaf_hashes[k:])
         return compute_internal_hash(left_root, right_root)

    Args:
        leaf_hashes: Ordered sequence of 32-byte leaf digests.

    Returns:
        32 raw bytes of the Merkle root digest.
    """
    n = len(leaf_hashes)
    if n == 0:
        return EMPTY_MERKLE_ROOT_BYTES
    if n == 1:
        return leaf_hashes[0]

    k = _largest_power_of_two_less_than(n)
    left_root = compute_rfc6962_merkle_root(leaf_hashes[:k])
    right_root = compute_rfc6962_merkle_root(leaf_hashes[k:])
    return compute_internal_hash(left_root, right_root)


class MerkleTree:
    """Immutable, fully structured RFC 6962 binary Merkle tree representation."""

    def __init__(self, leaves: Sequence[MerkleLeaf]) -> None:
        self._leaves: Tuple[MerkleLeaf, ...] = tuple(leaves)
        self._leaf_hashes: Tuple[bytes, ...] = tuple(leaf.leaf_hash_bytes for leaf in self._leaves)
        self._root_bytes: bytes = compute_rfc6962_merkle_root(self._leaf_hashes)
        self._path_to_index: Dict[str, int] = {
            leaf.relative_path: idx for idx, leaf in enumerate(self._leaves)
        }

    @property
    def leaves(self) -> Tuple[MerkleLeaf, ...]:
        """Sequence of sorted Merkle leaves."""
        return self._leaves

    @property
    def total_leaves(self) -> int:
        """Total number of leaves in the tree."""
        return len(self._leaves)

    @property
    def root_bytes(self) -> bytes:
        """32 raw bytes of the Merkle root."""
        return self._root_bytes

    @property
    def root_hex(self) -> str:
        """64-character lowercase hexadecimal Merkle root string."""
        return self._root_bytes.hex().lower()

    def get_leaf_by_index(self, index: int) -> MerkleLeaf:
        """Retrieve leaf by integer index."""
        if index < 0 or index >= len(self._leaves):
            raise IndexError(f"Leaf index {index} out of bounds for tree with {len(self._leaves)} leaves.")
        return self._leaves[index]

    def get_leaf_by_path(self, relative_path: str) -> Optional[MerkleLeaf]:
        """Retrieve leaf by its relative path."""
        idx = self._path_to_index.get(relative_path)
        if idx is not None:
            return self._leaves[idx]
        return None


def collate_and_build_merkle_tree(
    sample_fingerprints: Sequence[Tuple[CanonicalSample, str]],
) -> MerkleTree:
    """Collate sample fingerprints and construct a deterministic RFC 6962 Merkle tree.

    Ordering & Invariant Rules:
      1. All samples are sorted strictly by `relative_path` in ascending UTF-8 byte order.
      2. Rejects duplicate `relative_path` with DuplicateSamplePathError.
      3. Rejects duplicate `sample_id` with DuplicateSampleIdError.
      4. Computes leaf hashes via compute_leaf_hash().
      5. Constructs balanced binary tree.

    Args:
        sample_fingerprints: Sequence of (CanonicalSample, sample_fingerprint_hex) pairs.

    Returns:
        Structured MerkleTree instance.

    Raises:
        DuplicateSamplePathError: If two samples have identical paths.
        DuplicateSampleIdError: If two samples have identical sample IDs.
    """
    # Check for duplicate sample_ids and relative_paths
    seen_paths: Dict[str, str] = {}
    seen_ids: Dict[str, str] = {}

    for sample, _ in sample_fingerprints:
        if not isinstance(sample, CanonicalSample):
            raise InvalidCanonicalInputError(f"Expected CanonicalSample, got {type(sample).__name__}.")

        norm_path = sample.relative_path.replace("\\", "/")
        if norm_path in seen_paths:
            raise DuplicateSamplePathError(
                f"Duplicate sample relative_path detected: '{norm_path}'.",
                details={"relative_path": norm_path, "sample_id": sample.sample_id},
            )
        seen_paths[norm_path] = sample.sample_id

        if sample.sample_id in seen_ids:
            raise DuplicateSampleIdError(
                f"Duplicate sample_id detected: '{sample.sample_id}'.",
                details={"sample_id": sample.sample_id, "relative_path": norm_path},
            )
        seen_ids[sample.sample_id] = norm_path

    # Sort strictly by relative_path (UTF-8 binary collation)
    sorted_pairs = sorted(
        sample_fingerprints,
        key=lambda pair: pair[0].relative_path.encode("utf-8"),
    )

    leaves: List[MerkleLeaf] = []
    for idx, (sample, fp_hex) in enumerate(sorted_pairs):
        leaf_hash = compute_leaf_hash(fp_hex)
        leaves.append(
            MerkleLeaf(
                index=idx,
                sample_id=sample.sample_id,
                relative_path=sample.relative_path,
                sample_fingerprint=fp_hex,
                leaf_hash_bytes=leaf_hash,
            )
        )

    return MerkleTree(leaves)
