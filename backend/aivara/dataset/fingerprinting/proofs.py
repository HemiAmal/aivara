"""Merkle Inclusion Proof Generation and Verification Engine (Phase 5.3).

Provides cryptographic proof of inclusion/exclusion for individual samples within
a dataset version Merkle tree without requiring the complete dataset.
"""

from __future__ import annotations

from enum import Enum
from typing import List, Sequence

from pydantic import BaseModel, ConfigDict, Field, field_validator

from aivara.crypto.hashing import secure_compare_hashes
from aivara.dataset.fingerprinting.exceptions import (
    FingerprintVersionMismatchError,
    InvalidInclusionProofError,
)
from aivara.dataset.fingerprinting.merkle import (
    MerkleTree,
    _largest_power_of_two_less_than,
    compute_internal_hash,
    compute_rfc6962_merkle_root,
)

PROOF_SCHEMA_VERSION: str = "1.0"


class ProofStepDirection(str, Enum):
    """Direction of sibling hash in Merkle audit path.

    LEFT: The sibling is on the left; current accumulated node is on the right.
    RIGHT: The sibling is on the right; current accumulated node is on the left.
    """
    LEFT = "left"
    RIGHT = "right"


class MerkleProofStep(BaseModel):
    """Single step in a Merkle inclusion audit path."""

    model_config = ConfigDict(frozen=True)

    sibling_hash: str = Field(
        ...,
        pattern=r"^[0-9a-f]{64}$",
        description="64-character lowercase hexadecimal sibling node digest",
    )
    direction: ProofStepDirection = Field(
        ...,
        description="Relative direction of sibling in internal node concatenation",
    )


class MerkleInclusionProof(BaseModel):
    """Cryptographic Merkle inclusion proof for a dataset sample."""

    model_config = ConfigDict(frozen=True)

    proof_version: str = Field(
        default=PROOF_SCHEMA_VERSION,
        description="Proof format schema version",
    )
    dataset_merkle_root: str = Field(
        ...,
        pattern=r"^[0-9a-f]{64}$",
        description="Expected 64-character lowercase hex dataset Merkle root",
    )
    leaf_index: int = Field(..., ge=0, description="0-based integer leaf index")
    total_leaves: int = Field(..., ge=1, description="Total leaves in the dataset Merkle tree")
    sample_path: str = Field(..., min_length=1, description="Normalized relative path of target sample")
    leaf_hash: str = Field(
        ...,
        pattern=r"^[0-9a-f]{64}$",
        description="64-character lowercase hex leaf digest (SHA-256(0x00 || sample_fingerprint))",
    )
    audit_path: List[MerkleProofStep] = Field(
        default_factory=list,
        description="Ordered sequence of sibling hashes and directions from leaf to root",
    )

    @field_validator("proof_version")
    @classmethod
    def _validate_version(cls, v: str) -> str:
        if v != PROOF_SCHEMA_VERSION:
            raise ValueError(f"Unsupported proof version '{v}'. Expected '{PROOF_SCHEMA_VERSION}'.")
        return v


def _generate_rfc6962_audit_path(
    m: int,
    leaf_hashes: Sequence[bytes],
) -> List[MerkleProofStep]:
    """Recursively generate RFC 6962 audit path for leaf index m."""
    n = len(leaf_hashes)
    if n <= 1:
        return []

    k = _largest_power_of_two_less_than(n)
    if m < k:
        # Target leaf is in the left sub-tree
        # Sibling is the root of the right sub-tree
        right_root = compute_rfc6962_merkle_root(leaf_hashes[k:])
        sub_path = _generate_rfc6962_audit_path(m, leaf_hashes[:k])
        sub_path.append(
            MerkleProofStep(
                sibling_hash=right_root.hex().lower(),
                direction=ProofStepDirection.RIGHT,
            )
        )
        return sub_path
    else:
        # Target leaf is in the right sub-tree
        # Sibling is the root of the left sub-tree
        left_root = compute_rfc6962_merkle_root(leaf_hashes[:k])
        sub_path = _generate_rfc6962_audit_path(m - k, leaf_hashes[k:])
        sub_path.append(
            MerkleProofStep(
                sibling_hash=left_root.hex().lower(),
                direction=ProofStepDirection.LEFT,
            )
        )
        return sub_path


def generate_inclusion_proof(tree: MerkleTree, leaf_index: int) -> MerkleInclusionProof:
    """Generate a cryptographic inclusion proof for a leaf in the Merkle tree.

    Args:
        tree: Instantiated MerkleTree.
        leaf_index: 0-indexed leaf position.

    Returns:
        Immutable MerkleInclusionProof.

    Raises:
        InvalidInclusionProofError: If leaf_index is out of range or tree is empty.
    """
    if tree.total_leaves == 0:
        raise InvalidInclusionProofError("Cannot generate inclusion proof for an empty Merkle tree.")

    if leaf_index < 0 or leaf_index >= tree.total_leaves:
        raise InvalidInclusionProofError(
            f"Leaf index {leaf_index} out of bounds for tree with {tree.total_leaves} leaves."
        )

    leaf = tree.get_leaf_by_index(leaf_index)
    leaf_hashes = [l.leaf_hash_bytes for l in tree.leaves]

    audit_path = _generate_rfc6962_audit_path(leaf_index, leaf_hashes)

    return MerkleInclusionProof(
        proof_version=PROOF_SCHEMA_VERSION,
        dataset_merkle_root=tree.root_hex,
        leaf_index=leaf_index,
        total_leaves=tree.total_leaves,
        sample_path=leaf.relative_path,
        leaf_hash=leaf.leaf_hash_hex,
        audit_path=audit_path,
    )


def verify_inclusion_proof(proof: MerkleInclusionProof) -> bool:
    """Cryptographically verify a Merkle inclusion proof against its root.

    Ascends the tree from leaf_hash using audit_path siblings and verifies that
    the computed root matches proof.dataset_merkle_root in constant time.

    Args:
        proof: MerkleInclusionProof instance to verify.

    Returns:
        True if the proof is cryptographically valid, False otherwise.
    """
    if not isinstance(proof, MerkleInclusionProof):
        return False

    if proof.proof_version != PROOF_SCHEMA_VERSION:
        return False

    if proof.total_leaves <= 0 or proof.leaf_index < 0 or proof.leaf_index >= proof.total_leaves:
        return False

    try:
        current_hash = bytes.fromhex(proof.leaf_hash)
    except ValueError:
        return False

    if len(current_hash) != 32:
        return False

    # Single-leaf tree special case
    if proof.total_leaves == 1:
        if len(proof.audit_path) != 0:
            return False
        return secure_compare_hashes(proof.leaf_hash, proof.dataset_merkle_root)

    for step in proof.audit_path:
        try:
            sibling_hash = bytes.fromhex(step.sibling_hash)
        except ValueError:
            return False

        if len(sibling_hash) != 32:
            return False

        if step.direction == ProofStepDirection.RIGHT:
            # Sibling is right child, current is left child
            current_hash = compute_internal_hash(current_hash, sibling_hash)
        elif step.direction == ProofStepDirection.LEFT:
            # Sibling is left child, current is right child
            current_hash = compute_internal_hash(sibling_hash, current_hash)
        else:
            return False

    computed_root_hex = current_hash.hex().lower()
    return secure_compare_hashes(computed_root_hex, proof.dataset_merkle_root)
