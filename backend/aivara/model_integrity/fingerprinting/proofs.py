"""Merkle Inclusion Proof Generation and Standalone Verification for Model Weights.

Generates and cryptographically verifies proofs that an individual parameter tensor
is included within a model's weight Merkle tree without requiring the complete artifact.
"""

from __future__ import annotations

from typing import List, Sequence, Union

from aivara.crypto.hashing import secure_compare_hashes
from aivara.model_integrity.fingerprinting.exceptions import InvalidMerkleProofError
from aivara.model_integrity.fingerprinting.merkle import (
    WeightMerkleTree,
    _largest_power_of_two_less_than,
    compute_internal_node_hash,
    compute_weight_merkle_root,
)
from aivara.model_integrity.fingerprinting.schemas import (
    MerkleInclusionProof,
    MerkleProofStep,
    ProofStepDirection,
)


def _generate_audit_path(
    target_idx: int,
    leaf_hashes: Sequence[str],
) -> List[MerkleProofStep]:
    """Recursively construct RFC 6962 audit path for leaf index."""
    n = len(leaf_hashes)
    if n <= 1:
        return []

    k = _largest_power_of_two_less_than(n)
    if target_idx < k:
        # Target in left subtree; sibling is root of right subtree
        right_root = compute_weight_merkle_root(leaf_hashes[k:])
        sub_path = _generate_audit_path(target_idx, leaf_hashes[:k])
        sub_path.append(
            MerkleProofStep(
                sibling_hash=right_root.lower(),
                direction=ProofStepDirection.RIGHT,
            )
        )
        return sub_path
    else:
        # Target in right subtree; sibling is root of left subtree
        left_root = compute_weight_merkle_root(leaf_hashes[:k])
        sub_path = _generate_audit_path(target_idx - k, leaf_hashes[k:])
        sub_path.append(
            MerkleProofStep(
                sibling_hash=left_root.lower(),
                direction=ProofStepDirection.LEFT,
            )
        )
        return sub_path


def generate_weight_inclusion_proof(
    tree: WeightMerkleTree,
    target: Union[str, int],
) -> MerkleInclusionProof:
    """Generate cryptographic Merkle inclusion proof for a parameter tensor.

    Args:
        tree: Instantiated WeightMerkleTree.
        target: Tensor name (str) or 0-indexed leaf position (int).

    Returns:
        Immutable MerkleInclusionProof object.

    Raises:
        InvalidMerkleProofError: If target is not found or tree is empty.
    """
    if tree.total_leaves == 0:
        raise InvalidMerkleProofError("Cannot generate inclusion proof for an empty Merkle tree.")

    if isinstance(target, int):
        if target < 0 or target >= tree.total_leaves:
            raise InvalidMerkleProofError(
                f"Leaf index {target} out of bounds for tree with {tree.total_leaves} leaves."
            )
        leaf = tree.get_leaf_by_index(target)
        leaf_idx = target
    elif isinstance(target, str):
        leaf = tree.get_leaf_by_name(target)
        if leaf is None:
            raise InvalidMerkleProofError(f"Tensor '{target}' not found in Merkle tree.")
        # Find index
        leaf_idx = [l.name for l in tree.leaves].index(target)
    else:
        raise InvalidMerkleProofError(f"Invalid target type {type(target).__name__}.")

    audit_path = _generate_audit_path(leaf_idx, tree.leaf_hashes)

    return MerkleInclusionProof(
        proof_version="1.0",
        weight_merkle_root=tree.root_hex,
        leaf_index=leaf_idx,
        total_leaves=tree.total_leaves,
        tensor_name=leaf.name,
        leaf_hash=leaf.leaf_hash,
        audit_path=audit_path,
    )


def verify_weight_inclusion_proof(proof: MerkleInclusionProof) -> bool:
    """Cryptographically verify a Merkle inclusion proof against its root.

    Ascends from proof.leaf_hash using audit_path siblings and compares
    the computed root with proof.weight_merkle_root in constant time.

    Args:
        proof: MerkleInclusionProof instance to verify.

    Returns:
        True if the proof is cryptographically valid, False otherwise.
    """
    if not isinstance(proof, MerkleInclusionProof):
        return False

    if proof.proof_version != "1.0":
        return False

    if proof.total_leaves <= 0 or proof.leaf_index < 0 or proof.leaf_index >= proof.total_leaves:
        return False

    current_hash = proof.leaf_hash.lower()

    # Single-leaf tree special case
    if proof.total_leaves == 1:
        if len(proof.audit_path) != 0:
            return False
        return secure_compare_hashes(current_hash, proof.weight_merkle_root)

    for step in proof.audit_path:
        sibling = step.sibling_hash.lower()
        if len(sibling) != 64:
            return False

        if step.direction == ProofStepDirection.RIGHT:
            current_hash = compute_internal_node_hash(current_hash, sibling)
        elif step.direction == ProofStepDirection.LEFT:
            current_hash = compute_internal_node_hash(sibling, current_hash)
        else:
            return False

    return secure_compare_hashes(current_hash, proof.weight_merkle_root)
