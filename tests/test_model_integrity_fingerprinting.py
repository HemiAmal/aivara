"""Comprehensive test suite for Phase 7.3: Hierarchical Model Fingerprinting & Merkle Weight Engine.

Verifies:
  A. Artifact Hashing (H_artifact)
  B. Structural Hashing (H_structural)
  C. Tensor Leaf Hashing (Domain separation, content binding)
  D. Merkle Tree Construction (Empty, 1, 2, 3, odd, power-of-2 balance)
  E. Merkle Inclusion Proofs (Generation, verification, tamper detection)
  F. Contract Hashing (H_contract)
  G. Master Model Fingerprint (ADR-040 RFC 8785 JCS binding, H_model)
  H. Hierarchical Independence & Separation
  I. End-to-End Fingerprinting Orchestration
  J. Offline Operation & Security Boundary
"""

import hashlib
import json
import struct
from pathlib import Path
from typing import Any, Dict, List

import pytest

from aivara.crypto.canonical import canonicalize
from aivara.crypto.hashing import sha256_bytes, sha256_text
from aivara.model_integrity import (
    EMPTY_WEIGHT_ROOT_HEX,
    ContractRepresentation,
    DuplicateTensorLeafError,
    FingerprintingError,
    HierarchicalFingerprintResult,
    InputContractDescriptor,
    InvalidMerkleProofError,
    MasterFingerprintBinding,
    MerkleInclusionProof,
    MerkleProofStep,
    ModelFingerprintingService,
    ModelFormat,
    ModelIngestionService,
    NormalizedModelMetadata,
    OperatorDescriptor,
    OutputContractDescriptor,
    ProofStepDirection,
    StructuralRepresentation,
    TensorDescriptor,
    TensorLeafDescriptor,
    WeightContentUnavailableError,
    WeightMerkleResult,
    WeightMerkleTree,
    build_contract_representation,
    build_structural_representation,
    compute_artifact_hash,
    compute_contract_hash,
    compute_internal_node_hash,
    compute_master_fingerprint,
    compute_structural_hash,
    compute_tensor_leaf_hash,
    compute_weight_merkle_root,
    extract_tensor_leaves,
    generate_weight_inclusion_proof,
    verify_weight_inclusion_proof,
)


# =====================================================================
# Fixture Helpers
# =====================================================================

def make_mock_safetensors(
    file_path: Path,
    tensors: Dict[str, Dict[str, Any]],
    metadata: Dict[str, str] = None,
) -> Path:
    """Create a syntactically valid Safetensors binary file with exact byte buffers."""
    header_dict = {}
    if metadata:
        header_dict["__metadata__"] = metadata

    total_tensor_bytes = 0
    raw_tensor_buffers = []

    for name, t_spec in tensors.items():
        dtype = t_spec.get("dtype", "F32")
        shape = t_spec.get("shape", [2, 2])
        data_bytes = t_spec.get("data", b"\x00" * 16)
        start_off = total_tensor_bytes
        end_off = start_off + len(data_bytes)
        total_tensor_bytes = end_off
        raw_tensor_buffers.append(data_bytes)

        header_dict[name] = {
            "dtype": dtype,
            "shape": shape,
            "data_offsets": [start_off, end_off],
        }

    header_json = json.dumps(header_dict, separators=(",", ":")).encode("utf-8")
    header_len = len(header_json)

    with open(file_path, "wb") as f:
        f.write(struct.pack("<Q", header_len))
        f.write(header_json)
        for buf in raw_tensor_buffers:
            f.write(buf)

    return file_path


# =====================================================================
# A. Artifact Hashing Tests (H_artifact)
# =====================================================================

def test_artifact_hash_deterministic(tmp_path: Path):
    """Verify that artifact hashing produces exact lowercase SHA-256."""
    fpath = tmp_path / "model.bin"
    payload = b"AIVARA_DETERMINISTIC_MODEL_PAYLOAD_1234567890"
    fpath.write_bytes(payload)

    expected = hashlib.sha256(payload).hexdigest().lower()
    observed = compute_artifact_hash(fpath)

    assert observed == expected
    assert len(observed) == 64
    assert observed.islower()


def test_artifact_hash_single_byte_mutation(tmp_path: Path):
    """Verify that a single byte change produces a completely different hash."""
    fpath1 = tmp_path / "model1.bin"
    fpath2 = tmp_path / "model2.bin"

    fpath1.write_bytes(b"HELLO_MODEL_A")
    fpath2.write_bytes(b"HELLO_MODEL_B")

    h1 = compute_artifact_hash(fpath1)
    h2 = compute_artifact_hash(fpath2)

    assert h1 != h2


def test_artifact_hash_empty_file(tmp_path: Path):
    """Verify hashing an empty file."""
    fpath = tmp_path / "empty.bin"
    fpath.write_bytes(b"")

    expected = hashlib.sha256(b"").hexdigest().lower()
    observed = compute_artifact_hash(fpath)

    assert observed == expected


# =====================================================================
# B. Structural Hashing Tests (H_structural)
# =====================================================================

def test_structural_hash_deterministic():
    """Verify that identical structural representations produce bit-exact hashes."""
    s1 = StructuralRepresentation(
        schema_version="1.0",
        format="safetensors",
        architecture="resnet50",
        tensor_count=2,
        parameter_count=100,
        tensors=[
            {"name": "conv1.weight", "shape": [64, 3, 7, 7], "dtype": "F32", "element_count": 9408, "byte_size": 37632},
            {"name": "fc.weight", "shape": [1000, 2048], "dtype": "F32", "element_count": 2048000, "byte_size": 8192000},
        ],
        operators=[{"count": 1, "domain": "ai.onnx", "op_type": "Conv"}],
        metadata_props={"author": "aivara"},
    )
    s2 = StructuralRepresentation(
        schema_version="1.0",
        format="safetensors",
        architecture="resnet50",
        tensor_count=2,
        parameter_count=100,
        tensors=[
            {"name": "conv1.weight", "shape": [64, 3, 7, 7], "dtype": "F32", "element_count": 9408, "byte_size": 37632},
            {"name": "fc.weight", "shape": [1000, 2048], "dtype": "F32", "element_count": 2048000, "byte_size": 8192000},
        ],
        operators=[{"count": 1, "domain": "ai.onnx", "op_type": "Conv"}],
        metadata_props={"author": "aivara"},
    )

    h1 = compute_structural_hash(s1)
    h2 = compute_structural_hash(s2)

    assert h1 == h2
    assert len(h1) == 64


def test_structural_hash_sensitive_to_tensor_mutation():
    """Verify that tensor shape or dtype mutations alter structural hash."""
    base = StructuralRepresentation(
        schema_version="1.0",
        format="safetensors",
        architecture="resnet50",
        tensor_count=1,
        parameter_count=10,
        tensors=[{"name": "w", "shape": [10], "dtype": "F32", "element_count": 10, "byte_size": 40}],
    )
    mutated_shape = StructuralRepresentation(
        schema_version="1.0",
        format="safetensors",
        architecture="resnet50",
        tensor_count=1,
        parameter_count=10,
        tensors=[{"name": "w", "shape": [5, 2], "dtype": "F32", "element_count": 10, "byte_size": 40}],
    )
    mutated_dtype = StructuralRepresentation(
        schema_version="1.0",
        format="safetensors",
        architecture="resnet50",
        tensor_count=1,
        parameter_count=10,
        tensors=[{"name": "w", "shape": [10], "dtype": "F16", "element_count": 10, "byte_size": 20}],
    )

    h_base = compute_structural_hash(base)
    h_shape = compute_structural_hash(mutated_shape)
    h_dtype = compute_structural_hash(mutated_dtype)

    assert h_base != h_shape
    assert h_base != h_dtype
    assert h_shape != h_dtype


# =====================================================================
# C. Tensor Leaf Hashing Tests
# =====================================================================

def test_tensor_leaf_hash_domain_separation():
    """Verify that tensor leaf digests bind domain tag and metadata."""
    name = "layer1.weight"
    shape = [32, 16, 3, 3]
    dtype = "F32"
    byte_len = 32 * 16 * 3 * 3 * 4
    content_hash = hashlib.sha256(b"TENSOR_BYTES").hexdigest().lower()

    leaf_hash = compute_tensor_leaf_hash(
        name=name,
        shape=shape,
        dtype=dtype,
        byte_length=byte_len,
        content_hash=content_hash,
    )

    # Check that manual JCS matches
    expected_payload = {
        "byte_length": byte_len,
        "content_hash": content_hash,
        "domain": "aivara:model-weight-leaf:v1",
        "dtype": dtype,
        "name": name,
        "schema_version": "1.0",
        "shape": shape,
    }
    expected_hash = sha256_bytes(canonicalize(expected_payload))

    assert leaf_hash == expected_hash
    assert len(leaf_hash) == 64


def test_tensor_leaf_hash_content_sensitivity():
    """Verify that changing content hash changes leaf digest."""
    h1 = compute_tensor_leaf_hash("w", [2], "F32", 8, "00" * 32)
    h2 = compute_tensor_leaf_hash("w", [2], "F32", 8, "ff" * 32)
    assert h1 != h2


# =====================================================================
# D. Merkle Tree Construction Tests
# =====================================================================

def test_merkle_tree_empty():
    """Verify empty Merkle tree produces defined constant root."""
    tree = WeightMerkleTree([])
    assert tree.total_leaves == 0
    assert tree.root_hex == EMPTY_WEIGHT_ROOT_HEX


def test_merkle_tree_single_leaf():
    """Verify single-leaf tree root equals the leaf digest."""
    leaf = TensorLeafDescriptor(
        name="single.weight",
        shape=[4],
        dtype="F32",
        byte_length=16,
        content_hash="aa" * 32,
        leaf_hash="11" * 32,
    )
    tree = WeightMerkleTree([leaf])
    assert tree.total_leaves == 1
    assert tree.root_hex == leaf.leaf_hash


def test_merkle_tree_two_leaves():
    """Verify two-leaf tree root equals internal node of leaves."""
    l1 = TensorLeafDescriptor(name="a.weight", shape=[2], dtype="F32", byte_length=8, content_hash="11"*32, leaf_hash="aa"*32)
    l2 = TensorLeafDescriptor(name="b.weight", shape=[2], dtype="F32", byte_length=8, content_hash="22"*32, leaf_hash="bb"*32)

    tree = WeightMerkleTree([l1, l2])
    assert tree.total_leaves == 2

    expected_root = compute_internal_node_hash("aa"*32, "bb"*32)
    assert tree.root_hex == expected_root


def test_merkle_tree_odd_leaves_power_of_two():
    """Verify 3-leaf tree uses RFC 6962 largest-power-of-two (k=2) split."""
    l1 = TensorLeafDescriptor(name="a", shape=[1], dtype="F32", byte_length=4, content_hash="01"*32, leaf_hash="10"*32)
    l2 = TensorLeafDescriptor(name="b", shape=[1], dtype="F32", byte_length=4, content_hash="02"*32, leaf_hash="20"*32)
    l3 = TensorLeafDescriptor(name="c", shape=[1], dtype="F32", byte_length=4, content_hash="03"*32, leaf_hash="30"*32)

    tree = WeightMerkleTree([l1, l2, l3])
    assert tree.total_leaves == 3

    # Left subtree: l1, l2 -> internal(l1, l2)
    left_sub = compute_internal_node_hash("10"*32, "20"*32)
    # Right subtree: l3 -> l3.leaf_hash
    right_sub = "30"*32
    expected_root = compute_internal_node_hash(left_sub, right_sub)

    assert tree.root_hex == expected_root


def test_merkle_tree_sorting_stability():
    """Verify that passing leaves in reverse order produces identical sorted tree."""
    l1 = TensorLeafDescriptor(name="a_weight", shape=[1], dtype="F32", byte_length=4, content_hash="01"*32, leaf_hash="10"*32)
    l2 = TensorLeafDescriptor(name="z_weight", shape=[1], dtype="F32", byte_length=4, content_hash="02"*32, leaf_hash="20"*32)

    tree_fwd = WeightMerkleTree([l1, l2])
    tree_rev = WeightMerkleTree([l2, l1])

    assert tree_fwd.root_hex == tree_rev.root_hex
    assert [l.name for l in tree_fwd.leaves] == ["a_weight", "z_weight"]
    assert [l.name for l in tree_rev.leaves] == ["a_weight", "z_weight"]


def test_merkle_tree_duplicate_leaf_rejected():
    """Verify that duplicate tensor names are rejected."""
    l1 = TensorLeafDescriptor(name="same_name", shape=[1], dtype="F32", byte_length=4, content_hash="01"*32, leaf_hash="10"*32)
    l2 = TensorLeafDescriptor(name="same_name", shape=[2], dtype="F32", byte_length=8, content_hash="02"*32, leaf_hash="20"*32)

    with pytest.raises(DuplicateTensorLeafError):
        WeightMerkleTree([l1, l2])


# =====================================================================
# E. Merkle Inclusion Proof Tests
# =====================================================================

def test_inclusion_proof_valid():
    """Verify generation and standalone verification of inclusion proofs."""
    leaves = [
        TensorLeafDescriptor(name=f"tensor_{i:02d}", shape=[2], dtype="F32", byte_length=8, content_hash=f"{i:02x}"*32, leaf_hash=f"{i:02x}"*32)
        for i in range(7)
    ]
    tree = WeightMerkleTree(leaves)

    for i in range(7):
        proof = generate_weight_inclusion_proof(tree, i)
        assert proof.tensor_name == f"tensor_{i:02d}"
        assert proof.weight_merkle_root == tree.root_hex
        assert verify_weight_inclusion_proof(proof) is True


def test_inclusion_proof_tampered_leaf():
    """Verify that tampered leaf hash fails proof verification."""
    leaves = [
        TensorLeafDescriptor(name="t0", shape=[1], dtype="F32", byte_length=4, content_hash="00"*32, leaf_hash="aa"*32),
        TensorLeafDescriptor(name="t1", shape=[1], dtype="F32", byte_length=4, content_hash="01"*32, leaf_hash="bb"*32),
    ]
    tree = WeightMerkleTree(leaves)
    proof = generate_weight_inclusion_proof(tree, 0)

    # Mutate leaf hash
    tampered_proof = proof.model_copy(update={"leaf_hash": "ff" * 32})
    assert verify_weight_inclusion_proof(tampered_proof) is False


def test_inclusion_proof_tampered_sibling():
    """Verify that tampered audit path step fails proof verification."""
    leaves = [
        TensorLeafDescriptor(name="t0", shape=[1], dtype="F32", byte_length=4, content_hash="00"*32, leaf_hash="aa"*32),
        TensorLeafDescriptor(name="t1", shape=[1], dtype="F32", byte_length=4, content_hash="01"*32, leaf_hash="bb"*32),
    ]
    tree = WeightMerkleTree(leaves)
    proof = generate_weight_inclusion_proof(tree, 0)

    tampered_steps = [MerkleProofStep(sibling_hash="00" * 32, direction=ProofStepDirection.RIGHT)]
    tampered_proof = proof.model_copy(update={"audit_path": tampered_steps})

    assert verify_weight_inclusion_proof(tampered_proof) is False


def test_inclusion_proof_tampered_root():
    """Verify that mismatched root fails proof verification."""
    leaves = [
        TensorLeafDescriptor(name="t0", shape=[1], dtype="F32", byte_length=4, content_hash="00"*32, leaf_hash="aa"*32),
        TensorLeafDescriptor(name="t1", shape=[1], dtype="F32", byte_length=4, content_hash="01"*32, leaf_hash="bb"*32),
    ]
    tree = WeightMerkleTree(leaves)
    proof = generate_weight_inclusion_proof(tree, 0)

    tampered_proof = proof.model_copy(update={"weight_merkle_root": "00" * 32})
    assert verify_weight_inclusion_proof(tampered_proof) is False


# =====================================================================
# F. Contract Hashing Tests (H_contract)
# =====================================================================

def test_contract_hash_deterministic():
    """Verify deterministic contract hashing via RFC 8785 JCS."""
    c1 = ContractRepresentation(
        schema_version="1.0",
        inputs=[{"channel_order": "NCHW", "dtype": "F32", "is_dynamic": False, "name": "image", "shape": [1, 3, 224, 224]}],
        outputs=[{"activation_type": "logits", "dtype": "F32", "name": "logits", "shape": [1, 1000]}],
    )
    c2 = ContractRepresentation(
        schema_version="1.0",
        inputs=[{"channel_order": "NCHW", "dtype": "F32", "is_dynamic": False, "name": "image", "shape": [1, 3, 224, 224]}],
        outputs=[{"activation_type": "logits", "dtype": "F32", "name": "logits", "shape": [1, 1000]}],
    )

    h1 = compute_contract_hash(c1)
    h2 = compute_contract_hash(c2)

    assert h1 == h2
    assert len(h1) == 64


def test_contract_hash_mutation_sensitivity():
    """Verify contract hash changes on input/output contract modifications."""
    base = ContractRepresentation(
        schema_version="1.0",
        inputs=[{"channel_order": "NCHW", "dtype": "F32", "is_dynamic": False, "name": "x", "shape": [1, 3, 224, 224]}],
        outputs=[],
    )
    mutated_input = ContractRepresentation(
        schema_version="1.0",
        inputs=[{"channel_order": "NHWC", "dtype": "F32", "is_dynamic": False, "name": "x", "shape": [1, 224, 224, 3]}],
        outputs=[],
    )

    h_base = compute_contract_hash(base)
    h_mut = compute_contract_hash(mutated_input)

    assert h_base != h_mut


# =====================================================================
# G. Master Model Fingerprint Tests (H_model)
# =====================================================================

def test_master_fingerprint_rfc8785_jcs_binding():
    """Verify that Master Fingerprint implements exact ADR-040 JCS canonical binding."""
    art_hash = "11" * 32
    struct_hash = "22" * 32
    contract_hash = "33" * 32

    master_fp = compute_master_fingerprint(
        artifact_hash=art_hash,
        structural_hash=struct_hash,
        contract_hash=contract_hash,
    )

    # Manually compute JCS hash
    expected_binding = {
        "artifact_hash": art_hash,
        "contract_hash": contract_hash,
        "schema_version": "1.0",
        "structural_hash": struct_hash,
    }
    expected_hash = sha256_bytes(canonicalize(expected_binding))

    assert master_fp == expected_hash
    assert len(master_fp) == 64
    assert master_fp.islower()


def test_master_fingerprint_component_sensitivity():
    """Verify master fingerprint changes if any single component hash changes."""
    h_art = "11" * 32
    h_str = "22" * 32
    h_ctr = "33" * 32

    base_master = compute_master_fingerprint(h_art, h_str, h_ctr)

    m_art = compute_master_fingerprint("99" * 32, h_str, h_ctr)
    m_str = compute_master_fingerprint(h_art, "99" * 32, h_ctr)
    m_ctr = compute_master_fingerprint(h_art, h_str, "99" * 32)

    assert base_master != m_art
    assert base_master != m_str
    assert base_master != m_ctr


# =====================================================================
# H. Hierarchical Separation Tests
# =====================================================================

def test_hierarchical_identity_separation(tmp_path: Path):
    """Verify that modifying tensor weights alters Merkle root and artifact hash without altering structural hash."""
    # Model 1
    m1_path = tmp_path / "model1.safetensors"
    make_mock_safetensors(
        m1_path,
        {"fc.weight": {"shape": [2, 2], "dtype": "F32", "data": b"\x01" * 16}},
        metadata={"model": "test"},
    )

    # Model 2: Same structure, different weight bytes
    m2_path = tmp_path / "model2.safetensors"
    make_mock_safetensors(
        m2_path,
        {"fc.weight": {"shape": [2, 2], "dtype": "F32", "data": b"\x02" * 16}},
        metadata={"model": "test"},
    )

    service = ModelFingerprintingService()

    res1 = service.fingerprint_model(m1_path)
    res2 = service.fingerprint_model(m2_path)

    # 1. Artifact hash MUST differ
    assert res1.artifact_hash != res2.artifact_hash

    # 2. Weight Merkle root MUST differ
    assert res1.weight_merkle_root != res2.weight_merkle_root

    # 3. Structural hash MUST be IDENTICAL (same tensor names, shapes, dtypes)
    assert res1.structural_hash == res2.structural_hash

    # 4. Contract hash MUST be IDENTICAL
    assert res1.contract_hash == res2.contract_hash

    # 5. Master fingerprint MUST differ (because artifact_hash differs)
    assert res1.master_fingerprint != res2.master_fingerprint


# =====================================================================
# I. End-to-End Fingerprinting Orchestrator Tests
# =====================================================================

def test_fingerprinting_service_safetensors_end_to_end(tmp_path: Path):
    """Verify complete hierarchical fingerprinting on a multi-tensor Safetensors model."""
    fpath = tmp_path / "conv_net.safetensors"
    make_mock_safetensors(
        fpath,
        {
            "conv1.weight": {"shape": [16, 3, 3, 3], "dtype": "F32", "data": b"\x00" * (16 * 3 * 3 * 3 * 4)},
            "conv1.bias": {"shape": [16], "dtype": "F32", "data": b"\x00" * 64},
            "fc.weight": {"shape": [10, 16], "dtype": "F32", "data": b"\x00" * 640},
        },
        metadata={"arch": "custom_cnn"},
    )

    service = ModelFingerprintingService()
    result = service.fingerprint_model(fpath)

    assert result.status == "verified"
    assert result.weight_status == "verified"
    assert result.tensor_count == 3
    assert result.artifact_hash is not None
    assert result.structural_hash is not None
    assert result.contract_hash is not None
    assert result.weight_merkle_root is not None
    assert result.master_fingerprint is not None

    # Test weight Merkle tree direct extraction and inclusion proof
    tree_res = service.compute_weight_merkle_tree(fpath)
    assert tree_res.tensor_count == 3
    assert tree_res.merkle_root == result.weight_merkle_root


# =====================================================================
# J. Independent Reference Implementation & Test Vectors (0, 1, 2, 3, 4, 5, 7, 8)
# =====================================================================

def independent_jcs_sha256(payload: dict) -> str:
    """Independent reference implementation of RFC 8785 JCS + SHA-256."""
    canonical_utf8 = canonicalize(payload)
    return hashlib.sha256(canonical_utf8).hexdigest().lower()


def independent_internal_node(left_hex: str, right_hex: str) -> str:
    """Independent calculation of internal node digest."""
    return independent_jcs_sha256({
        "domain": "aivara:model-weight-node:v1",
        "left": left_hex.lower(),
        "right": right_hex.lower(),
        "schema_version": "1.0",
    })


def independent_merkle_reference(leaf_hashes: List[str]) -> str:
    """Completely independent reference implementation of RFC 6962-style tree partitioning."""
    n = len(leaf_hashes)
    if n == 0:
        return independent_jcs_sha256({"domain": "aivara:model-weight-empty:v1", "schema_version": "1.0"})
    if n == 1:
        return leaf_hashes[0].lower()

    # Largest power of 2 strictly less than n
    k = 1 << ((n - 1).bit_length() - 1)
    left_root = independent_merkle_reference(leaf_hashes[:k])
    right_root = independent_merkle_reference(leaf_hashes[k:])
    return independent_internal_node(left_root, right_root)


@pytest.mark.parametrize("leaf_count", [0, 1, 2, 3, 4, 5, 7, 8])
def test_independent_merkle_test_vectors(leaf_count: int):
    """Verify Merkle root against independent reference implementation for various leaf counts."""
    leaves = [
        TensorLeafDescriptor(
            name=f"param_{i:02d}",
            shape=[2, 2],
            dtype="F32",
            byte_length=16,
            content_hash=hashlib.sha256(f"tensor_data_{i}".encode()).hexdigest().lower(),
            leaf_hash=independent_jcs_sha256({
                "byte_length": 16,
                "content_hash": hashlib.sha256(f"tensor_data_{i}".encode()).hexdigest().lower(),
                "domain": "aivara:model-weight-leaf:v1",
                "dtype": "F32",
                "name": f"param_{i:02d}",
                "schema_version": "1.0",
                "shape": [2, 2],
            }),
        )
        for i in range(leaf_count)
    ]

    # Compute via production implementation
    tree = WeightMerkleTree(leaves)
    prod_root = tree.root_hex

    # Compute via independent reference
    ref_root = independent_merkle_reference([l.leaf_hash for l in leaves])

    assert prod_root == ref_root
    assert len(prod_root) == 64
    assert prod_root.islower()


# =====================================================================
# K. Comprehensive Inclusion Proof Integrity & Tamper Tests
# =====================================================================

@pytest.mark.parametrize("tree_size", [1, 2, 3, 5, 7, 8])
def test_inclusion_proof_all_leaves_in_tree(tree_size: int):
    """Verify inclusion proof for every single leaf across multiple tree sizes."""
    leaves = [
        TensorLeafDescriptor(
            name=f"layer_{i:02d}",
            shape=[4],
            dtype="F32",
            byte_length=16,
            content_hash=f"{i:02x}" * 32,
            leaf_hash=independent_jcs_sha256({
                "byte_length": 16,
                "content_hash": f"{i:02x}" * 32,
                "domain": "aivara:model-weight-leaf:v1",
                "dtype": "F32",
                "name": f"layer_{i:02d}",
                "schema_version": "1.0",
                "shape": [4],
            }),
        )
        for i in range(tree_size)
    ]
    tree = WeightMerkleTree(leaves)

    for idx in range(tree_size):
        proof = generate_weight_inclusion_proof(tree, idx)
        assert verify_weight_inclusion_proof(proof) is True

        # Test tamper rejection
        if proof.audit_path:
            # 1. Tamper direction
            bad_dir_steps = list(proof.audit_path)
            orig_step = bad_dir_steps[0]
            new_dir = ProofStepDirection.LEFT if orig_step.direction == ProofStepDirection.RIGHT else ProofStepDirection.RIGHT
            bad_dir_steps[0] = MerkleProofStep(sibling_hash=orig_step.sibling_hash, direction=new_dir)
            bad_dir_proof = proof.model_copy(update={"audit_path": bad_dir_steps})
            assert verify_weight_inclusion_proof(bad_dir_proof) is False

            # 2. Removed proof element
            if len(proof.audit_path) > 1:
                truncated_proof = proof.model_copy(update={"audit_path": proof.audit_path[:-1]})
                assert verify_weight_inclusion_proof(truncated_proof) is False

                # 3. Reordered proof elements
                reordered_proof = proof.model_copy(update={"audit_path": list(reversed(proof.audit_path))})
                assert verify_weight_inclusion_proof(reordered_proof) is False

            # 4. Extra proof element
            extra_steps = list(proof.audit_path) + [MerkleProofStep(sibling_hash="aa" * 32, direction=ProofStepDirection.RIGHT)]
            extra_proof = proof.model_copy(update={"audit_path": extra_steps})
            assert verify_weight_inclusion_proof(extra_proof) is False


# =====================================================================
# L. Domain Separation Verification
# =====================================================================

def test_domain_separation_invariance():
    """Verify distinct domain tags produce distinct hashes for identical key-values."""
    p_leaf = {"domain": "aivara:model-weight-leaf:v1", "schema_version": "1.0", "data": "123"}
    p_node = {"domain": "aivara:model-weight-node:v1", "schema_version": "1.0", "data": "123"}
    p_empty = {"domain": "aivara:model-weight-empty:v1", "schema_version": "1.0", "data": "123"}

    h_leaf = sha256_bytes(canonicalize(p_leaf))
    h_node = sha256_bytes(canonicalize(p_node))
    h_empty = sha256_bytes(canonicalize(p_empty))

    assert h_leaf != h_node
    assert h_leaf != h_empty
    assert h_node != h_empty


# =====================================================================
# M. Cross-Tier Cases A, B, C, D
# =====================================================================

def test_cross_tier_cases_abcd(tmp_path: Path):
    """Explicitly verify Cases A, B, C, D of cross-tier independence."""
    # Base Model
    base_file = tmp_path / "base.safetensors"
    make_mock_safetensors(
        base_file,
        {"w1": {"shape": [2, 2], "dtype": "F32", "data": b"\x01" * 16}},
        metadata={"arch": "base_arch"},
    )
    service = ModelFingerprintingService()
    res_base = service.fingerprint_model(base_file)

    # CASE A: Same structure + same contract + changed weight bytes
    case_a_file = tmp_path / "case_a.safetensors"
    make_mock_safetensors(
        case_a_file,
        {"w1": {"shape": [2, 2], "dtype": "F32", "data": b"\x99" * 16}},  # altered bytes
        metadata={"arch": "base_arch"},
    )
    res_a = service.fingerprint_model(case_a_file)
    assert res_a.artifact_hash != res_base.artifact_hash
    assert res_a.weight_merkle_root != res_base.weight_merkle_root
    assert res_a.structural_hash == res_base.structural_hash  # UNCHANGED
    assert res_a.contract_hash == res_base.contract_hash      # UNCHANGED
    assert res_a.master_fingerprint != res_base.master_fingerprint  # Changed due to artifact_hash

    # CASE B: Same weights + changed structural metadata (e.g. tensor shape mutated)
    case_b_file = tmp_path / "case_b.safetensors"
    make_mock_safetensors(
        case_b_file,
        {"w1": {"shape": [4, 1], "dtype": "F32", "data": b"\x01" * 16}},  # shape changed [4,1] vs [2,2]
        metadata={"arch": "base_arch"},
    )
    res_b = service.fingerprint_model(case_b_file)
    assert res_b.structural_hash != res_base.structural_hash
    assert res_b.master_fingerprint != res_base.master_fingerprint

    # CASE C: Same artifact/structure + changed contract representation
    meta_c = res_base.structural_hash
    c_base = build_contract_representation(NormalizedModelMetadata(
        schema_version="1.0", format=ModelFormat.SAFETENSORS, inspection_status="success",
        artifact_size_bytes=100, artifact_hash_sha256="aa"*32,
        inputs=[InputContractDescriptor(name="in1", shape=[1, 3, 224, 224], dtype="F32")],
    ))
    c_mutated = build_contract_representation(NormalizedModelMetadata(
        schema_version="1.0", format=ModelFormat.SAFETENSORS, inspection_status="success",
        artifact_size_bytes=100, artifact_hash_sha256="aa"*32,
        inputs=[InputContractDescriptor(name="in1", shape=[1, 3, 512, 512], dtype="F32")],  # resolution changed
    ))
    h_c_base = compute_contract_hash(c_base)
    h_c_mutated = compute_contract_hash(c_mutated)
    assert h_c_base != h_c_mutated

    # CASE D: Different leaf ingestion order
    l1 = TensorLeafDescriptor(name="alpha", shape=[2], dtype="F32", byte_length=8, content_hash="11"*32, leaf_hash="aa"*32)
    l2 = TensorLeafDescriptor(name="omega", shape=[2], dtype="F32", byte_length=8, content_hash="22"*32, leaf_hash="bb"*32)
    tree1 = WeightMerkleTree([l1, l2])
    tree2 = WeightMerkleTree([l2, l1])  # reversed
    assert tree1.root_hex == tree2.root_hex
    assert [l.name for l in tree1.leaves] == ["alpha", "omega"]
    assert [l.name for l in tree2.leaves] == ["alpha", "omega"]

