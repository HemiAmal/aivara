"""Comprehensive unit and integration tests for Reference Model Comparison & Drift Attribution (Phase 7.5).

Tests multi-tier comparison, 8-state drift classification, tensor-level attribution,
structural diffing, contract diffing, reference trust boundary resolution, and semantic safety invariants.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import List

import pytest

from aivara.model_integrity.comparison import (
    ArtifactComparisonStatus,
    ComparisonStatus,
    ContractComparisonStatus,
    DriftClassification,
    ModelComparisonResult,
    ModelComparisonService,
    StructuralComparisonStatus,
    TensorChangeType,
    WeightComparisonStatus,
    attribute_tensor_changes,
    classify_drift,
    compare_artifact_hashes,
    compare_contract_hashes,
    compare_master_fingerprints,
    compare_structural_hashes,
    compare_weight_roots,
    determine_comparison_status,
    diff_contract_metadata,
    diff_structural_metadata,
)
from aivara.model_integrity.contract_verification.schemas import (
    ContractCompleteness,
    ContractStatus,
    ContractVerificationResult,
    PreprocessingDeclaration,
    PreprocessingSource,
    ValidatedInputContract,
    ValidatedOutputContract,
)
from aivara.model_integrity.fingerprinting.master import compute_master_fingerprint
from aivara.model_integrity.fingerprinting.schemas import (
    ContractRepresentation,
    HierarchicalFingerprintResult,
    TensorLeafDescriptor,
)
from aivara.model_integrity.schemas import (
    InputContractDescriptor,
    InspectionStatus,
    ModelFormat,
    NormalizedModelMetadata,
    OperatorDescriptor,
    OutputContractDescriptor,
    ReasonCode,
    TensorDescriptor,
)


def _make_dummy_fingerprints(
    art_hash: str = "1111111111111111111111111111111111111111111111111111111111111111",
    struct_hash: str = "2222222222222222222222222222222222222222222222222222222222222222",
    weight_root: str | None = "3333333333333333333333333333333333333333333333333333333333333333",
    contract_hash: str = "4444444444444444444444444444444444444444444444444444444444444444",
) -> HierarchicalFingerprintResult:
    """Construct a clean HierarchicalFingerprintResult."""
    master_fp = compute_master_fingerprint(
        artifact_hash=art_hash,
        structural_hash=struct_hash,
        contract_hash=contract_hash,
    )
    return HierarchicalFingerprintResult(
        schema_version="1.0",
        status="verified",
        artifact_hash=art_hash,
        structural_hash=struct_hash,
        contract_hash=contract_hash,
        weight_merkle_root=weight_root,
        master_fingerprint=master_fp,
        weight_status="verified" if weight_root else "unavailable",
    )


def _make_dummy_leaf(
    name: str,
    shape: List[int],
    dtype: str = "F32",
    content_hex: str = "aaaa0000aaaa0000aaaa0000aaaa0000aaaa0000aaaa0000aaaa0000aaaa0000",
) -> TensorLeafDescriptor:
    """Construct a TensorLeafDescriptor fixture."""
    return TensorLeafDescriptor(
        name=name,
        shape=shape,
        dtype=dtype,
        byte_length=100,
        content_hash=content_hex,
        leaf_hash="ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000",
    )


# ============================================================
# 1. EXACT MATCH & ARTIFACT COMPARISON TESTS
# ============================================================

def test_exact_integrity_match():
    """Verify identical reference and candidate yield EXACT_INTEGRITY_MATCH."""
    fp_ref = _make_dummy_fingerprints()
    fp_cand = _make_dummy_fingerprints()

    service = ModelComparisonService()
    res = service.compare_models(fp_ref, fp_cand)

    assert res.drift_classification == DriftClassification.EXACT_INTEGRITY_MATCH
    assert res.is_exact_artifact_match is True
    assert res.is_exact_master_match is True
    assert res.artifact_status == ArtifactComparisonStatus.ARTIFACT_MATCH
    assert res.structural_status == StructuralComparisonStatus.STRUCTURE_MATCH
    assert res.weight_status == WeightComparisonStatus.WEIGHT_MERKLE_MATCH
    assert res.contract_status == ContractComparisonStatus.CONTRACT_MATCH
    assert res.comparison_status == ComparisonStatus.COMPARABLE


def test_artifact_only_difference():
    """Verify different artifact hash but identical higher-level identities."""
    fp_ref = _make_dummy_fingerprints(art_hash="1111111111111111111111111111111111111111111111111111111111111111")
    fp_cand = _make_dummy_fingerprints(art_hash="9999999999999999999999999999999999999999999999999999999999999999")

    service = ModelComparisonService()
    res = service.compare_models(fp_ref, fp_cand)

    assert res.drift_classification == DriftClassification.EXACT_INTEGRITY_MATCH
    assert res.is_exact_artifact_match is False
    assert res.is_exact_master_match is False
    assert res.artifact_status == ArtifactComparisonStatus.ARTIFACT_DIFFERENT


# ============================================================
# 2. EIGHT-STATE DRIFT MATRIX TESTS
# ============================================================

def test_weight_only_drift():
    """Verify same structure and contract but different weights."""
    fp_ref = _make_dummy_fingerprints(weight_root="3333333333333333333333333333333333333333333333333333333333333333")
    fp_cand = _make_dummy_fingerprints(weight_root="7777777777777777777777777777777777777777777777777777777777777777")

    service = ModelComparisonService()
    res = service.compare_models(fp_ref, fp_cand)

    assert res.drift_classification == DriftClassification.WEIGHT_ONLY_DRIFT
    assert res.weight_status == WeightComparisonStatus.WEIGHT_DRIFT
    assert res.structural_status == StructuralComparisonStatus.STRUCTURE_MATCH
    assert res.contract_status == ContractComparisonStatus.CONTRACT_MATCH


def test_structural_only_drift():
    """Verify different structure with identical weight and contract identities."""
    fp_ref = _make_dummy_fingerprints(struct_hash="2222222222222222222222222222222222222222222222222222222222222222")
    fp_cand = _make_dummy_fingerprints(struct_hash="8888888888888888888888888888888888888888888888888888888888888888")

    service = ModelComparisonService()
    res = service.compare_models(fp_ref, fp_cand)

    assert res.drift_classification == DriftClassification.STRUCTURAL_ONLY_DRIFT
    assert res.structural_status == StructuralComparisonStatus.STRUCTURAL_DRIFT


def test_contract_only_drift():
    """Verify different contract with identical structure and weights."""
    fp_ref = _make_dummy_fingerprints(contract_hash="4444444444444444444444444444444444444444444444444444444444444444")
    fp_cand = _make_dummy_fingerprints(contract_hash="5555555555555555555555555555555555555555555555555555555555555555")

    service = ModelComparisonService()
    res = service.compare_models(fp_ref, fp_cand)

    assert res.drift_classification == DriftClassification.CONTRACT_ONLY_DRIFT
    assert res.contract_status == ContractComparisonStatus.CONTRACT_DRIFT


def test_combined_drift_states():
    """Verify all dual and triple drift states."""
    service = ModelComparisonService()

    # Structure + Weight
    r_sw = _make_dummy_fingerprints(struct_hash="1111" * 16, weight_root="2222" * 16, contract_hash="3333" * 16)
    c_sw = _make_dummy_fingerprints(struct_hash="aaaa" * 16, weight_root="bbbb" * 16, contract_hash="3333" * 16)
    res_sw = service.compare_models(r_sw, c_sw)
    assert res_sw.drift_classification == DriftClassification.STRUCTURAL_AND_WEIGHT_DRIFT

    # Structure + Contract
    r_sc = _make_dummy_fingerprints(struct_hash="1111" * 16, weight_root="2222" * 16, contract_hash="3333" * 16)
    c_sc = _make_dummy_fingerprints(struct_hash="aaaa" * 16, weight_root="2222" * 16, contract_hash="cccc" * 16)
    res_sc = service.compare_models(r_sc, c_sc)
    assert res_sc.drift_classification == DriftClassification.STRUCTURAL_AND_CONTRACT_DRIFT

    # Weight + Contract
    r_wc = _make_dummy_fingerprints(struct_hash="1111" * 16, weight_root="2222" * 16, contract_hash="3333" * 16)
    c_wc = _make_dummy_fingerprints(struct_hash="1111" * 16, weight_root="bbbb" * 16, contract_hash="cccc" * 16)
    res_wc = service.compare_models(r_wc, c_wc)
    assert res_wc.drift_classification == DriftClassification.WEIGHT_AND_CONTRACT_DRIFT

    # Structure + Weight + Contract
    r_all = _make_dummy_fingerprints(struct_hash="1111" * 16, weight_root="2222" * 16, contract_hash="3333" * 16)
    c_all = _make_dummy_fingerprints(struct_hash="aaaa" * 16, weight_root="bbbb" * 16, contract_hash="cccc" * 16)
    res_all = service.compare_models(r_all, c_all)
    assert res_all.drift_classification == DriftClassification.STRUCTURAL_WEIGHT_CONTRACT_DRIFT


# ============================================================
# 3. TENSOR-LEVEL ATTRIBUTION TESTS
# ============================================================

def test_tensor_attribution_granular_categories():
    """Verify accurate categorization of unchanged, added, removed, content_changed, and metadata_changed tensors."""
    leaf_unchanged = _make_dummy_leaf("t_same", [10, 10], "F32", "1" * 64)
    leaf_content_mod_ref = _make_dummy_leaf("t_content_mod", [10, 10], "F32", "2" * 64)
    leaf_content_mod_cand = _make_dummy_leaf("t_content_mod", [10, 10], "F32", "3" * 64)
    leaf_meta_mod_ref = _make_dummy_leaf("t_meta_mod", [10, 10], "F32", "4" * 64)
    leaf_meta_mod_cand = _make_dummy_leaf("t_meta_mod", [20, 20], "F32", "4" * 64)
    leaf_both_mod_ref = _make_dummy_leaf("t_both_mod", [10, 10], "F32", "5" * 64)
    leaf_both_mod_cand = _make_dummy_leaf("t_both_mod", [10, 10], "F16", "6" * 64)
    leaf_removed = _make_dummy_leaf("t_removed", [5], "I64", "7" * 64)
    leaf_added = _make_dummy_leaf("t_added", [5], "I64", "8" * 64)

    ref_leaves = [leaf_unchanged, leaf_content_mod_ref, leaf_meta_mod_ref, leaf_both_mod_ref, leaf_removed]
    cand_leaves = [leaf_unchanged, leaf_content_mod_cand, leaf_meta_mod_cand, leaf_both_mod_cand, leaf_added]

    records, summary = attribute_tensor_changes(ref_leaves, cand_leaves)

    rec_map = {r.tensor_name: r.change_type for r in records}

    assert rec_map["t_same"] == TensorChangeType.UNCHANGED
    assert rec_map["t_content_mod"] == TensorChangeType.CONTENT_CHANGED
    assert rec_map["t_meta_mod"] == TensorChangeType.METADATA_CHANGED
    assert rec_map["t_both_mod"] == TensorChangeType.CONTENT_AND_METADATA_CHANGED
    assert rec_map["t_removed"] == TensorChangeType.REMOVED
    assert rec_map["t_added"] == TensorChangeType.ADDED

    assert summary["unchanged"] == 1
    assert summary["content_changed"] == 1
    assert summary["metadata_changed"] == 1
    assert summary["content_and_metadata_changed"] == 1
    assert summary["removed"] == 1
    assert summary["added"] == 1


# ============================================================
# 4. STRUCTURAL & CONTRACT DIFFING TESTS
# ============================================================

def test_structural_diffing_operators_and_counts():
    """Verify detailed field diffing for operators and parameter counts."""
    meta_ref = NormalizedModelMetadata(
        schema_version="1.0",
        format=ModelFormat.ONNX,
        inspection_status=InspectionStatus.SUCCESS,
        artifact_size_bytes=1000,
        artifact_hash_sha256="1" * 64,
        tensor_count=2,
        parameter_count=200,
        inputs=[],
        outputs=[],
        operators=[OperatorDescriptor(op_type="Conv", count=5, domain="ai.onnx")],
        tensors=[TensorDescriptor(name="w1", shape=[10, 10], dtype="F32", element_count=100, byte_size=400)],
        metadata_props={},
        warnings=[],
        reason_codes=[],
    )
    meta_cand = NormalizedModelMetadata(
        schema_version="1.0",
        format=ModelFormat.ONNX,
        inspection_status=InspectionStatus.SUCCESS,
        artifact_size_bytes=1200,
        artifact_hash_sha256="2" * 64,
        tensor_count=3,
        parameter_count=300,
        inputs=[],
        outputs=[],
        operators=[OperatorDescriptor(op_type="Conv", count=6, domain="ai.onnx")],
        tensors=[
            TensorDescriptor(name="w1", shape=[10, 10], dtype="F32", element_count=100, byte_size=400),
            TensorDescriptor(name="w2", shape=[10, 10], dtype="F32", element_count=100, byte_size=400),
        ],
        metadata_props={},
        warnings=[],
        reason_codes=[],
    )

    diffs = diff_structural_metadata(meta_ref, meta_cand)
    diff_codes = {d.reason_code for d in diffs}

    assert "TENSOR_COUNT_MISMATCH" in diff_codes
    assert "PARAMETER_COUNT_MISMATCH" in diff_codes
    assert "OPERATOR_COUNT_MISMATCH" in diff_codes
    assert "ADDED_TENSOR_DETECTED" in diff_codes


def test_contract_diffing_inputs_outputs():
    """Verify detailed field diffing for I/O contracts."""
    c_ref = ContractVerificationResult(
        schema_version="1.0",
        status=ContractStatus.VERIFIED,
        completeness=ContractCompleteness.COMPLETE,
        inputs=[ValidatedInputContract(name="in1", index=0, dtype="F32", rank=4, shape=[1, 3, 224, 224])],
        outputs=[ValidatedOutputContract(name="out1", index=0, dtype="F32", rank=2, shape=[1, 1000])],
        preprocessing=None,
        findings=[],
        contract_representation=ContractRepresentation(schema_version="1.0", inputs=[], outputs=[]),
        contract_hash="1" * 64,
        warnings=[],
    )
    c_cand = ContractVerificationResult(
        schema_version="1.0",
        status=ContractStatus.VERIFIED,
        completeness=ContractCompleteness.COMPLETE,
        inputs=[ValidatedInputContract(name="in1", index=0, dtype="F32", rank=4, shape=[1, 3, 256, 256])],
        outputs=[ValidatedOutputContract(name="out1", index=0, dtype="F32", rank=2, shape=[1, 500])],
        preprocessing=None,
        findings=[],
        contract_representation=ContractRepresentation(schema_version="1.0", inputs=[], outputs=[]),
        contract_hash="2" * 64,
        warnings=[],
    )

    diffs = diff_contract_metadata(c_ref, c_cand)
    diff_codes = {d.reason_code for d in diffs}

    assert "INPUT_SHAPE_MUTATION" in diff_codes
    assert "OUTPUT_SHAPE_MUTATION" in diff_codes


# ============================================================
# 5. REFERENCE TRUST & AVAILABILITY SEMANTICS
# ============================================================

def test_reference_trust_boundaries():
    """Verify comparison status respects invalid and unverifiable reference boundaries."""
    fp_ref = _make_dummy_fingerprints()
    fp_cand = _make_dummy_fingerprints()
    service = ModelComparisonService()

    # Unverifiable reference
    res_unverif = service.compare_models(fp_ref, fp_cand, reference_trust="UNVERIFIABLE")
    assert res_unverif.comparison_status == ComparisonStatus.REFERENCE_UNVERIFIABLE

    # Invalid reference
    res_invalid = service.compare_models(fp_ref, fp_cand, reference_trust="INVALID")
    assert res_invalid.comparison_status == ComparisonStatus.INVALID_REFERENCE

    # Invalid candidate
    res_cand_inv = service.compare_models(fp_ref, fp_cand, candidate_trust="INVALID")
    assert res_cand_inv.comparison_status == ComparisonStatus.INVALID_CANDIDATE


def test_availability_semantics_not_collapsed_to_match():
    """Verify unavailable identities return UNAVAILABLE rather than matching."""
    fp_ref = _make_dummy_fingerprints(weight_root=None)
    fp_cand = _make_dummy_fingerprints(weight_root="3" * 64)

    service = ModelComparisonService()
    res = service.compare_models(fp_ref, fp_cand)

    assert res.weight_status == WeightComparisonStatus.WEIGHT_COMPARISON_UNAVAILABLE
    assert res.comparison_status == ComparisonStatus.PARTIALLY_COMPARABLE


# ============================================================
# 6. DETERMINISM & SEMANTIC SAFETY TESTS
# ============================================================

def test_comparison_determinism():
    """Verify repeated comparison runs produce bit-for-bit identical outputs."""
    fp_ref = _make_dummy_fingerprints()
    fp_cand = _make_dummy_fingerprints(struct_hash="9999" * 16)

    service = ModelComparisonService()
    res1 = service.compare_models(fp_ref, fp_cand)
    res2 = service.compare_models(fp_ref, fp_cand)

    assert res1.model_dump() == res2.model_dump()


def test_semantic_safety_zero_prohibited_terms():
    """Verify reason codes, statuses, and diff records strictly contain zero prohibited human intent terms."""
    fp_ref = _make_dummy_fingerprints()
    fp_cand = _make_dummy_fingerprints(
        art_hash="aaaa" * 16,
        struct_hash="bbbb" * 16,
        weight_root="cccc" * 16,
        contract_hash="dddd" * 16,
    )
    service = ModelComparisonService()
    res = service.compare_models(fp_ref, fp_cand)

    prohibited = ["malicious", "maliciously", "collusion", "culpable", "intentional", "attacker", "compromised"]
    serialized = json.dumps(res.model_dump())

    for word in prohibited:
        assert word not in serialized.lower(), f"Prohibited semantic word '{word}' found in comparison output"


def test_uncomparable_status():
    """Verify UNCOMPARABLE status when all identities are unavailable."""
    fp_ref = {
        "artifact_hash": None,
        "structural_hash": None,
        "weight_merkle_root": None,
        "contract_hash": None,
        "master_fingerprint": None,
    }
    fp_cand = {
        "artifact_hash": None,
        "structural_hash": None,
        "weight_merkle_root": None,
        "contract_hash": None,
        "master_fingerprint": None,
    }
    service = ModelComparisonService()
    res = service.compare_models(fp_ref, fp_cand)

    assert res.comparison_status == ComparisonStatus.UNCOMPARABLE
    assert res.drift_classification == DriftClassification.DRIFT_UNAVAILABLE


def test_compare_artifacts_on_disk(tmp_path: Path):
    """Verify compare_artifacts runs safely on two files on disk."""
    f1 = tmp_path / "model1.safetensors"
    f2 = tmp_path / "model2.safetensors"

    header1 = json.dumps({"w1": {"dtype": "F32", "shape": [2, 2], "data_offsets": [0, 16]}}).encode("utf-8")
    payload1 = len(header1).to_bytes(8, "little") + header1 + b"\x00" * 16
    f1.write_bytes(payload1)

    header2 = json.dumps({"w1": {"dtype": "F32", "shape": [2, 2], "data_offsets": [0, 16]}}).encode("utf-8")
    payload2 = len(header2).to_bytes(8, "little") + header2 + b"\x01" * 16
    f2.write_bytes(payload2)

    service = ModelComparisonService()
    res = service.compare_artifacts(f1, f2)

    assert res.drift_classification == DriftClassification.WEIGHT_ONLY_DRIFT
    assert res.weight_status == WeightComparisonStatus.WEIGHT_DRIFT
    assert res.structural_status == StructuralComparisonStatus.STRUCTURE_MATCH

