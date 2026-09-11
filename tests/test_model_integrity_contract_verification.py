"""Comprehensive unit and integration tests for Model Contract & Preprocessing Verification (Phase 7.4).

Tests bounded shape validation, rank checking, dtype normalization, semantic ordering,
preprocessing consistency, static graph integrity cross-checks, completeness categories,
cryptographic contract hashing integration, and semantic safety invariants.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import List

import pytest

from aivara.model_integrity.contract_verification import (
    ContractCompleteness,
    ContractFindingCode,
    ContractStatus,
    FindingSeverity,
    ModelContractVerificationService,
    PreprocessingDeclaration,
    PreprocessingSource,
    ValidatedInputContract,
    ValidatedOutputContract,
    build_canonical_contract_representation,
    extract_preprocessing_from_metadata,
    inspect_input_contract,
    inspect_output_contract,
    normalize_dtype,
    normalize_shape_entry,
    validate_contract_integrity,
    validate_preprocessing_consistency,
)
from aivara.model_integrity.fingerprinting.contract import (
    build_contract_representation,
    compute_contract_hash,
)
from aivara.model_integrity.limits import ModelIngestionLimits
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


def _make_dummy_metadata(
    inputs: List[InputContractDescriptor] | None = None,
    outputs: List[OutputContractDescriptor] | None = None,
    tensors: List[TensorDescriptor] | None = None,
    metadata_props: dict | None = None,
    fmt: ModelFormat = ModelFormat.ONNX,
) -> NormalizedModelMetadata:
    """Helper to generate a clean NormalizedModelMetadata fixture."""
    return NormalizedModelMetadata(
        schema_version="1.0",
        format=fmt,
        inspection_status=InspectionStatus.SUCCESS,
        artifact_size_bytes=1024,
        artifact_hash_sha256="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        tensor_count=len(tensors or []),
        parameter_count=sum(t.element_count for t in (tensors or [])),
        inputs=inputs or [],
        outputs=outputs or [],
        operators=[OperatorDescriptor(op_type="Conv", count=1, domain="ai.onnx")],
        tensors=tensors or [],
        metadata_props=metadata_props or {},
        warnings=[],
        reason_codes=[ReasonCode.SAFE_INSPECTION_PASSED],
    )


# ============================================================
# 1. INPUT CONTRACT VALIDATION TESTS
# ============================================================

def test_input_contract_valid_fixed_shape():
    """Verify inspection of a standard valid 4D input contract."""
    raw = InputContractDescriptor(
        name="input_tensor",
        shape=[1, 3, 224, 224],
        dtype="float32",
        channel_order="NCHW",
        is_dynamic=False,
    )
    validated, findings = inspect_input_contract(raw, index=0)

    assert validated.name == "input_tensor"
    assert validated.index == 0
    assert validated.dtype == "F32"
    assert validated.rank == 4
    assert validated.shape == [1, 3, 224, 224]
    assert validated.layout == "NCHW"
    assert validated.channel_count == 3
    assert not validated.is_dynamic
    assert len(findings) == 0


def test_input_contract_dynamic_and_symbolic_shape():
    """Verify inspection of dynamic and symbolic dimensions."""
    raw = InputContractDescriptor(
        name="images",
        shape=[None, 3, None, None],
        dtype="tensor(float16)",
        channel_order="NCHW",
        is_dynamic=True,
    )
    validated, findings = inspect_input_contract(raw, index=0)

    assert validated.dtype == "F16"
    assert validated.is_dynamic is True
    assert validated.dynamic_dimensions == [0, 2, 3]
    assert validated.channel_count == 3
    assert len(findings) == 0


def test_input_contract_invalid_dimensions():
    """Verify detection of invalid negative dimensions."""
    raw = InputContractDescriptor(
        name="bad_input",
        shape=[1, -5, 224, 224],
        dtype="float32",
        channel_order="NCHW",
        is_dynamic=False,
    )
    validated, findings = inspect_input_contract(raw, index=0)

    assert any(f.code == ContractFindingCode.INVALID_DIMENSION for f in findings)


def test_input_contract_rank_exceeded():
    """Verify rejection when tensor rank exceeds safety bounds."""
    limits = ModelIngestionLimits(max_tensor_dimensions=4)
    raw = InputContractDescriptor(
        name="high_rank",
        shape=[1, 2, 3, 4, 5],
        dtype="float32",
    )
    validated, findings = inspect_input_contract(raw, index=0, limits=limits)

    assert any(f.code == ContractFindingCode.RANK_MISMATCH for f in findings)


def test_input_contract_dtype_normalization():
    """Verify comprehensive dtype alias mapping."""
    test_cases = [
        ("float32", "F32", True),
        ("tensor(int64)", "I64", True),
        ("torch.float16", "F16", True),
        ("uint8", "U8", True),
        ("bfloat16", "BF16", True),
        ("bool", "BOOL", True),
        ("custom_unsupported_type", "CUSTOM_UNSUPPORTED_TYPE", False),
    ]
    for raw_dt, expected_canon, expected_recog in test_cases:
        canon, recog = normalize_dtype(raw_dt)
        assert canon == expected_canon
        assert recog == expected_recog


# ============================================================
# 2. OUTPUT CONTRACT VALIDATION TESTS
# ============================================================

def test_output_contract_valid():
    """Verify output contract extraction and activation capture."""
    raw = OutputContractDescriptor(
        name="probabilities",
        shape=[1, 1000],
        dtype="float32",
        activation_type="softmax",
    )
    validated, findings = inspect_output_contract(raw, index=0)

    assert validated.name == "probabilities"
    assert validated.dtype == "F32"
    assert validated.rank == 2
    assert validated.shape == [1, 1000]
    assert validated.activation_type == "softmax"
    assert "probabilities" in validated.semantic_descriptors
    assert len(findings) == 0


def test_output_contract_malformed_name_and_dim():
    """Verify handling of empty name and invalid dimension."""
    raw = OutputContractDescriptor(
        name="",
        shape=[-10],
        dtype="int32",
    )
    validated, findings = inspect_output_contract(raw, index=1)

    assert any(f.code == ContractFindingCode.INVALID_CONTRACT_METADATA for f in findings)
    assert any(f.code == ContractFindingCode.INVALID_DIMENSION for f in findings)


# ============================================================
# 3. PREPROCESSING CONTRACT & CONSISTENCY TESTS
# ============================================================

def test_preprocessing_extraction_from_metadata():
    """Verify extraction of preprocessing properties from metadata props."""
    meta = _make_dummy_metadata(
        metadata_props={
            "image_mean": "[0.485, 0.456, 0.406]",
            "image_std": "[0.229, 0.224, 0.225]",
            "resize_shape": "[224, 224]",
            "target_layout": "NCHW",
            "target_dtype": "F32",
        }
    )
    prep = extract_preprocessing_from_metadata(meta)
    assert prep is not None
    assert prep.source == PreprocessingSource.INFERRED_FROM_STATIC_STRUCTURE
    assert prep.normalization_mean == [0.485, 0.456, 0.406]
    assert prep.normalization_std == [0.229, 0.224, 0.225]
    assert prep.resize_shape == [224, 224]
    assert prep.target_layout == "NCHW"


def test_preprocessing_consistency_pass():
    """Verify consistency pass when preprocessing aligns with input contract."""
    inp = ValidatedInputContract(
        name="input",
        index=0,
        dtype="F32",
        rank=4,
        shape=[1, 3, 224, 224],
        layout="NCHW",
        channel_count=3,
    )
    prep = PreprocessingDeclaration(
        source=PreprocessingSource.EXPLICITLY_DECLARED,
        resize_shape=[224, 224],
        channels=3,
        normalization_mean=[0.485, 0.456, 0.406],
        normalization_std=[0.229, 0.224, 0.225],
        target_layout="NCHW",
        target_dtype="F32",
    )
    findings = validate_preprocessing_consistency(prep, [inp])
    assert len(findings) == 0


def test_preprocessing_channel_mismatch():
    """Verify detection when preprocessing channels contradict input contract."""
    inp = ValidatedInputContract(
        name="input",
        index=0,
        dtype="F32",
        rank=4,
        shape=[1, 3, 224, 224],
        layout="NCHW",
        channel_count=3,
    )
    prep = PreprocessingDeclaration(
        source=PreprocessingSource.EXPLICITLY_DECLARED,
        channels=1,  # Inconsistent: 1 channel vs 3
    )
    findings = validate_preprocessing_consistency(prep, [inp])
    assert any(f.code == ContractFindingCode.CHANNEL_COUNT_MISMATCH for f in findings)


def test_preprocessing_normalization_length_mismatch():
    """Verify detection when mean vector length does not match channels."""
    inp = ValidatedInputContract(
        name="input",
        index=0,
        dtype="F32",
        rank=4,
        shape=[1, 3, 224, 224],
        layout="NCHW",
        channel_count=3,
    )
    prep = PreprocessingDeclaration(
        source=PreprocessingSource.EXPLICITLY_DECLARED,
        normalization_mean=[0.5, 0.5],  # 2 values for 3 channels
    )
    findings = validate_preprocessing_consistency(prep, [inp])
    assert any(f.code == ContractFindingCode.NORMALIZATION_LENGTH_MISMATCH for f in findings)


def test_preprocessing_resize_mismatch():
    """Verify detection when resize shape does not match fixed input spatial dimensions."""
    inp = ValidatedInputContract(
        name="input",
        index=0,
        dtype="F32",
        rank=4,
        shape=[1, 3, 224, 224],
        layout="NCHW",
        channel_count=3,
    )
    prep = PreprocessingDeclaration(
        source=PreprocessingSource.EXPLICITLY_DECLARED,
        resize_shape=[384, 384],  # Inconsistent with 224x224
    )
    findings = validate_preprocessing_consistency(prep, [inp])
    assert any(f.code == ContractFindingCode.RESIZE_SHAPE_MISMATCH for f in findings)


# ============================================================
# 4. CROSS-CONSISTENCY & GRAPH INTEGRITY TESTS
# ============================================================

def test_duplicate_input_name_detection():
    """Verify detection of duplicate input interface names."""
    inp1 = ValidatedInputContract(name="same_name", index=0, dtype="F32", rank=1, shape=[10])
    inp2 = ValidatedInputContract(name="same_name", index=1, dtype="F32", rank=1, shape=[10])
    meta = _make_dummy_metadata()

    findings, comp, status = validate_contract_integrity(meta, [inp1, inp2], [])
    assert any(f.code == ContractFindingCode.DUPLICATE_INTERFACE_NAME for f in findings)
    assert status == ContractStatus.INVALID


def test_input_initializer_collision():
    """Verify detection of collision between input interface and model parameter tensor."""
    tensor = TensorDescriptor(name="weight_conv1", shape=[64, 3, 7, 7], dtype="F32", element_count=9408, byte_size=37632)
    inp = ValidatedInputContract(name="weight_conv1", index=0, dtype="F32", rank=4, shape=[64, 3, 7, 7])
    meta = _make_dummy_metadata(tensors=[tensor])

    findings, comp, status = validate_contract_integrity(meta, [inp], [])
    assert any(f.code == ContractFindingCode.INITIALIZER_INTERFACE_COLLISION for f in findings)


def test_input_output_name_collision():
    """Verify detection when an identifier is declared as both input and output."""
    inp = ValidatedInputContract(name="shared_io", index=0, dtype="F32", rank=1, shape=[10])
    out = ValidatedOutputContract(name="shared_io", index=0, dtype="F32", rank=1, shape=[10])
    meta = _make_dummy_metadata()

    findings, comp, status = validate_contract_integrity(meta, [inp], [out])
    assert any(f.code == ContractFindingCode.INVALID_CONTRACT_METADATA for f in findings)


# ============================================================
# 5. AVAILABILITY & STATUS CATEGORIES TESTS
# ============================================================

def test_safetensors_contract_unavailable_status():
    """Verify Safetensors without interface returns UNAVAILABLE without failing as INVALID."""
    meta = _make_dummy_metadata(inputs=[], outputs=[], fmt=ModelFormat.SAFETENSORS)
    service = ModelContractVerificationService()
    res = service.verify_contract(meta)

    assert res.status == ContractStatus.UNAVAILABLE
    assert res.completeness == ContractCompleteness.UNAVAILABLE
    assert any(f.code == ContractFindingCode.SHAPE_METADATA_UNAVAILABLE for f in res.findings)


def test_onnx_verified_complete():
    """Verify standard ONNX interface returns VERIFIED and COMPLETE."""
    meta = _make_dummy_metadata(
        inputs=[InputContractDescriptor(name="input", shape=[1, 3, 224, 224], dtype="F32", channel_order="NCHW")],
        outputs=[OutputContractDescriptor(name="output", shape=[1, 1000], dtype="F32")],
        fmt=ModelFormat.ONNX,
    )
    service = ModelContractVerificationService()
    res = service.verify_contract(meta)

    assert res.status == ContractStatus.VERIFIED
    assert res.completeness == ContractCompleteness.COMPLETE
    assert len(res.inputs) == 1
    assert len(res.outputs) == 1


def test_onnx_dynamic_partial():
    """Verify dynamic input returns VERIFIED and PARTIAL completeness."""
    meta = _make_dummy_metadata(
        inputs=[InputContractDescriptor(name="input", shape=[None, 3, None, None], dtype="F32", is_dynamic=True)],
        outputs=[OutputContractDescriptor(name="output", shape=[None, 1000], dtype="F32")],
        fmt=ModelFormat.ONNX,
    )
    service = ModelContractVerificationService()
    res = service.verify_contract(meta)

    assert res.status == ContractStatus.VERIFIED
    assert res.completeness == ContractCompleteness.PARTIAL


# ============================================================
# 6. DETERMINISM & CANONICAL HASHING TESTS
# ============================================================

def test_contract_hashing_determinism_and_phase73_integration():
    """Verify contract hash is deterministic, 64-char lowercase hex, and matches Phase 7.3."""
    meta = _make_dummy_metadata(
        inputs=[
            InputContractDescriptor(name="z_input", shape=[1, 10], dtype="F32"),
            InputContractDescriptor(name="a_input", shape=[1, 20], dtype="I64"),
        ],
        outputs=[
            OutputContractDescriptor(name="out2", shape=[1, 5], dtype="F32"),
            OutputContractDescriptor(name="out1", shape=[1, 2], dtype="F32"),
        ],
    )
    service = ModelContractVerificationService()
    res1 = service.verify_contract(meta)
    res2 = service.verify_contract(meta)

    assert res1.contract_hash == res2.contract_hash
    assert len(res1.contract_hash) == 64
    assert res1.contract_hash.islower()

    # Verify matching directly with Phase 7.3 function
    rep_p73 = build_contract_representation(meta)
    hash_p73 = compute_contract_hash(rep_p73)
    assert res1.contract_hash == hash_p73


def test_contract_hash_sensitivity():
    """Verify modifying input, output, or dtype changes the contract hash."""
    meta_base = _make_dummy_metadata(
        inputs=[InputContractDescriptor(name="input", shape=[1, 3, 224, 224], dtype="F32")],
        outputs=[OutputContractDescriptor(name="output", shape=[1, 1000], dtype="F32")],
    )
    meta_mod_in = _make_dummy_metadata(
        inputs=[InputContractDescriptor(name="input", shape=[1, 3, 256, 256], dtype="F32")],
        outputs=[OutputContractDescriptor(name="output", shape=[1, 1000], dtype="F32")],
    )
    meta_mod_dt = _make_dummy_metadata(
        inputs=[InputContractDescriptor(name="input", shape=[1, 3, 224, 224], dtype="F16")],
        outputs=[OutputContractDescriptor(name="output", shape=[1, 1000], dtype="F32")],
    )
    meta_mod_out = _make_dummy_metadata(
        inputs=[InputContractDescriptor(name="input", shape=[1, 3, 224, 224], dtype="F32")],
        outputs=[OutputContractDescriptor(name="output", shape=[1, 500], dtype="F32")],
    )

    service = ModelContractVerificationService()
    h_base = service.verify_contract(meta_base).contract_hash
    h_mod_in = service.verify_contract(meta_mod_in).contract_hash
    h_mod_dt = service.verify_contract(meta_mod_dt).contract_hash
    h_mod_out = service.verify_contract(meta_mod_out).contract_hash

    assert h_base != h_mod_in
    assert h_base != h_mod_dt
    assert h_base != h_mod_out


# ============================================================
# 7. SEMANTIC SAFETY & AIR-GAP AUDIT
# ============================================================

def test_semantic_safety_zero_prohibited_terms():
    """Verify findings and messages strictly contain zero prohibited human intent terms."""
    meta = _make_dummy_metadata(
        inputs=[InputContractDescriptor(name="bad_in", shape=[-10, -20], dtype="invalid_type")],
        outputs=[OutputContractDescriptor(name="bad_in", shape=[-5], dtype="invalid_type")],
    )
    service = ModelContractVerificationService()
    res = service.verify_contract(meta)

    prohibited = ["malicious", "maliciously", "collusion", "culpable", "intentional", "attacker", "compromised"]
    serialized = json.dumps(res.model_dump())

    for word in prohibited:
        assert word not in serialized.lower(), f"Prohibited semantic word '{word}' found in contract verification result"


# ============================================================
# 8. ADDITIONAL COMPREHENSIVE COVERAGE TESTS
# ============================================================

def test_pytorch_and_torchscript_contract_unavailable():
    """Verify PyTorch StateDict and TorchScript return UNAVAILABLE without failing as INVALID."""
    service = ModelContractVerificationService()
    
    meta_pt = _make_dummy_metadata(inputs=[], outputs=[], fmt=ModelFormat.PYTORCH_STATE_DICT)
    res_pt = service.verify_contract(meta_pt)
    assert res_pt.status == ContractStatus.UNAVAILABLE
    assert res_pt.completeness == ContractCompleteness.UNAVAILABLE

    meta_ts = _make_dummy_metadata(inputs=[], outputs=[], fmt=ModelFormat.TORCHSCRIPT)
    res_ts = service.verify_contract(meta_ts)
    assert res_ts.status == ContractStatus.UNAVAILABLE
    assert res_ts.completeness == ContractCompleteness.UNAVAILABLE


def test_preprocessing_layout_and_dtype_mismatch():
    """Verify detection when preprocessing layout and dtype contradict input contract."""
    inp = ValidatedInputContract(
        name="input",
        index=0,
        dtype="F32",
        rank=4,
        shape=[1, 3, 224, 224],
        layout="NCHW",
        channel_count=3,
    )
    prep = PreprocessingDeclaration(
        source=PreprocessingSource.EXPLICITLY_DECLARED,
        target_layout="NHWC",  # Mismatched layout
        target_dtype="I64",    # Mismatched dtype
    )
    findings = validate_preprocessing_consistency(prep, [inp])
    assert any(f.code == ContractFindingCode.LAYOUT_MISMATCH for f in findings)
    assert any(f.code == ContractFindingCode.DTYPE_MISMATCH for f in findings)


def test_preprocessing_value_range_invalid():
    """Verify detection of invalid value range where min >= max."""
    prep = PreprocessingDeclaration(
        source=PreprocessingSource.EXPLICITLY_DECLARED,
        value_range=[1.0, 0.0],  # Invalid range min > max
    )
    findings = validate_preprocessing_consistency(prep, [])
    assert any(f.code == ContractFindingCode.VALUE_RANGE_INVALID for f in findings)


def test_interface_tensor_type_conflict():
    """Verify detection when input interface dtype contradicts underlying weight tensor dtype."""
    tensor = TensorDescriptor(name="input_tensor", shape=[1, 10], dtype="I64", element_count=10, byte_size=80)
    inp = ValidatedInputContract(name="input_tensor", index=0, dtype="F32", rank=2, shape=[1, 10])
    meta = _make_dummy_metadata(tensors=[tensor])

    findings, comp, status = validate_contract_integrity(meta, [inp], [])
    assert any(f.code == ContractFindingCode.INTERFACE_TENSOR_TYPE_CONFLICT for f in findings)
    assert any(f.code == ContractFindingCode.INITIALIZER_INTERFACE_COLLISION for f in findings)


def test_duplicate_output_name_detection():
    """Verify detection of duplicate output contract names."""
    out1 = ValidatedOutputContract(name="same_out", index=0, dtype="F32", rank=1, shape=[10])
    out2 = ValidatedOutputContract(name="same_out", index=1, dtype="F32", rank=1, shape=[10])
    meta = _make_dummy_metadata()

    findings, comp, status = validate_contract_integrity(meta, [], [out1, out2])
    assert any(f.code == ContractFindingCode.DUPLICATE_INTERFACE_NAME for f in findings)
    assert status == ContractStatus.INVALID


def test_verify_artifact_contract_with_file(tmp_path: Path):
    """Verify artifact verification on disk safely handles a non-model or empty file."""
    bad_file = tmp_path / "corrupted.onnx"
    bad_file.write_bytes(b"not a real onnx file")

    service = ModelContractVerificationService()
    res = service.verify_artifact_contract(bad_file)
    assert res.status == ContractStatus.INVALID
    assert res.completeness == ContractCompleteness.INVALID
    assert len(res.contract_hash) == 64

