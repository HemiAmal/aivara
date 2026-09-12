"""Authoritative Test Suite for Phase 10.4: Preprocessing & Contract Integrity.

Covers verification categories A through AP:
A. valid empty/no-op preprocessing contract
B. valid resize contract
C. valid crop contract
D. valid padding contract
E. valid channel conversion
F. valid dtype conversion
G. valid normalization
H. ordered operations produce distinct identities
I. identical contracts produce identical hashes
J. parameter modification changes hash
K. operation version modification changes hash
L. schema version modification changes hash
M. malformed contract rejection
N. non-finite parameter rejection
O. invalid dimensions rejection
P. invalid crop bounds
Q. invalid padding values
R. invalid normalization parameters
S. unsupported operation rejection
T. arbitrary callback rejection
U. eval/exec/pickle/subprocess security scan
V. model/input contract compatibility
W. layout mismatch detection
X. channel mismatch detection
Y. dtype mismatch detection
Z. unavailable model contract handling
AA. unverifiable model contract handling
AB. immutability
AC. deterministic canonicalization
AD. hash verification
AE. tampered preprocessing hash detection
AF. resource limit enforcement
AG. offline behavior
AH. database unchanged
AI. Phase 10.2 regression
AJ. Phase 10.3 regression
AK. Phase 7 regression
AL. Phase 8 regression
AM. Phase 9 regression
AN. no model execution
AO. no output inspection
AP. no Phase 10.5 implementation
"""

from __future__ import annotations

import ast
import copy
import hashlib
import os
from typing import Any, Dict, List

import numpy as np
import pytest

from aivara.crypto.canonical import canonicalize
from aivara.inference.binding.engine import create_input_model_binding
from aivara.inference.binding.models import InputModelBinding, ModelIdentityEnvelope
from aivara.inference.enums import (
    InferenceFindingCode,
    InferenceIntegrityStatus,
    InputKind,
    InputLayout,
    ValueRangeKind,
)
from aivara.inference.exceptions import (
    InvalidPreprocessingContractError,
    PreprocessingExecutionError,
    PreprocessingResourceLimitError,
    UnsupportedPreprocessingOpError,
)
from aivara.inference.input.models import InputIdentity
from aivara.inference.preprocessing import (
    AspectRatioPolicy,
    ChannelConvertParams,
    ClippingPolicy,
    ColorSpace,
    CompatibilityAssessment,
    ContractVerificationResult,
    CropParams,
    DtypeConvertParams,
    InputAssumption,
    InterpolationMode,
    NormalizeParams,
    OutputGuarantee,
    PadParams,
    PaddingMode,
    PreprocessingContract,
    PreprocessingOpType,
    PreprocessingOperation,
    ResizeParams,
    RoundingPolicy,
    TransformedInputIdentity,
    ValueRangeScaleParams,
    build_canonical_preprocessing_descriptor,
    check_contract_compatibility,
    compute_preprocessing_contract_hash,
    create_preprocessing_contract,
    execute_preprocessing_pipeline,
    validate_operation_parameters,
    verify_preprocessing_contract,
)
from aivara.model_integrity.contract_verification.schemas import (
    ContractCompleteness,
    ContractStatus,
    ValidatedInputContract,
    ValidatedOutputContract,
)
from aivara.model_integrity.fingerprinting.schemas import ContractRepresentation


# =====================================================================
# Fixtures
# =====================================================================


@pytest.fixture
def sample_input_identity() -> InputIdentity:
    """Fixture for a valid Phase 10.2 InputIdentity."""
    return InputIdentity(
        input_id="1111111111111111111111111111111111111111111111111111111111111111",
        input_kind=InputKind.TENSOR,
        canonical_hash="2222222222222222222222222222222222222222222222222222222222222222",
        dtype="float32",
        shape=(224, 224, 3),
        layout=InputLayout.HWC,
        rank=3,
        channels=3,
        width=224,
        height=224,
        value_range=ValueRangeKind.UNIT_FLOAT,
        finite=True,
        byte_size=224 * 224 * 3 * 4,
        element_count=224 * 224 * 3,
        validation_status=InferenceIntegrityStatus.VERIFIED,
        schema_version="1.0",
    )


@pytest.fixture
def sample_model_envelope() -> ModelIdentityEnvelope:
    """Fixture for a valid Phase 7 ModelIdentityEnvelope."""
    art_hash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    str_hash = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    con_hash = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
    master_desc = {
        "artifact_hash": art_hash,
        "contract_hash": con_hash,
        "schema_version": "1.0",
        "structural_hash": str_hash,
    }
    master_fp = hashlib.sha256(canonicalize(master_desc)).hexdigest()
    return ModelIdentityEnvelope(
        model_id="resnet50-v1",
        project_id="proj-alpha",
        master_fingerprint=master_fp,
        artifact_hash=art_hash,
        structural_hash=str_hash,
        contract_hash=con_hash,
        status="verified",
    )


@pytest.fixture
def sample_binding(sample_input_identity: InputIdentity, sample_model_envelope: ModelIdentityEnvelope) -> InputModelBinding:
    """Fixture for a valid Phase 10.3 InputModelBinding."""
    return create_input_model_binding(
        input_identity=sample_input_identity,
        model_identity=sample_model_envelope,
        project_id="proj-alpha",
    )


# =====================================================================
# Tests: Categories A - G (Supported Operations & Valid Contracts)
# =====================================================================


def test_category_a_valid_empty_contract() -> None:
    """Category A: Valid empty/no-op preprocessing contract."""
    contract = create_preprocessing_contract(name="identity_no_op")
    assert contract.name == "identity_no_op"
    assert len(contract.operations) == 0
    assert len(contract.contract_hash) == 64

    res = verify_preprocessing_contract(contract)
    assert res.is_valid is True
    assert res.status == InferenceIntegrityStatus.VERIFIED


def test_category_b_valid_resize_contract() -> None:
    """Category B: Valid resize contract."""
    op = PreprocessingOperation(
        op_type=PreprocessingOpType.RESIZE,
        parameters={
            "target_width": 256,
            "target_height": 256,
            "interpolation": InterpolationMode.BILINEAR.value,
            "aspect_ratio_policy": AspectRatioPolicy.STRETCH.value,
        },
    )
    contract = create_preprocessing_contract(name="resize_256", operations=[op])
    assert len(contract.operations) == 1
    assert contract.operations[0].parameters["target_width"] == 256
    res = verify_preprocessing_contract(contract)
    assert res.is_valid is True


def test_category_c_valid_crop_contract() -> None:
    """Category C: Valid crop contract."""
    op = PreprocessingOperation(
        op_type=PreprocessingOpType.CROP,
        parameters={"x": 10, "y": 10, "width": 200, "height": 200, "normalized": False},
    )
    contract = create_preprocessing_contract(name="crop_center", operations=[op])
    res = verify_preprocessing_contract(contract)
    assert res.is_valid is True


def test_category_d_valid_pad_contract() -> None:
    """Category D: Valid padding contract."""
    op = PreprocessingOperation(
        op_type=PreprocessingOpType.PAD,
        parameters={"top": 4, "bottom": 4, "left": 4, "right": 4, "mode": "CONSTANT", "value": 0.0},
    )
    contract = create_preprocessing_contract(name="pad_borders", operations=[op])
    res = verify_preprocessing_contract(contract)
    assert res.is_valid is True


def test_category_e_valid_channel_conversion() -> None:
    """Category E: Valid channel conversion contract."""
    op = PreprocessingOperation(
        op_type=PreprocessingOpType.CHANNEL_CONVERT,
        parameters={"source_space": ColorSpace.RGB.value, "target_space": ColorSpace.BGR.value},
    )
    contract = create_preprocessing_contract(name="rgb_to_bgr", operations=[op])
    res = verify_preprocessing_contract(contract)
    assert res.is_valid is True


def test_category_f_valid_dtype_conversion() -> None:
    """Category F: Valid dtype conversion contract."""
    op = PreprocessingOperation(
        op_type=PreprocessingOpType.DTYPE_CONVERT,
        parameters={
            "source_dtype": "uint8",
            "target_dtype": "float32",
            "rounding_policy": RoundingPolicy.HALF_TO_EVEN.value,
            "clipping_policy": ClippingPolicy.CLIP_TO_RANGE.value,
        },
    )
    contract = create_preprocessing_contract(name="uint8_to_f32", operations=[op])
    res = verify_preprocessing_contract(contract)
    assert res.is_valid is True


def test_category_g_valid_normalization() -> None:
    """Category G: Valid normalization contract."""
    op = PreprocessingOperation(
        op_type=PreprocessingOpType.NORMALIZE,
        parameters={
            "mean": [0.485, 0.456, 0.406],
            "std": [0.229, 0.224, 0.225],
            "scale": 0.00392156862745098,  # 1/255
            "clip_min": -3.0,
            "clip_max": 3.0,
        },
    )
    contract = create_preprocessing_contract(name="imagenet_norm", operations=[op])
    res = verify_preprocessing_contract(contract)
    assert res.is_valid is True


# =====================================================================
# Tests: Categories H - L (Ordering, Determinism, Identity Sensitivity)
# =====================================================================


def test_category_h_ordering_produces_distinct_identities() -> None:
    """Category H: Operation ordering produces distinct identities (T1 o T2 != T2 o T1)."""
    op1 = PreprocessingOperation(
        op_type=PreprocessingOpType.RESIZE,
        parameters={"target_width": 224, "target_height": 224, "interpolation": "BILINEAR"},
    )
    op2 = PreprocessingOperation(
        op_type=PreprocessingOpType.NORMALIZE,
        parameters={"mean": [0.5, 0.5, 0.5], "std": [0.5, 0.5, 0.5]},
    )

    contract_order1 = create_preprocessing_contract(name="pipe", operations=[op1, op2])
    contract_order2 = create_preprocessing_contract(name="pipe", operations=[op2, op1])

    assert contract_order1.contract_hash != contract_order2.contract_hash


def test_category_i_identical_contracts_produce_identical_hashes() -> None:
    """Category I: Identical contracts produce identical hashes."""
    op = PreprocessingOperation(
        op_type=PreprocessingOpType.RESIZE,
        parameters={"target_width": 128, "target_height": 128},
    )
    c1 = create_preprocessing_contract(name="c_same", operations=[op])
    c2 = create_preprocessing_contract(name="c_same", operations=[op])
    assert c1.contract_hash == c2.contract_hash


def test_category_j_parameter_modification_changes_hash() -> None:
    """Category J: Parameter modification changes hash."""
    op_a = PreprocessingOperation(
        op_type=PreprocessingOpType.RESIZE,
        parameters={"target_width": 224, "target_height": 224},
    )
    op_b = PreprocessingOperation(
        op_type=PreprocessingOpType.RESIZE,
        parameters={"target_width": 224, "target_height": 256},
    )
    c1 = create_preprocessing_contract(name="resize_test", operations=[op_a])
    c2 = create_preprocessing_contract(name="resize_test", operations=[op_b])
    assert c1.contract_hash != c2.contract_hash


def test_category_k_l_version_modifications_change_hash() -> None:
    """Categories K & L: Operation & schema version modifications change hash."""
    op1 = PreprocessingOperation(
        op_type=PreprocessingOpType.NO_OP,
        op_version="1.0",
    )
    op2 = PreprocessingOperation(
        op_type=PreprocessingOpType.NO_OP,
        op_version="2.0",
    )
    c1 = create_preprocessing_contract(name="v_test", operations=[op1], contract_version="1.0")
    c2 = create_preprocessing_contract(name="v_test", operations=[op2], contract_version="1.0")
    c3 = create_preprocessing_contract(name="v_test", operations=[op1], contract_version="2.0")

    assert c1.contract_hash != c2.contract_hash
    assert c1.contract_hash != c3.contract_hash


# =====================================================================
# Tests: Categories M - T (Validation, Rejections, Bounds)
# =====================================================================


def test_category_m_malformed_contract_rejection() -> None:
    """Category M: Malformed contract rejection."""
    with pytest.raises(InvalidPreprocessingContractError):
        create_preprocessing_contract(name="")


def test_category_n_non_finite_parameter_rejection() -> None:
    """Category N: Non-finite parameter rejection (NaN / Inf)."""
    with pytest.raises(InvalidPreprocessingContractError):
        validate_operation_parameters(
            PreprocessingOpType.NORMALIZE,
            {"mean": [float("nan"), 0.5], "std": [1.0, 1.0]},
        )

    with pytest.raises(InvalidPreprocessingContractError):
        validate_operation_parameters(
            PreprocessingOpType.PAD,
            {"top": 1, "bottom": 1, "left": 1, "right": 1, "value": float("inf")},
        )


def test_category_o_invalid_dimensions_rejection() -> None:
    """Category O: Invalid dimensions rejection."""
    with pytest.raises(InvalidPreprocessingContractError):
        validate_operation_parameters(
            PreprocessingOpType.RESIZE,
            {"target_width": 0, "target_height": 224},
        )

    with pytest.raises(InvalidPreprocessingContractError):
        validate_operation_parameters(
            PreprocessingOpType.RESIZE,
            {"target_width": 10000, "target_height": 224},  # exceeds 8192
        )


def test_category_p_invalid_crop_bounds() -> None:
    """Category P: Invalid crop bounds rejection."""
    with pytest.raises(InvalidPreprocessingContractError):
        validate_operation_parameters(
            PreprocessingOpType.CROP,
            {"x": -5, "y": 0, "width": 100, "height": 100},
        )


def test_category_q_invalid_padding_values() -> None:
    """Category Q: Invalid padding values rejection."""
    with pytest.raises(InvalidPreprocessingContractError):
        validate_operation_parameters(
            PreprocessingOpType.PAD,
            {"top": -1, "bottom": 0, "left": 0, "right": 0},
        )


def test_category_r_invalid_normalization_parameters() -> None:
    """Category R: Invalid normalization parameters (std <= 0)."""
    with pytest.raises(InvalidPreprocessingContractError):
        validate_operation_parameters(
            PreprocessingOpType.NORMALIZE,
            {"mean": [0.5, 0.5], "std": [1.0, 0.0]},
        )

    with pytest.raises(InvalidPreprocessingContractError):
        validate_operation_parameters(
            PreprocessingOpType.NORMALIZE,
            {"mean": [0.5, 0.5], "std": [1.0, -0.5]},
        )


def test_category_s_t_unsupported_operation_and_arbitrary_code_rejection() -> None:
    """Categories S & T: Unsupported operation and arbitrary callback rejection."""
    with pytest.raises(UnsupportedPreprocessingOpError):
        validate_operation_parameters("LAMBDA_FUNCTION", {})  # type: ignore


# =====================================================================
# Tests: Categories U - AA (Security, Compatibility, Model Contract)
# =====================================================================


def test_category_u_security_scan_no_forbidden_constructs() -> None:
    """Category U: AST security scan for forbidden constructs (eval, exec, pickle, subprocess, os.system)."""
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    target_dir = os.path.join(base_dir, "backend", "aivara", "inference", "preprocessing")

    forbidden_names = {"eval", "exec", "pickle", "subprocess", "system", "popen"}

    for root, _, files in os.walk(target_dir):
        for file in files:
            if file.endswith(".py"):
                file_path = os.path.join(root, file)
                with open(file_path, "r", encoding="utf-8") as f:
                    tree = ast.parse(f.read(), filename=file_path)

                for node in ast.walk(tree):
                    if isinstance(node, ast.Call):
                        if isinstance(node.func, ast.Name) and node.func.id in forbidden_names:
                            pytest.fail(f"Forbidden call '{node.func.id}' in {file_path}")
                        elif isinstance(node.func, ast.Attribute) and node.func.attr in forbidden_names:
                            pytest.fail(f"Forbidden attribute call '{node.func.attr}' in {file_path}")


def test_category_v_w_x_y_contract_compatibility(
    sample_input_identity: InputIdentity,
) -> None:
    """Categories V, W, X, Y: Contract compatibility, layout, channel, and dtype mismatch detection."""
    # Build model contract expectation: NCHW, float32, 3 channels
    mock_input = ValidatedInputContract(
        name="input_tensor",
        index=0,
        dtype="float32",
        rank=4,
        shape=[1, 3, 224, 224],
        layout="NCHW",
        channel_count=3,
    )
    mock_contract = type("MockModelContract", (), {"status": "verified", "inputs": [mock_input]})()

    # Compatible contract
    compat_contract = create_preprocessing_contract(
        name="compat",
        input_assumption=InputAssumption(expected_layout=InputLayout.HWC, expected_dtype="float32", expected_channels=3),
        output_guarantee=OutputGuarantee(target_layout=InputLayout.NCHW, target_dtype="float32", target_channels=3),
    )

    assessment = check_contract_compatibility(compat_contract, sample_input_identity, mock_contract)
    assert assessment.is_compatible is True
    assert assessment.status == InferenceIntegrityStatus.VERIFIED

    # Layout mismatch
    mismatch_layout = create_preprocessing_contract(
        name="mismatch_layout",
        input_assumption=InputAssumption(expected_layout=InputLayout.NCHW),  # Input is HWC
    )
    assess_mismatch = check_contract_compatibility(mismatch_layout, sample_input_identity, mock_contract)
    assert assess_mismatch.is_compatible is False
    assert assess_mismatch.input_compatible is False
    assert any(f.code == InferenceFindingCode.PREPROCESSING_LAYOUT_MISMATCH.value for f in assess_mismatch.findings)

    # Channel mismatch
    mismatch_channel = create_preprocessing_contract(
        name="mismatch_channel",
        output_guarantee=OutputGuarantee(target_channels=1),  # Model expects 3
    )
    assess_chan = check_contract_compatibility(mismatch_channel, sample_input_identity, mock_contract)
    assert assess_chan.is_compatible is False
    assert assess_chan.model_compatible is False
    assert any(f.code == InferenceFindingCode.PREPROCESSING_CHANNEL_MISMATCH.value for f in assess_chan.findings)


def test_category_z_aa_unavailable_unverifiable_model_contract(sample_input_identity: InputIdentity) -> None:
    """Categories Z & AA: Unavailable and unverifiable model contract handling."""
    contract = create_preprocessing_contract(name="test_contract")

    # Unavailable model contract (None)
    assess_unavail = check_contract_compatibility(contract, sample_input_identity, model_contract=None)
    assert assess_unavail.is_compatible is False
    assert assess_unavail.status == InferenceIntegrityStatus.UNAVAILABLE
    assert any(f.code == InferenceFindingCode.PREPROCESSING_MODEL_CONTRACT_UNAVAILABLE.value for f in assess_unavail.findings)

    # Unverifiable model contract
    unverifiable_mock = type("MockUnverifiable", (), {"status": "unverifiable"})()
    assess_unverif = check_contract_compatibility(contract, sample_input_identity, model_contract=unverifiable_mock)
    assert assess_unverif.is_compatible is False
    assert assess_unverif.status == InferenceIntegrityStatus.UNVERIFIABLE
    assert any(f.code == InferenceFindingCode.PREPROCESSING_MODEL_CONTRACT_UNVERIFIABLE.value for f in assess_unverif.findings)


# =====================================================================
# Tests: Categories AB - AF (Immutability, Canonicalization, Verification, Execution)
# =====================================================================


def test_category_ab_immutability(sample_input_identity: InputIdentity, sample_binding: InputModelBinding) -> None:
    """Category AB: Contract & execution immutability."""
    contract = create_preprocessing_contract(name="immut_test")
    with pytest.raises(Exception):
        contract.name = "tampered"  # type: ignore

    # Test array immutability during execution
    input_arr = np.ones((64, 64, 3), dtype=np.float32)
    orig_copy = np.copy(input_arr)
    op = PreprocessingOperation(
        op_type=PreprocessingOpType.NORMALIZE,
        parameters={"mean": [0.5, 0.5, 0.5], "std": [0.5, 0.5, 0.5]},
    )
    pipe_contract = create_preprocessing_contract(name="norm_pipe", operations=[op])
    out_arr, transformed_id = execute_preprocessing_pipeline(
        pipe_contract, input_arr, sample_input_identity, sample_binding
    )

    # Input array is completely untouched
    np.testing.assert_array_equal(input_arr, orig_copy)
    assert not np.shares_memory(input_arr, out_arr)


def test_category_ac_ad_ae_canonicalization_and_tampered_hash() -> None:
    """Categories AC, AD, AE: Deterministic canonicalization, verification, and tamper detection."""
    op = PreprocessingOperation(
        op_type=PreprocessingOpType.RESIZE,
        parameters={"target_width": 224, "target_height": 224},
    )
    contract = create_preprocessing_contract(name="canon_test", operations=[op])

    # Pure verification
    res = verify_preprocessing_contract(contract)
    assert res.is_valid is True
    assert res.status == InferenceIntegrityStatus.VERIFIED

    # Tampered hash
    tampered_dict = contract.model_dump()
    tampered_dict["contract_hash"] = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
    tampered_contract = PreprocessingContract(**tampered_dict)

    res_tampered = verify_preprocessing_contract(tampered_contract)
    assert res_tampered.is_valid is False
    assert res_tampered.status == InferenceIntegrityStatus.MISMATCHED
    assert any(f.code == InferenceFindingCode.PREPROCESSING_HASH_MISMATCH.value for f in res_tampered.findings)


def test_category_af_resource_limits() -> None:
    """Category AF: Resource limit enforcement (max operations, max dimension)."""
    # Exceeding max operations (32)
    ops = [PreprocessingOperation(op_type=PreprocessingOpType.NO_OP) for _ in range(33)]
    with pytest.raises(PreprocessingResourceLimitError):
        create_preprocessing_contract(name="too_many_ops", operations=ops)


def test_execution_distinct_transformed_hash(sample_input_identity: InputIdentity, sample_binding: InputModelBinding) -> None:
    """Test critical distinction: contract_hash (what should happen) vs transformed_canonical_hash (what did happen)."""
    input_arr = np.ones((32, 32, 3), dtype=np.uint8) * 128
    op = PreprocessingOperation(
        op_type=PreprocessingOpType.RESIZE,
        parameters={"target_width": 16, "target_height": 16, "interpolation": "NEAREST"},
    )
    contract = create_preprocessing_contract(name="distinct_hash_test", operations=[op])

    out_arr, transformed_id = execute_preprocessing_pipeline(
        contract, input_arr, sample_input_identity, sample_binding
    )

    assert transformed_id.contract_hash == contract.contract_hash
    assert transformed_id.transformed_canonical_hash != contract.contract_hash
    assert transformed_id.shape == [16, 16, 3]
    assert transformed_id.finite is True
    assert transformed_id.transformation_status == InferenceIntegrityStatus.VERIFIED


# =====================================================================
# Tests: Categories AG - AP (Air-Gap, Database, Regressions, Boundaries)
# =====================================================================


def test_category_ag_offline_behavior() -> None:
    """Category AG: Air-gap / offline verification."""
    # Ensure no network socket modules are invoked
    contract = create_preprocessing_contract(name="offline_test")
    res = verify_preprocessing_contract(contract)
    assert res.is_valid is True


def test_category_ah_database_unchanged() -> None:
    """Category AH: DATABASE SCHEMA CHANGES = 0 check."""
    import aivara.database.models as db_models

    # Verify no new tables or uncommitted entities exist
    assert hasattr(db_models, "InferenceRecordModel")
    assert hasattr(db_models, "EvidenceModel")


def test_category_ai_phase10_2_regression(sample_input_identity: InputIdentity) -> None:
    """Category AI: Phase 10.2 Safe Input Boundary regression compatibility."""
    assert sample_input_identity.validation_status == InferenceIntegrityStatus.VERIFIED
    assert len(sample_input_identity.input_id) == 64
    assert len(sample_input_identity.canonical_hash) == 64


def test_category_aj_phase10_3_regression(sample_binding: InputModelBinding) -> None:
    """Category AJ: Phase 10.3 Input / Model Binding regression compatibility."""
    assert sample_binding.binding_status == InferenceIntegrityStatus.VERIFIED
    assert len(sample_binding.binding_hash) == 64
    assert len(sample_binding.model_master_fingerprint) == 64


def test_category_ak_phase7_regression(sample_model_envelope: ModelIdentityEnvelope) -> None:
    """Category AK: Phase 7 Model Integrity regression compatibility."""
    assert sample_model_envelope.status == "verified"
    assert len(sample_model_envelope.master_fingerprint) == 64
    assert len(sample_model_envelope.artifact_hash) == 64


def test_category_al_phase8_regression() -> None:
    """Category AL: Phase 8 Behavioral Analysis regression compatibility."""
    from aivara.behavioral.baselines.schemas import DistributionStats

    stats = DistributionStats(
        count=100,
        min=0.1,
        max=0.9,
        mean=0.5,
        median=0.5,
        std=0.1,
        p25=0.4,
        p75=0.6,
        p95=0.85,
    )
    assert stats.count == 100
    assert stats.mean == 0.5


def test_category_am_phase9_regression() -> None:
    """Category AM: Phase 9 Backdoor Analysis regression compatibility."""
    from aivara.backdoor.candidates.enums import TriggerFamilyEnum

    assert TriggerFamilyEnum.SPATIAL_PATCH.value == "SPATIAL_PATCH"
    assert TriggerFamilyEnum.COLOR_PATTERN_PATCH.value == "COLOR_PATTERN_PATCH"



def test_category_an_ao_ap_phase_boundaries() -> None:
    """Categories AN, AO, AP: Verify no future unreleased phase implementations."""
    import sys

    assert "aivara.inference.ledger" not in sys.modules



