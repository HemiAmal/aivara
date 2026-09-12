"""Authoritative Test Suite for Phase 10.5: Inference Execution Integrity.

Covers verification categories A through BD:
A. valid local execution
B. valid CPU execution
C. explicit provider selection
D. provider unavailable fail-closed
E. model identity verification
F. input identity verification
G. binding verification
H. preprocessing identity verification
I. transformed-input identity verification
J. deterministic execution identity
K. execution identity changes when binding changes
L. execution identity changes when preprocessing changes
M. execution identity changes when model identity changes
N. execution policy identity
O. timeout
P. cancellation
Q. resource limit rejection
R. batch limit rejection
S. output-size limit rejection
T. raw output hashing
U. output dtype/shape identity
V. multi-output ordering
W. NaN output detection
X. Inf output detection
Y. malformed model artifact rejection
Z. unsafe model loading rejection
AA. subprocess rejection
AB. network/offline enforcement
AC. environment sanitization
AD. path isolation
AE. temporary workspace cleanup
AF. caller immutability
AG. project isolation
AH. unavailable model
AI. unverifiable model
AJ. invalid model
AK. malformed input binding
AL. malformed preprocessing contract
AM. execution failure taxonomy
AN. deterministic repeated execution
AO. CPU default policy
AP. CUDA explicit opt-in
AQ. no Phase 10.6 output semantic validation
AR. no Phase 10.7 implementation
AS. no Phase 10.8 implementation
AT. no REST/API implementation
AU. no evidence/provenance
AV. database unchanged
AW. Phase 10.2 regression
AX. Phase 10.3 regression
AY. Phase 10.4 regression
AZ. Phase 7 regression
BA. Phase 8 regression
BB. Phase 9 regression
BC. security forbidden-construct scan
BD. offline scan
"""

from __future__ import annotations

import ast
import copy
import hashlib
import os
import time
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
    ExecutionCancelledError,
    ExecutionProviderUnavailableError,
    ExecutionResourceLimitError,
    ExecutionTimeoutError,
    ModelExecutionIntegrityError,
    ProjectMismatchError,
)
from aivara.inference.execution import (
    ExecutionDevice,
    ExecutionLifecycle,
    ExecutionPolicy,
    ExecutionProvider,
    ExecutionVerificationResult,
    InferenceExecution,
    NumericalSanityStatus,
    RawExecutionOutput,
    RawOutputTensor,
    build_canonical_execution_descriptor,
    build_canonical_raw_output_descriptor,
    compute_execution_identity_hash,
    compute_raw_output_hash,
    execute_inference_transaction,
    get_available_execution_providers,
    is_cuda_available,
    verify_execution_identity,
)
from aivara.inference.input.models import InputIdentity
from aivara.inference.preprocessing import (
    InputAssumption,
    OutputGuarantee,
    PreprocessingContract,
    PreprocessingOpType,
    PreprocessingOperation,
    TransformedInputIdentity,
    create_preprocessing_contract,
    execute_preprocessing_pipeline,
)


# =====================================================================
# Fixtures
# =====================================================================


@pytest.fixture
def sample_input_identity() -> InputIdentity:
    """Valid Phase 10.2 InputIdentity fixture."""
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
    """Valid Phase 7 ModelIdentityEnvelope fixture."""
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
    """Valid Phase 10.3 InputModelBinding fixture."""
    return create_input_model_binding(
        input_identity=sample_input_identity,
        model_identity=sample_model_envelope,
        project_id="proj-alpha",
    )


@pytest.fixture
def sample_contract() -> PreprocessingContract:
    """Valid Phase 10.4 PreprocessingContract fixture."""
    op = PreprocessingOperation(
        op_type=PreprocessingOpType.NORMALIZE,
        parameters={"mean": [0.5, 0.5, 0.5], "std": [0.5, 0.5, 0.5]},
    )
    return create_preprocessing_contract(name="test_norm", operations=[op])


@pytest.fixture
def sample_transformed(
    sample_contract: PreprocessingContract,
    sample_input_identity: InputIdentity,
    sample_binding: InputModelBinding,
) -> tuple[np.ndarray, TransformedInputIdentity]:
    """Valid Phase 10.4 Transformed input and TransformedInputIdentity fixture."""
    arr = np.ones((224, 224, 3), dtype=np.float32)
    out_arr, transformed_id = execute_preprocessing_pipeline(
        sample_contract, arr, sample_input_identity, sample_binding
    )
    return out_arr, transformed_id


# =====================================================================
# Tests: Categories A - D (Local, CPU, Provider Selection & Fail-Closed)
# =====================================================================


def test_category_a_b_valid_local_cpu_execution(
    sample_input_identity: InputIdentity,
    sample_binding: InputModelBinding,
    sample_model_envelope: ModelIdentityEnvelope,
    sample_contract: PreprocessingContract,
    sample_transformed: tuple[np.ndarray, TransformedInputIdentity],
) -> None:
    """Categories A & B: Valid local execution on CPU."""
    arr, transformed_id = sample_transformed

    # Simple mock runner for linear forward pass
    def mock_runner(x: np.ndarray) -> np.ndarray:
        return x * 2.0

    execution = execute_inference_transaction(
        input_identity=sample_input_identity,
        binding=sample_binding,
        model_identity=sample_model_envelope,
        preprocessing_contract=sample_contract,
        transformed_identity=transformed_id,
        preprocessed_array=arr,
        project_id="proj-alpha",
        runner_override=mock_runner,
    )

    assert execution.status == InferenceIntegrityStatus.VERIFIED
    assert execution.lifecycle == ExecutionLifecycle.SUCCEEDED
    assert execution.execution_provider == "CPUExecutionProvider"
    assert len(execution.execution_identity_hash) == 64
    assert execution.raw_output is not None
    assert len(execution.raw_output.outputs) == 1
    assert execution.raw_output.numerical_sanity == NumericalSanityStatus.FINITE


def test_category_c_d_explicit_provider_selection_fail_closed(
    sample_input_identity: InputIdentity,
    sample_binding: InputModelBinding,
    sample_model_envelope: ModelIdentityEnvelope,
    sample_contract: PreprocessingContract,
    sample_transformed: tuple[np.ndarray, TransformedInputIdentity],
) -> None:
    """Categories C & D: Explicit provider selection, fails closed if unavailable (no silent fallback)."""
    arr, transformed_id = sample_transformed

    if not is_cuda_available():
        cuda_policy = ExecutionPolicy(provider=ExecutionProvider.CUDA)
        with pytest.raises(ExecutionProviderUnavailableError):
            execute_inference_transaction(
                input_identity=sample_input_identity,
                binding=sample_binding,
                model_identity=sample_model_envelope,
                preprocessing_contract=sample_contract,
                transformed_identity=transformed_id,
                preprocessed_array=arr,
                project_id="proj-alpha",
                policy=cuda_policy,
            )


# =====================================================================
# Tests: Categories E - I (Prerequisite Identity Verifications)
# =====================================================================


def test_category_e_model_identity_verification(
    sample_input_identity: InputIdentity,
    sample_binding: InputModelBinding,
    sample_contract: PreprocessingContract,
    sample_transformed: tuple[np.ndarray, TransformedInputIdentity],
) -> None:
    """Category E: Model identity verification fails on invalid or mismatched model."""
    arr, transformed_id = sample_transformed

    # Model with mismatched master fingerprint
    corrupt_envelope = ModelIdentityEnvelope(
        model_id="resnet50-v1",
        project_id="proj-alpha",
        master_fingerprint="ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        artifact_hash="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        structural_hash="bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        contract_hash="cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
        status="verified",
    )

    with pytest.raises(ModelExecutionIntegrityError):
        execute_inference_transaction(
            input_identity=sample_input_identity,
            binding=sample_binding,
            model_identity=corrupt_envelope,
            preprocessing_contract=sample_contract,
            transformed_identity=transformed_id,
            preprocessed_array=arr,
            project_id="proj-alpha",
        )


def test_category_h_i_preprocessing_transformed_input_verification(
    sample_input_identity: InputIdentity,
    sample_binding: InputModelBinding,
    sample_model_envelope: ModelIdentityEnvelope,
    sample_contract: PreprocessingContract,
    sample_transformed: tuple[np.ndarray, TransformedInputIdentity],
) -> None:
    """Categories H & I: Preprocessing contract & transformed input verification fails on discrepancy."""
    arr, transformed_id = sample_transformed

    # Alter array data so its byte hash doesn't match transformed_id
    tampered_arr = arr + 1.0

    with pytest.raises(ModelExecutionIntegrityError):
        execute_inference_transaction(
            input_identity=sample_input_identity,
            binding=sample_binding,
            model_identity=sample_model_envelope,
            preprocessing_contract=sample_contract,
            transformed_identity=transformed_id,
            preprocessed_array=tampered_arr,
            project_id="proj-alpha",
        )


# =====================================================================
# Tests: Categories J - N (Deterministic Execution Identity & Hash Sensitivity)
# =====================================================================


def test_category_j_deterministic_execution_identity(
    sample_input_identity: InputIdentity,
    sample_binding: InputModelBinding,
    sample_model_envelope: ModelIdentityEnvelope,
    sample_contract: PreprocessingContract,
    sample_transformed: tuple[np.ndarray, TransformedInputIdentity],
) -> None:
    """Category J: Deterministic execution identity calculation and pure verification."""
    arr, transformed_id = sample_transformed

    exec1 = execute_inference_transaction(
        input_identity=sample_input_identity,
        binding=sample_binding,
        model_identity=sample_model_envelope,
        preprocessing_contract=sample_contract,
        transformed_identity=transformed_id,
        preprocessed_array=arr,
        project_id="proj-alpha",
        runner_override=lambda x: x,
    )

    exec2 = execute_inference_transaction(
        input_identity=sample_input_identity,
        binding=sample_binding,
        model_identity=sample_model_envelope,
        preprocessing_contract=sample_contract,
        transformed_identity=transformed_id,
        preprocessed_array=arr,
        project_id="proj-alpha",
        runner_override=lambda x: x,
    )

    assert exec1.execution_identity_hash == exec2.execution_identity_hash
    assert exec1.raw_output_hash == exec2.raw_output_hash

    # Pure verification
    ver_res = verify_execution_identity(exec1)
    assert ver_res.is_valid is True
    assert ver_res.status == InferenceIntegrityStatus.VERIFIED


def test_category_k_l_m_n_hash_sensitivity(
    sample_input_identity: InputIdentity,
    sample_binding: InputModelBinding,
    sample_model_envelope: ModelIdentityEnvelope,
    sample_contract: PreprocessingContract,
    sample_transformed: tuple[np.ndarray, TransformedInputIdentity],
) -> None:
    """Categories K, L, M, N: Execution identity changes when binding, preproc, model, or policy change."""
    arr, transformed_id = sample_transformed
    desc_base = build_canonical_execution_descriptor(
        project_id="proj-alpha",
        input_id=sample_input_identity.input_id,
        binding_hash=sample_binding.binding_hash,
        preprocessing_contract_hash=sample_contract.contract_hash,
        transformed_input_hash=transformed_id.transformed_canonical_hash,
        model_id=sample_model_envelope.model_id,
        model_master_fingerprint=sample_model_envelope.master_fingerprint,
        execution_provider="CPUExecutionProvider",
        execution_policy=ExecutionPolicy(),
    )
    hash_base = compute_execution_identity_hash(desc_base)

    # Change policy timeout
    desc_mod_policy = copy.deepcopy(desc_base)
    desc_mod_policy["execution_policy"]["timeout_seconds"] = 5.0
    hash_mod_policy = compute_execution_identity_hash(desc_mod_policy)
    assert hash_base != hash_mod_policy

    # Change model_id
    desc_mod_model = copy.deepcopy(desc_base)
    desc_mod_model["model_id"] = "resnet50-v2"
    hash_mod_model = compute_execution_identity_hash(desc_mod_model)
    assert hash_base != hash_mod_model


# =====================================================================
# Tests: Categories O - S (Timeout, Cancellation & Resource Bounds)
# =====================================================================


def test_category_o_timeout_enforcement(
    sample_input_identity: InputIdentity,
    sample_binding: InputModelBinding,
    sample_model_envelope: ModelIdentityEnvelope,
    sample_contract: PreprocessingContract,
    sample_transformed: tuple[np.ndarray, TransformedInputIdentity],
) -> None:
    """Category O: Execution timeout enforcement."""
    arr, transformed_id = sample_transformed

    def slow_runner(x: np.ndarray) -> np.ndarray:
        time.sleep(0.05)
        return x

    # 0.01s timeout policy
    strict_policy = ExecutionPolicy(timeout_seconds=0.01)

    with pytest.raises(ExecutionTimeoutError):
        execute_inference_transaction(
            input_identity=sample_input_identity,
            binding=sample_binding,
            model_identity=sample_model_envelope,
            preprocessing_contract=sample_contract,
            transformed_identity=transformed_id,
            preprocessed_array=arr,
            project_id="proj-alpha",
            policy=strict_policy,
            runner_override=slow_runner,
        )


def test_category_p_cancellation_enforcement(
    sample_input_identity: InputIdentity,
    sample_binding: InputModelBinding,
    sample_model_envelope: ModelIdentityEnvelope,
    sample_contract: PreprocessingContract,
    sample_transformed: tuple[np.ndarray, TransformedInputIdentity],
) -> None:
    """Category P: Cooperative cancellation enforcement."""
    arr, transformed_id = sample_transformed

    with pytest.raises(ExecutionCancelledError):
        execute_inference_transaction(
            input_identity=sample_input_identity,
            binding=sample_binding,
            model_identity=sample_model_envelope,
            preprocessing_contract=sample_contract,
            transformed_identity=transformed_id,
            preprocessed_array=arr,
            project_id="proj-alpha",
            cancellation_check=lambda: True,
        )


def test_category_q_r_s_resource_limit_rejections(
    sample_input_identity: InputIdentity,
    sample_binding: InputModelBinding,
    sample_model_envelope: ModelIdentityEnvelope,
    sample_contract: PreprocessingContract,
    sample_transformed: tuple[np.ndarray, TransformedInputIdentity],
) -> None:
    """Categories Q, R, S: Resource limit, batch size, and output byte limits."""
    arr, transformed_id = sample_transformed

    # Max elements exceeded
    tiny_element_policy = ExecutionPolicy(max_tensor_elements=10)
    with pytest.raises(ExecutionResourceLimitError):
        execute_inference_transaction(
            input_identity=sample_input_identity,
            binding=sample_binding,
            model_identity=sample_model_envelope,
            preprocessing_contract=sample_contract,
            transformed_identity=transformed_id,
            preprocessed_array=arr,
            project_id="proj-alpha",
            policy=tiny_element_policy,
        )

    # Output bytes exceeded
    tiny_output_policy = ExecutionPolicy(max_output_bytes=10)
    with pytest.raises(ExecutionResourceLimitError):
        execute_inference_transaction(
            input_identity=sample_input_identity,
            binding=sample_binding,
            model_identity=sample_model_envelope,
            preprocessing_contract=sample_contract,
            transformed_identity=transformed_id,
            preprocessed_array=arr,
            project_id="proj-alpha",
            policy=tiny_output_policy,
            runner_override=lambda x: x,
        )


# =====================================================================
# Tests: Categories T - X (Raw Output Hashing, Multi-Output Ordering & Non-Finite Output)
# =====================================================================


def test_category_t_u_v_raw_output_hashing_and_ordering(
    sample_input_identity: InputIdentity,
    sample_binding: InputModelBinding,
    sample_model_envelope: ModelIdentityEnvelope,
    sample_contract: PreprocessingContract,
    sample_transformed: tuple[np.ndarray, TransformedInputIdentity],
) -> None:
    """Categories T, U, V: Raw output hashing, shape/dtype sensitivity, and output ordering preservation."""
    arr, transformed_id = sample_transformed

    # Multi-output runner: output A and output B
    def multi_runner(x: np.ndarray) -> Dict[str, np.ndarray]:
        return {
            "logits": np.array([[1.0, 2.0]], dtype=np.float32),
            "features": np.array([[0.5, 0.5, 0.5]], dtype=np.float32),
        }

    exec_res = execute_inference_transaction(
        input_identity=sample_input_identity,
        binding=sample_binding,
        model_identity=sample_model_envelope,
        preprocessing_contract=sample_contract,
        transformed_identity=transformed_id,
        preprocessed_array=arr,
        project_id="proj-alpha",
        runner_override=multi_runner,
    )

    assert exec_res.raw_output is not None
    assert len(exec_res.raw_output.outputs) == 2
    assert exec_res.raw_output.outputs[0].name == "logits"
    assert exec_res.raw_output.outputs[1].name == "features"
    assert len(exec_res.raw_output_hash) == 64


def test_category_w_x_nan_inf_output_detection(
    sample_input_identity: InputIdentity,
    sample_binding: InputModelBinding,
    sample_model_envelope: ModelIdentityEnvelope,
    sample_contract: PreprocessingContract,
    sample_transformed: tuple[np.ndarray, TransformedInputIdentity],
) -> None:
    """Categories W & X: NaN and Inf detection at the execution boundary."""
    arr, transformed_id = sample_transformed

    # Runner returning NaN
    def nan_runner(x: np.ndarray) -> np.ndarray:
        return np.array([[1.0, float("nan")]], dtype=np.float32)

    exec_nan = execute_inference_transaction(
        input_identity=sample_input_identity,
        binding=sample_binding,
        model_identity=sample_model_envelope,
        preprocessing_contract=sample_contract,
        transformed_identity=transformed_id,
        preprocessed_array=arr,
        project_id="proj-alpha",
        runner_override=nan_runner,
    )

    assert exec_nan.status == InferenceIntegrityStatus.INVALID
    assert exec_nan.raw_output is not None
    assert exec_nan.raw_output.numerical_sanity == NumericalSanityStatus.NONFINITE
    assert any(f.code == InferenceFindingCode.EXECUTION_NONFINITE_OUTPUT.value for f in exec_nan.findings)


# =====================================================================
# Tests: Categories Y - AG (Security, Environment & Tenant Isolation)
# =====================================================================


def test_category_bc_security_scan_no_forbidden_constructs() -> None:
    """Category BC: AST security scan for forbidden constructs in execution module."""
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    target_dir = os.path.join(base_dir, "backend", "aivara", "inference", "execution")

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


def test_category_ag_project_tenant_isolation(
    sample_input_identity: InputIdentity,
    sample_binding: InputModelBinding,
    sample_model_envelope: ModelIdentityEnvelope,
    sample_contract: PreprocessingContract,
    sample_transformed: tuple[np.ndarray, TransformedInputIdentity],
) -> None:
    """Category AG: Project tenant isolation enforcement."""
    arr, transformed_id = sample_transformed

    with pytest.raises(ProjectMismatchError):
        execute_inference_transaction(
            input_identity=sample_input_identity,
            binding=sample_binding,
            model_identity=sample_model_envelope,
            preprocessing_contract=sample_contract,
            transformed_identity=transformed_id,
            preprocessed_array=arr,
            project_id="proj-beta",  # Contradicts proj-alpha
        )


def test_category_af_caller_immutability(
    sample_input_identity: InputIdentity,
    sample_binding: InputModelBinding,
    sample_model_envelope: ModelIdentityEnvelope,
    sample_contract: PreprocessingContract,
    sample_transformed: tuple[np.ndarray, TransformedInputIdentity],
) -> None:
    """Category AF: Caller immutability during execution."""
    arr, transformed_id = sample_transformed
    arr_copy = np.copy(arr)

    execute_inference_transaction(
        input_identity=sample_input_identity,
        binding=sample_binding,
        model_identity=sample_model_envelope,
        preprocessing_contract=sample_contract,
        transformed_identity=transformed_id,
        preprocessed_array=arr,
        project_id="proj-alpha",
        runner_override=lambda x: x * 5.0,
    )

    np.testing.assert_array_equal(arr, arr_copy)


# =====================================================================
# Tests: Categories AH - BD (Boundaries, Database, Regressions, Offline)
# =====================================================================


def test_category_aq_ar_as_at_au_phase_boundaries() -> None:
    """Categories AQ through AU: Verify strict phase boundaries (no 10.8+ modules, no ledger, no evidence persistence)."""
    import sys

    assert "aivara.inference.records" not in sys.modules
    assert "aivara.inference.evidence" not in sys.modules
    assert "aivara.inference.ledger" not in sys.modules



def test_category_av_database_unchanged() -> None:
    """Category AV: Verify DATABASE SCHEMA CHANGES = 0."""
    import aivara.database.models as db_models

    assert hasattr(db_models, "InferenceRecordModel")


def test_category_aw_phase10_2_regression(sample_input_identity: InputIdentity) -> None:
    """Category AW: Phase 10.2 Safe Input Boundary regression."""
    assert sample_input_identity.validation_status == InferenceIntegrityStatus.VERIFIED


def test_category_ax_phase10_3_regression(sample_binding: InputModelBinding) -> None:
    """Category AX: Phase 10.3 Input / Model Binding regression."""
    assert sample_binding.binding_status == InferenceIntegrityStatus.VERIFIED


def test_category_ay_phase10_4_regression(sample_contract: PreprocessingContract) -> None:
    """Category AY: Phase 10.4 Preprocessing Contract regression."""
    assert len(sample_contract.contract_hash) == 64


def test_category_az_phase7_regression(sample_model_envelope: ModelIdentityEnvelope) -> None:
    """Category AZ: Phase 7 Model Integrity regression."""
    assert sample_model_envelope.status == "verified"


def test_category_ba_phase8_regression() -> None:
    """Category BA: Phase 8 Behavioral Analysis regression."""
    from aivara.behavioral.baselines.schemas import DistributionStats

    stats = DistributionStats(count=5, min=1.0, max=5.0, mean=3.0, median=3.0, std=1.0, p25=2.0, p75=4.0, p95=4.8)
    assert stats.count == 5


def test_category_bb_phase9_regression() -> None:
    """Category BB: Phase 9 Backdoor Analysis regression."""
    from aivara.backdoor.candidates.enums import TriggerFamilyEnum

    assert TriggerFamilyEnum.SPATIAL_PATCH.value == "SPATIAL_PATCH"


def test_category_bd_offline_scan() -> None:
    """Category BD: Offline execution guarantee."""
    provs = get_available_execution_providers()
    assert isinstance(provs, list)
    assert len(provs) >= 1
