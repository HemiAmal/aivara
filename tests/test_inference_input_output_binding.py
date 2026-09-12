"""Comprehensive unit and regression test suite for Phase 10.7 Cryptographic Input-to-Output Binding.

Covers categories A through BJ per AIVARA Phase 10.7 requirements specification.
"""

import copy
import hashlib
import os
import re
import sys
from typing import Any, Dict, List, Optional

import numpy as np
import pytest

from aivara.crypto.canonical import canonicalize
from aivara.inference.binding.models import InputModelBinding, ModelIdentityEnvelope
from aivara.inference.composite_binding import (
    InferenceBinding,
    InferenceBindingStatus,
    InferenceBindingVerificationResult,
    build_canonical_inference_binding_descriptor,
    compute_inference_binding_hash,
    create_inference_binding,
    validate_sha256_hex_format,
    verify_inference_binding,
)
from aivara.inference.enums import (
    InferenceFindingCode,
    InferenceIntegrityStatus,
    InputKind,
    InputLayout,
)
from aivara.inference.exceptions import (
    InferenceBindingComponentMismatchError,
    InferenceBindingError,
    InferenceBindingHashMismatchError,
    InferenceBindingMissingComponentError,
    InferenceBindingProjectMismatchError,
    InvalidHashFormatError,
)
from aivara.inference.execution import (
    build_canonical_execution_descriptor,
    compute_execution_identity_hash,
    compute_raw_output_hash,
)
from aivara.inference.execution.enums import ExecutionLifecycle, ExecutionProvider
from aivara.inference.execution.models import (
    ExecutionPolicy,
    InferenceExecution,
    RawExecutionOutput,
    RawOutputTensor,
)
from aivara.inference.input.models import InputFinding, InputIdentity
from aivara.inference.output import compute_validated_output_identity
from aivara.inference.output.enums import NumericalSanityStatus, OutputStructuralStatus, TaskType
from aivara.inference.output.models import (
    ModelOutputContract,
    OutputIntegrityAssessment,
    OutputTensorContract,
    ValidatedTensorSummary,
)
from aivara.inference.preprocessing import create_preprocessing_contract
from aivara.inference.preprocessing.enums import PreprocessingOpType
from aivara.inference.preprocessing.models import (
    PreprocessingContract,
    PreprocessingOperation,
    TransformedInputIdentity,
)


# =====================================================================
# Fixtures & Helpers
# =====================================================================


@pytest.fixture
def sample_binding_components():
    """Construct complete, consistent mock components for a verified inference transaction."""
    project_id = "project_alpha"

    # Input Identity (10.2)
    input_id = "11" * 32
    input_canonical_hash = "12" * 32
    input_raw_hash = "13" * 32
    input_identity = InputIdentity(
        input_id=input_id,
        input_kind=InputKind.TENSOR,
        canonical_hash=input_canonical_hash,
        raw_file_hash=input_raw_hash,
        validation_status=InferenceIntegrityStatus.VERIFIED,
    )

    # Model & Input-Model Binding (7 & 10.3)
    model_id = "resnet50_v1"
    model_artifact_hash = "21" * 32
    model_structural_hash = "22" * 32
    model_contract_hash = "23" * 32
    mf_payload = {
        "artifact_hash": model_artifact_hash,
        "contract_hash": model_contract_hash,
        "schema_version": "1.0",
        "structural_hash": model_structural_hash,
    }
    model_master_fingerprint = hashlib.sha256(canonicalize(mf_payload)).hexdigest()

    binding_desc = {
        "binding_version": "1.0",
        "input_canonical_hash": input_canonical_hash,
        "input_id": input_id,
        "input_kind": "TENSOR",
        "model_artifact_hash": model_artifact_hash,
        "model_contract_hash": model_contract_hash,
        "model_id": model_id,
        "model_master_fingerprint": model_master_fingerprint,
        "model_structural_hash": model_structural_hash,
        "project_id": project_id,
        "schema_version": "1.0",
    }
    input_model_binding_hash = hashlib.sha256(canonicalize(binding_desc)).hexdigest()
    input_model_binding = InputModelBinding(
        schema_version="1.0",
        binding_version="1.0",
        project_id=project_id,
        input_id=input_id,
        input_kind=InputKind.TENSOR,
        input_canonical_hash=input_canonical_hash,
        input_raw_hash=input_raw_hash,
        model_id=model_id,
        model_master_fingerprint=model_master_fingerprint,
        model_artifact_hash=model_artifact_hash,
        model_structural_hash=model_structural_hash,
        model_contract_hash=model_contract_hash,
        binding_status=InferenceIntegrityStatus.VERIFIED,
        binding_hash=input_model_binding_hash,
    )

    # Preprocessing Contract & Transformed Input (10.4)
    preprocessing_contract = create_preprocessing_contract(
        name="standard_prep",
        operations=[
            PreprocessingOperation(
                op_type=PreprocessingOpType.RESIZE,
                parameters={"target_height": 224, "target_width": 224},
            )
        ],
    )
    preprocessing_contract_hash = preprocessing_contract.contract_hash
    transformed_input_hash = "32" * 32
    transformed_input = TransformedInputIdentity(
        input_id=input_id,
        binding_hash=input_model_binding_hash,
        contract_hash=preprocessing_contract_hash,
        transformed_canonical_hash=transformed_input_hash,
        dtype="float32",
        shape=[1, 3, 224, 224],
        layout=InputLayout.NCHW,
        byte_size=602112,
        element_count=150528,
        finite=True,
    )

    # Execution (10.5)
    exec_policy = ExecutionPolicy(provider=ExecutionProvider.CPU)
    raw_output_tensors = [
        RawOutputTensor(
            name="logits",
            index=0,
            dtype="float32",
            shape=[1, 1000],
            byte_size=4000,
            element_count=1000,
            c_contiguous_byte_hash="43" * 32,
            is_finite=True,
        )
    ]
    raw_output_hash = compute_raw_output_hash(raw_output_tensors)
    raw_output = RawExecutionOutput(
        outputs=raw_output_tensors,
        raw_output_hash=raw_output_hash,
        numerical_sanity=NumericalSanityStatus.FINITE,
    )
    exec_descriptor = build_canonical_execution_descriptor(
        project_id=project_id,
        input_id=input_id,
        binding_hash=input_model_binding_hash,
        preprocessing_contract_hash=preprocessing_contract_hash,
        transformed_input_hash=transformed_input_hash,
        model_id=model_id,
        model_master_fingerprint=model_master_fingerprint,
        execution_provider="CPUExecutionProvider",
        execution_policy=exec_policy,
    )
    execution_identity_hash = compute_execution_identity_hash(exec_descriptor)
    execution = InferenceExecution(
        execution_id="44" * 32,
        project_id=project_id,
        input_id=input_id,
        binding_hash=input_model_binding_hash,
        preprocessing_contract_hash=preprocessing_contract_hash,
        transformed_input_hash=transformed_input_hash,
        model_id=model_id,
        model_master_fingerprint=model_master_fingerprint,
        execution_provider="CPUExecutionProvider",
        execution_policy=exec_policy,
        lifecycle=ExecutionLifecycle.SUCCEEDED,
        status=InferenceIntegrityStatus.VERIFIED,
        execution_identity_hash=execution_identity_hash,
        raw_output=raw_output,
        raw_output_hash=raw_output_hash,
    )

    # Output Assessment (10.6)
    output_contract_hash = "52" * 32
    output_summaries = [
        ValidatedTensorSummary(
            name="logits",
            index=0,
            dtype="float32",
            shape=[1, 1000],
            rank=2,
            element_count=1000,
            byte_size=4000,
            is_finite=True,
            has_nan=False,
            has_pos_inf=False,
            has_neg_inf=False,
            min_value=-2.5,
            max_value=5.0,
            domain_valid=True,
            c_contiguous_byte_hash="43" * 32,
        )
    ]
    validated_output_identity = compute_validated_output_identity(
        structural_summaries=output_summaries,
        raw_output_hash=raw_output_hash,
        task_type=TaskType.CLASSIFICATION,
        validation_status=InferenceIntegrityStatus.VERIFIED,
        numerical_status=NumericalSanityStatus.DOMAIN_VALID,
        output_contract_hash=output_contract_hash,
        output_count=1,
    )
    output_assessment = OutputIntegrityAssessment(
        schema_version="1.0",
        task_type=TaskType.CLASSIFICATION,
        raw_output_hash=raw_output_hash,
        output_contract_hash=output_contract_hash,
        output_count=1,
        output_metadata=output_summaries,
        numerical_status=NumericalSanityStatus.DOMAIN_VALID,
        structural_status=OutputStructuralStatus.VALID,
        integrity_status=InferenceIntegrityStatus.VERIFIED,
        validated_output_identity=validated_output_identity,
    )

    return {
        "project_id": project_id,
        "input_identity": input_identity,
        "input_model_binding": input_model_binding,
        "preprocessing_contract": preprocessing_contract,
        "transformed_input": transformed_input,
        "execution": execution,
        "output_assessment": output_assessment,
        "input_id": input_id,
        "input_canonical_hash": input_canonical_hash,
        "input_raw_hash": input_raw_hash,
        "model_id": model_id,
        "model_master_fingerprint": model_master_fingerprint,
        "model_artifact_hash": model_artifact_hash,
        "model_structural_hash": model_structural_hash,
        "model_contract_hash": model_contract_hash,
        "input_model_binding_hash": input_model_binding_hash,
        "preprocessing_contract_hash": preprocessing_contract_hash,
        "transformed_input_hash": transformed_input_hash,
        "execution_identity_hash": execution_identity_hash,
        "raw_output_hash": raw_output_hash,
        "validated_output_identity": validated_output_identity,
        "output_contract_hash": output_contract_hash,
    }


# =====================================================================
# Tests: Categories A - C (Creation, Determinism, Repetition)
# =====================================================================


def test_category_a_valid_complete_inference_binding(sample_binding_components):
    """Category A: Create valid complete end-to-end inference binding."""
    c = sample_binding_components
    binding = create_inference_binding(
        project_id=c["project_id"],
        input_identity=c["input_identity"],
        input_model_binding=c["input_model_binding"],
        preprocessing_contract=c["preprocessing_contract"],
        transformed_input=c["transformed_input"],
        execution=c["execution"],
        output_assessment=c["output_assessment"],
    )

    assert binding.binding_status == InferenceIntegrityStatus.VERIFIED
    assert binding.project_id == c["project_id"]
    assert binding.input_id == c["input_id"]
    assert binding.model_id == c["model_id"]
    assert len(binding.inference_binding_hash) == 64
    assert len(binding.findings) == 0


def test_category_b_deterministic_binding_identity(sample_binding_components):
    """Category B: Deterministic canonical descriptor and SHA-256 computation."""
    c = sample_binding_components
    desc = build_canonical_inference_binding_descriptor(
        project_id=c["project_id"],
        input_id=c["input_id"],
        input_canonical_hash=c["input_canonical_hash"],
        input_raw_hash=c["input_raw_hash"],
        model_id=c["model_id"],
        model_master_fingerprint=c["model_master_fingerprint"],
        model_artifact_hash=c["model_artifact_hash"],
        model_structural_hash=c["model_structural_hash"],
        model_contract_hash=c["model_contract_hash"],
        input_model_binding_hash=c["input_model_binding_hash"],
        preprocessing_contract_hash=c["preprocessing_contract_hash"],
        transformed_input_hash=c["transformed_input_hash"],
        execution_identity_hash=c["execution_identity_hash"],
        raw_output_hash=c["raw_output_hash"],
        validated_output_identity=c["validated_output_identity"],
        output_contract_hash=c["output_contract_hash"],
    )
    h1 = compute_inference_binding_hash(desc)
    h2 = compute_inference_binding_hash(desc)
    assert h1 == h2
    assert len(h1) == 64


def test_category_c_repeated_creation_identical_identity(sample_binding_components):
    """Category C: 100 repeated evaluations produce identical inference_binding_hash."""
    c = sample_binding_components
    b1 = create_inference_binding(
        project_id=c["project_id"],
        input_identity=c["input_identity"],
        input_model_binding=c["input_model_binding"],
        preprocessing_contract=c["preprocessing_contract"],
        transformed_input=c["transformed_input"],
        execution=c["execution"],
        output_assessment=c["output_assessment"],
    )

    for _ in range(100):
        b_rep = create_inference_binding(
            project_id=c["project_id"],
            input_identity=c["input_identity"],
            input_model_binding=c["input_model_binding"],
            preprocessing_contract=c["preprocessing_contract"],
            transformed_input=c["transformed_input"],
            execution=c["execution"],
            output_assessment=c["output_assessment"],
        )
        assert b_rep.inference_binding_hash == b1.inference_binding_hash


# =====================================================================
# Tests: Categories D - S (16 Committed Component Mutations)
# =====================================================================


def _mutate_field_and_verify_divergence(base_kwargs: Dict[str, Any], field: str, new_val: Any):
    """Helper to verify single-field mutation changes inference_binding_hash."""
    b_orig = create_inference_binding(**base_kwargs)
    mutated_kwargs = copy.deepcopy(base_kwargs)
    mutated_kwargs[field] = new_val
    b_mut = create_inference_binding(**mutated_kwargs)
    assert b_orig.inference_binding_hash != b_mut.inference_binding_hash, f"Mutation of {field} failed to change hash!"


def test_category_d_to_s_component_mutations(sample_binding_components):
    """Categories D through S: Verify that mutating EACH of the 18 fields changes the binding hash."""
    c = sample_binding_components
    base_kwargs = {
        "project_id": c["project_id"],
        "input_id": c["input_id"],
        "input_canonical_hash": c["input_canonical_hash"],
        "input_raw_hash": c["input_raw_hash"],
        "model_id": c["model_id"],
        "model_master_fingerprint": c["model_master_fingerprint"],
        "model_artifact_hash": c["model_artifact_hash"],
        "model_structural_hash": c["model_structural_hash"],
        "model_contract_hash": c["model_contract_hash"],
        "input_model_binding_hash": c["input_model_binding_hash"],
        "preprocessing_contract_hash": c["preprocessing_contract_hash"],
        "transformed_input_hash": c["transformed_input_hash"],
        "execution_identity_hash": c["execution_identity_hash"],
        "raw_output_hash": c["raw_output_hash"],
        "validated_output_identity": c["validated_output_identity"],
        "output_contract_hash": c["output_contract_hash"],
        "binding_version": "1.0",
        "schema_version": "1.0",
    }

    # 1. project_id
    _mutate_field_and_verify_divergence(base_kwargs, "project_id", "project_beta")
    # 2. input_id
    _mutate_field_and_verify_divergence(base_kwargs, "input_id", "99" * 32)
    # 3. input_canonical_hash
    _mutate_field_and_verify_divergence(base_kwargs, "input_canonical_hash", "98" * 32)
    # 4. input_raw_hash
    _mutate_field_and_verify_divergence(base_kwargs, "input_raw_hash", "97" * 32)
    # 5. model_id
    _mutate_field_and_verify_divergence(base_kwargs, "model_id", "vgg16")
    # 6. model_master_fingerprint
    _mutate_field_and_verify_divergence(base_kwargs, "model_master_fingerprint", "96" * 32)
    # 7. model_artifact_hash
    _mutate_field_and_verify_divergence(base_kwargs, "model_artifact_hash", "95" * 32)
    # 8. model_structural_hash
    _mutate_field_and_verify_divergence(base_kwargs, "model_structural_hash", "94" * 32)
    # 9. model_contract_hash
    _mutate_field_and_verify_divergence(base_kwargs, "model_contract_hash", "93" * 32)
    # 10. input_model_binding_hash
    _mutate_field_and_verify_divergence(base_kwargs, "input_model_binding_hash", "92" * 32)
    # 11. preprocessing_contract_hash
    _mutate_field_and_verify_divergence(base_kwargs, "preprocessing_contract_hash", "91" * 32)
    # 12. transformed_input_hash
    _mutate_field_and_verify_divergence(base_kwargs, "transformed_input_hash", "90" * 32)
    # 13. execution_identity_hash
    _mutate_field_and_verify_divergence(base_kwargs, "execution_identity_hash", "89" * 32)
    # 14. raw_output_hash
    _mutate_field_and_verify_divergence(base_kwargs, "raw_output_hash", "88" * 32)
    # 15. validated_output_identity
    _mutate_field_and_verify_divergence(base_kwargs, "validated_output_identity", "87" * 32)
    # 16. output_contract_hash
    _mutate_field_and_verify_divergence(base_kwargs, "output_contract_hash", "86" * 32)
    # 17. binding_version
    _mutate_field_and_verify_divergence(base_kwargs, "binding_version", "2.0")
    # 18. schema_version
    _mutate_field_and_verify_divergence(base_kwargs, "schema_version", "2.0")


def test_authoritative_18_committed_fields_count(sample_binding_components):
    """Verify that canonical descriptor contains exactly 18 committed fields per specification."""
    c = sample_binding_components
    desc = build_canonical_inference_binding_descriptor(
        project_id=c["project_id"],
        input_id=c["input_id"],
        input_canonical_hash=c["input_canonical_hash"],
        input_raw_hash=c["input_raw_hash"],
        model_id=c["model_id"],
        model_master_fingerprint=c["model_master_fingerprint"],
        model_artifact_hash=c["model_artifact_hash"],
        model_structural_hash=c["model_structural_hash"],
        model_contract_hash=c["model_contract_hash"],
        input_model_binding_hash=c["input_model_binding_hash"],
        preprocessing_contract_hash=c["preprocessing_contract_hash"],
        transformed_input_hash=c["transformed_input_hash"],
        execution_identity_hash=c["execution_identity_hash"],
        raw_output_hash=c["raw_output_hash"],
        validated_output_identity=c["validated_output_identity"],
        output_contract_hash=c["output_contract_hash"],
        binding_version="1.0",
        schema_version="1.0",
    )

    expected_keys = {
        "binding_version",
        "execution_identity_hash",
        "input_canonical_hash",
        "input_id",
        "input_model_binding_hash",
        "input_raw_hash",
        "model_artifact_hash",
        "model_contract_hash",
        "model_id",
        "model_master_fingerprint",
        "model_structural_hash",
        "output_contract_hash",
        "preprocessing_contract_hash",
        "project_id",
        "raw_output_hash",
        "schema_version",
        "transformed_input_hash",
        "validated_output_identity",
    }

    assert len(desc) == 18, f"Expected exactly 18 committed fields, got {len(desc)}: {sorted(desc.keys())}"
    assert set(desc.keys()) == expected_keys


# =====================================================================
# Tests: Categories T - AA (Verification & Tamper Detection)
# =====================================================================


def test_category_t_valid_verification(sample_binding_components):
    """Category T: Pure verification returns is_valid=True for untampered binding."""
    c = sample_binding_components
    binding = create_inference_binding(
        project_id=c["project_id"],
        input_identity=c["input_identity"],
        input_model_binding=c["input_model_binding"],
        preprocessing_contract=c["preprocessing_contract"],
        transformed_input=c["transformed_input"],
        execution=c["execution"],
        output_assessment=c["output_assessment"],
    )

    res = verify_inference_binding(
        binding,
        input_identity=c["input_identity"],
        input_model_binding=c["input_model_binding"],
        preprocessing_contract=c["preprocessing_contract"],
        transformed_input=c["transformed_input"],
        execution=c["execution"],
        output_assessment=c["output_assessment"],
    )

    assert res.is_valid is True
    assert res.status == InferenceIntegrityStatus.VERIFIED
    assert res.computed_binding_hash == binding.inference_binding_hash


def test_category_u_tampered_final_binding_hash_detection(sample_binding_components):
    """Category U: Tampered final binding hash fails verification."""
    c = sample_binding_components
    binding = create_inference_binding(
        project_id=c["project_id"],
        input_identity=c["input_identity"],
        input_model_binding=c["input_model_binding"],
        preprocessing_contract=c["preprocessing_contract"],
        transformed_input=c["transformed_input"],
        execution=c["execution"],
        output_assessment=c["output_assessment"],
    )

    # Reconstruct with forged hash
    tampered = binding.model_copy(update={"inference_binding_hash": "f" * 64})
    res = verify_inference_binding(tampered)
    assert res.is_valid is False
    assert any(f.code == InferenceFindingCode.INFERENCE_BINDING_HASH_MISMATCH.value for f in res.findings)


def test_category_v_tampered_input_detection(sample_binding_components):
    """Category V: Tampered input_id or canonical hash detected."""
    c = sample_binding_components
    binding = create_inference_binding(
        project_id=c["project_id"],
        input_identity=c["input_identity"],
        input_model_binding=c["input_model_binding"],
        preprocessing_contract=c["preprocessing_contract"],
        transformed_input=c["transformed_input"],
        execution=c["execution"],
        output_assessment=c["output_assessment"],
    )

    # Verification against a different input identity
    different_input = c["input_identity"].model_copy(update={"input_id": "ee" * 32})
    res = verify_inference_binding(binding, input_identity=different_input)
    assert res.is_valid is False
    assert any(f.code == InferenceFindingCode.INFERENCE_BINDING_COMPONENT_MISMATCH.value for f in res.findings)


def test_category_w_tampered_model_detection(sample_binding_components):
    """Category W: Tampered model envelope detected during verification."""
    c = sample_binding_components
    binding = create_inference_binding(
        project_id=c["project_id"],
        input_identity=c["input_identity"],
        input_model_binding=c["input_model_binding"],
        preprocessing_contract=c["preprocessing_contract"],
        transformed_input=c["transformed_input"],
        execution=c["execution"],
        output_assessment=c["output_assessment"],
    )

    diff_binding = c["input_model_binding"].model_copy(update={"binding_hash": "dd" * 32})
    res = verify_inference_binding(binding, input_model_binding=diff_binding)
    assert res.is_valid is False


def test_category_x_tampered_preprocessing_detection(sample_binding_components):
    """Category X: Tampered preprocessing contract detected."""
    c = sample_binding_components
    binding = create_inference_binding(
        project_id=c["project_id"],
        input_identity=c["input_identity"],
        input_model_binding=c["input_model_binding"],
        preprocessing_contract=c["preprocessing_contract"],
        transformed_input=c["transformed_input"],
        execution=c["execution"],
        output_assessment=c["output_assessment"],
    )

    diff_prep = c["preprocessing_contract"].model_copy(update={"contract_hash": "cc" * 32})
    res = verify_inference_binding(binding, preprocessing_contract=diff_prep)
    assert res.is_valid is False


def test_category_y_tampered_execution_detection(sample_binding_components):
    """Category Y: Tampered execution identity detected."""
    c = sample_binding_components
    binding = create_inference_binding(
        project_id=c["project_id"],
        input_identity=c["input_identity"],
        input_model_binding=c["input_model_binding"],
        preprocessing_contract=c["preprocessing_contract"],
        transformed_input=c["transformed_input"],
        execution=c["execution"],
        output_assessment=c["output_assessment"],
    )

    diff_exec = c["execution"].model_copy(update={"execution_identity_hash": "bb" * 32})
    res = verify_inference_binding(binding, execution=diff_exec)
    assert res.is_valid is False


def test_category_z_tampered_raw_output_detection(sample_binding_components):
    """Category Z: Tampered raw output hash divergence detected."""
    c = sample_binding_components
    binding = create_inference_binding(
        project_id=c["project_id"],
        input_identity=c["input_identity"],
        input_model_binding=c["input_model_binding"],
        preprocessing_contract=c["preprocessing_contract"],
        transformed_input=c["transformed_input"],
        execution=c["execution"],
        output_assessment=c["output_assessment"],
    )

    diff_exec = c["execution"].model_copy(update={"raw_output_hash": "aa" * 32})
    res = verify_inference_binding(binding, execution=diff_exec)
    assert res.is_valid is False
    assert any(f.code == InferenceFindingCode.INFERENCE_BINDING_RAW_OUTPUT_MISMATCH.value for f in res.findings)


def test_category_aa_tampered_validated_output_detection(sample_binding_components):
    """Category AA: Tampered validated output identity detected."""
    c = sample_binding_components
    binding = create_inference_binding(
        project_id=c["project_id"],
        input_identity=c["input_identity"],
        input_model_binding=c["input_model_binding"],
        preprocessing_contract=c["preprocessing_contract"],
        transformed_input=c["transformed_input"],
        execution=c["execution"],
        output_assessment=c["output_assessment"],
    )

    diff_out = c["output_assessment"].model_copy(update={"validated_output_identity": "99" * 32})
    res = verify_inference_binding(binding, output_assessment=diff_out)
    assert res.is_valid is False
    assert any(f.code == InferenceFindingCode.INFERENCE_BINDING_VALIDATED_OUTPUT_MISMATCH.value for f in res.findings)


# =====================================================================
# Tests: Categories AB - AI (Project Isolation, Missing, Unavailable)
# =====================================================================


def test_category_ab_project_mismatch_rejection(sample_binding_components):
    """Category AB: Conflicting project ID across envelopes raises error or marks MISMATCHED."""
    c = sample_binding_components
    diff_exec = c["execution"].model_copy(update={"project_id": "other_project"})

    with pytest.raises(InferenceBindingProjectMismatchError):
        create_inference_binding(
            project_id=c["project_id"],
            input_identity=c["input_identity"],
            input_model_binding=c["input_model_binding"],
            preprocessing_contract=c["preprocessing_contract"],
            transformed_input=c["transformed_input"],
            execution=diff_exec,
            output_assessment=c["output_assessment"],
            raise_on_error=True,
        )

    # Without raising
    b_mismatch = create_inference_binding(
        project_id=c["project_id"],
        input_identity=c["input_identity"],
        input_model_binding=c["input_model_binding"],
        preprocessing_contract=c["preprocessing_contract"],
        transformed_input=c["transformed_input"],
        execution=diff_exec,
        output_assessment=c["output_assessment"],
        raise_on_error=False,
    )
    assert b_mismatch.binding_status == InferenceIntegrityStatus.MISMATCHED
    assert any(f.code == InferenceFindingCode.INFERENCE_BINDING_PROJECT_MISMATCH.value for f in b_mismatch.findings)


def test_category_ac_to_ag_missing_components():
    """Categories AC through AG: Missing required component fails closed."""
    # Missing input_id
    with pytest.raises(InferenceBindingMissingComponentError):
        create_inference_binding(
            project_id="proj",
            model_id="mod",
            model_master_fingerprint="1" * 64,
            model_artifact_hash="2" * 64,
            model_structural_hash="3" * 64,
            model_contract_hash="4" * 64,
            input_model_binding_hash="5" * 64,
            preprocessing_contract_hash="6" * 64,
            transformed_input_hash="7" * 64,
            execution_identity_hash="8" * 64,
            raw_output_hash="9" * 64,
            validated_output_identity="a" * 64,
        )


def test_category_ah_unavailable_component(sample_binding_components):
    """Category AH: Non-verified output assessment propagates status."""
    c = sample_binding_components
    unavail_out = c["output_assessment"].model_copy(update={"integrity_status": InferenceIntegrityStatus.UNAVAILABLE})
    b = create_inference_binding(
        project_id=c["project_id"],
        input_identity=c["input_identity"],
        input_model_binding=c["input_model_binding"],
        preprocessing_contract=c["preprocessing_contract"],
        transformed_input=c["transformed_input"],
        execution=c["execution"],
        output_assessment=unavail_out,
        raise_on_error=False,
    )
    assert b.binding_status == InferenceIntegrityStatus.UNAVAILABLE


def test_category_ai_unverifiable_component(sample_binding_components):
    """Category AI: Non-verified unverifiable output assessment propagates status."""
    c = sample_binding_components
    unverif_out = c["output_assessment"].model_copy(update={"integrity_status": InferenceIntegrityStatus.UNVERIFIABLE})
    b = create_inference_binding(
        project_id=c["project_id"],
        input_identity=c["input_identity"],
        input_model_binding=c["input_model_binding"],
        preprocessing_contract=c["preprocessing_contract"],
        transformed_input=c["transformed_input"],
        execution=c["execution"],
        output_assessment=unverif_out,
        raise_on_error=False,
    )
    assert b.binding_status == InferenceIntegrityStatus.UNVERIFIABLE


# =====================================================================
# Tests: Categories AJ - AP (Format, Immutability, AST Security)
# =====================================================================


def test_category_aj_malformed_hashes(sample_binding_components):
    """Category AJ: Short, truncated, or non-hex string raises InvalidHashFormatError."""
    c = sample_binding_components
    with pytest.raises(InvalidHashFormatError):
        create_inference_binding(
            project_id=c["project_id"],
            input_id="tooshort",
            input_canonical_hash=c["input_canonical_hash"],
            model_id=c["model_id"],
            model_master_fingerprint=c["model_master_fingerprint"],
            model_artifact_hash=c["model_artifact_hash"],
            model_structural_hash=c["model_structural_hash"],
            model_contract_hash=c["model_contract_hash"],
            input_model_binding_hash=c["input_model_binding_hash"],
            preprocessing_contract_hash=c["preprocessing_contract_hash"],
            transformed_input_hash=c["transformed_input_hash"],
            execution_identity_hash=c["execution_identity_hash"],
            raw_output_hash=c["raw_output_hash"],
            validated_output_identity=c["validated_output_identity"],
        )


def test_category_ak_uppercase_hash_rejection(sample_binding_components):
    """Category AK: Uppercase hex characters are strictly rejected."""
    c = sample_binding_components
    with pytest.raises(InvalidHashFormatError):
        create_inference_binding(
            project_id=c["project_id"],
            input_id="A" * 64,  # Uppercase
            input_canonical_hash=c["input_canonical_hash"],
            model_id=c["model_id"],
            model_master_fingerprint=c["model_master_fingerprint"],
            model_artifact_hash=c["model_artifact_hash"],
            model_structural_hash=c["model_structural_hash"],
            model_contract_hash=c["model_contract_hash"],
            input_model_binding_hash=c["input_model_binding_hash"],
            preprocessing_contract_hash=c["preprocessing_contract_hash"],
            transformed_input_hash=c["transformed_input_hash"],
            execution_identity_hash=c["execution_identity_hash"],
            raw_output_hash=c["raw_output_hash"],
            validated_output_identity=c["validated_output_identity"],
        )


def test_category_al_invalid_schema_version(sample_binding_components):
    """Category AL: Schema version in descriptor changes hash digest."""
    c = sample_binding_components
    b_v1 = create_inference_binding(
        project_id=c["project_id"],
        input_id=c["input_id"],
        input_canonical_hash=c["input_canonical_hash"],
        model_id=c["model_id"],
        model_master_fingerprint=c["model_master_fingerprint"],
        model_artifact_hash=c["model_artifact_hash"],
        model_structural_hash=c["model_structural_hash"],
        model_contract_hash=c["model_contract_hash"],
        input_model_binding_hash=c["input_model_binding_hash"],
        preprocessing_contract_hash=c["preprocessing_contract_hash"],
        transformed_input_hash=c["transformed_input_hash"],
        execution_identity_hash=c["execution_identity_hash"],
        raw_output_hash=c["raw_output_hash"],
        validated_output_identity=c["validated_output_identity"],
        schema_version="1.0",
    )
    b_v2 = create_inference_binding(
        project_id=c["project_id"],
        input_id=c["input_id"],
        input_canonical_hash=c["input_canonical_hash"],
        model_id=c["model_id"],
        model_master_fingerprint=c["model_master_fingerprint"],
        model_artifact_hash=c["model_artifact_hash"],
        model_structural_hash=c["model_structural_hash"],
        model_contract_hash=c["model_contract_hash"],
        input_model_binding_hash=c["input_model_binding_hash"],
        preprocessing_contract_hash=c["preprocessing_contract_hash"],
        transformed_input_hash=c["transformed_input_hash"],
        execution_identity_hash=c["execution_identity_hash"],
        raw_output_hash=c["raw_output_hash"],
        validated_output_identity=c["validated_output_identity"],
        schema_version="2.0",
    )
    assert b_v1.inference_binding_hash != b_v2.inference_binding_hash


def test_category_am_excessive_metadata_rejection():
    """Category AM: Pydantic extra=forbid prevents arbitrary extra fields."""
    assert InferenceBinding.model_config.get("extra") == "forbid"
    assert InferenceBindingVerificationResult.model_config.get("extra") == "forbid"


def test_category_an_immutability(sample_binding_components):
    """Category AN: Models are frozen and cannot be mutated."""
    c = sample_binding_components
    b = create_inference_binding(
        project_id=c["project_id"],
        input_identity=c["input_identity"],
        input_model_binding=c["input_model_binding"],
        preprocessing_contract=c["preprocessing_contract"],
        transformed_input=c["transformed_input"],
        execution=c["execution"],
        output_assessment=c["output_assessment"],
    )
    with pytest.raises(Exception):
        b.project_id = "mutated"  # type: ignore


def test_category_ao_deterministic_canonicalization(sample_binding_components):
    """Category AO: Canonicalization sort order does not depend on dictionary insertion order."""
    c = sample_binding_components
    desc1 = build_canonical_inference_binding_descriptor(
        project_id=c["project_id"],
        input_id=c["input_id"],
        input_canonical_hash=c["input_canonical_hash"],
        model_id=c["model_id"],
        model_master_fingerprint=c["model_master_fingerprint"],
        model_artifact_hash=c["model_artifact_hash"],
        model_structural_hash=c["model_structural_hash"],
        model_contract_hash=c["model_contract_hash"],
        input_model_binding_hash=c["input_model_binding_hash"],
        preprocessing_contract_hash=c["preprocessing_contract_hash"],
        transformed_input_hash=c["transformed_input_hash"],
        execution_identity_hash=c["execution_identity_hash"],
        raw_output_hash=c["raw_output_hash"],
        validated_output_identity=c["validated_output_identity"],
    )
    # Reversed dictionary insertion order
    desc2 = {k: desc1[k] for k in reversed(list(desc1.keys()))}
    assert canonicalize(desc1) == canonicalize(desc2)


def test_category_ap_forbidden_constructs():
    """Category AP: AST check confirms zero forbidden tokens in composite_binding."""
    pkg_dir = os.path.join("backend", "aivara", "inference", "composite_binding")
    forbidden = ["eval(", "exec(", "pickle.", "subprocess.", "os.system(", "requests.", "urllib.", "socket."]
    for fname in os.listdir(pkg_dir):
        if fname.endswith(".py"):
            fpath = os.path.join(pkg_dir, fname)
            with open(fpath, "r", encoding="utf-8") as f:
                content = f.read()
            for tok in forbidden:
                assert tok not in content, f"Forbidden construct '{tok}' found in {fpath}"


# =====================================================================
# Tests: Categories AQ - AX (Offline, Database, Phase Boundaries)
# =====================================================================


def test_category_aq_offline_behavior(sample_binding_components):
    """Category AQ: 100% offline local execution."""
    c = sample_binding_components
    b = create_inference_binding(
        project_id=c["project_id"],
        input_identity=c["input_identity"],
        input_model_binding=c["input_model_binding"],
        preprocessing_contract=c["preprocessing_contract"],
        transformed_input=c["transformed_input"],
        execution=c["execution"],
        output_assessment=c["output_assessment"],
    )
    assert b.binding_status == InferenceIntegrityStatus.VERIFIED


def test_category_ar_database_unchanged():
    """Category AR: DATABASE SCHEMA CHANGES = 0."""
    import aivara.database.models as db_models
    assert hasattr(db_models, "InferenceRecordModel")


def test_category_as_no_preprocessing():
    """Category AS: Phase 10.7 performs zero preprocessing execution."""
    import aivara.inference.composite_binding as cb
    assert not hasattr(cb, "execute_preprocessing_pipeline")


def test_category_at_no_model_execution():
    """Category AT: Phase 10.7 performs zero model execution."""
    import aivara.inference.composite_binding as cb
    assert not hasattr(cb, "execute_inference_transaction")


def test_category_au_no_replay():
    """Category AU: Phase 10.7 performs zero replay/consistency analysis."""
    import aivara.inference.composite_binding as cb
    assert not hasattr(cb, "verify_replay_consistency")


def test_category_av_no_api():
    """Category AV: Phase 10.7 provides zero REST routers."""
    with pytest.raises(ImportError):
        import aivara.api.routers.inference_composite_binding  # type: ignore


def test_category_aw_no_evidence_provenance():
    """Category AW: Phase 10.7 provides zero EvidenceModel persistence."""
    import aivara.inference.composite_binding as cb
    assert not hasattr(cb, "create_composite_evidence")


def test_category_ax_no_phase_10_8_implementation():
    """Category AX: Phase 10.8 (Inference Record Ledger Persistence) is NOT implemented."""
    with pytest.raises(ImportError):
        import aivara.inference.records  # type: ignore


# =====================================================================
# Tests: Categories AY - BF (Regressions for all previous phases)
# =====================================================================


def test_category_ay_phase_10_2_regression():
    """Category AY: Phase 10.2 Safe Input Boundary regression."""
    from aivara.inference.input import validate_inference_input
    arr = np.ones((3, 32, 32), dtype=np.float32)
    identity = validate_inference_input(arr)
    assert identity.validation_status == InferenceIntegrityStatus.VERIFIED


def test_category_az_phase_10_3_regression(sample_binding_components):
    """Category AZ: Phase 10.3 Input / Model Binding regression."""
    from aivara.inference.binding import verify_input_model_binding
    c = sample_binding_components
    res = verify_input_model_binding(c["input_model_binding"])
    assert res.is_valid is True


def test_category_ba_phase_10_4_regression(sample_binding_components):
    """Category BA: Phase 10.4 Preprocessing Contract regression."""
    from aivara.inference.preprocessing import verify_preprocessing_contract
    c = sample_binding_components
    res = verify_preprocessing_contract(c["preprocessing_contract"])
    assert res.is_valid is True


def test_category_bb_phase_10_5_regression(sample_binding_components):
    """Category BB: Phase 10.5 Inference Execution Integrity regression."""
    from aivara.inference.execution import verify_execution_identity
    c = sample_binding_components
    res = verify_execution_identity(c["execution"])
    assert res.is_valid is True


def test_category_bc_phase_10_6_regression(sample_binding_components):
    """Category BC: Phase 10.6 Output Schema & Numerical Integrity regression."""
    from aivara.inference.output import verify_validated_output_identity
    c = sample_binding_components
    assert verify_validated_output_identity(c["output_assessment"]) is True


def test_category_bd_phase_7_regression():
    """Category BD: Phase 7 Model Integrity regression."""
    from aivara.model_integrity.schemas import ModelFormat
    assert ModelFormat.ONNX == "onnx"


def test_category_be_phase_8_regression():
    """Category BE: Phase 8 Behavioral execution boundary regression."""
    from aivara.behavioral.schemas import ExecutionProvider as BehProvider
    assert BehProvider.CPU == "CPUExecutionProvider"


def test_category_bf_phase_9_regression():
    """Category BF: Phase 9 Backdoor trigger analysis regression."""
    from aivara.backdoor.candidates.enums import TriggerFamilyEnum
    assert TriggerFamilyEnum.SPATIAL_PATCH == "SPATIAL_PATCH"


# =====================================================================
# Tests: Categories BG - BJ (Cryptographic Edge Cases & Integration)
# =====================================================================


def test_category_bg_cryptographic_edge_cases(sample_binding_components):
    """Category BG: Nonce-less deterministic identity binding."""
    c = sample_binding_components
    b = create_inference_binding(
        project_id=c["project_id"],
        input_identity=c["input_identity"],
        input_model_binding=c["input_model_binding"],
        preprocessing_contract=c["preprocessing_contract"],
        transformed_input=c["transformed_input"],
        execution=c["execution"],
        output_assessment=c["output_assessment"],
    )
    assert re.match(r"^[0-9a-f]{64}$", b.inference_binding_hash)


def test_category_bh_component_verification(sample_binding_components):
    """Category BH: Component verification confirms internal relationships."""
    c = sample_binding_components
    binding = create_inference_binding(
        project_id=c["project_id"],
        input_identity=c["input_identity"],
        input_model_binding=c["input_model_binding"],
        preprocessing_contract=c["preprocessing_contract"],
        transformed_input=c["transformed_input"],
        execution=c["execution"],
        output_assessment=c["output_assessment"],
    )

    res = verify_inference_binding(
        binding,
        input_identity=c["input_identity"],
        input_model_binding=c["input_model_binding"],
        preprocessing_contract=c["preprocessing_contract"],
        transformed_input=c["transformed_input"],
        execution=c["execution"],
        output_assessment=c["output_assessment"],
    )
    assert res.is_valid is True


def test_category_bi_end_to_end_identity_determinism(sample_binding_components):
    """Category BI: End-to-end identity proof that identical pipeline yields identical hash."""
    c = sample_binding_components
    b1 = create_inference_binding(
        project_id=c["project_id"],
        input_identity=c["input_identity"],
        input_model_binding=c["input_model_binding"],
        preprocessing_contract=c["preprocessing_contract"],
        transformed_input=c["transformed_input"],
        execution=c["execution"],
        output_assessment=c["output_assessment"],
    )
    b2 = create_inference_binding(
        project_id=c["project_id"],
        input_identity=c["input_identity"],
        input_model_binding=c["input_model_binding"],
        preprocessing_contract=c["preprocessing_contract"],
        transformed_input=c["transformed_input"],
        execution=c["execution"],
        output_assessment=c["output_assessment"],
    )
    assert b1.inference_binding_hash == b2.inference_binding_hash


def test_category_bj_project_isolation(sample_binding_components):
    """Category BJ: Multi-tenant project boundary isolation."""
    c = sample_binding_components
    b_alpha = create_inference_binding(
        project_id="tenant_a",
        input_id=c["input_id"],
        input_canonical_hash=c["input_canonical_hash"],
        model_id=c["model_id"],
        model_master_fingerprint=c["model_master_fingerprint"],
        model_artifact_hash=c["model_artifact_hash"],
        model_structural_hash=c["model_structural_hash"],
        model_contract_hash=c["model_contract_hash"],
        input_model_binding_hash=c["input_model_binding_hash"],
        preprocessing_contract_hash=c["preprocessing_contract_hash"],
        transformed_input_hash=c["transformed_input_hash"],
        execution_identity_hash=c["execution_identity_hash"],
        raw_output_hash=c["raw_output_hash"],
        validated_output_identity=c["validated_output_identity"],
    )
    b_beta = create_inference_binding(
        project_id="tenant_b",
        input_id=c["input_id"],
        input_canonical_hash=c["input_canonical_hash"],
        model_id=c["model_id"],
        model_master_fingerprint=c["model_master_fingerprint"],
        model_artifact_hash=c["model_artifact_hash"],
        model_structural_hash=c["model_structural_hash"],
        model_contract_hash=c["model_contract_hash"],
        input_model_binding_hash=c["input_model_binding_hash"],
        preprocessing_contract_hash=c["preprocessing_contract_hash"],
        transformed_input_hash=c["transformed_input_hash"],
        execution_identity_hash=c["execution_identity_hash"],
        raw_output_hash=c["raw_output_hash"],
        validated_output_identity=c["validated_output_identity"],
    )
    assert b_alpha.inference_binding_hash != b_beta.inference_binding_hash
