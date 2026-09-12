"""Comprehensive test suite for Phase 10.9 Replay & Consistency Verification."""

import copy
import hashlib
import os
import re
from typing import Any, Dict, List, Optional

import numpy as np
import pytest

from aivara.crypto.canonical import canonicalize
from aivara.inference.binding.engine import create_input_model_binding
from aivara.inference.binding.models import (
    InputModelBinding,
    ModelIdentityEnvelope,
)
from aivara.inference.composite_binding.engine import (
    build_canonical_inference_binding_descriptor,
    compute_inference_binding_hash,
)
from aivara.inference.composite_binding.models import InferenceBinding
from aivara.inference.enums import (
    InferenceFindingCode,
    InferenceIntegrityStatus,
    InputKind,
    InputLayout,
    ValueRangeKind,
)
from aivara.inference.exceptions import (
    ExecutionResourceLimitError,
    ExecutionTimeoutError,
    InvalidHashFormatError,
    ReplayIneligibleError,
    ReplayNumericalDivergenceError,
    ReplayProjectMismatchError,
    ReplayRecordInvalidError,
    ReplayStructuralDivergenceError,
    ReplayVersionUnsupportedError,
)
from aivara.inference.execution.enums import ExecutionProvider
from aivara.inference.execution.models import (
    ExecutionPolicy,
    InferenceExecution,
    RawExecutionOutput,
    RawOutputTensor,
)
from aivara.inference.input.models import InputIdentity
from aivara.inference.preprocessing.engine import create_preprocessing_contract
from aivara.inference.preprocessing.models import (
    PreprocessingContract,
    TransformedInputIdentity,
)
from aivara.inference.records.engine import (
    build_canonical_record_descriptor,
    compute_record_integrity_hash,
    create_inference_record,
)
from aivara.inference.records.enums import (
    InferenceRecordStatus,
    InferenceRecordType,
)
from aivara.inference.records.models import InferenceRecord
from aivara.inference.replay import (
    DEFAULT_DETERMINISTIC_POLICY,
    DEFAULT_TOLERANT_POLICY,
    ComparisonStatus,
    InferenceReplayService,
    ReplayComparisonResult,
    ReplayConsistencyStatus,
    ReplayEligibilityStatus,
    ReplayEnvironment,
    ReplayMode,
    ReplayPolicy,
    ReplayVerificationResult,
    assess_replay_eligibility,
    compare_raw_outputs,
    execute_replay_transaction,
    validate_replay_policy,
    verify_replay_consistency,
)


@pytest.fixture
def sample_verified_record_and_components():
    """Fixture providing a verified Phase 10.8 InferenceRecord and its underlying Phase 10.2-10.7 components."""
    project_id = "project_alpha"
    model_id = "model_resnet"

    # Input Identity (10.2)
    input_id = "11" * 32
    input_raw_hash = "12" * 32
    input_canonical_hash = "13" * 32
    input_identity = InputIdentity(
        schema_version="1.0",
        input_id=input_id,
        input_kind=InputKind.TENSOR,
        canonical_hash=input_canonical_hash,
        dtype="float32",
        shape=(1, 3, 32, 32),
        layout=InputLayout.NCHW,
        value_range=ValueRangeKind.UNIT_FLOAT,
        finite=True,
        byte_size=12288,
        element_count=3072,
        validation_status=InferenceIntegrityStatus.VERIFIED,
    )

    # Model Identity (10.3 / Phase 7)
    model_artifact_hash = "21" * 32
    model_structural_hash = "22" * 32
    model_contract_hash = "23" * 32
    master_desc = {
        "artifact_hash": model_artifact_hash,
        "contract_hash": model_contract_hash,
        "schema_version": "1.0",
        "structural_hash": model_structural_hash,
    }
    model_master_fingerprint = hashlib.sha256(canonicalize(master_desc)).hexdigest()
    model_envelope = ModelIdentityEnvelope(
        model_id=model_id,
        project_id=project_id,
        master_fingerprint=model_master_fingerprint,
        artifact_hash=model_artifact_hash,
        structural_hash=model_structural_hash,
        contract_hash=model_contract_hash,
        status="verified",
    )

    # Input-Model Binding (10.3)
    binding = create_input_model_binding(
        input_identity=input_identity,
        model_identity=model_envelope,
        project_id=project_id,
    )
    input_model_binding_hash = binding.binding_hash

    # Preprocessing (10.4)
    preprocessing_contract = create_preprocessing_contract(
        name="test_prep_contract",
        operations=[],
    )
    preprocessing_contract_hash = preprocessing_contract.contract_hash
    preprocessed_array = np.ones((1, 3, 32, 32), dtype=np.float32)
    array_bytes = np.ascontiguousarray(preprocessed_array).tobytes()
    transformed_input_hash = hashlib.sha256(array_bytes).hexdigest()

    transformed_input = TransformedInputIdentity(
        input_id=input_id,
        binding_hash=input_model_binding_hash,
        contract_hash=preprocessing_contract_hash,
        transformed_canonical_hash=transformed_input_hash,
        dtype="float32",
        shape=[1, 3, 32, 32],
        layout=InputLayout.NCHW,
        byte_size=12288,
        element_count=3072,
        finite=True,
    )

    # Execution (10.5)
    raw_output_array = np.array([[0.1, 0.9, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0]], dtype=np.float32)
    baseline_exec = execute_replay_transaction(
        project_id=project_id,
        input_identity=input_identity,
        binding=binding,
        model_identity=model_envelope,
        preprocessing_contract=preprocessing_contract,
        transformed_identity=transformed_input,
        preprocessed_array=preprocessed_array,
        runner_override=lambda arr: raw_output_array,
    )
    execution_identity_hash = baseline_exec.execution_identity_hash
    raw_output_hash = baseline_exec.raw_output.raw_output_hash

    # Validated Output (10.6)
    validated_output_identity = "51" * 32
    output_contract_hash = "52" * 32

    # Composite Binding (10.7)
    comp_desc = build_canonical_inference_binding_descriptor(
        project_id=project_id,
        input_id=input_id,
        input_canonical_hash=input_canonical_hash,
        input_raw_hash=input_raw_hash,
        model_id=model_id,
        model_master_fingerprint=model_master_fingerprint,
        model_artifact_hash=model_artifact_hash,
        model_structural_hash=model_structural_hash,
        model_contract_hash=model_contract_hash,
        input_model_binding_hash=input_model_binding_hash,
        preprocessing_contract_hash=preprocessing_contract_hash,
        transformed_input_hash=transformed_input_hash,
        execution_identity_hash=execution_identity_hash,
        raw_output_hash=raw_output_hash,
        validated_output_identity=validated_output_identity,
        output_contract_hash=output_contract_hash,
        binding_version="1.0",
        schema_version="1.0",
    )
    inference_binding_hash = compute_inference_binding_hash(comp_desc)
    composite_binding = InferenceBinding(
        schema_version="1.0",
        binding_version="1.0",
        project_id=project_id,
        input_id=input_id,
        input_canonical_hash=input_canonical_hash,
        input_raw_hash=input_raw_hash,
        model_id=model_id,
        model_master_fingerprint=model_master_fingerprint,
        model_artifact_hash=model_artifact_hash,
        model_structural_hash=model_structural_hash,
        model_contract_hash=model_contract_hash,
        input_model_binding_hash=input_model_binding_hash,
        preprocessing_contract_hash=preprocessing_contract_hash,
        transformed_input_hash=transformed_input_hash,
        execution_identity_hash=execution_identity_hash,
        raw_output_hash=raw_output_hash,
        validated_output_identity=validated_output_identity,
        output_contract_hash=output_contract_hash,
        inference_binding_hash=inference_binding_hash,
        binding_status=InferenceIntegrityStatus.VERIFIED,
        details={
            "raw_output_tensors": [
                {"name": "output_0", "shape": [1, 10], "dtype": "float32"}
            ]
        },
    )

    # Persistent Record (10.8)
    record = create_inference_record(
        project_id=project_id,
        binding=composite_binding,
        record_id="rec_alpha_001",
        record_type=InferenceRecordType.STANDARD,
    )

    return {
        "record": record,
        "input_identity": input_identity,
        "model_envelope": model_envelope,
        "binding": binding,
        "preprocessing_contract": preprocessing_contract,
        "transformed_input": transformed_input,
        "preprocessed_array": preprocessed_array,
        "raw_output_array": raw_output_array,
        "raw_output_hash": raw_output_hash,
        "composite_binding": composite_binding,
    }


# =====================================================================
# CATEGORY A — ELIGIBILITY
# =====================================================================


def test_category_a_valid_record_is_replay_eligible(sample_verified_record_and_components):
    """Category A: 1. Valid Phase 10.8 record with verified Phase 10.7 binding is replay eligible."""
    rec = sample_verified_record_and_components["record"]
    status, findings = assess_replay_eligibility(rec, expected_project_id="project_alpha")
    assert status == ReplayEligibilityStatus.ELIGIBLE
    assert len(findings) == 0


def test_category_a_tampered_record_rejected(sample_verified_record_and_components):
    """Category A: 2. Tampered record (invalid integrity hash) is rejected."""
    rec = sample_verified_record_and_components["record"]
    # Mutate record integrity hash
    tampered_rec = InferenceRecord(
        schema_version=rec.schema_version,
        record_version=rec.record_version,
        record_id=rec.record_id,
        project_id=rec.project_id,
        record_type=rec.record_type,
        binding_version=rec.binding_version,
        inference_binding_hash=rec.inference_binding_hash,
        record_integrity_hash="99" * 32,  # tampered
        record_status=rec.record_status,
        binding=rec.binding,
    )

    status, findings = assess_replay_eligibility(tampered_rec, expected_project_id="project_alpha")
    assert status == ReplayEligibilityStatus.INVALID_RECORD
    assert any(f.code == InferenceFindingCode.INFERENCE_REPLAY_RECORD_INVALID.value for f in findings)


def test_category_a_invalid_binding_rejected(sample_verified_record_and_components):
    """Category A: 3. Tampered Phase 10.7 binding within record is rejected."""
    rec = sample_verified_record_and_components["record"]
    tampered_binding = copy.deepcopy(rec.binding)
    # Tamper binding hash
    tampered_binding_obj = InferenceBinding(
        schema_version=tampered_binding.schema_version,
        binding_version=tampered_binding.binding_version,
        project_id=tampered_binding.project_id,
        input_id=tampered_binding.input_id,
        input_canonical_hash=tampered_binding.input_canonical_hash,
        input_raw_hash=tampered_binding.input_raw_hash,
        model_id=tampered_binding.model_id,
        model_master_fingerprint=tampered_binding.model_master_fingerprint,
        model_artifact_hash=tampered_binding.model_artifact_hash,
        model_structural_hash=tampered_binding.model_structural_hash,
        model_contract_hash=tampered_binding.model_contract_hash,
        input_model_binding_hash=tampered_binding.input_model_binding_hash,
        preprocessing_contract_hash=tampered_binding.preprocessing_contract_hash,
        transformed_input_hash=tampered_binding.transformed_input_hash,
        execution_identity_hash=tampered_binding.execution_identity_hash,
        raw_output_hash=tampered_binding.raw_output_hash,
        validated_output_identity=tampered_binding.validated_output_identity,
        inference_binding_hash="88" * 32,  # wrong hash
        binding_status=InferenceIntegrityStatus.VERIFIED,
    )

    rec_with_bad_binding = InferenceRecord(
        schema_version="1.0",
        record_version="1.0",
        record_id="rec_bad_b",
        project_id=rec.project_id,
        record_type=rec.record_type,
        binding_version=rec.binding_version,
        inference_binding_hash=tampered_binding_obj.inference_binding_hash,
        record_integrity_hash="77" * 32,
        record_status=InferenceRecordStatus.INVALID,
        binding=tampered_binding_obj,
    )
    status, findings = assess_replay_eligibility(rec_with_bad_binding, expected_project_id="project_alpha")
    assert status in (ReplayEligibilityStatus.INVALID_BINDING, ReplayEligibilityStatus.INVALID_RECORD)


def test_category_a_project_mismatch_rejected(sample_verified_record_and_components):
    """Category A: 4. Project mismatch is rejected prior to execution."""
    rec = sample_verified_record_and_components["record"]
    status, findings = assess_replay_eligibility(rec, expected_project_id="project_other")
    assert status == ReplayEligibilityStatus.PROJECT_MISMATCH
    assert any(f.code == InferenceFindingCode.INFERENCE_REPLAY_PROJECT_MISMATCH.value for f in findings)


def test_category_a_unsupported_version_rejected(sample_verified_record_and_components):
    """Category A: 7. Unsupported replay policy version fails closed."""
    rec = sample_verified_record_and_components["record"]
    bad_policy = ReplayPolicy(policy_version="99.0")
    status, findings = assess_replay_eligibility(rec, policy=bad_policy)
    assert status == ReplayEligibilityStatus.UNSUPPORTED_VERSION


# =====================================================================
# CATEGORY B — EXACT REPLAY & CONTROLLED EXECUTION
# =====================================================================


def test_category_b_exact_deterministic_replay(sample_verified_record_and_components):
    """Category B: 8-11 Controlled replay producing identical output is classified CONSISTENT_EXACT."""
    c = sample_verified_record_and_components
    service = InferenceReplayService()

    # Replay using identical output runner override
    result = service.orchestrate_replay(
        record=c["record"],
        input_identity=c["input_identity"],
        binding=c["binding"],
        model_identity=c["model_envelope"],
        preprocessing_contract=c["preprocessing_contract"],
        transformed_identity=c["transformed_input"],
        preprocessed_array=c["preprocessed_array"],
        runner_override=lambda arr: c["raw_output_array"],
        expected_project_id="project_alpha",
    )

    assert result.is_consistent is True
    assert result.consistency_status == ReplayConsistencyStatus.CONSISTENT_EXACT
    assert result.eligibility_status == ReplayEligibilityStatus.ELIGIBLE
    assert result.comparison is not None
    assert result.comparison.exact_hash_match is True
    assert result.comparison.comparison_status == ComparisonStatus.EXACT_MATCH
    assert result.replay_execution_identity is not None
    assert result.replay_execution_identity == result.recorded_execution_identity


def test_category_b_replay_does_not_mutate_original_record(sample_verified_record_and_components):
    """Category B: 10. Replay execution leaves original InferenceRecord untouched."""
    c = sample_verified_record_and_components
    orig_record_hash = c["record"].record_integrity_hash
    orig_binding_hash = c["record"].inference_binding_hash

    service = InferenceReplayService()
    result = service.orchestrate_replay(
        record=c["record"],
        input_identity=c["input_identity"],
        binding=c["binding"],
        model_identity=c["model_envelope"],
        preprocessing_contract=c["preprocessing_contract"],
        transformed_identity=c["transformed_input"],
        preprocessed_array=c["preprocessed_array"],
        runner_override=lambda arr: c["raw_output_array"],
        expected_project_id="project_alpha",
    )

    assert c["record"].record_integrity_hash == orig_record_hash
    assert c["record"].inference_binding_hash == orig_binding_hash


# =====================================================================
# CATEGORY C — NUMERICAL TOLERANCE COMPARISON
# =====================================================================


def test_category_c_numerical_tolerance_within_threshold(sample_verified_record_and_components):
    """Category C: 12. Tiny floating point deviation within policy tolerance is classified CONSISTENT_TOLERANT."""
    c = sample_verified_record_and_components
    base_arr = c["raw_output_array"]
    # Perturb slightly: delta = 1e-6 < atol (1e-5)
    perturbed_arr = base_arr + np.float32(1e-6)

    service = InferenceReplayService()
    result = service.orchestrate_replay(
        record=c["record"],
        input_identity=c["input_identity"],
        binding=c["binding"],
        model_identity=c["model_envelope"],
        preprocessing_contract=c["preprocessing_contract"],
        transformed_identity=c["transformed_input"],
        preprocessed_array=c["preprocessed_array"],
        runner_override=lambda arr: perturbed_arr,
        replay_policy=DEFAULT_TOLERANT_POLICY,
        expected_project_id="project_alpha",
        recorded_arrays=[base_arr],
    )

    assert result.is_consistent is True
    assert result.consistency_status == ReplayConsistencyStatus.CONSISTENT_TOLERANT
    assert result.comparison is not None
    assert result.comparison.exact_hash_match is False
    assert result.comparison.numerical_match is True
    assert result.comparison.max_absolute_error > 0.0
    assert result.comparison.max_absolute_error <= 1e-5


def test_category_c_numerical_tolerance_beyond_threshold_rejected(sample_verified_record_and_components):
    """Category C: 13. Numerical deviation exceeding tolerance is classified NUMERICAL_DIVERGENCE."""
    c = sample_verified_record_and_components
    base_arr = c["raw_output_array"]
    # Perturb beyond tolerance: delta = 0.05 > atol (1e-5)
    divergent_arr = base_arr + np.float32(0.05)

    service = InferenceReplayService()
    result = service.orchestrate_replay(
        record=c["record"],
        input_identity=c["input_identity"],
        binding=c["binding"],
        model_identity=c["model_envelope"],
        preprocessing_contract=c["preprocessing_contract"],
        transformed_identity=c["transformed_input"],
        preprocessed_array=c["preprocessed_array"],
        runner_override=lambda arr: divergent_arr,
        replay_policy=DEFAULT_TOLERANT_POLICY,
        expected_project_id="project_alpha",
        recorded_arrays=[base_arr],
    )

    assert result.is_consistent is False
    assert result.consistency_status == ReplayConsistencyStatus.NUMERICAL_DIVERGENCE
    assert result.comparison is not None
    assert result.comparison.numerical_match is False
    assert result.comparison.mismatch_count > 0


def test_category_c_nan_inf_handling():
    """Category C: 14-15. Unexpected NaN / Inf in replay produces NUMERICAL_MISMATCH."""
    a = np.array([1.0, 2.0, 3.0], dtype=np.float32)
    b_nan = np.array([1.0, np.nan, 3.0], dtype=np.float32)
    b_inf = np.array([1.0, np.inf, 3.0], dtype=np.float32)

    res_nan = compare_raw_outputs(
        recorded_raw_hash="aa" * 32,
        replay_raw_hash="bb" * 32,
        recorded_tensors=[{"name": "o1", "shape": [3], "dtype": "float32"}],
        replay_tensors=[{"name": "o1", "shape": [3], "dtype": "float32"}],
        policy=DEFAULT_TOLERANT_POLICY,
        recorded_arrays=[a],
        replay_arrays=[b_nan],
    )
    assert res_nan.numerical_match is False
    assert res_nan.comparison_status == ComparisonStatus.NUMERICAL_MISMATCH

    res_inf = compare_raw_outputs(
        recorded_raw_hash="aa" * 32,
        replay_raw_hash="cc" * 32,
        recorded_tensors=[{"name": "o1", "shape": [3], "dtype": "float32"}],
        replay_tensors=[{"name": "o1", "shape": [3], "dtype": "float32"}],
        policy=DEFAULT_TOLERANT_POLICY,
        recorded_arrays=[a],
        replay_arrays=[b_inf],
    )
    assert res_inf.numerical_match is False
    assert res_inf.comparison_status == ComparisonStatus.NUMERICAL_MISMATCH


def test_category_c_asymmetric_reference_recorded_baseline_demonstration():
    """Category C: Boundary test proving recorded output is the authoritative reference.

    Case 1:
      recorded = 100.0, replay = 110.0, delta = 10.0
      rtol = 0.095 (9.5%), atol = 0.0
      If reference is recorded: allowable = 0.0 + 0.095 * 100 = 9.5 -> delta (10.0) > 9.5 -> REJECTED (NUMERICAL_MISMATCH).
      If reference were replay: allowable = 0.0 + 0.095 * 110 = 10.45 -> delta (10.0) <= 10.45 -> would pass.
      Result: Must be NUMERICAL_MISMATCH.

    Case 2:
      recorded = 110.0, replay = 100.0, delta = 10.0
      rtol = 0.095 (9.5%), atol = 0.0
      If reference is recorded: allowable = 0.0 + 0.095 * 110 = 10.45 -> delta (10.0) <= 10.45 -> ACCEPTED (TOLERANT_MATCH).
      If reference were replay: allowable = 0.0 + 0.095 * 100 = 9.5 -> delta (10.0) > 9.5 -> would fail.
      Result: Must be TOLERANT_MATCH.
    """
    asym_policy = ReplayPolicy(
        mode=ReplayMode.NUMERICALLY_TOLERANT,
        atol=0.0,
        rtol=0.095,
    )

    # Case 1: recorded = 100, replay = 110 -> 10.0 > 9.5 -> rejected
    rec_1 = np.array([100.0], dtype=np.float32)
    rep_1 = np.array([110.0], dtype=np.float32)
    res_1 = compare_raw_outputs(
        recorded_raw_hash="11" * 32,
        replay_raw_hash="22" * 32,
        recorded_tensors=[{"name": "o1", "shape": [1], "dtype": "float32"}],
        replay_tensors=[{"name": "o1", "shape": [1], "dtype": "float32"}],
        policy=asym_policy,
        recorded_arrays=[rec_1],
        replay_arrays=[rep_1],
    )
    assert res_1.numerical_match is False
    assert res_1.comparison_status == ComparisonStatus.NUMERICAL_MISMATCH
    assert res_1.mismatch_count == 1
    assert pytest.approx(res_1.max_absolute_error, rel=1e-5) == 10.0
    # Relative error computed with recorded (100.0) as denominator: 10 / 100 = 0.10
    assert pytest.approx(res_1.max_relative_error, rel=1e-3) == 0.10

    # Case 2: recorded = 110, replay = 100 -> 10.0 <= 10.45 -> accepted
    rec_2 = np.array([110.0], dtype=np.float32)
    rep_2 = np.array([100.0], dtype=np.float32)
    res_2 = compare_raw_outputs(
        recorded_raw_hash="33" * 32,
        replay_raw_hash="44" * 32,
        recorded_tensors=[{"name": "o1", "shape": [1], "dtype": "float32"}],
        replay_tensors=[{"name": "o1", "shape": [1], "dtype": "float32"}],
        policy=asym_policy,
        recorded_arrays=[rec_2],
        replay_arrays=[rep_2],
    )
    assert res_2.numerical_match is True
    assert res_2.comparison_status == ComparisonStatus.TOLERANT_MATCH
    assert res_2.mismatch_count == 0
    assert pytest.approx(res_2.max_absolute_error, rel=1e-5) == 10.0
    # Relative error computed with recorded (110.0) as denominator: 10 / 110 = 0.0909
    assert pytest.approx(res_2.max_relative_error, rel=1e-3) == (10.0 / 110.0)


def test_category_c_zero_reference_numerical_handling():
    """Category C: Verify zero-reference baseline behavior does not cause division-by-zero, NaN, or Inf."""
    zero_policy = ReplayPolicy(
        mode=ReplayMode.NUMERICALLY_TOLERANT,
        atol=1e-4,
        rtol=0.1,
    )

    # Element 0: diff = 1e-5 <= atol (1e-4) -> acceptable
    # Element 1: diff = 1e-3 > atol (1e-4) -> unacceptable
    rec = np.array([0.0, 0.0], dtype=np.float32)
    rep = np.array([1e-5, 1e-3], dtype=np.float32)

    res = compare_raw_outputs(
        recorded_raw_hash="55" * 32,
        replay_raw_hash="66" * 32,
        recorded_tensors=[{"name": "o1", "shape": [2], "dtype": "float32"}],
        replay_tensors=[{"name": "o1", "shape": [2], "dtype": "float32"}],
        policy=zero_policy,
        recorded_arrays=[rec],
        replay_arrays=[rep],
    )

    assert res.numerical_match is False
    assert res.comparison_status == ComparisonStatus.NUMERICAL_MISMATCH
    assert res.mismatch_count == 1  # Only element 1 failed
    assert np.isfinite(res.max_absolute_error)
    assert np.isfinite(res.max_relative_error)


# =====================================================================
# CATEGORY D — STRUCTURAL COMPARISON
# =====================================================================


def test_category_d_shape_mismatch():
    """Category D: 19. Shape mismatch produces SHAPE_MISMATCH / STRUCTURAL_DIVERGENCE."""
    res = compare_raw_outputs(
        recorded_raw_hash="aa" * 32,
        replay_raw_hash="bb" * 32,
        recorded_tensors=[{"name": "o1", "shape": [1, 10], "dtype": "float32"}],
        replay_tensors=[{"name": "o1", "shape": [1, 5], "dtype": "float32"}],
        policy=DEFAULT_DETERMINISTIC_POLICY,
    )
    assert res.structural_match is False
    assert res.comparison_status == ComparisonStatus.SHAPE_MISMATCH


def test_category_d_rank_mismatch():
    """Category D: 20. Tensor rank mismatch produces RANK_MISMATCH."""
    res = compare_raw_outputs(
        recorded_raw_hash="aa" * 32,
        replay_raw_hash="bb" * 32,
        recorded_tensors=[{"name": "o1", "shape": [1, 10], "dtype": "float32"}],
        replay_tensors=[{"name": "o1", "shape": [1, 10, 1], "dtype": "float32"}],
        policy=DEFAULT_DETERMINISTIC_POLICY,
    )
    assert res.structural_match is False
    assert res.comparison_status == ComparisonStatus.RANK_MISMATCH


def test_category_d_tensor_count_mismatch():
    """Category D: 21. Tensor count mismatch produces COUNT_MISMATCH."""
    res = compare_raw_outputs(
        recorded_raw_hash="aa" * 32,
        replay_raw_hash="bb" * 32,
        recorded_tensors=[{"name": "o1", "shape": [1, 10], "dtype": "float32"}],
        replay_tensors=[
            {"name": "o1", "shape": [1, 10], "dtype": "float32"},
            {"name": "o2", "shape": [1, 5], "dtype": "float32"},
        ],
        policy=DEFAULT_DETERMINISTIC_POLICY,
    )
    assert res.structural_match is False
    assert res.comparison_status == ComparisonStatus.COUNT_MISMATCH


def test_category_d_dtype_mismatch_without_policy_allowance():
    """Category D: 23. Dtype mismatch without explicit policy allowance produces DTYPE_MISMATCH."""
    res = compare_raw_outputs(
        recorded_raw_hash="aa" * 32,
        replay_raw_hash="bb" * 32,
        recorded_tensors=[{"name": "o1", "shape": [1, 10], "dtype": "float32"}],
        replay_tensors=[{"name": "o1", "shape": [1, 10], "dtype": "float64"}],
        policy=DEFAULT_DETERMINISTIC_POLICY,
    )
    assert res.structural_match is False
    assert res.comparison_status == ComparisonStatus.DTYPE_MISMATCH


# =====================================================================
# CATEGORY E — HASH SEMANTICS
# =====================================================================


def test_category_e_hash_inequality_with_tolerance_succeeds():
    """Category E: 26-27. Hash inequality + within-tolerance output produces CONSISTENT_TOLERANT."""
    a = np.array([1.0, 2.0, 3.0], dtype=np.float32)
    b = np.array([1.000001, 2.000002, 3.000001], dtype=np.float32)

    res = compare_raw_outputs(
        recorded_raw_hash="aa" * 32,
        replay_raw_hash="bb" * 32,
        recorded_tensors=[{"name": "o", "shape": [3], "dtype": "float32"}],
        replay_tensors=[{"name": "o", "shape": [3], "dtype": "float32"}],
        policy=DEFAULT_TOLERANT_POLICY,
        recorded_arrays=[a],
        replay_arrays=[b],
    )
    assert res.exact_hash_match is False
    assert res.numerical_match is True
    assert res.comparison_status == ComparisonStatus.TOLERANT_MATCH


# =====================================================================
# CATEGORY F — ENVIRONMENT POLICIES
# =====================================================================


def test_category_f_unsupported_cuda_request_fails_closed(sample_verified_record_and_components):
    """Category F: 31. Explicit CUDA requested when unavailable fails closed without silent fallback."""
    c = sample_verified_record_and_components
    service = InferenceReplayService()

    cuda_policy = ExecutionPolicy(provider=ExecutionProvider.CUDA)
    result = service.orchestrate_replay(
        record=c["record"],
        input_identity=c["input_identity"],
        binding=c["binding"],
        model_identity=c["model_envelope"],
        preprocessing_contract=c["preprocessing_contract"],
        transformed_identity=c["transformed_input"],
        preprocessed_array=c["preprocessed_array"],
        execution_policy=cuda_policy,
        expected_project_id="project_alpha",
    )

    # Unless host actually has CUDA, should fail as NON_REPRODUCIBLE
    assert result.is_consistent is False
    assert result.consistency_status == ReplayConsistencyStatus.NON_REPRODUCIBLE


# =====================================================================
# CATEGORY G — SECURITY & BOUNDED RESOURCE ENFORCEMENT
# =====================================================================


def test_category_g_forbidden_constructs():
    """Category G: 36-39. AST scan confirms zero eval, exec, pickle, subprocess, os.system, or socket in replay subsystem."""
    subsystem_dir = os.path.join("backend", "aivara", "inference", "replay")
    forbidden_tokens = ["eval(", "exec(", "pickle.", "subprocess.", "os.system(", "requests.", "urllib.", "socket."]

    for fname in os.listdir(subsystem_dir):
        if fname.endswith(".py"):
            fpath = os.path.join(subsystem_dir, fname)
            with open(fpath, "r", encoding="utf-8") as f:
                content = f.read()
            for tok in forbidden_tokens:
                assert tok not in content, f"Forbidden construct '{tok}' detected in {fpath}"


def test_category_g_resource_limits_enforced(sample_verified_record_and_components):
    """Category G: 35. Replay exceeding resource limits fails closed."""
    c = sample_verified_record_and_components
    service = InferenceReplayService()

    # Policy with ultra-low element bound
    tight_policy = ExecutionPolicy(max_tensor_elements=10)
    result = service.orchestrate_replay(
        record=c["record"],
        input_identity=c["input_identity"],
        binding=c["binding"],
        model_identity=c["model_envelope"],
        preprocessing_contract=c["preprocessing_contract"],
        transformed_identity=c["transformed_input"],
        preprocessed_array=c["preprocessed_array"],
        execution_policy=tight_policy,
        expected_project_id="project_alpha",
    )
    assert result.is_consistent is False
    assert result.consistency_status == ReplayConsistencyStatus.NON_REPRODUCIBLE


# =====================================================================
# CATEGORY H — PROJECT ISOLATION
# =====================================================================


def test_category_h_project_isolation(sample_verified_record_and_components):
    """Category H: 40-42. Tenant boundary: Project A cannot replay Project B records."""
    c = sample_verified_record_and_components
    service = InferenceReplayService()

    result = service.orchestrate_replay(
        record=c["record"],
        input_identity=c["input_identity"],
        binding=c["binding"],
        model_identity=c["model_envelope"],
        preprocessing_contract=c["preprocessing_contract"],
        transformed_identity=c["transformed_input"],
        preprocessed_array=c["preprocessed_array"],
        expected_project_id="project_beta",  # mismatch
    )
    assert result.is_consistent is False
    assert result.eligibility_status == ReplayEligibilityStatus.PROJECT_MISMATCH


# =====================================================================
# CATEGORY I — IMMUTABILITY
# =====================================================================


def test_category_i_result_model_immutability():
    """Category I: 46. ReplayVerificationResult is frozen and immutable."""
    res = ReplayVerificationResult(
        record_id="rec_1",
        project_id="proj_1",
        inference_binding_hash="aa" * 32,
        is_consistent=True,
        consistency_status=ReplayConsistencyStatus.CONSISTENT_EXACT,
        eligibility_status=ReplayEligibilityStatus.ELIGIBLE,
        recorded_execution_identity="bb" * 32,
        replay_execution_identity="cc" * 32,
    )
    with pytest.raises(Exception):
        res.is_consistent = False  # type: ignore


# =====================================================================
# CATEGORY J — PHASE BOUNDARIES (NO PHASE 10.10)
# =====================================================================


def test_category_j_phase_boundaries():
    """Category J: 47-53. Verify Phase 10.9 does not implement unreleased future phases or blockchain."""
    import aivara.inference.replay as rep_subsystem

    assert not hasattr(rep_subsystem, "bind_replay_to_provenance_ledger")
    assert not hasattr(rep_subsystem, "create_replay_evidence")
    assert not hasattr(rep_subsystem, "blockchain")

    with pytest.raises(ImportError):
        import aivara.inference.ledger  # type: ignore



# =====================================================================
# CATEGORY A EXTENDED — MALFORMED & MISSING IDENTITIES
# =====================================================================


def test_category_a_missing_binding_rejected():
    """Category A: Replay eligibility rejects record without binding."""
    rec = InferenceRecord(
        schema_version="1.0",
        record_version="1.0",
        record_id="rec_nobind",
        project_id="proj_a",
        record_type=InferenceRecordType.STANDARD,
        binding_version="1.0",
        inference_binding_hash="11" * 32,
        record_integrity_hash="22" * 32,
        record_status=InferenceRecordStatus.INVALID,
        binding=None,
    )
    status, findings = assess_replay_eligibility(rec, expected_project_id="proj_a")
    assert status == ReplayEligibilityStatus.INVALID_RECORD


def test_category_a_malformed_hash_rejected(sample_verified_record_and_components):
    """Category A: Malformed non-hex hash fails validation."""
    from aivara.inference.composite_binding.engine import validate_sha256_hex_format

    with pytest.raises(InvalidHashFormatError):
        validate_sha256_hex_format("test_hash", "INVALID_HEX_STRING")


# =====================================================================
# CATEGORY B & G EXTENDED — CANCELLATION & TIMEOUT
# =====================================================================


def test_category_b_cancellation_check(sample_verified_record_and_components):
    """Category B: Cancellation callback triggers immediate abort during replay."""
    c = sample_verified_record_and_components
    service = InferenceReplayService()

    result = service.orchestrate_replay(
        record=c["record"],
        input_identity=c["input_identity"],
        binding=c["binding"],
        model_identity=c["model_envelope"],
        preprocessing_contract=c["preprocessing_contract"],
        transformed_identity=c["transformed_input"],
        preprocessed_array=c["preprocessed_array"],
        cancellation_check=lambda: True,  # Abort immediately
        expected_project_id="project_alpha",
    )
    assert result.is_consistent is False
    assert result.consistency_status == ReplayConsistencyStatus.NON_REPRODUCIBLE


def test_category_g_timeout_handling(sample_verified_record_and_components):
    """Category G: 34. Timeout policy violation fails closed gracefully."""
    import time
    c = sample_verified_record_and_components
    service = InferenceReplayService()

    def _slow_runner(arr: np.ndarray) -> np.ndarray:
        time.sleep(0.05)
        return arr

    timeout_policy = ExecutionPolicy(timeout_seconds=0.001)
    result = service.orchestrate_replay(
        record=c["record"],
        input_identity=c["input_identity"],
        binding=c["binding"],
        model_identity=c["model_envelope"],
        preprocessing_contract=c["preprocessing_contract"],
        transformed_identity=c["transformed_input"],
        preprocessed_array=c["preprocessed_array"],
        runner_override=_slow_runner,
        execution_policy=timeout_policy,
        expected_project_id="project_alpha",
    )
    assert result.is_consistent is False
    assert result.consistency_status == ReplayConsistencyStatus.NON_REPRODUCIBLE


# =====================================================================
# CATEGORY D EXTENDED — TENSOR NAME & ORDERING MISMATCH
# =====================================================================


def test_category_d_tensor_name_mismatch():
    """Category D: 22. Output tensor name mismatch produces NAME_MISMATCH."""
    res = compare_raw_outputs(
        recorded_raw_hash="aa" * 32,
        replay_raw_hash="bb" * 32,
        recorded_tensors=[{"name": "probabilities", "shape": [1, 10], "dtype": "float32"}],
        replay_tensors=[{"name": "logits", "shape": [1, 10], "dtype": "float32"}],
        policy=DEFAULT_DETERMINISTIC_POLICY,
    )
    assert res.structural_match is False
    assert res.comparison_status == ComparisonStatus.NAME_MISMATCH


# =====================================================================
# CATEGORY F EXTENDED — CPU ENVIRONMENT VALIDATION
# =====================================================================


def test_category_f_cpu_environment_match(sample_verified_record_and_components):
    """Category F: 29. Host CPU execution environment matches recorded baseline."""
    c = sample_verified_record_and_components
    service = InferenceReplayService()

    result = service.orchestrate_replay(
        record=c["record"],
        input_identity=c["input_identity"],
        binding=c["binding"],
        model_identity=c["model_envelope"],
        preprocessing_contract=c["preprocessing_contract"],
        transformed_identity=c["transformed_input"],
        preprocessed_array=c["preprocessed_array"],
        runner_override=lambda arr: c["raw_output_array"],
        expected_project_id="project_alpha",
    )
    assert result.environment_match is True


# =====================================================================
# CATEGORY I EXTENDED — MODEL IMMUTABILITY
# =====================================================================


def test_category_i_environment_and_comparison_models_immutable():
    """Category I: 46. ReplayEnvironment and ReplayComparisonResult are immutable."""
    env = ReplayEnvironment(provider=ExecutionProvider.CPU)
    with pytest.raises(Exception):
        env.provider = ExecutionProvider.CUDA  # type: ignore

    comp = ReplayComparisonResult(
        recorded_raw_output_hash="aa" * 32,
        replay_raw_output_hash="bb" * 32,
        exact_hash_match=False,
        structural_match=True,
        numerical_match=True,
        comparison_status=ComparisonStatus.TOLERANT_MATCH,
    )
    with pytest.raises(Exception):
        comp.exact_hash_match = True  # type: ignore


# =====================================================================
# CATEGORY K — REGRESSION TESTS (PHASES 10.2 - 10.8)
# =====================================================================


def test_category_k_phase_10_8_record_integrity(sample_verified_record_and_components):
    """Category K: 60. Phase 10.8 persistent inference record integrity verification."""
    from aivara.inference.records.engine import verify_inference_record

    rec = sample_verified_record_and_components["record"]
    verif = verify_inference_record(rec)
    assert verif.is_valid is True
    assert verif.status == InferenceRecordStatus.VERIFIED


def test_category_k_phase_10_7_binding_integrity(sample_verified_record_and_components):
    """Category K: 59. Phase 10.7 composite binding verification."""
    from aivara.inference.composite_binding.engine import verify_inference_binding

    binding = sample_verified_record_and_components["composite_binding"]
    verif = verify_inference_binding(binding)
    assert verif.is_valid is True
    assert verif.status == InferenceIntegrityStatus.VERIFIED


def test_category_k_phase_10_4_contract_integrity(sample_verified_record_and_components):
    """Category K: 56. Phase 10.4 preprocessing contract integrity verification."""
    from aivara.inference.preprocessing.engine import verify_preprocessing_contract

    contract = sample_verified_record_and_components["preprocessing_contract"]
    verif = verify_preprocessing_contract(contract)
    assert verif.is_valid is True
    assert verif.status == InferenceIntegrityStatus.VERIFIED


def test_category_k_phase_10_3_input_model_binding_integrity(sample_verified_record_and_components):
    """Category K: 55. Phase 10.3 input-model binding integrity verification."""
    from aivara.inference.binding.engine import verify_input_model_binding

    c = sample_verified_record_and_components
    verif = verify_input_model_binding(c["binding"])
    assert verif.is_valid is True
    assert verif.status == InferenceIntegrityStatus.VERIFIED
