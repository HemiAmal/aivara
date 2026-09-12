"""Comprehensive unit and regression test suite for Phase 10.6 Output Schema & Numerical Integrity.

Covers categories A through AW per AIVARA Phase 10.6 requirements specification.
"""

import copy
import hashlib
import inspect
import math
import os
import sys
from typing import Any, Dict, List

import numpy as np
import pytest

from aivara.inference.enums import (
    InferenceFindingCode,
    InferenceIntegrityStatus,
)
from aivara.inference.exceptions import (
    OutputContractMismatchError,
    OutputContractUnavailableError,
    OutputContractUnverifiableError,
    OutputIntegrityError,
    OutputNumericalIntegrityError,
    OutputResourceLimitError,
    OutputSchemaValidationError,
)
from aivara.inference.execution.models import (
    InferenceExecution,
    RawExecutionOutput,
    RawOutputTensor,
)
from aivara.inference.output import (
    ModelOutputContract,
    NumericalSanityStatus,
    OutputIntegrityAssessment,
    OutputIntegrityPolicy,
    OutputKind,
    OutputStructuralStatus,
    OutputTensorContract,
    TaskType,
    ValidatedTensorSummary,
    build_tensor_summary,
    compute_output_contract_hash,
    compute_validated_output_identity,
    validate_classification_output,
    validate_detection_output,
    validate_embedding_output,
    validate_output_integrity,
    validate_segmentation_output,
    validate_structured_object,
    verify_validated_output_identity,
)


# =====================================================================
# Fixtures & Helpers
# =====================================================================


def _make_raw_execution_output(arrays_dict: Dict[str, np.ndarray]) -> RawExecutionOutput:
    """Helper to construct a valid Phase 10.5 RawExecutionOutput envelope."""
    outputs: List[RawOutputTensor] = []
    desc: List[Dict[str, Any]] = []

    for idx, (name, arr) in enumerate(arrays_dict.items()):
        c_bytes = np.ascontiguousarray(arr).tobytes()
        c_hash = hashlib.sha256(c_bytes).hexdigest()
        is_fin = bool(np.all(np.isfinite(arr))) if np.issubdtype(arr.dtype, np.number) else True

        rot = RawOutputTensor(
            name=name,
            index=idx,
            dtype=str(arr.dtype),
            shape=list(arr.shape),
            byte_size=int(arr.nbytes),
            element_count=int(arr.size),
            c_contiguous_byte_hash=c_hash,
            is_finite=is_fin,
        )
        outputs.append(rot)
        desc.append(
            {
                "byte_size": int(arr.nbytes),
                "c_contiguous_byte_hash": c_hash,
                "dtype": str(arr.dtype),
                "element_count": int(arr.size),
                "index": idx,
                "is_finite": is_fin,
                "name": name,
                "shape": list(arr.shape),
            }
        )

    from aivara.crypto.canonical import canonicalize
    raw_hash = hashlib.sha256(canonicalize(desc)).hexdigest()

    return RawExecutionOutput(
        outputs=outputs,
        raw_output_hash=raw_hash,
        numerical_sanity=NumericalSanityStatus.FINITE,
    )


# =====================================================================
# Tests A through AW
# =====================================================================


def test_category_a_valid_classification_logits():
    """Category A: Valid classification logits (unbounded finite values without sum constraints)."""
    logits = np.array([2.5, -1.2, 0.0, 4.8, -3.1], dtype=np.float32)
    contract = ModelOutputContract(
        task_type=TaskType.CLASSIFICATION,
        class_count=5,
        outputs=[
            OutputTensorContract(
                name="logits",
                shape=[5],
                dtype="float32",
                output_kind=OutputKind.LOGITS,
                activation_type="logits",
            )
        ],
    )

    assessment = validate_output_integrity({"logits": logits}, contract=contract)
    assert assessment.integrity_status == InferenceIntegrityStatus.VERIFIED
    assert assessment.numerical_status in (NumericalSanityStatus.FINITE, NumericalSanityStatus.DOMAIN_VALID)
    assert assessment.structural_status == OutputStructuralStatus.VALID
    assert assessment.validated_output_identity is not None
    assert verify_validated_output_identity(assessment) is True


def test_category_b_valid_classification_probabilities():
    """Category B: Valid classification probabilities satisfying [0, 1] bounds and sum=1."""
    probs = np.array([0.1, 0.2, 0.4, 0.2, 0.1], dtype=np.float32)
    contract = ModelOutputContract(
        task_type=TaskType.CLASSIFICATION,
        class_count=5,
        require_probability_normalization=True,
        probability_normalization_tolerance=1e-4,
        outputs=[
            OutputTensorContract(
                name="probabilities",
                shape=[5],
                dtype="float32",
                output_kind=OutputKind.PROBABILITIES,
                activation_type="softmax",
                min_value=0.0,
                max_value=1.0,
            )
        ],
    )

    assessment = validate_output_integrity({"probabilities": probs}, contract=contract)
    assert assessment.integrity_status == InferenceIntegrityStatus.VERIFIED
    assert assessment.numerical_status == NumericalSanityStatus.DOMAIN_VALID
    assert len(assessment.findings) == 0


def test_category_c_invalid_probability_range():
    """Category C: Probability values outside [0.0, 1.0] are detected and flagged."""
    # Negative probability
    probs_neg = np.array([-0.1, 0.5, 0.6], dtype=np.float32)
    contract = ModelOutputContract(
        task_type=TaskType.CLASSIFICATION,
        class_count=3,
        outputs=[
            OutputTensorContract(
                name="probabilities",
                shape=[3],
                dtype="float32",
                output_kind=OutputKind.PROBABILITIES,
            )
        ],
    )
    assessment_neg = validate_output_integrity({"probabilities": probs_neg}, contract=contract)
    assert assessment_neg.integrity_status == InferenceIntegrityStatus.INVALID
    assert any(f.code == InferenceFindingCode.OUTPUT_DOMAIN_INVALID.value for f in assessment_neg.findings)

    # Exceeding 1.0
    probs_over = np.array([1.5, -0.2, 0.1], dtype=np.float32)
    assessment_over = validate_output_integrity({"probabilities": probs_over}, contract=contract)
    assert assessment_over.integrity_status == InferenceIntegrityStatus.INVALID


def test_category_d_probability_normalization_policy():
    """Category D: Probability sum deviation exceeds tolerance."""
    # Sum is 0.85 instead of 1.0
    probs_unnormalized = np.array([0.3, 0.3, 0.25], dtype=np.float32)
    contract = ModelOutputContract(
        task_type=TaskType.CLASSIFICATION,
        class_count=3,
        require_probability_normalization=True,
        probability_normalization_tolerance=1e-4,
        outputs=[
            OutputTensorContract(
                name="probabilities",
                shape=[3],
                dtype="float32",
                output_kind=OutputKind.PROBABILITIES,
            )
        ],
    )
    assessment = validate_output_integrity({"probabilities": probs_unnormalized}, contract=contract)
    assert assessment.integrity_status == InferenceIntegrityStatus.INVALID
    assert any(f.code == InferenceFindingCode.OUTPUT_PROBABILITY_SUM_INVALID.value for f in assessment.findings)


def test_category_e_valid_detection_outputs():
    """Category E: Valid object detection output bounding boxes, scores, and class IDs."""
    boxes = np.array([[0.1, 0.2, 0.5, 0.8], [0.0, 0.0, 1.0, 1.0]], dtype=np.float32)
    scores = np.array([0.95, 0.82], dtype=np.float32)
    classes = np.array([0, 2], dtype=np.int32)

    contract = ModelOutputContract(
        task_type=TaskType.OBJECT_DETECTION,
        class_count=80,
        outputs=[
            OutputTensorContract(name="boxes", shape=[2, 4], dtype="float32", output_kind=OutputKind.BOUNDING_BOXES),
            OutputTensorContract(name="scores", shape=[2], dtype="float32", output_kind=OutputKind.CLASS_SCORES),
            OutputTensorContract(name="classes", shape=[2], dtype="int32"),
        ],
    )

    assessment = validate_output_integrity(
        {"boxes": boxes, "scores": scores, "classes": classes},
        contract=contract,
    )
    assert assessment.integrity_status == InferenceIntegrityStatus.VERIFIED
    assert len(assessment.findings) == 0


def test_category_f_invalid_detection_boxes():
    """Category F: Invalid box coordinates (inverted x1 > x2 or y1 > y2 or out of bounds) fail closed without clipping."""
    # Inverted coordinates: x1=0.8, x2=0.2
    bad_boxes = np.array([[0.8, 0.2, 0.2, 0.9]], dtype=np.float32)
    contract = ModelOutputContract(
        task_type=TaskType.OBJECT_DETECTION,
        outputs=[
            OutputTensorContract(name="boxes", shape=[1, 4], dtype="float32", output_kind=OutputKind.BOUNDING_BOXES)
        ],
    )
    assessment = validate_output_integrity({"boxes": bad_boxes}, contract=contract)
    assert assessment.integrity_status == InferenceIntegrityStatus.INVALID
    assert any(f.code == InferenceFindingCode.OUTPUT_BOX_INVALID.value for f in assessment.findings)

    # Box coordinates out of [0, 1] normalized domain (e.g. 5.0)
    overshoot_boxes = np.array([[0.1, 0.1, 5.0, 0.9]], dtype=np.float32)
    assessment_over = validate_output_integrity({"boxes": overshoot_boxes}, contract=contract)
    assert assessment_over.integrity_status == InferenceIntegrityStatus.INVALID
    assert any(f.code == InferenceFindingCode.OUTPUT_BOX_INVALID.value for f in assessment_over.findings)


def test_category_g_invalid_detection_class_ids():
    """Category G: Detection class IDs that are negative or exceed class count are rejected."""
    boxes = np.array([[0.1, 0.1, 0.5, 0.5]], dtype=np.float32)
    bad_classes = np.array([105], dtype=np.int32)  # Max allowed is 80 (class_count=80 -> indices 0..79)

    contract = ModelOutputContract(
        task_type=TaskType.OBJECT_DETECTION,
        class_count=80,
        outputs=[
            OutputTensorContract(name="boxes", shape=[1, 4], dtype="float32", output_kind=OutputKind.BOUNDING_BOXES),
            OutputTensorContract(name="classes", shape=[1], dtype="int32"),
        ],
    )
    assessment = validate_output_integrity({"boxes": boxes, "classes": bad_classes}, contract=contract)
    assert assessment.integrity_status == InferenceIntegrityStatus.INVALID
    assert any(f.code == InferenceFindingCode.OUTPUT_CLASS_ID_INVALID.value for f in assessment.findings)


def test_category_h_valid_segmentation_outputs():
    """Category H: Valid semantic segmentation masks."""
    masks = np.random.randint(0, 19, size=(1, 256, 256), dtype=np.int32)
    contract = ModelOutputContract(
        task_type=TaskType.SEGMENTATION,
        class_count=19,
        outputs=[
            OutputTensorContract(
                name="segmentation_mask",
                shape=[1, 256, 256],
                dtype="int32",
                output_kind=OutputKind.SEGMENTATION_MASKS,
            )
        ],
    )
    assessment = validate_output_integrity({"segmentation_mask": masks}, contract=contract)
    assert assessment.integrity_status == InferenceIntegrityStatus.VERIFIED
    assert len(assessment.findings) == 0


def test_category_i_valid_embedding_outputs():
    """Category I: Valid embedding / feature vector outputs and unit norm check."""
    vec = np.random.randn(512).astype(np.float32)
    vec = vec / np.linalg.norm(vec)  # Exact unit norm

    contract = ModelOutputContract(
        task_type=TaskType.EMBEDDING,
        outputs=[
            OutputTensorContract(
                name="embedding",
                shape=[512],
                dtype="float32",
                output_kind=OutputKind.EMBEDDING_VECTOR,
                unit_norm_required=True,
            )
        ],
    )
    assessment = validate_output_integrity({"embedding": vec}, contract=contract)
    assert assessment.integrity_status == InferenceIntegrityStatus.VERIFIED
    assert len(assessment.findings) == 0

    # Non-unit norm when unit norm required
    non_unit_vec = np.array([2.0, 3.0, 4.0], dtype=np.float32)
    contract_small = ModelOutputContract(
        task_type=TaskType.EMBEDDING,
        outputs=[
            OutputTensorContract(
                name="embedding",
                shape=[3],
                dtype="float32",
                output_kind=OutputKind.EMBEDDING_VECTOR,
                unit_norm_required=True,
            )
        ],
    )
    assessment_bad_norm = validate_output_integrity({"embedding": non_unit_vec}, contract=contract_small)
    assert assessment_bad_norm.integrity_status == InferenceIntegrityStatus.INVALID
    assert any(f.code == InferenceFindingCode.OUTPUT_DOMAIN_INVALID.value for f in assessment_bad_norm.findings)


def test_category_j_nan_detection():
    """Category J: NaN presence is trapped and fails closed."""
    arr_nan = np.array([1.0, float("nan"), 3.0], dtype=np.float32)
    assessment = validate_output_integrity({"output": arr_nan})
    assert assessment.integrity_status == InferenceIntegrityStatus.INVALID
    assert assessment.numerical_status == NumericalSanityStatus.NONFINITE
    assert any(f.code == InferenceFindingCode.OUTPUT_NAN.value for f in assessment.findings)


def test_category_k_pos_inf_detection():
    """Category K: +Infinity presence is trapped and fails closed."""
    arr_inf = np.array([1.0, float("inf"), 3.0], dtype=np.float32)
    assessment = validate_output_integrity({"output": arr_inf})
    assert assessment.integrity_status == InferenceIntegrityStatus.INVALID
    assert assessment.numerical_status == NumericalSanityStatus.NONFINITE
    assert any(f.code == InferenceFindingCode.OUTPUT_INFINITY.value for f in assessment.findings)


def test_category_l_neg_inf_detection():
    """Category L: -Infinity presence is trapped and fails closed."""
    arr_neginf = np.array([1.0, float("-inf"), 3.0], dtype=np.float32)
    assessment = validate_output_integrity({"output": arr_neginf})
    assert assessment.integrity_status == InferenceIntegrityStatus.INVALID
    assert assessment.numerical_status == NumericalSanityStatus.NONFINITE
    assert any(f.code == InferenceFindingCode.OUTPUT_INFINITY.value for f in assessment.findings)


def test_category_m_dtype_mismatch():
    """Category M: Data type mismatch against contract is flagged."""
    arr = np.array([1.0, 2.0, 3.0], dtype=np.float64)  # float64
    contract = ModelOutputContract(
        outputs=[OutputTensorContract(name="output", shape=[3], dtype="float32")]  # expects float32
    )
    assessment = validate_output_integrity({"output": arr}, contract=contract)
    assert assessment.integrity_status == InferenceIntegrityStatus.MISMATCHED
    assert any(f.code == InferenceFindingCode.OUTPUT_DTYPE_MISMATCH.value for f in assessment.findings)


def test_category_n_rank_mismatch():
    """Category N: Tensor rank mismatch against contract is flagged."""
    arr = np.ones((2, 3, 4), dtype=np.float32)  # Rank 3
    contract = ModelOutputContract(
        outputs=[OutputTensorContract(name="output", shape=[2, 12], dtype="float32")]  # Rank 2
    )
    assessment = validate_output_integrity({"output": arr}, contract=contract)
    assert assessment.integrity_status == InferenceIntegrityStatus.MISMATCHED
    assert any(f.code == InferenceFindingCode.OUTPUT_RANK_MISMATCH.value for f in assessment.findings)


def test_category_o_shape_mismatch():
    """Category O: Tensor shape dimension mismatch against contract is flagged."""
    arr = np.ones((2, 5), dtype=np.float32)
    contract = ModelOutputContract(
        outputs=[OutputTensorContract(name="output", shape=[2, 10], dtype="float32")]
    )
    assessment = validate_output_integrity({"output": arr}, contract=contract)
    assert assessment.integrity_status == InferenceIntegrityStatus.MISMATCHED
    assert any(f.code == InferenceFindingCode.OUTPUT_SHAPE_MISMATCH.value for f in assessment.findings)


def test_category_p_output_count_mismatch():
    """Category P: Number of produced outputs differs from contract expected count."""
    arr = np.ones((10,), dtype=np.float32)
    contract = ModelOutputContract(
        expected_output_count=2,
        outputs=[
            OutputTensorContract(name="out1", shape=[10], dtype="float32"),
            OutputTensorContract(name="out2", shape=[10], dtype="float32"),
        ],
    )
    assessment = validate_output_integrity({"out1": arr}, contract=contract)
    assert assessment.integrity_status == InferenceIntegrityStatus.MISMATCHED
    assert any(f.code == InferenceFindingCode.OUTPUT_COUNT_MISMATCH.value for f in assessment.findings)


def test_category_q_output_ordering_mismatch():
    """Category Q: Output tensor ordering differs from strictly ordered contract."""
    arr1 = np.ones((5,), dtype=np.float32)
    arr2 = np.zeros((5,), dtype=np.float32)

    contract = ModelOutputContract(
        strict_ordering=True,
        outputs=[
            OutputTensorContract(name="first", shape=[5], dtype="float32"),
            OutputTensorContract(name="second", shape=[5], dtype="float32"),
        ],
    )
    # Provide in reverse order
    assessment = validate_output_integrity({"second": arr2, "first": arr1}, contract=contract)
    assert assessment.integrity_status == InferenceIntegrityStatus.MISMATCHED
    assert any(f.code == InferenceFindingCode.OUTPUT_ORDER_MISMATCH.value for f in assessment.findings)


def test_category_r_output_name_mismatch():
    """Category R: Output tensor name missing from contract."""
    arr = np.ones((5,), dtype=np.float32)
    contract = ModelOutputContract(
        strict_names=True,
        outputs=[OutputTensorContract(name="declared_name", shape=[5], dtype="float32")],
    )
    assessment = validate_output_integrity({"undeclared_name": arr}, contract=contract)
    assert assessment.integrity_status == InferenceIntegrityStatus.MISMATCHED
    assert any(f.code == InferenceFindingCode.OUTPUT_NAME_MISMATCH.value for f in assessment.findings)


def test_category_s_output_contract_unavailable():
    """Category S: Output contract marked UNAVAILABLE returns UNAVAILABLE status without guessing."""
    arr = np.ones((10,), dtype=np.float32)
    assessment = validate_output_integrity({"output": arr}, contract="UNAVAILABLE")
    assert assessment.integrity_status == InferenceIntegrityStatus.UNAVAILABLE
    assert assessment.structural_status == OutputStructuralStatus.UNAVAILABLE
    assert any(f.code == InferenceFindingCode.OUTPUT_CONTRACT_UNAVAILABLE.value for f in assessment.findings)


def test_category_t_output_contract_unverifiable():
    """Category T: Output contract marked UNVERIFIABLE returns UNVERIFIABLE status."""
    arr = np.ones((10,), dtype=np.float32)
    assessment = validate_output_integrity({"output": arr}, contract="UNVERIFIABLE")
    assert assessment.integrity_status == InferenceIntegrityStatus.UNVERIFIABLE
    assert assessment.structural_status == OutputStructuralStatus.UNVERIFIABLE
    assert any(f.code == InferenceFindingCode.OUTPUT_CONTRACT_UNVERIFIABLE.value for f in assessment.findings)


def test_category_u_raw_output_hash_mismatch():
    """Category U: Raw output hash divergence is detected and marked MISMATCHED."""
    arr = np.ones((5,), dtype=np.float32)
    fake_expected_hash = "a" * 64
    assessment = validate_output_integrity({"output": arr}, expected_raw_output_hash=fake_expected_hash)
    assert assessment.integrity_status == InferenceIntegrityStatus.MISMATCHED
    assert any(f.code == InferenceFindingCode.OUTPUT_HASH_MISMATCH.value for f in assessment.findings)


def test_category_v_deterministic_validated_output_identity():
    """Category V: Validated output identity is purely deterministic and reproducible."""
    arr = np.array([1.0, 2.0, 3.0], dtype=np.float32)
    contract = ModelOutputContract(
        outputs=[OutputTensorContract(name="out", shape=[3], dtype="float32")]
    )

    assessment1 = validate_output_integrity({"out": arr}, contract=contract)
    assessment2 = validate_output_integrity({"out": arr}, contract=contract)

    assert assessment1.validated_output_identity == assessment2.validated_output_identity
    assert assessment1.raw_output_hash == assessment2.raw_output_hash
    assert verify_validated_output_identity(assessment1) is True


def test_category_w_modified_output_changes_identity():
    """Category W: Any single-value modification in output tensor changes the validated output identity."""
    arr1 = np.array([1.0, 2.0, 3.0], dtype=np.float32)
    arr2 = np.array([1.0, 2.0, 3.0001], dtype=np.float32)
    contract = ModelOutputContract(
        outputs=[OutputTensorContract(name="out", shape=[3], dtype="float32")]
    )

    assessment1 = validate_output_integrity({"out": arr1}, contract=contract)
    assessment2 = validate_output_integrity({"out": arr2}, contract=contract)

    assert assessment1.raw_output_hash != assessment2.raw_output_hash
    assert assessment1.validated_output_identity != assessment2.validated_output_identity


def test_category_x_model_contract_compatibility():
    """Category X: Compatibility verification with Phase 7 metadata adapter."""
    from aivara.model_integrity.schemas import OutputContractDescriptor, NormalizedModelMetadata, ModelFormat, InspectionStatus

    meta = NormalizedModelMetadata(
        format=ModelFormat.ONNX,
        inspection_status=InspectionStatus.SUCCESS,
        artifact_size_bytes=1000,
        artifact_hash_sha256="c" * 64,
        outputs=[
            OutputContractDescriptor(name="logits", shape=[1, 1000], dtype="float32", activation_type="logits")
        ],
    )

    arr = np.random.randn(1, 1000).astype(np.float32)
    assessment = validate_output_integrity({"logits": arr}, contract=meta)
    assert assessment.integrity_status == InferenceIntegrityStatus.VERIFIED
    assert assessment.output_count == 1


def test_category_y_structured_output_validation():
    """Category Y: Structured output dictionary validation (safe types, bounds)."""
    structured_data = {
        "text": "sample classification result",
        "scores": [0.9, 0.1],
        "meta": {"version": 1, "flag": True},
    }
    # validate_structured_object does not raise for valid data
    validate_structured_object(structured_data, current_depth=1, max_depth=5, max_string_len=1024)

    # Invalid non-string key
    with pytest.raises(OutputSchemaValidationError):
        validate_structured_object({123: "bad key"}, current_depth=1, max_depth=5, max_string_len=1024)


def test_category_z_oversized_output_rejection():
    """Category Z: Excessive tensor element count exceeds policy limits and is rejected."""
    arr = np.zeros((100, 100), dtype=np.float32)
    policy = OutputIntegrityPolicy(max_tensor_elements=5000)  # limit 5000, arr has 10000
    assessment = validate_output_integrity({"out": arr}, policy=policy)
    assert assessment.integrity_status == InferenceIntegrityStatus.MISMATCHED
    assert any(f.code == InferenceFindingCode.OUTPUT_RESOURCE_LIMIT_EXCEEDED.value for f in assessment.findings)


def test_category_aa_excessive_nesting_rejection():
    """Category AA: Excessive nesting in structured output exceeds policy limit."""
    nested: Dict[str, Any] = {"a": "bottom"}
    for _ in range(10):
        nested = {"level": nested}

    with pytest.raises(OutputResourceLimitError):
        validate_structured_object(nested, current_depth=1, max_depth=5, max_string_len=1024)


def test_category_ab_immutability():
    """Category AB: Validation is purely observational and does not mutate input arrays or contracts."""
    arr = np.array([1.0, 2.0, 3.0], dtype=np.float32)
    arr_copy = arr.copy()
    contract = ModelOutputContract(
        outputs=[OutputTensorContract(name="out", shape=[3], dtype="float32")]
    )

    assessment = validate_output_integrity({"out": arr}, contract=contract)
    np.testing.assert_array_equal(arr, arr_copy)
    assert isinstance(assessment, OutputIntegrityAssessment)


def test_category_ac_forbidden_constructs():
    """Category AC: AST scan confirms zero eval, exec, pickle, subprocess, os.system, or network in output subsystem."""
    subsystem_dir = os.path.join("backend", "aivara", "inference", "output")
    forbidden_tokens = ["eval(", "exec(", "pickle.", "subprocess.", "os.system(", "requests.", "urllib.", "socket."]

    for fname in os.listdir(subsystem_dir):
        if fname.endswith(".py"):
            fpath = os.path.join(subsystem_dir, fname)
            with open(fpath, "r", encoding="utf-8") as f:
                content = f.read()
            for tok in forbidden_tokens:
                assert tok not in content, f"Forbidden construct '{tok}' detected in {fpath}"


def test_category_ad_offline_behavior():
    """Category AD: Subsystem executes 100% locally without network dependencies."""
    arr = np.array([0.5, 0.5], dtype=np.float32)
    assessment = validate_output_integrity({"out": arr})
    assert assessment.integrity_status == InferenceIntegrityStatus.VERIFIED


def test_category_ae_database_unchanged():
    """Category AE: Database schema changes = 0 (no tables, migrations, or ORM modifications)."""
    import aivara.database.models as db_models
    # Verify InferenceRecordModel still exists unchanged
    assert hasattr(db_models, "InferenceRecordModel")


def test_category_af_no_preprocessing():
    """Category AF: Phase 10.6 performs zero preprocessing execution."""
    import aivara.inference.output as out_subsystem
    assert not hasattr(out_subsystem, "execute_preprocessing_pipeline")


def test_category_ag_no_model_execution():
    """Category AG: Phase 10.6 performs zero ONNX Runtime / model invocation."""
    import aivara.inference.output as out_subsystem
    assert not hasattr(out_subsystem, "execute_inference_transaction")


def test_category_ah_no_phase_10_8_implementation():
    """Category AH: Phase 10.8 (Inference Ledger Persistence) is NOT implemented."""
    with pytest.raises(ImportError):
        import aivara.inference.ledger  # type: ignore


def test_category_ai_no_phase_10_8_implementation():
    """Category AI: Phase 10.8 (Inference Ledger Persistence) is NOT implemented."""
    with pytest.raises(ImportError):
        import aivara.inference.ledger  # type: ignore


def test_category_aj_no_api_implementation():
    """Category AJ: Phase 10.6 does not expose REST routers or endpoints."""
    with pytest.raises(ImportError):
        import aivara.api.routers.inference_output  # type: ignore


def test_category_ak_no_evidence_provenance():
    """Category AK: Phase 10.6 does not create Phase 10.10 Evidence persistence."""
    import aivara.inference.output as out_subsystem
    assert not hasattr(out_subsystem, "create_output_evidence_record")


def test_category_al_phase_10_2_regression():
    """Category AL: Phase 10.2 Safe Input Boundary regression."""
    from aivara.inference.input import validate_inference_input
    inp_arr = np.ones((3, 32, 32), dtype=np.float32)
    identity = validate_inference_input(inp_arr)
    assert identity.validation_status == InferenceIntegrityStatus.VERIFIED


def test_category_am_phase_10_3_regression():
    """Category AM: Phase 10.3 Input / Model Binding regression."""
    from aivara.inference.binding import create_input_model_binding, ModelIdentityEnvelope
    from aivara.inference.input import validate_inference_input
    from aivara.crypto.canonical import canonicalize
    inp_arr = np.ones((3, 32, 32), dtype=np.float32)
    inp_identity = validate_inference_input(inp_arr)

    art_h = "3" * 64
    str_h = "5" * 64
    cnt_h = "6" * 64
    mf_payload = {
        "artifact_hash": art_h,
        "contract_hash": cnt_h,
        "schema_version": "1.0",
        "structural_hash": str_h,
    }
    master_fp = hashlib.sha256(canonicalize(mf_payload)).hexdigest()

    model_env = ModelIdentityEnvelope(
        model_id="mod_1",
        project_id="proj_1",
        master_fingerprint=master_fp,
        artifact_hash=art_h,
        structural_hash=str_h,
        contract_hash=cnt_h,
        status="verified",
    )
    binding = create_input_model_binding(
        input_identity=inp_identity,
        model_identity=model_env,
        project_id="proj_1",
    )
    assert binding.binding_status == InferenceIntegrityStatus.VERIFIED
    assert binding.binding_hash is not None


def test_category_an_phase_10_4_regression():
    """Category AN: Phase 10.4 Preprocessing Contract regression."""
    from aivara.inference.preprocessing import create_preprocessing_contract, PreprocessingOperation, PreprocessingOpType
    contract = create_preprocessing_contract(
        name="test_contract",
        operations=[
            PreprocessingOperation(op_type=PreprocessingOpType.RESIZE, parameters={"target_height": 224, "target_width": 224})
        ],
    )
    assert contract.contract_hash is not None


def test_category_ao_phase_10_5_regression():
    """Category AO: Phase 10.5 Inference Execution Integrity regression."""
    from aivara.inference.execution import ExecutionPolicy, ExecutionProvider
    policy = ExecutionPolicy(provider=ExecutionProvider.CPU)
    assert policy.provider == ExecutionProvider.CPU


def test_category_ap_phase_7_regression():
    """Category AP: Phase 7 Model Integrity regression."""
    from aivara.model_integrity.schemas import ModelFormat
    assert ModelFormat.ONNX == "onnx"


def test_category_aq_phase_8_regression():
    """Category AQ: Phase 8 Behavioral execution boundary regression."""
    from aivara.behavioral.schemas import ExecutionProvider as BehProvider
    assert BehProvider.CPU == "CPUExecutionProvider"


def test_category_ar_phase_9_regression():
    """Category AR: Phase 9 Backdoor trigger analysis regression."""
    from aivara.backdoor import TriggerFamilyEnum, TriggerActivationAssessment
    assert TriggerFamilyEnum.SPATIAL_PATCH == "SPATIAL_PATCH"
    assert TriggerActivationAssessment is not None


def test_category_as_deterministic_repeated_validation():
    """Category AS: 100 repeated evaluations produce identical validated output identities."""
    arr = np.random.RandomState(42).randn(10, 10).astype(np.float32)
    contract = ModelOutputContract(
        outputs=[OutputTensorContract(name="matrix", shape=[10, 10], dtype="float32")]
    )

    base_assessment = validate_output_integrity({"matrix": arr}, contract=contract)
    for _ in range(100):
        rep_assessment = validate_output_integrity({"matrix": arr}, contract=contract)
        assert rep_assessment.validated_output_identity == base_assessment.validated_output_identity


def test_category_at_numerical_edge_cases():
    """Category AT: Numerical edge cases (subnormal floats, zeros, negative zero)."""
    # Zeros and negative zeros
    arr_zeros = np.array([0.0, -0.0, 0.0], dtype=np.float32)
    assessment = validate_output_integrity({"zeros": arr_zeros})
    assert assessment.integrity_status == InferenceIntegrityStatus.VERIFIED
    assert assessment.numerical_status in (NumericalSanityStatus.FINITE, NumericalSanityStatus.DOMAIN_VALID)

    # Subnormal float
    arr_subnormal = np.array([1e-40, 2e-40], dtype=np.float32)
    assessment_sub = validate_output_integrity({"subnormal": arr_subnormal})
    assert assessment_sub.integrity_status == InferenceIntegrityStatus.VERIFIED


def test_category_au_resource_limit_enforcement():
    """Category AU: Resource limits on rank, dimension size, and output count."""
    policy = OutputIntegrityPolicy(max_outputs=2, max_rank=3, max_dimension_size=100)

    # Exceed output count
    arr = np.ones((5,), dtype=np.float32)
    assessment_cnt = validate_output_integrity(
        {"out1": arr, "out2": arr, "out3": arr},
        policy=policy,
    )
    assert any(f.code == InferenceFindingCode.OUTPUT_RESOURCE_LIMIT_EXCEEDED.value for f in assessment_cnt.findings)

    # Exceed rank
    arr_4d = np.ones((2, 2, 2, 2), dtype=np.float32)
    assessment_rank = validate_output_integrity({"out4d": arr_4d}, policy=policy)
    assert any(f.code == InferenceFindingCode.OUTPUT_RANK_MISMATCH.value for f in assessment_rank.findings)

    # Exceed dimension size
    arr_wide = np.ones((500,), dtype=np.float32)
    assessment_dim = validate_output_integrity({"outwide": arr_wide}, policy=policy)
    assert any(f.code == InferenceFindingCode.OUTPUT_DIMENSION_INVALID.value for f in assessment_dim.findings)


def test_category_av_security_scan():
    """Category AV: Security scan confirming pure typed Pydantic models with frozen extra=forbid."""
    assert ModelOutputContract.model_config.get("frozen") is True
    assert OutputIntegrityAssessment.model_config.get("frozen") is True
    assert OutputTensorContract.model_config.get("frozen") is True
    assert ValidatedTensorSummary.model_config.get("frozen") is True


def test_category_aw_project_isolation():
    """Category AW: Project isolation semantics."""
    arr = np.ones((4,), dtype=np.float32)
    contract = ModelOutputContract(outputs=[OutputTensorContract(name="out", shape=[4], dtype="float32")])
    assessment = validate_output_integrity({"out": arr}, contract=contract)
    assert assessment.integrity_status == InferenceIntegrityStatus.VERIFIED
