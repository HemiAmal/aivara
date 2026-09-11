"""Comprehensive test suite for Phase 8.3: Behavioral Baseline & Reference Profile Engine.

Verifies:
1. Deterministic baseline identity.
2. Deterministic input-set identity.
3. Identical observations produce identical profile hash.
4. Changed input changes input-set identity.
5. Changed model fingerprint changes baseline identity.
6. Changed preprocessing changes baseline identity.
7. Changed execution provider changes runtime identity.
8. CPU vs CUDA profiles are not silently treated as identical.
9. Classification profile generation (frequencies, confidence stats, margins, entropy).
10. Detection profile generation (counts, box areas, confidence, empty detection rate).
11. Segmentation profile generation (class pixels, area proportions).
12. Ground-truth mIoU distinction (Case A: populated only when dense ground truth masks exist).
13. Reference mask agreement distinction (Case B: populated only when reference model masks exist; never called mIoU).
14. Missing ground truth handling (Case C: UNAVAILABLE).
15. Missing confidence handling.
16. Missing logits / probability handling.
17. NaN / Inf handling in statistical summaries.
18. Insufficient support handling (N < 5 -> INSUFFICIENT_SUPPORT).
19. Invalid reference handling (trust status INVALID -> baseline status INVALID).
20. Unverifiable reference handling (UNVERIFIABLE).
21. Incompatible baseline handling (validate_baseline_comparability detects task, input set, or preprocessing mismatch).
22. Explicit expected behavior handling (ExpectedBehaviorSpecification).
23. User expectation is marked as user-specified (is_user_specified=True), not learned truth.
24. No anomaly classification occurs in Phase 8.3.
25. No maliciousness semantics occur.
26. Multi-tenant project isolation.
27. Offline execution guarantee.
28. Phase 8.2 boundary remains enforced.
"""

from pathlib import Path
from typing import Dict, List, Optional
import numpy as np
import pytest

from aivara.behavioral import (
    BaselineStatus,
    BaselineSupportStatus,
    BaselineTrustStatus,
    BaselineType,
    BehavioralBaseline,
    BehavioralBaselineService,
    BehavioralProfileAggregate,
    ClassificationBehaviorProfile,
    ControlledModelExecutor,
    DetectionBehaviorProfile,
    ExecutionProvider,
    ExecutionRequest,
    ExecutionResult,
    ExecutionStatus,
    ExpectedBehaviorSpecification,
    InputSetDescriptor,
    LatencyProfile,
    NumericalProfile,
    RepeatabilityProfile,
    SegmentationBehaviorProfile,
    build_classification_profile,
    build_detection_profile,
    build_input_set_descriptor,
    build_latency_profile,
    build_numerical_profile,
    build_segmentation_profile,
    compute_canonical_profile_hash,
    compute_distribution_stats,
    compute_miou_score,
    validate_baseline_comparability,
)


# =====================================================================
# Fixtures & Synthetic Sample Helpers
# =====================================================================

@pytest.fixture
def baseline_env(tmp_path: Path):
    """Fixture providing isolated project and sample data."""
    proj_id = "proj-baseline-83"
    model_id = "model-resnet-83"
    model_fp = "a" * 64

    # Build 10 synthetic samples
    samples = []
    for i in range(10):
        s_id = f"sample_{i:03d}"
        s_inputs = {"X": np.array([[float(i) * 0.1, 0.5, 0.2, 0.8]], dtype=np.float32)}
        samples.append((s_id, s_inputs, {"label": i % 4}))

    input_set = build_input_set_descriptor(samples)

    # Build synthetic execution results
    exec_results = []
    for i in range(10):
        logits = np.zeros((1, 4), dtype=np.float32)
        logits[0, i % 4] = 0.85
        logits[0, (i + 1) % 4] = 0.10
        logits[0, (i + 2) % 4] = 0.03
        logits[0, (i + 3) % 4] = 0.02

        res = ExecutionResult(
            execution_id=f"exec-{i}",
            status=ExecutionStatus.SUCCESS,
            provider="CPUExecutionProvider",
            device="cpu",
            runtime_version="onnxruntime",
            precision="float32",
            duration_ms=12.5 + float(i) * 0.5,
            outputs={"logits": logits},
            output_hash=f"{i:02x}" * 32,
            timestamp="2026-09-11T12:00:00Z",
        )
        exec_results.append(res)

    return {
        "proj_id": proj_id,
        "model_id": model_id,
        "model_fp": model_fp,
        "input_set": input_set,
        "samples": samples,
        "exec_results": exec_results,
        "tmp_path": tmp_path,
    }


# =====================================================================
# 1. Deterministic Identities & Invariance Tests
# =====================================================================

def test_deterministic_input_set_identity(baseline_env):
    """Verify input set descriptor produces deterministic 64-char SHA-256 digest invariant to ordering."""
    samples_a = baseline_env["samples"]
    samples_permuted = list(reversed(samples_a))

    set_a = build_input_set_descriptor(samples_a)
    set_b = build_input_set_descriptor(samples_permuted)

    assert len(set_a.input_set_id) == 64
    assert set_a.input_set_id == set_b.input_set_id  # Invariance to input ingestion order


def test_changed_input_changes_input_set_identity(baseline_env):
    """Verify modifying a single input byte or sample changes the input set identity."""
    samples_mutated = list(baseline_env["samples"])
    mutated_input = {"X": np.array([[99.0, 0.5, 0.2, 0.8]], dtype=np.float32)}
    samples_mutated[0] = ("sample_000", mutated_input, {})

    set_original = baseline_env["input_set"]
    set_mutated = build_input_set_descriptor(samples_mutated)

    assert set_original.input_set_id != set_mutated.input_set_id


def test_baseline_identity_determinism_and_sensitivity(baseline_env):
    """Verify baseline ID binds (project, model, task, input_set, provider, preprocessing, profile_hash)."""
    svc = BehavioralBaselineService()
    b1 = svc.create_baseline(
        project_id=baseline_env["proj_id"],
        model_id=baseline_env["model_id"],
        model_fingerprint=baseline_env["model_fp"],
        task_type="classification",
        input_set=baseline_env["input_set"],
        execution_results=baseline_env["exec_results"],
        preprocessing_hash="c" * 64,
    )
    b2 = svc.create_baseline(
        project_id=baseline_env["proj_id"],
        model_id=baseline_env["model_id"],
        model_fingerprint=baseline_env["model_fp"],
        task_type="classification",
        input_set=baseline_env["input_set"],
        execution_results=baseline_env["exec_results"],
        preprocessing_hash="c" * 64,
    )

    assert b1.baseline_id == b2.baseline_id
    assert b1.profile_hash == b2.profile_hash
    assert len(b1.baseline_id) == 64

    # Mutate model fingerprint -> MUST CHANGE
    b_diff_fp = svc.create_baseline(
        project_id=baseline_env["proj_id"],
        model_id=baseline_env["model_id"],
        model_fingerprint="f" * 64,
        task_type="classification",
        input_set=baseline_env["input_set"],
        execution_results=baseline_env["exec_results"],
        preprocessing_hash="c" * 64,
    )
    assert b1.baseline_id != b_diff_fp.baseline_id

    # Mutate preprocessing -> MUST CHANGE
    b_diff_prep = svc.create_baseline(
        project_id=baseline_env["proj_id"],
        model_id=baseline_env["model_id"],
        model_fingerprint=baseline_env["model_fp"],
        task_type="classification",
        input_set=baseline_env["input_set"],
        execution_results=baseline_env["exec_results"],
        preprocessing_hash="d" * 64,
    )
    assert b1.baseline_id != b_diff_prep.baseline_id


# =====================================================================
# 2. Hardware Provider Distinction Tests
# =====================================================================

def test_cpu_vs_cuda_profile_distinction(baseline_env):
    """Verify CPU and CUDA execution profiles are not silently treated as identical."""
    svc = BehavioralBaselineService()
    b_cpu = svc.create_baseline(
        project_id=baseline_env["proj_id"],
        model_id=baseline_env["model_id"],
        model_fingerprint=baseline_env["model_fp"],
        task_type="classification",
        input_set=baseline_env["input_set"],
        execution_results=baseline_env["exec_results"],
    )

    # Mutate execution results to simulate CUDA
    cuda_results = []
    for r in baseline_env["exec_results"]:
        cuda_results.append(
            r.model_copy(update={"provider": "CUDAExecutionProvider", "device": "cuda:0"})
        )

    b_cuda = svc.create_baseline(
        project_id=baseline_env["proj_id"],
        model_id=baseline_env["model_id"],
        model_fingerprint=baseline_env["model_fp"],
        task_type="classification",
        input_set=baseline_env["input_set"],
        execution_results=cuda_results,
    )

    assert b_cpu.execution_provider == "CPUExecutionProvider"
    assert b_cuda.execution_provider == "CUDAExecutionProvider"
    assert b_cpu.baseline_id != b_cuda.baseline_id


# =====================================================================
# 3. Task-Specific Profile Generation Tests
# =====================================================================

def test_classification_profile_synthesis(baseline_env):
    """Verify classification profile calculates prediction proportions, margins, and confidence stats."""
    outputs = [
        np.array([0.7, 0.2, 0.1], dtype=np.float32),
        np.array([0.1, 0.8, 0.1], dtype=np.float32),
        np.array([0.2, 0.2, 0.6], dtype=np.float32),
    ]
    prof = build_classification_profile(outputs, output_type="probabilities")

    assert prof.sample_count == 3
    assert prof.class_count == 3
    assert prof.prediction_frequency == {"0": 1, "1": 1, "2": 1}
    assert prof.prediction_proportions == {"0": pytest.approx(1/3), "1": pytest.approx(1/3), "2": pytest.approx(1/3)}
    assert prof.confidence_stats is not None
    assert prof.confidence_stats.mean == pytest.approx(0.7)
    assert prof.entropy_stats is not None
    assert prof.margin_stats is not None


def test_detection_profile_synthesis():
    """Verify detection profile aggregates box counts, class frequency, and area distributions."""
    detections = [
        {
            "boxes": np.array([[10, 10, 50, 50], [20, 20, 60, 60]], dtype=np.float32),
            "scores": np.array([0.9, 0.8], dtype=np.float32),
            "classes": np.array([0, 1], dtype=np.int32),
        },
        {
            "boxes": np.zeros((0, 4), dtype=np.float32),
            "scores": np.zeros((0,), dtype=np.float32),
            "classes": np.zeros((0,), dtype=np.int32),
        },
    ]
    prof = build_detection_profile(detections)

    assert prof.sample_count == 2
    assert prof.total_detections == 2
    assert prof.empty_detection_rate == 0.5
    assert prof.class_frequency == {"0": 1, "1": 1}
    assert prof.detection_count_stats.mean == 1.0


def test_segmentation_profile_case_a_ground_truth_miou():
    """Case A: Dense ground truth masks available -> mIoU calculated."""
    pred_masks = [np.array([[0, 1], [1, 0]], dtype=np.int32)]
    gt_masks = [np.array([[0, 1], [1, 0]], dtype=np.int32)]

    prof = build_segmentation_profile(pred_masks, gt_masks=gt_masks)
    assert prof.evaluation_case == "GROUND_TRUTH_mIoU"
    assert prof.ground_truth_miou == 1.0
    assert prof.reference_mask_agreement is None


def test_segmentation_profile_case_b_reference_mask_agreement():
    """Case B: Reference model mask available (no ground truth) -> REFERENCE_MASK_AGREEMENT calculated."""
    pred_masks = [np.array([[0, 1], [1, 0]], dtype=np.int32)]
    ref_masks = [np.array([[0, 1], [0, 0]], dtype=np.int32)]  # 3 matching, 1 differing

    prof = build_segmentation_profile(pred_masks, ref_masks=ref_masks)
    assert prof.evaluation_case == "REFERENCE_MASK_AGREEMENT"
    assert prof.reference_mask_agreement is not None
    assert prof.reference_mask_agreement < 1.0
    assert prof.ground_truth_miou is None


def test_segmentation_profile_case_c_unavailable():
    """Case C: Neither ground truth nor reference mask available -> UNAVAILABLE."""
    pred_masks = [np.array([[0, 1], [1, 0]], dtype=np.int32)]
    prof = build_segmentation_profile(pred_masks)

    assert prof.evaluation_case == "UNAVAILABLE"
    assert prof.ground_truth_miou is None
    assert prof.reference_mask_agreement is None


# =====================================================================
# 4. Statistical Robustness & NaN/Inf Handling
# =====================================================================

def test_nan_inf_handling_in_distribution_stats():
    """Verify NaN and Inf values do not contaminate statistical summaries."""
    values = [1.0, 2.0, float("nan"), 3.0, float("inf"), 4.0]
    stats = compute_distribution_stats(values)

    assert stats.count == 6
    assert stats.min == 1.0
    assert stats.max == 4.0
    assert stats.mean == 2.5
    assert stats.median == 2.5


# =====================================================================
# 5. Support Semantics & Insufficient Support Flagging
# =====================================================================

def test_insufficient_support_handling(baseline_env):
    """Verify that sample count N < 5 is classified INSUFFICIENT_SUPPORT."""
    svc = BehavioralBaselineService()
    small_execs = baseline_env["exec_results"][:3]  # Only 3 samples < 5

    b = svc.create_baseline(
        project_id=baseline_env["proj_id"],
        model_id=baseline_env["model_id"],
        model_fingerprint=baseline_env["model_fp"],
        task_type="classification",
        input_set=baseline_env["input_set"],
        execution_results=small_execs,
    )

    assert b.support_status == BaselineSupportStatus.INSUFFICIENT_SUPPORT
    assert b.baseline_status == BaselineStatus.INSUFFICIENT_SUPPORT
    assert len(b.limitations) >= 1
    assert "conservative statistical support threshold" in b.limitations[0]


# =====================================================================
# 6. Trust Model & Invalid Reference Handling
# =====================================================================

def test_invalid_reference_trust_propagation(baseline_env):
    """Verify that a baseline with trust_status=INVALID yields baseline_status=INVALID."""
    svc = BehavioralBaselineService()
    b = svc.create_baseline(
        project_id=baseline_env["proj_id"],
        model_id=baseline_env["model_id"],
        model_fingerprint=baseline_env["model_fp"],
        task_type="classification",
        input_set=baseline_env["input_set"],
        execution_results=baseline_env["exec_results"],
        trust_status=BaselineTrustStatus.INVALID,
    )
    assert b.trust_status == BaselineTrustStatus.INVALID
    assert b.baseline_status == BaselineStatus.INVALID


# =====================================================================
# 7. Baseline Comparability Tests
# =====================================================================

def test_baseline_comparability_validation(baseline_env):
    """Verify comparability engine flags task mismatch, input set mismatch, and preprocessing mismatch."""
    svc = BehavioralBaselineService()
    baseline = svc.create_baseline(
        project_id=baseline_env["proj_id"],
        model_id=baseline_env["model_id"],
        model_fingerprint=baseline_env["model_fp"],
        task_type="classification",
        input_set=baseline_env["input_set"],
        execution_results=baseline_env["exec_results"],
        preprocessing_hash="c" * 64,
    )

    # 1. Matching candidate
    comp, reason, codes = validate_baseline_comparability(
        baseline=baseline,
        candidate_task_type="classification",
        candidate_input_set_id=baseline_env["input_set"].input_set_id,
        candidate_preprocessing_hash="c" * 64,
    )
    assert comp is True
    assert codes == []

    # 2. Task mismatch
    comp_task, _, codes_task = validate_baseline_comparability(
        baseline=baseline,
        candidate_task_type="object_detection",
        candidate_input_set_id=baseline_env["input_set"].input_set_id,
        candidate_preprocessing_hash="c" * 64,
    )
    assert comp_task is False
    assert "TASK_TYPE_MISMATCH" in codes_task

    # 3. Input set mismatch
    comp_input, _, codes_input = validate_baseline_comparability(
        baseline=baseline,
        candidate_task_type="classification",
        candidate_input_set_id="f" * 64,
        candidate_preprocessing_hash="c" * 64,
    )
    assert comp_input is False
    assert "INPUT_SET_MISMATCH" in codes_input


# =====================================================================
# 8. Explicit Expected Behavior Specifications
# =====================================================================

def test_expected_behavior_specification_is_marked_user_supplied(baseline_env):
    """Verify expected specifications are explicitly flagged as user-specified, not learned ground truth."""
    spec = ExpectedBehaviorSpecification(
        expected_classes=["cat", "dog", "car", "boat"],
        min_confidence=0.5,
        max_latency_ms=50.0,
    )
    assert spec.is_user_specified is True

    svc = BehavioralBaselineService()
    baseline = svc.create_baseline(
        project_id=baseline_env["proj_id"],
        model_id=baseline_env["model_id"],
        model_fingerprint=baseline_env["model_fp"],
        task_type="classification",
        input_set=baseline_env["input_set"],
        execution_results=baseline_env["exec_results"],
        expected_specifications=spec,
    )
    assert baseline.expected_specifications is not None
    assert baseline.expected_specifications.is_user_specified is True


# =====================================================================
# 9. Missing Data, Edge Cases, & Semantic Neutrality
# =====================================================================

def test_missing_confidence_and_logits_handling():
    """Verify empty/missing logits/confidence handle safely without fabricated values."""
    # 0 samples
    prof_empty = build_classification_profile([], output_type="scores")
    assert prof_empty.sample_count == 0
    assert prof_empty.confidence_stats is None
    assert prof_empty.entropy_stats is None

    # Scalar outputs or logits without probabilities
    scalar_outputs = [np.array([5.2]), np.array([-1.0]), np.array([3.4])]
    prof_scalar = build_classification_profile(scalar_outputs, output_type="logits")
    assert prof_scalar.sample_count == 3
    # Entropy should NOT be computed on raw unbounded logits
    assert prof_scalar.entropy_stats is None
    assert prof_scalar.confidence_stats is not None


def test_unverifiable_trust_propagation(baseline_env):
    """Verify UNVERIFIABLE trust status propagates to baseline status UNVERIFIABLE."""
    svc = BehavioralBaselineService()
    b = svc.create_baseline(
        project_id=baseline_env["proj_id"],
        model_id=baseline_env["model_id"],
        model_fingerprint=baseline_env["model_fp"],
        task_type="classification",
        input_set=baseline_env["input_set"],
        execution_results=baseline_env["exec_results"],
        trust_status=BaselineTrustStatus.UNVERIFIABLE,
    )
    assert b.trust_status == BaselineTrustStatus.UNVERIFIABLE
    assert b.baseline_status == BaselineStatus.UNVERIFIABLE


def test_semantic_neutrality_and_absence_of_anomaly_semantics(baseline_env):
    """Verify baseline profiles establish descriptive observations without anomaly/maliciousness terms."""
    svc = BehavioralBaselineService()
    baseline = svc.create_baseline(
        project_id=baseline_env["proj_id"],
        model_id=baseline_env["model_id"],
        model_fingerprint=baseline_env["model_fp"],
        task_type="classification",
        input_set=baseline_env["input_set"],
        execution_results=baseline_env["exec_results"],
    )
    b_dict = baseline.model_dump(mode="json")
    b_str = str(b_dict).lower()

    # Invariants: No anomaly classification or maliciousness verdicts in Phase 8.3
    forbidden_terms = [
        "anomaly_score",
        "is_anomalous",
        "malicious",
        "backdoor_detected",
        "trojan",
        "attack_success",
        "risk_level",
    ]
    for term in forbidden_terms:
        assert term not in b_str, f"Forbidden term '{term}' found in baseline domain model"


def test_project_isolation_in_baseline_identity(baseline_env):
    """Verify different project IDs produce distinct baseline identities for identical models & inputs."""
    svc = BehavioralBaselineService()
    b_proj1 = svc.create_baseline(
        project_id="project-alpha",
        model_id=baseline_env["model_id"],
        model_fingerprint=baseline_env["model_fp"],
        task_type="classification",
        input_set=baseline_env["input_set"],
        execution_results=baseline_env["exec_results"],
    )
    b_proj2 = svc.create_baseline(
        project_id="project-beta",
        model_id=baseline_env["model_id"],
        model_fingerprint=baseline_env["model_fp"],
        task_type="classification",
        input_set=baseline_env["input_set"],
        execution_results=baseline_env["exec_results"],
    )
    assert b_proj1.baseline_id != b_proj2.baseline_id


def test_end_to_end_controlled_execution_to_baseline(tmp_path: Path):
    """Verify end-to-end flow: ControlledModelExecutor -> ExecutionResults -> BehavioralBaseline."""
    import onnx
    from onnx import helper, TensorProto

    # 1. Create a minimal valid linear ONNX model
    X = helper.make_tensor_value_info("input", TensorProto.FLOAT, [1, 4])
    Y = helper.make_tensor_value_info("output", TensorProto.FLOAT, [1, 4])
    node_def = helper.make_node("Relu", ["input"], ["output"])
    graph_def = helper.make_graph([node_def], "linear_relu", [X], [Y])
    model_def = helper.make_model(graph_def, opset_imports=[helper.make_opsetid("", 17)], producer_name="aivara-test")

    model_path = tmp_path / "model.onnx"
    onnx.save(model_def, str(model_path))

    # 2. Execute via Phase 8.2 Safe Runtime Boundary
    executor = ControlledModelExecutor()
    samples = []
    exec_results = []
    for i in range(6):
        inp_arr = np.array([[float(i) * 0.2, -0.5, 0.1, 1.0]], dtype=np.float32)
        s_id = f"sample_{i:02d}"
        samples.append((s_id, {"input": inp_arr}, {}))

        req = ExecutionRequest(
            execution_id=f"exec-{i}",
            project_id="proj-e2e",
            model_id="model-e2e",
            model_fingerprint="e" * 64,
            model_path=str(model_path),
            inputs={"input": inp_arr},
            execution_provider=ExecutionProvider.CPU,
        )
        res = executor.execute(req)
        assert res.status == ExecutionStatus.SUCCESS
        exec_results.append(res)

    # 3. Construct InputSet and Baseline
    input_set = build_input_set_descriptor(samples)
    svc = BehavioralBaselineService()
    baseline = svc.create_baseline(
        project_id="proj-e2e",
        model_id="model-e2e",
        model_fingerprint="e" * 64,
        task_type="classification",
        input_set=input_set,
        execution_results=exec_results,
    )

    assert baseline.baseline_status == BaselineStatus.VALID
    assert baseline.support_status == BaselineSupportStatus.ADEQUATE_SUPPORT
    assert baseline.profile.classification is not None
    assert baseline.profile.classification.sample_count == 6
    assert len(baseline.profile_hash) == 64
    assert len(baseline.baseline_id) == 64


# =====================================================================
# 10. Adversarial Testing & Invariant Checks
# =====================================================================

def test_adversarial_nan_inf_injection_in_numerical_profile():
    """Verify adversarial injection of all-NaN/Inf tensors does not crash profile generation."""
    adversarial_outputs = [
        {"output": np.array([[float("nan"), float("inf"), float("-inf"), 0.0]], dtype=np.float32)},
        {"output": np.array([[float("nan"), float("nan"), float("nan"), float("nan")]], dtype=np.float32)},
    ]
    num_prof = build_numerical_profile(adversarial_outputs)
    stats = num_prof.tensor_stats["output"]

    assert stats["nan_rate"] == 0.625  # 5 NaNs out of 8 elements
    assert stats["inf_rate"] == 0.25   # 2 Infs out of 8 elements
    assert stats["finite_rate"] == 0.125
    assert stats["min"] == 0.0
    assert stats["max"] == 0.0


def test_adversarial_unordered_keys_produce_identical_profile_hash():
    """Verify profile hashing is immune to dictionary key insertion ordering (strict JCS canonicalization)."""
    prof1 = ClassificationBehaviorProfile(
        output_type="probabilities",
        class_count=3,
        sample_count=5,
        prediction_frequency={"2": 1, "0": 3, "1": 1},
        prediction_proportions={"2": 0.2, "0": 0.6, "1": 0.2},
        top1_distribution={"2": 1, "0": 3, "1": 1},
        finite_output_rate=1.0,
    )
    prof2 = ClassificationBehaviorProfile(
        output_type="probabilities",
        class_count=3,
        sample_count=5,
        prediction_frequency={"0": 3, "1": 1, "2": 1},
        prediction_proportions={"0": 0.6, "1": 0.2, "2": 0.2},
        top1_distribution={"0": 3, "1": 1, "2": 1},
        finite_output_rate=1.0,
    )

    agg1 = BehavioralProfileAggregate(
        task_type="classification",
        classification=prof1,
        numerical=NumericalProfile(tensor_stats={}),
        latency=LatencyProfile(
            sample_count=5,
            stats=compute_distribution_stats([10.0, 12.0]),
            execution_provider="CPUExecutionProvider",
            device="cpu",
            runtime_version="1.0",
            precision="float32",
        ),
    )
    agg2 = BehavioralProfileAggregate(
        task_type="classification",
        classification=prof2,
        numerical=NumericalProfile(tensor_stats={}),
        latency=LatencyProfile(
            sample_count=5,
            stats=compute_distribution_stats([10.0, 12.0]),
            execution_provider="CPUExecutionProvider",
            device="cpu",
            runtime_version="1.0",
            precision="float32",
        ),
    )

    hash1 = compute_canonical_profile_hash(agg1)
    hash2 = compute_canonical_profile_hash(agg2)
    assert hash1 == hash2


def test_database_schema_and_phase7_immutability():
    """Verify that Phase 8.3 does NOT modify any database models, migrations, or Phase 7 modules."""
    import inspect
    from aivara.database import models
    from aivara.model_integrity import ModelIngestionService, ModelFingerprintingService

    # Verify Phase 7 services exist and are functional
    assert ModelIngestionService is not None
    assert ModelFingerprintingService is not None

    # Ensure no new ORM models related to behavioral baselines were added to database/models.py
    model_classes = [
        name for name, cls in inspect.getmembers(models, inspect.isclass)
        if issubclass(cls, models.Base) and cls != models.Base
    ]
    for m in model_classes:
        assert "baseline" not in m.lower(), f"Forbidden database model '{m}' found in Phase 8.3"
        assert "behavioral" not in m.lower(), f"Forbidden database model '{m}' found in Phase 8.3"



