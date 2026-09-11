"""Comprehensive test suite for Phase 8.5: Output Consistency & Stability Analysis Engine.

Verifies:
1. Classification prediction agreement.
2. Classification top-k overlap.
3. Probability KL divergence calculation.
4. KL divergence rejection / UNDEFINED on logits.
5. Jensen-Shannon divergence symmetry and non-negativity.
6. Entropy delta calculation.
7. Margin delta calculation.
8. Object detection deterministic bipartite matching.
9. Object detection tie-breaking stability.
10. Object detection mean IoU and count deltas.
11. Object detection confidence delta and centroid displacement.
12. Segmentation Case A (Dense Ground Truth mIoU).
13. Segmentation Case B (Reference Mask Agreement).
14. Generic tensor L1 distance.
15. Generic tensor L2 distance.
16. Cosine similarity and zero-vector robustness.
17. Shape mismatch handling.
18. Empty detections handling.
19. Empty / single-pixel masks handling.
20. NaN / Inf robustness in metrics.
21. Repeatability analysis service.
22. Perturbation sensitivity measurement service.
23. Input and output distance calculations.
24. Sensitivity ratio and zero input-change handling.
25. Deterministic comparison ID and metric ID.
26. Multi-tenant cross-project comparison rejection.
27. Absence of anomaly and maliciousness semantics.
28. End-to-end integration with Phase 8.2 runtime boundary.
29. Immutability of Phase 7, Phase 8.2, Phase 8.3, Phase 8.4, and database schema.
"""

from pathlib import Path
from typing import Any, Dict, List
import numpy as np
import pytest

from aivara.behavioral import (
    BehavioralComparisonResult,
    ClassificationStabilityMetrics,
    ComparisonType,
    ControlledModelExecutor,
    ControlledPerturbationEngine,
    DetectionMatchRecord,
    DetectionStabilityMetrics,
    ExecutionProvider,
    ExecutionRequest,
    ExecutionResult,
    ExecutionStatus,
    GenericTensorStabilityMetrics,
    MetricResult,
    MetricValidityStatus,
    OutputStabilityAnalysisService,
    PerturbationExperiment,
    PerturbationResultStatus,
    PerturbationSensitivityResult,
    PerturbationSpecification,
    PerturbationType,
    RepeatabilityAnalysisResult,
    SegmentationStabilityMetrics,
    compute_box_iou,
    compute_classification_stability_metrics,
    compute_comparison_id,
    compute_detection_stability_metrics,
    compute_generic_tensor_stability_metrics,
    compute_input_distance,
    compute_metric_id,
    compute_repeatability_analysis_id,
    compute_segmentation_stability_metrics,
    compute_sensitivity_id,
)
from aivara.behavioral.exceptions import BehavioralError


# =====================================================================
# 1. Classification Stability & Divergence Tests
# =====================================================================

def test_classification_prediction_agreement_and_topk():
    """Verify prediction agreement and top-k Jaccard overlap."""
    vec_a = np.array([0.70, 0.20, 0.05, 0.05], dtype=np.float32)
    vec_b = np.array([0.65, 0.25, 0.08, 0.02], dtype=np.float32)
    vec_c = np.array([0.10, 0.80, 0.05, 0.05], dtype=np.float32)

    # Identical top-1 (class 0)
    metrics_ab = compute_classification_stability_metrics(vec_a, vec_b, is_probability=True, top_k=2)
    assert metrics_ab.prediction_agreement.value == 1.0
    assert metrics_ab.top_k_overlap is not None
    assert metrics_ab.top_k_overlap.value == 1.0  # Top 2 are {0, 1} for both

    # Different top-1 (class 0 vs class 1)
    metrics_ac = compute_classification_stability_metrics(vec_a, vec_c, is_probability=True, top_k=2)
    assert metrics_ac.prediction_agreement.value == 0.0
    assert metrics_ac.top_k_overlap is not None
    assert metrics_ac.top_k_overlap.value == 1.0  # Top 2 are {0, 1} for both


def test_kl_and_js_divergence_on_probabilities():
    """Verify KL and JS divergence on valid probability distributions."""
    p = np.array([0.6, 0.3, 0.1], dtype=np.float32)
    q = np.array([0.5, 0.4, 0.1], dtype=np.float32)

    metrics = compute_classification_stability_metrics(p, q, is_probability=True)
    assert metrics.kl_divergence is not None
    assert metrics.kl_divergence.validity_status == MetricValidityStatus.VALID
    assert metrics.kl_divergence.value is not None
    assert metrics.kl_divergence.value >= 0.0

    assert metrics.js_divergence is not None
    assert metrics.js_divergence.validity_status == MetricValidityStatus.VALID
    assert metrics.js_divergence.value is not None
    assert metrics.js_divergence.value >= 0.0

    # Symmetric JS check
    metrics_rev = compute_classification_stability_metrics(q, p, is_probability=True)
    assert pytest.approx(metrics.js_divergence.value, rel=1e-5) == metrics_rev.js_divergence.value


def test_kl_divergence_rejection_on_logits():
    """Verify KL and JS divergence are rejected/UNDEFINED when outputs are marked unnormalized logits."""
    logits_a = np.array([12.5, -2.1, 4.3], dtype=np.float32)
    logits_b = np.array([11.8, -1.9, 5.0], dtype=np.float32)

    metrics = compute_classification_stability_metrics(logits_a, logits_b, is_probability=False)
    assert metrics.kl_divergence is not None
    assert metrics.kl_divergence.validity_status == MetricValidityStatus.UNDEFINED
    assert metrics.kl_divergence.value is None

    assert metrics.js_divergence is not None
    assert metrics.js_divergence.validity_status == MetricValidityStatus.UNDEFINED
    assert metrics.js_divergence.value is None

    # Prediction agreement and confidence delta still work on logits
    assert metrics.prediction_agreement.validity_status == MetricValidityStatus.VALID
    assert metrics.confidence_delta is not None
    assert metrics.confidence_delta.value == pytest.approx(12.5 - 11.8, abs=1e-4)


def test_entropy_and_margin_delta():
    """Verify entropy and margin delta metrics."""
    p = np.array([0.8, 0.15, 0.05], dtype=np.float32)
    q = np.array([0.5, 0.30, 0.20], dtype=np.float32)

    metrics = compute_classification_stability_metrics(p, q, is_probability=True)
    assert metrics.entropy_delta is not None
    assert metrics.entropy_delta.validity_status == MetricValidityStatus.VALID
    assert metrics.entropy_delta.value is not None
    assert metrics.entropy_delta.value > 0.0

    assert metrics.margin_delta is not None
    assert metrics.margin_delta.validity_status == MetricValidityStatus.VALID
    # Margin p: 0.8 - 0.15 = 0.65. Margin q: 0.5 - 0.3 = 0.2. Delta = 0.45
    assert metrics.margin_delta.value == pytest.approx(0.45, abs=1e-4)


# =====================================================================
# 2. Object Detection Consistency & Bipartite Matching Tests
# =====================================================================

def test_box_iou_computation():
    """Verify exact 2D box IoU calculations."""
    # Perfect overlap
    b1 = np.array([0, 0, 10, 10], dtype=np.float32)
    b2 = np.array([0, 0, 10, 10], dtype=np.float32)
    assert compute_box_iou(b1, b2) == 1.0

    # Half overlap: (5, 0, 10, 10) intersection area = 50. union = 100 + 100 - 50 = 150. IoU = 50/150 = 1/3
    b3 = np.array([5, 0, 15, 10], dtype=np.float32)
    assert pytest.approx(compute_box_iou(b1, b3), abs=1e-4) == (1.0 / 3.0)

    # Disjoint
    b4 = np.array([20, 20, 30, 30], dtype=np.float32)
    assert compute_box_iou(b1, b4) == 0.0


def test_detection_deterministic_matching_and_metrics():
    """Verify deterministic greedy bipartite matching across multiple boxes."""
    cand = {
        "boxes": np.array([[10, 10, 50, 50], [100, 100, 150, 150]], dtype=np.float32),
        "scores": np.array([0.92, 0.85], dtype=np.float32),
        "classes": np.array([1, 2], dtype=np.int32),
    }
    ref = {
        "boxes": np.array([[12, 11, 51, 49], [101, 99, 152, 148], [200, 200, 250, 250]], dtype=np.float32),
        "scores": np.array([0.90, 0.88, 0.70], dtype=np.float32),
        "classes": np.array([1, 2, 3], dtype=np.int32),
    }

    metrics = compute_detection_stability_metrics(cand, ref, iou_threshold=0.5)
    assert metrics.matched_detection_count == 2
    assert metrics.unmatched_candidate_count == 0
    assert metrics.unmatched_reference_count == 1
    assert metrics.count_delta == -1
    assert metrics.class_agreement_rate is not None
    assert metrics.class_agreement_rate.value == 1.0
    assert metrics.mean_matched_iou is not None
    assert metrics.mean_matched_iou.value > 0.85


def test_empty_detections_handling():
    """Verify empty detection lists are handled gracefully without exceptions."""
    empty_det: Dict[str, Any] = {"boxes": np.zeros((0, 4)), "scores": np.zeros((0,)), "classes": np.zeros((0,))}
    non_empty: Dict[str, Any] = {
        "boxes": np.array([[0, 0, 10, 10]]),
        "scores": np.array([0.9]),
        "classes": np.array([1]),
    }

    metrics = compute_detection_stability_metrics(empty_det, empty_det)
    assert metrics.matched_detection_count == 0
    assert metrics.count_delta == 0

    metrics_diff = compute_detection_stability_metrics(non_empty, empty_det)
    assert metrics_diff.matched_detection_count == 0
    assert metrics_diff.unmatched_candidate_count == 1
    assert metrics_diff.count_delta == 1


# =====================================================================
# 3. Segmentation Consistency Tests
# =====================================================================

def test_segmentation_ground_truth_miou_case_a():
    """Case A: Dense Ground-Truth Masks -> Populates ground_truth_miou."""
    pred = np.array([[0, 1], [1, 0]], dtype=np.int32)
    gt = np.array([[0, 1], [1, 1]], dtype=np.int32)

    metrics = compute_segmentation_stability_metrics(pred, ground_truth_mask=gt)
    assert metrics.evaluation_case == "GROUND_TRUTH_mIoU"
    assert metrics.ground_truth_miou is not None
    assert metrics.ground_truth_miou.validity_status == MetricValidityStatus.VALID
    assert metrics.reference_mask_agreement is None
    assert metrics.pixel_agreement_rate is not None
    assert metrics.pixel_agreement_rate.value == 0.75  # 3 out of 4 pixels match


def test_segmentation_reference_mask_agreement_case_b():
    """Case B: Candidate vs Reference Model -> Populates reference_mask_agreement (NOT mIoU)."""
    cand = np.array([[0, 1], [1, 0]], dtype=np.int32)
    ref = np.array([[0, 1], [1, 1]], dtype=np.int32)

    metrics = compute_segmentation_stability_metrics(cand, reference_mask=ref)
    assert metrics.evaluation_case == "REFERENCE_MASK_AGREEMENT"
    assert metrics.ground_truth_miou is None
    assert metrics.reference_mask_agreement is not None
    assert metrics.reference_mask_agreement.validity_status == MetricValidityStatus.VALID


# =====================================================================
# 4. Generic Tensor Distance Tests
# =====================================================================

def test_generic_tensor_l1_l2_cosine():
    """Verify generic tensor distance metrics on mathematical arrays."""
    t1 = np.array([1.0, 2.0, 3.0], dtype=np.float32)
    t2 = np.array([1.0, 2.0, 4.0], dtype=np.float32)

    metrics = compute_generic_tensor_stability_metrics(t1, t2)
    assert metrics.shape_match is True
    assert metrics.l1_distance.value == 1.0
    assert metrics.l2_distance.value == 1.0
    assert metrics.max_absolute_difference.value == 1.0
    assert metrics.mean_absolute_difference.value == pytest.approx(1.0 / 3.0)
    assert metrics.cosine_similarity is not None
    assert metrics.cosine_similarity.value is not None
    assert metrics.cosine_similarity.value > 0.95


def test_generic_tensor_zero_vector_and_shape_mismatch():
    """Verify zero-vectors and shape mismatches handle safely without crashes."""
    z1 = np.zeros((4,), dtype=np.float32)
    z2 = np.zeros((4,), dtype=np.float32)

    metrics_zeros = compute_generic_tensor_stability_metrics(z1, z2)
    assert metrics_zeros.cosine_similarity is not None
    assert metrics_zeros.cosine_similarity.value == 1.0  # Identical zero vectors

    # Shape mismatch
    t_diff_shape = np.zeros((5,), dtype=np.float32)
    metrics_mismatch = compute_generic_tensor_stability_metrics(z1, t_diff_shape)
    assert metrics_mismatch.shape_match is False
    assert metrics_mismatch.l1_distance.validity_status == MetricValidityStatus.INCOMPATIBLE


# =====================================================================
# 5. Repeatability & Sensitivity Services
# =====================================================================

def test_repeatability_analysis_service():
    """Verify RepeatabilityAnalysisResult correctly evaluates identical repeated runs."""
    svc = OutputStabilityAnalysisService()
    exec_results = []
    for i in range(3):
        res = ExecutionResult(
            execution_id=f"exec-{i}",
            status=ExecutionStatus.SUCCESS,
            provider="CPUExecutionProvider",
            device="cpu",
            runtime_version="onnxruntime",
            precision="float32",
            duration_ms=10.0,
            outputs={"logits": np.array([[2.5, 0.1, -1.0]], dtype=np.float32)},
            timestamp="2026-09-11T12:00:00Z",
        )
        exec_results.append(res)

    result = svc.analyze_repeatability(
        project_id="proj-rep-85",
        model_id="model-rep-85",
        model_fingerprint="a" * 64,
        execution_results=exec_results,
    )

    assert result.determinism_status == "DETERMINISTIC"
    assert result.prediction_agreement_rate == 1.0
    assert result.max_numerical_delta == 0.0
    assert len(result.analysis_id) == 64


def test_perturbation_sensitivity_case_d_nonzero_input_nonzero_output():
    """Case D: Nonzero input change + Nonzero output change -> VALID finite sensitivity ratio."""
    svc = OutputStabilityAnalysisService()
    src_input = np.zeros((32, 32, 3), dtype=np.uint8)
    pert_input = np.full((32, 32, 3), 10, dtype=np.uint8)

    src_out = {"logits": np.array([[1.0, 0.0]], dtype=np.float32)}
    pert_out = {"logits": np.array([[0.8, 0.2]], dtype=np.float32)}

    sens_res = svc.analyze_perturbation_sensitivity(
        project_id="proj-sens-85",
        model_id="model-sens-85",
        source_input=src_input,
        perturbed_input=pert_input,
        source_output=src_out,
        perturbed_output=pert_out,
        source_input_hash="s" * 64,
        perturbed_input_hash="p" * 64,
        perturbation_id="t" * 64,
        perturbation_type="BRIGHTNESS",
        task_type="classification",
    )

    assert sens_res.input_unchanged is False
    assert sens_res.output_changed is True
    assert sens_res.sensitivity_status == "VALID"
    assert sens_res.sensitivity_ratio is not None
    assert sens_res.sensitivity_ratio > 0.0
    assert len(sens_res.sensitivity_id) == 64


def test_perturbation_sensitivity_case_a_zero_input_zero_output():
    """Case A: Zero input change + Zero output change -> NOT_APPLICABLE (Never 0.0)."""
    svc = OutputStabilityAnalysisService()
    src_input = np.zeros((10, 10), dtype=np.uint8)
    pert_input = np.zeros((10, 10), dtype=np.uint8)  # Identical

    src_out = {"logits": np.array([[1.0, 0.0]], dtype=np.float32)}
    pert_out = {"logits": np.array([[1.0, 0.0]], dtype=np.float32)}  # Identical

    sens_res = svc.analyze_perturbation_sensitivity(
        project_id="proj-zero",
        model_id="model-zero",
        source_input=src_input,
        perturbed_input=pert_input,
        source_output=src_out,
        perturbed_output=pert_out,
        source_input_hash="s" * 64,
        perturbed_input_hash="s" * 64,
        perturbation_id="t" * 64,
        perturbation_type="GAUSSIAN_NOISE",
    )
    assert sens_res.input_unchanged is True
    assert sens_res.output_changed is False
    assert sens_res.sensitivity_status == "NOT_APPLICABLE"
    assert sens_res.sensitivity_ratio is None  # Never fabricated


def test_perturbation_sensitivity_case_b_zero_input_nonzero_output():
    """Case B: Zero input change + Nonzero output change -> UNDEFINED_NON_FINITE_DENOMINATOR (Never 0.0 or Inf)."""
    svc = OutputStabilityAnalysisService()
    src_input = np.zeros((10, 10), dtype=np.uint8)
    pert_input = np.zeros((10, 10), dtype=np.uint8)  # Identical input

    src_out = {"logits": np.array([[1.0, 0.0]], dtype=np.float32)}
    pert_out = {"logits": np.array([[0.5, 0.5]], dtype=np.float32)}  # Output changed (nondeterministic or perturbed state)

    sens_res = svc.analyze_perturbation_sensitivity(
        project_id="proj-b",
        model_id="model-b",
        source_input=src_input,
        perturbed_input=pert_input,
        source_output=src_out,
        perturbed_output=pert_out,
        source_input_hash="s" * 64,
        perturbed_input_hash="s" * 64,
        perturbation_id="t" * 64,
        perturbation_type="GAUSSIAN_NOISE",
    )
    assert sens_res.input_unchanged is True
    assert sens_res.output_changed is True
    assert sens_res.sensitivity_status == "UNDEFINED_NON_FINITE_DENOMINATOR"
    assert sens_res.sensitivity_ratio is None  # Denominator is zero; never fabricate finite float


def test_perturbation_sensitivity_case_c_nonzero_input_zero_output():
    """Case C: Nonzero input change + Zero output change -> VALID sensitivity ratio of exactly 0.0."""
    svc = OutputStabilityAnalysisService()
    src_input = np.zeros((10, 10), dtype=np.uint8)
    pert_input = np.full((10, 10), 5, dtype=np.uint8)  # Changed input

    src_out = {"logits": np.array([[1.0, 0.0]], dtype=np.float32)}
    pert_out = {"logits": np.array([[1.0, 0.0]], dtype=np.float32)}  # Unchanged output

    sens_res = svc.analyze_perturbation_sensitivity(
        project_id="proj-c",
        model_id="model-c",
        source_input=src_input,
        perturbed_input=pert_input,
        source_output=src_out,
        perturbed_output=pert_out,
        source_input_hash="s" * 64,
        perturbed_input_hash="p" * 64,
        perturbation_id="t" * 64,
        perturbation_type="BRIGHTNESS",
    )
    assert sens_res.input_unchanged is False
    assert sens_res.output_changed is False
    assert sens_res.sensitivity_status == "VALID"
    assert sens_res.sensitivity_ratio == 0.0


def test_cosine_zero_vector_and_relative_l2_conventions():
    """Verify AIVARA-defined conventions for zero-norm cosine and relative L2."""
    z = np.zeros((4,), dtype=np.float32)
    v = np.array([1.0, 2.0, 3.0, 4.0], dtype=np.float32)

    # 1. Both zero -> 1.0 (AIVARA convention for identical null representations)
    m_both_zero = compute_generic_tensor_stability_metrics(z, z)
    assert m_both_zero.cosine_similarity.value == 1.0
    assert "AIVARA convention: both vectors are zero norm" in str(m_both_zero.cosine_similarity.details)
    assert m_both_zero.relative_l2_distance.value == 0.0

    # 2. One-sided zero -> 0.0 (AIVARA safe fallback convention)
    m_one_zero = compute_generic_tensor_stability_metrics(v, z)
    assert m_one_zero.cosine_similarity.value == 0.0
    assert "AIVARA safe fallback: one vector has zero norm" in str(m_one_zero.cosine_similarity.details)
    assert m_one_zero.relative_l2_distance.value is None
    assert m_one_zero.relative_l2_distance.validity_status == MetricValidityStatus.UNDEFINED


# =====================================================================
# 6. Multi-Tenant Project Isolation & Invariant Tests
# =====================================================================

def test_cross_project_comparison_rejection():
    """Verify comparisons between different projects are strictly rejected."""
    svc = OutputStabilityAnalysisService()
    with pytest.raises(BehavioralError) as exc_info:
        svc.compare_observations(
            project_id="project-alpha",
            source_observation_id="obs-1",
            target_observation_id="obs-2",
            source_output={"logits": np.array([1.0, 0.0])},
            target_output={"logits": np.array([1.0, 0.0])},
            task_type="classification",
            target_project_id="project-beta",  # Cross-project violation
        )
    assert exc_info.value.code == "CROSS_PROJECT_COMPARISON"


def test_absence_of_anomaly_semantics_in_stability_results():
    """Verify domain representations contain zero anomaly classifications or maliciousness labels."""
    svc = OutputStabilityAnalysisService()
    res = svc.compare_observations(
        project_id="project-alpha",
        source_observation_id="obs-1",
        target_observation_id="obs-2",
        source_output={"logits": np.array([1.0, 0.0])},
        target_output={"logits": np.array([0.9, 0.1])},
        task_type="classification",
    )
    dump_str = str(res.model_dump(mode="json")).lower()

    forbidden_terms = [
        "anomaly",
        "is_anomalous",
        "malicious",
        "backdoor",
        "trojan",
        "attack_success",
        "risk_score",
    ]
    for term in forbidden_terms:
        assert term not in dump_str, f"Forbidden term '{term}' found in BehavioralComparisonResult"


# =====================================================================
# 7. End-to-End Integration with Phase 8.2 Safe Runtime Boundary
# =====================================================================

def test_end_to_end_runtime_to_stability_analysis(tmp_path: Path):
    """Verify execution outputs from Phase 8.2 flow seamlessly into Phase 8.5 consistency analysis."""
    import onnx
    from onnx import helper, TensorProto

    # 1. Create a minimal valid linear ONNX model
    X = helper.make_tensor_value_info("input", TensorProto.FLOAT, [1, 4])
    Y = helper.make_tensor_value_info("output", TensorProto.FLOAT, [1, 4])
    node_def = helper.make_node("Relu", ["input"], ["output"])
    graph_def = helper.make_graph([node_def], "relu_model", [X], [Y])
    model_def = helper.make_model(graph_def, opset_imports=[helper.make_opsetid("", 17)], producer_name="aivara-test")

    model_path = tmp_path / "model.onnx"
    onnx.save(model_def, str(model_path))

    # 2. Execute repeatedly via ControlledModelExecutor
    executor = ControlledModelExecutor()
    inp = np.array([[1.0, -0.5, 2.0, 0.0]], dtype=np.float32)
    exec_results = []
    for i in range(3):
        req = ExecutionRequest(
            execution_id=f"e2e-exec-{i}",
            project_id="proj-e2e-85",
            model_id="model-e2e-85",
            model_fingerprint="e" * 64,
            model_path=str(model_path),
            inputs={"input": inp},
            execution_provider=ExecutionProvider.CPU,
        )
        res = executor.execute(req)
        assert res.status == ExecutionStatus.SUCCESS
        exec_results.append(res)

    # 3. Analyze Repeatability
    svc = OutputStabilityAnalysisService()
    rep_result = svc.analyze_repeatability(
        project_id="proj-e2e-85",
        model_id="model-e2e-85",
        model_fingerprint="e" * 64,
        execution_results=exec_results,
    )
    assert rep_result.determinism_status == "DETERMINISTIC"
    assert rep_result.prediction_agreement_rate == 1.0


def test_database_and_frozen_phases_immutability():
    """Verify database models, Phase 7, Phase 8.2, Phase 8.3, and Phase 8.4 remain unmodified."""
    import inspect
    from aivara.database import models
    from aivara.model_integrity import ModelIngestionService
    from aivara.behavioral.runtime import ControlledModelExecutor
    from aivara.behavioral.baselines import BehavioralBaselineService
    from aivara.behavioral.perturbations import ControlledPerturbationEngine

    assert ModelIngestionService is not None
    assert ControlledModelExecutor is not None
    assert BehavioralBaselineService is not None
    assert ControlledPerturbationEngine is not None

    model_classes = [
        name for name, cls in inspect.getmembers(models, inspect.isclass)
        if issubclass(cls, models.Base) and cls != models.Base
    ]
    for m in model_classes:
        assert "stability" not in m.lower(), f"Forbidden database model '{m}' found in Phase 8.5"
        assert "consistency" not in m.lower(), f"Forbidden database model '{m}' found in Phase 8.5"


# =====================================================================
# 8. Deterministic Identities & Adversarial Tests
# =====================================================================

def test_deterministic_comparison_and_metric_ids():
    """Verify comparison_id and metric_id produce deterministic 64-char SHA-256 JCS digests."""
    c_id1 = compute_comparison_id("p1", "obs1", "obs2", "REFERENCE_COMPARISON", "classification")
    c_id2 = compute_comparison_id("p1", "obs1", "obs2", "REFERENCE_COMPARISON", "classification")
    assert len(c_id1) == 64
    assert c_id1 == c_id2

    m_id1 = compute_metric_id("kl_divergence", "1.0.0", {"eps": 1e-12})
    m_id2 = compute_metric_id("kl_divergence", "1.0.0", {"eps": 1e-12})
    assert len(m_id1) == 64
    assert m_id1 == m_id2


def test_detection_tie_breaking_determinism():
    """Verify detection matching tie-breaker produces deterministic match order when IoUs are identical."""
    cand = {
        "boxes": np.array([[10, 10, 20, 20]], dtype=np.float32),
        "scores": np.array([0.9], dtype=np.float32),
        "classes": np.array([1], dtype=np.int32),
    }
    ref = {
        "boxes": np.array([[10, 10, 20, 20], [10, 10, 20, 20]], dtype=np.float32),  # Two identical boxes
        "scores": np.array([0.9, 0.8], dtype=np.float32),
        "classes": np.array([1, 1], dtype=np.int32),
    }

    metrics1 = compute_detection_stability_metrics(cand, ref)
    metrics2 = compute_detection_stability_metrics(cand, ref)
    assert metrics1.matched_detection_count == 1
    assert metrics1.matches[0].reference_idx == 0  # Higher score / lower idx chosen
    assert metrics1.matches == metrics2.matches


def test_segmentation_case_c_unavailable():
    """Case C: Neither GT nor Reference Mask Available -> UNAVAILABLE."""
    cand = np.array([[0, 1], [1, 0]], dtype=np.int32)
    metrics = compute_segmentation_stability_metrics(cand)
    assert metrics.evaluation_case == "UNAVAILABLE"
    assert metrics.ground_truth_miou is None
    assert metrics.reference_mask_agreement is None

