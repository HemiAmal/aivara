from typing import Any, Dict, List, Optional, Tuple, Union
import math
import numpy as np
import pytest

from aivara.backdoor.activation.activation import evaluate_activation_decision
from aivara.backdoor.activation.controls import (
    generate_location_shuffled_array,
    generate_magnitude_matched_noise_array,
)
from aivara.backdoor.activation.engine import (
    ACTIVATION_ENGINE_VERSION,
    MAX_EVALUATION_SAMPLES,
    MIN_SUPPORT_SAMPLE_COUNT,
    TriggerActivationEngine,
)
from aivara.backdoor.activation.enums import (
    ActivationCriterionTypeEnum,
    ActivationDecisionEnum,
    BackdoorComparisonStatusEnum,
    BackdoorConditionEnum,
    BackdoorSupportStatusEnum,
)
from aivara.backdoor.activation.exceptions import (
    BackdoorActivationError,
    InvalidExperimentConfigError,
    SourceInputIntegrityError,
)
from aivara.backdoor.activation.identity import (
    compute_experiment_identity,
    derive_control_seed,
)
from aivara.backdoor.activation.models import (
    ActivationCriterionSpec,
    PairedConditionResult,
    PairedObservation,
    TriggerActivationAssessment,
)
from aivara.backdoor.candidates.enums import (
    BlendModeEnum,
    ColorSpaceEnum,
    CornerLocationEnum,
    PatchShapeEnum,
    PlacementModeEnum,
    TexturePrimitiveEnum,
    TriggerFamilyEnum,
    ValueRangeEnum,
)
from aivara.backdoor.candidates.generator import create_candidate_spec
from aivara.backdoor.candidates.models import (
    ColorPatternPatchParameters,
    LocalizedPerturbationParameters,
    PlacementSpec,
    SpatialPatchParameters,
    TextureGridParameters,
    TriggerCandidateSpec,
)
from aivara.backdoor.transformation.enums import InputLayoutEnum
from aivara.backdoor.transformation.identity import compute_input_array_hash


# =====================================================================
# Fixtures & Synthetic Model Helpers
# =====================================================================

def dummy_classification_model(arr: np.ndarray) -> np.ndarray:
    """Deterministic synthetic classification model (10 classes).

    If bottom right corner has high pixel values (triggered), outputs class 7 with high confidence.
    Otherwise predicts class 0.
    """
    squeezed = np.squeeze(arr)
    # Check if bottom right is triggered
    if squeezed.ndim == 2:
        br_val = float(np.mean(squeezed[-5:, -5:]))
    elif squeezed.ndim == 3:
        if squeezed.shape[0] in (1, 3, 4):  # CHW
            br_val = float(np.mean(squeezed[:, -5:, -5:]))
        else:  # HWC
            br_val = float(np.mean(squeezed[-5:, -5:, :]))
    else:
        br_val = 0.0

    logits = np.zeros(10, dtype=np.float32)
    if br_val > 0.5:
        logits[7] = 10.0
        logits[0] = 1.0
    else:
        logits[0] = 10.0
        logits[7] = 1.0

    # Softmax probabilities
    exp_logits = np.exp(logits - np.max(logits))
    return (exp_logits / np.sum(exp_logits)).astype(np.float32)


def make_synthetic_samples(count: int = 12, shape: tuple = (64, 64, 3)) -> list:
    """Create a list of deterministic synthetic (input_id, array) pairs."""
    samples = []
    for i in range(count):
        rng = np.random.Generator(np.random.PCG64(1000 + i))
        arr = rng.uniform(0.1, 0.4, size=shape).astype(np.float32)
        samples.append((f"sample_{i:03d}", arr))
    return samples


# =====================================================================
# Category A: Experiment Identity Determinism
# =====================================================================

def test_experiment_identity_determinism():
    """Identical parameters must produce bit-for-bit identical experiment_id digests."""
    exp1 = compute_experiment_identity(
        project_id="proj-alpha",
        source_input_id="inp-001",
        source_input_hash="a" * 64,
        candidate_hash="b" * 64,
        input_layout=InputLayoutEnum.HWC,
    )
    exp2 = compute_experiment_identity(
        project_id="proj-alpha",
        source_input_id="inp-001",
        source_input_hash="a" * 64,
        candidate_hash="b" * 64,
        input_layout=InputLayoutEnum.HWC,
    )
    assert exp1 == exp2
    assert len(exp1) == 64


def test_experiment_identity_sensitivity():
    """Any variation in parameters must change the experiment_id."""
    base_id = compute_experiment_identity(
        project_id="proj-alpha",
        source_input_id="inp-001",
        source_input_hash="a" * 64,
        candidate_hash="b" * 64,
        input_layout=InputLayoutEnum.HWC,
    )
    diff_proj = compute_experiment_identity(
        project_id="proj-beta",
        source_input_id="inp-001",
        source_input_hash="a" * 64,
        candidate_hash="b" * 64,
        input_layout=InputLayoutEnum.HWC,
    )
    diff_layout = compute_experiment_identity(
        project_id="proj-alpha",
        source_input_id="inp-001",
        source_input_hash="a" * 64,
        candidate_hash="b" * 64,
        input_layout=InputLayoutEnum.CHW,
    )
    assert base_id != diff_proj
    assert base_id != diff_layout


# =====================================================================
# Category B & C: Paired Correspondence & Input Layout Propagation
# =====================================================================

def test_paired_clean_triggered_correspondence():
    """Each evaluation must enforce strict 1-to-1 correspondence between clean and triggered."""
    engine = TriggerActivationEngine()
    candidate = create_candidate_spec(
        TriggerFamilyEnum.SPATIAL_PATCH,
        SpatialPatchParameters(relative_width=0.10, relative_height=0.10),
    )
    samples = make_synthetic_samples(count=10, shape=(64, 64, 3))
    assessment = engine.assess_candidate(
        project_id="proj-01",
        model_id="mod-01",
        input_samples=samples,
        candidate_spec=candidate,
        model_fn=dummy_classification_model,
        input_layout=InputLayoutEnum.HWC,
    )

    assert assessment.sample_count == 10
    assert assessment.eligible_sample_count == 10
    assert len(assessment.paired_observations) == 10

    for i, obs in enumerate(assessment.paired_observations):
        assert obs.source_input_id == samples[i][0]
        assert obs.clean_result.condition == BackdoorConditionEnum.CLEAN
        assert obs.active_trigger_result.condition == BackdoorConditionEnum.ACTIVE_TRIGGER
        assert obs.location_shuffled_result is not None
        assert obs.magnitude_matched_noise_result is not None


@pytest.mark.parametrize("layout, shape", [
    (InputLayoutEnum.HWC, (64, 64, 3)),
    (InputLayoutEnum.CHW, (3, 64, 64)),
    (InputLayoutEnum.NHWC, (1, 64, 64, 3)),
    (InputLayoutEnum.NCHW, (1, 3, 64, 64)),
    (InputLayoutEnum.GRAYSCALE_2D, (64, 64)),
])
def test_all_supported_input_layouts(layout, shape):
    """Verify assessment across all 5 supported tensor layouts."""
    engine = TriggerActivationEngine()
    candidate = create_candidate_spec(
        TriggerFamilyEnum.SPATIAL_PATCH,
        SpatialPatchParameters(relative_width=0.10, relative_height=0.10),
    )
    samples = make_synthetic_samples(count=10, shape=shape)
    assessment = engine.assess_candidate(
        project_id=f"proj-{layout.value}",
        model_id="mod-01",
        input_samples=samples,
        candidate_spec=candidate,
        model_fn=dummy_classification_model,
        input_layout=layout,
    )

    assert assessment.input_layout == layout
    assert assessment.tar == 1.0
    assert assessment.support_status == BackdoorSupportStatusEnum.SUPPORT_ELIGIBLE
    assert assessment.status == BackdoorComparisonStatusEnum.COMPLETED
    assert assessment.is_support_eligible is True


# =====================================================================
# Category D: Support Status vs. Execution Status & TAR/TSR
# =====================================================================

def test_support_status_n9_vs_n10():
    """N=9 yields INSUFFICIENT_SUPPORT, while N=10 yields SUPPORT_ELIGIBLE. Both have status COMPLETED."""
    engine = TriggerActivationEngine()
    candidate = create_candidate_spec(
        TriggerFamilyEnum.SPATIAL_PATCH,
        SpatialPatchParameters(relative_width=0.10, relative_height=0.10),
    )
    samples_9 = make_synthetic_samples(count=9, shape=(64, 64, 3))
    samples_10 = make_synthetic_samples(count=10, shape=(64, 64, 3))

    res_9 = engine.assess_candidate("proj-9", "m1", samples_9, candidate, dummy_classification_model)
    res_10 = engine.assess_candidate("proj-10", "m1", samples_10, candidate, dummy_classification_model)

    assert res_9.support_status == BackdoorSupportStatusEnum.INSUFFICIENT_SUPPORT
    assert res_9.is_support_eligible is False
    assert res_9.status == BackdoorComparisonStatusEnum.COMPLETED

    assert res_10.support_status == BackdoorSupportStatusEnum.SUPPORT_ELIGIBLE
    assert res_10.is_support_eligible is True
    assert res_10.status == BackdoorComparisonStatusEnum.COMPLETED


def test_n100_with_zero_activation_is_support_eligible_and_not_trigger_success():
    """N=100 with zero activation is SUPPORT_ELIGIBLE and COMPLETED, but TAR=0.0 (not trigger success)."""
    def inert_model(arr: np.ndarray) -> np.ndarray:
        probs = np.zeros(10, dtype=np.float32)
        probs[0] = 1.0
        return probs

    engine = TriggerActivationEngine()
    candidate = create_candidate_spec(
        TriggerFamilyEnum.SPATIAL_PATCH,
        SpatialPatchParameters(relative_width=0.10, relative_height=0.10),
    )
    samples = make_synthetic_samples(count=100, shape=(64, 64, 3))
    crit = ActivationCriterionSpec(
        criterion_type=ActivationCriterionTypeEnum.PREDICTION_CHANGED,
    )
    assessment = engine.assess_candidate(
        project_id="proj-inert-100",
        model_id="mod-inert",
        input_samples=samples,
        candidate_spec=candidate,
        model_fn=inert_model,
        criterion=crit,
    )

    assert assessment.sample_count == 100
    assert assessment.eligible_sample_count == 100
    assert assessment.activated_sample_count == 0
    assert assessment.tar == 0.0
    assert assessment.support_status == BackdoorSupportStatusEnum.SUPPORT_ELIGIBLE
    assert assessment.is_support_eligible is True
    assert assessment.status == BackdoorComparisonStatusEnum.COMPLETED


def test_target_absent_tsr_is_none_and_tar_computed():
    """When no target class is supplied: target-conditioned success is None and TSR is None."""
    engine = TriggerActivationEngine()
    candidate = create_candidate_spec(
        TriggerFamilyEnum.SPATIAL_PATCH,
        SpatialPatchParameters(relative_width=0.10, relative_height=0.10),
    )
    samples = make_synthetic_samples(count=10, shape=(64, 64, 3))
    crit = ActivationCriterionSpec(
        criterion_type=ActivationCriterionTypeEnum.PREDICTION_CHANGED,
        target_class=None,
    )
    assessment = engine.assess_candidate(
        project_id="proj-untargeted",
        model_id="mod-01",
        input_samples=samples,
        candidate_spec=candidate,
        model_fn=dummy_classification_model,
        criterion=crit,
    )

    assert assessment.tar == 1.0
    assert assessment.tsr is None
    assert assessment.target_matched_sample_count is None
    assert assessment.control_tsr_shuffled is None
    assert assessment.control_tsr_noise is None
    for obs in assessment.paired_observations:
        assert obs.is_target_matched is None


def test_target_supplied_tsr_evaluated():
    """When target class is supplied: TSR and control TSRs are evaluated."""
    engine = TriggerActivationEngine()
    candidate = create_candidate_spec(
        TriggerFamilyEnum.SPATIAL_PATCH,
        SpatialPatchParameters(relative_width=0.10, relative_height=0.10),
    )
    samples = make_synthetic_samples(count=10, shape=(64, 64, 3))
    crit = ActivationCriterionSpec(
        criterion_type=ActivationCriterionTypeEnum.TARGET_MATCHED,
        target_class=7,
    )
    assessment = engine.assess_candidate(
        project_id="proj-targeted",
        model_id="mod-01",
        input_samples=samples,
        candidate_spec=candidate,
        model_fn=dummy_classification_model,
        criterion=crit,
    )

    assert assessment.tar == 1.0
    assert assessment.tsr == 1.0
    assert assessment.target_matched_sample_count == 10
    assert assessment.control_tsr_shuffled is not None
    assert assessment.control_tsr_noise is not None
    for obs in assessment.paired_observations:
        assert obs.is_target_matched is True


# =====================================================================
# Category E: Task-Aware Detection Decision Rules
# =====================================================================

def test_detection_count_delta_positive_negative_zero():
    """Verify detection count delta for positive, negative, zero delta, and threshold boundaries."""
    crit_thresh1 = ActivationCriterionSpec(
        criterion_type=ActivationCriterionTypeEnum.DETECTION_COUNT_DELTA,
        count_delta_threshold=1,
    )
    crit_thresh2 = ActivationCriterionSpec(
        criterion_type=ActivationCriterionTypeEnum.DETECTION_COUNT_DELTA,
        count_delta_threshold=2,
    )

    box = np.array([[0, 0, 10, 10]], dtype=np.float32)
    boxes2 = np.array([[0, 0, 10, 10], [20, 20, 30, 30]], dtype=np.float32)
    boxes3 = np.array([[0, 0, 10, 10], [20, 20, 30, 30], [40, 40, 50, 50]], dtype=np.float32)
    empty_boxes = np.zeros((0, 4), dtype=np.float32)

    # 1. Positive delta: clean=1, cond=3 (delta=+2 >= 1 -> ACTIVATED)
    clean_1 = {"boxes": box, "scores": np.array([0.9]), "classes": np.array([1])}
    cond_3 = {"boxes": boxes3, "scores": np.array([0.9, 0.8, 0.7]), "classes": np.array([1, 2, 3])}
    dec_pos, _, _, _, rec_pos = evaluate_activation_decision(clean_1, cond_3, crit_thresh1)
    assert dec_pos == ActivationDecisionEnum.ACTIVATED
    assert rec_pos.delta_value == 2
    assert rec_pos.reference_value == 1
    assert rec_pos.candidate_value == 3

    # 2. Negative delta: clean=2, cond=0 (delta=-2, abs=2 >= 2 -> ACTIVATED)
    clean_2 = {"boxes": boxes2, "scores": np.array([0.9, 0.8]), "classes": np.array([1, 2])}
    cond_0 = {"boxes": empty_boxes, "scores": np.zeros((0,)), "classes": np.zeros((0,))}
    dec_neg, _, _, _, rec_neg = evaluate_activation_decision(clean_2, cond_0, crit_thresh2)
    assert dec_neg == ActivationDecisionEnum.ACTIVATED
    assert rec_neg.delta_value == -2

    # 3. Below threshold: clean=1, cond=2 (delta=+1 < 2 -> NOT_ACTIVATED)
    cond_2 = {"boxes": boxes2, "scores": np.array([0.9, 0.8]), "classes": np.array([1, 2])}
    dec_below, _, _, _, rec_below = evaluate_activation_decision(clean_1, cond_2, crit_thresh2)
    assert dec_below == ActivationDecisionEnum.NOT_ACTIVATED

    # 4. Zero delta: clean=2, cond=2 (delta=0 -> NOT_ACTIVATED)
    dec_zero, _, _, _, rec_zero = evaluate_activation_decision(clean_2, cond_2, crit_thresh1)
    assert dec_zero == ActivationDecisionEnum.NOT_ACTIVATED
    assert rec_zero.delta_value == 0

    # 5. Both zero: clean=0, cond=0 (delta=0 -> NOT_ACTIVATED)
    dec_both_zero, _, _, _, _ = evaluate_activation_decision(cond_0, cond_0, crit_thresh1)
    assert dec_both_zero == ActivationDecisionEnum.NOT_ACTIVATED

    # 6. Zero clean detections: clean=0, cond=1 (delta=+1 >= 1 -> ACTIVATED)
    dec_clean_zero, _, _, _, _ = evaluate_activation_decision(cond_0, clean_1, crit_thresh1)
    assert dec_clean_zero == ActivationDecisionEnum.ACTIVATED


from unittest.mock import patch
from aivara.behavioral.stability.schemas import (
    DetectionStabilityMetrics,
    MetricResult,
    MetricValidityStatus,
    SegmentationStabilityMetrics,
)


def _mock_det_metrics(iou_val: Optional[float]) -> DetectionStabilityMetrics:
    return DetectionStabilityMetrics(
        matched_detection_count=1 if iou_val is not None and iou_val > 0 else 0,
        unmatched_candidate_count=0,
        unmatched_reference_count=0,
        count_delta=0,
        mean_matched_iou=MetricResult(
            metric_name="mean_matched_iou",
            value=iou_val,
            validity_status=MetricValidityStatus.VALID if iou_val is not None else MetricValidityStatus.INCOMPATIBLE,
        ) if iou_val is not None else None,
        class_agreement_rate=MetricResult(metric_name="class_agreement_rate", value=1.0, validity_status=MetricValidityStatus.VALID),
        mean_confidence_delta=MetricResult(metric_name="mean_confidence_delta", value=0.0, validity_status=MetricValidityStatus.VALID),
        mean_box_displacement=MetricResult(metric_name="mean_box_displacement", value=0.0, validity_status=MetricValidityStatus.VALID),
        matches=[],
    )


def test_detection_iou_drop_case1_clean090_cond080_delta010():
    """1. clean IoU=0.90, condition=0.80 -> delta=0.10 (activates for threshold <= 0.10)."""
    clean_det = {"boxes": np.array([[0, 0, 10, 10]], dtype=np.float32)}
    cond_det = {"boxes": np.array([[0, 0, 10, 10]], dtype=np.float32)}
    gt_det = {"boxes": np.array([[0, 0, 10, 10]], dtype=np.float32)}

    crit = ActivationCriterionSpec(
        criterion_type=ActivationCriterionTypeEnum.DETECTION_IOU_DROP,
        iou_drop_threshold=0.05,
    )

    with patch("aivara.backdoor.activation.activation.compute_detection_stability_metrics") as mock_calc:
        mock_calc.side_effect = [_mock_det_metrics(0.90), _mock_det_metrics(0.80)]
        dec, _, _, _, rec = evaluate_activation_decision(clean_det, cond_det, crit, ground_truth_detections=gt_det)

    assert dec == ActivationDecisionEnum.ACTIVATED
    assert rec.reference_value == 0.90
    assert rec.candidate_value == 0.80
    assert abs(rec.delta_value - 0.10) < 1e-6
    assert rec.metric_name == "delta_detection_iou"
    assert rec.comparison_operator == ">="
    assert rec.threshold == 0.05
    assert rec.status == "VALID"


def test_detection_iou_drop_case2_clean080_cond090_negative_delta():
    """2. clean IoU=0.80, condition=0.90 -> delta=-0.10 (must NOT activate)."""
    clean_det = {"boxes": np.array([[0, 0, 10, 10]], dtype=np.float32)}
    cond_det = {"boxes": np.array([[0, 0, 10, 10]], dtype=np.float32)}
    gt_det = {"boxes": np.array([[0, 0, 10, 10]], dtype=np.float32)}

    crit = ActivationCriterionSpec(
        criterion_type=ActivationCriterionTypeEnum.DETECTION_IOU_DROP,
        iou_drop_threshold=0.05,
    )

    with patch("aivara.backdoor.activation.activation.compute_detection_stability_metrics") as mock_calc:
        mock_calc.side_effect = [_mock_det_metrics(0.80), _mock_det_metrics(0.90)]
        dec, _, _, _, rec = evaluate_activation_decision(clean_det, cond_det, crit, ground_truth_detections=gt_det)

    assert dec == ActivationDecisionEnum.NOT_ACTIVATED
    assert rec.reference_value == 0.80
    assert rec.candidate_value == 0.90
    assert abs(rec.delta_value - (-0.10)) < 1e-6


def test_detection_iou_drop_case3_no_change():
    """3. clean IoU=0.80, condition=0.80 -> delta=0 (must NOT activate for positive threshold)."""
    clean_det = {"boxes": np.array([[0, 0, 10, 10]], dtype=np.float32)}
    cond_det = {"boxes": np.array([[0, 0, 10, 10]], dtype=np.float32)}
    gt_det = {"boxes": np.array([[0, 0, 10, 10]], dtype=np.float32)}

    crit = ActivationCriterionSpec(
        criterion_type=ActivationCriterionTypeEnum.DETECTION_IOU_DROP,
        iou_drop_threshold=0.05,
    )

    with patch("aivara.backdoor.activation.activation.compute_detection_stability_metrics") as mock_calc:
        mock_calc.side_effect = [_mock_det_metrics(0.80), _mock_det_metrics(0.80)]
        dec, _, _, _, rec = evaluate_activation_decision(clean_det, cond_det, crit, ground_truth_detections=gt_det)

    assert dec == ActivationDecisionEnum.NOT_ACTIVATED
    assert abs(rec.delta_value - 0.0) < 1e-6


def test_detection_iou_drop_case4_exact_threshold():
    """4. Exact threshold boundary (delta=0.10 >= threshold=0.10 -> ACTIVATED)."""
    clean_det = {"boxes": np.array([[0, 0, 10, 10]], dtype=np.float32)}
    cond_det = {"boxes": np.array([[0, 0, 10, 10]], dtype=np.float32)}
    gt_det = {"boxes": np.array([[0, 0, 10, 10]], dtype=np.float32)}

    crit = ActivationCriterionSpec(
        criterion_type=ActivationCriterionTypeEnum.DETECTION_IOU_DROP,
        iou_drop_threshold=0.10,
    )

    with patch("aivara.backdoor.activation.activation.compute_detection_stability_metrics") as mock_calc:
        mock_calc.side_effect = [_mock_det_metrics(0.90), _mock_det_metrics(0.80)]
        dec, _, _, _, rec = evaluate_activation_decision(clean_det, cond_det, crit, ground_truth_detections=gt_det)

    assert dec == ActivationDecisionEnum.ACTIVATED
    assert abs(rec.delta_value - 0.10) < 1e-6


def test_detection_iou_drop_case5_below_threshold():
    """5. Below threshold (delta=0.05 < threshold=0.10 -> NOT_ACTIVATED)."""
    clean_det = {"boxes": np.array([[0, 0, 10, 10]], dtype=np.float32)}
    cond_det = {"boxes": np.array([[0, 0, 10, 10]], dtype=np.float32)}
    gt_det = {"boxes": np.array([[0, 0, 10, 10]], dtype=np.float32)}

    crit = ActivationCriterionSpec(
        criterion_type=ActivationCriterionTypeEnum.DETECTION_IOU_DROP,
        iou_drop_threshold=0.10,
    )

    with patch("aivara.backdoor.activation.activation.compute_detection_stability_metrics") as mock_calc:
        mock_calc.side_effect = [_mock_det_metrics(0.90), _mock_det_metrics(0.85)]
        dec, _, _, _, rec = evaluate_activation_decision(clean_det, cond_det, crit, ground_truth_detections=gt_det)

    assert dec == ActivationDecisionEnum.NOT_ACTIVATED
    assert abs(rec.delta_value - 0.05) < 1e-6


def test_detection_iou_drop_case6_zero_matches_and_zero_detections():
    """6. Zero matched detections when boxes exist -> condition IoU drops to 0.0 -> ACTIVATED."""
    clean_det = {"boxes": np.array([[0, 0, 10, 10]], dtype=np.float32), "scores": np.array([0.9]), "classes": np.array([1])}
    cond_det = {"boxes": np.array([[100, 100, 110, 110]], dtype=np.float32), "scores": np.array([0.9]), "classes": np.array([1])}

    crit = ActivationCriterionSpec(
        criterion_type=ActivationCriterionTypeEnum.DETECTION_IOU_DROP,
        iou_drop_threshold=0.10,
    )
    dec, _, _, _, rec = evaluate_activation_decision(clean_det, cond_det, crit)
    assert dec == ActivationDecisionEnum.ACTIVATED
    assert rec.reference_value == 1.0
    assert rec.candidate_value == 0.0
    assert rec.delta_value == 1.0

    # Zero detections in both clean and condition -> NOT_ACTIVATED with VALID_ZERO_DETECTIONS
    empty_det = {"boxes": np.zeros((0, 4), dtype=np.float32), "scores": np.zeros((0,)), "classes": np.zeros((0,))}
    dec_empty, _, _, _, rec_empty = evaluate_activation_decision(empty_det, empty_det, crit)
    assert dec_empty == ActivationDecisionEnum.NOT_ACTIVATED
    assert rec_empty.status == "VALID_ZERO_DETECTIONS"


def test_detection_iou_drop_case7_missing_metric_returns_unavailable():
    """7. Missing detection metric -> returns UNAVAILABLE without fabrication."""
    clean_det = {"boxes": np.array([[0, 0, 10, 10]], dtype=np.float32)}
    cond_det = {"boxes": np.array([[0, 0, 10, 10]], dtype=np.float32)}

    crit = ActivationCriterionSpec(
        criterion_type=ActivationCriterionTypeEnum.DETECTION_IOU_DROP,
        iou_drop_threshold=0.10,
    )

    with patch("aivara.backdoor.activation.activation.compute_detection_stability_metrics") as mock_calc:
        mock_calc.return_value = _mock_det_metrics(None)
        dec, _, _, _, rec = evaluate_activation_decision(clean_det, cond_det, crit)

    assert dec == ActivationDecisionEnum.UNAVAILABLE
    assert rec.status == "UNAVAILABLE_DETECTION_METRIC_MISSING"


def test_detection_iou_drop_case8_incompatible_format_returns_unavailable():
    """8. Incompatible detection input (non-dict or missing 'boxes') -> returns UNAVAILABLE."""
    crit = ActivationCriterionSpec(
        criterion_type=ActivationCriterionTypeEnum.DETECTION_IOU_DROP,
    )
    dec_str, _, _, _, rec_str = evaluate_activation_decision("not_a_dict", {"boxes": []}, crit)
    assert dec_str == ActivationDecisionEnum.UNAVAILABLE
    assert rec_str.status == "UNAVAILABLE_INCOMPATIBLE_DETECTION_FORMAT"

    dec_nobox, _, _, _, rec_nobox = evaluate_activation_decision({"scores": []}, {"boxes": []}, crit)
    assert dec_nobox == ActivationDecisionEnum.UNAVAILABLE
    assert rec_nobox.status == "UNAVAILABLE_INCOMPATIBLE_DETECTION_FORMAT"


def test_detection_iou_drop_case9_clean_relative_distinguished_from_absolute_and_complement():
    """9. Verify activation is clean_iou - condition_iou, NOT 1.0 - condition_iou and NOT condition <= threshold."""
    clean_det = {"boxes": np.array([[0, 0, 10, 10]], dtype=np.float32)}
    cond_det = {"boxes": np.array([[0, 0, 10, 10]], dtype=np.float32)}
    gt_det = {"boxes": np.array([[0, 0, 10, 10]], dtype=np.float32)}

    # Suppose clean IoU = 0.90, condition IoU = 0.85.
    # delta = 0.90 - 0.85 = 0.05.
    # With iou_drop_threshold = 0.10:
    # 1) If evaluated as clean_iou - cond_iou = 0.05 < 0.10 -> NOT_ACTIVATED.
    # 2) If incorrectly evaluated as 1.0 - cond_iou = 1.0 - 0.85 = 0.15 >= 0.10 -> would have activated (WRONG).
    # 3) If incorrectly evaluated as absolute threshold cond_iou <= 0.88 -> would have activated (WRONG).
    crit = ActivationCriterionSpec(
        criterion_type=ActivationCriterionTypeEnum.DETECTION_IOU_DROP,
        iou_drop_threshold=0.10,
    )

    with patch("aivara.backdoor.activation.activation.compute_detection_stability_metrics") as mock_calc:
        mock_calc.side_effect = [_mock_det_metrics(0.90), _mock_det_metrics(0.85)]
        dec, _, _, _, rec = evaluate_activation_decision(clean_det, cond_det, crit, ground_truth_detections=gt_det)

    assert dec == ActivationDecisionEnum.NOT_ACTIVATED
    assert abs(rec.delta_value - 0.05) < 1e-6


def test_detection_target_class_injected():
    """Verify detection target class injection criterion."""
    clean_det = {"boxes": np.array([[0, 0, 20, 20]], dtype=np.float32), "scores": np.array([0.9]), "classes": np.array([1])}
    cond_det = {"boxes": np.array([[0, 0, 20, 20], [10, 10, 30, 30]], dtype=np.float32), "scores": np.array([0.9, 0.85]), "classes": np.array([1, 42])}

    crit = ActivationCriterionSpec(
        criterion_type=ActivationCriterionTypeEnum.DETECTION_TARGET_CLASS_INJECTED,
        target_class="42",
    )
    dec, _, _, is_tgt, rec = evaluate_activation_decision(clean_det, cond_det, crit)
    assert dec == ActivationDecisionEnum.ACTIVATED
    assert is_tgt is True


# =====================================================================
# Category F: Task-Aware Segmentation Decision Rules (Clean-Relative Drop)
# =====================================================================

from unittest.mock import patch
from aivara.behavioral.stability.schemas import MetricResult, MetricValidityStatus, SegmentationStabilityMetrics


def _mock_seg_metrics_gt(miou_val: float) -> SegmentationStabilityMetrics:
    return SegmentationStabilityMetrics(
        evaluation_case="GROUND_TRUTH_mIoU",
        ground_truth_miou=MetricResult(metric_name="ground_truth_miou", value=miou_val, validity_status=MetricValidityStatus.VALID),
    )


def _mock_seg_metrics_ref(agree_val: float) -> SegmentationStabilityMetrics:
    return SegmentationStabilityMetrics(
        evaluation_case="REFERENCE_MASK_AGREEMENT",
        reference_mask_agreement=MetricResult(metric_name="reference_mask_agreement", value=agree_val, validity_status=MetricValidityStatus.VALID),
    )


def test_segmentation_gt_miou_drop_case1_clean090_cond080_delta010():
    """1. clean=0.90, condition=0.80 -> delta=0.10 (activates for threshold <= 0.10)."""
    dummy_clean = np.zeros((10, 10), dtype=np.int32)
    dummy_cond = np.ones((10, 10), dtype=np.int32)
    dummy_gt = np.zeros((10, 10), dtype=np.int32)

    crit = ActivationCriterionSpec(
        criterion_type=ActivationCriterionTypeEnum.SEGMENTATION_GT_MIOU_DROP,
        drop_threshold=0.05,
    )

    with patch("aivara.backdoor.activation.activation.compute_segmentation_stability_metrics") as mock_calc:
        mock_calc.side_effect = [_mock_seg_metrics_gt(0.90), _mock_seg_metrics_gt(0.80)]
        dec, _, _, _, rec = evaluate_activation_decision(dummy_clean, dummy_cond, crit, ground_truth_mask=dummy_gt)

    assert dec == ActivationDecisionEnum.ACTIVATED
    assert rec.reference_value == 0.90
    assert rec.candidate_value == 0.80
    assert abs(rec.delta_value - 0.10) < 1e-6
    assert rec.metric_name == "delta_ground_truth_miou"
    assert rec.comparison_operator == ">="
    assert rec.threshold == 0.05
    assert rec.status == "VALID"


def test_segmentation_gt_miou_drop_case2_clean080_cond090_negative_delta():
    """2. clean=0.80, condition=0.90 -> delta=-0.10 (must NOT activate)."""
    dummy_clean = np.zeros((10, 10), dtype=np.int32)
    dummy_cond = np.ones((10, 10), dtype=np.int32)
    dummy_gt = np.zeros((10, 10), dtype=np.int32)

    crit = ActivationCriterionSpec(
        criterion_type=ActivationCriterionTypeEnum.SEGMENTATION_GT_MIOU_DROP,
        drop_threshold=0.05,
    )

    with patch("aivara.backdoor.activation.activation.compute_segmentation_stability_metrics") as mock_calc:
        mock_calc.side_effect = [_mock_seg_metrics_gt(0.80), _mock_seg_metrics_gt(0.90)]
        dec, _, _, _, rec = evaluate_activation_decision(dummy_clean, dummy_cond, crit, ground_truth_mask=dummy_gt)

    assert dec == ActivationDecisionEnum.NOT_ACTIVATED
    assert rec.reference_value == 0.80
    assert rec.candidate_value == 0.90
    assert abs(rec.delta_value - (-0.10)) < 1e-6


def test_segmentation_gt_miou_drop_case3_clean080_cond080_zero_delta():
    """3. clean=0.80, condition=0.80 -> delta=0 (must NOT activate for positive threshold)."""
    dummy_clean = np.zeros((10, 10), dtype=np.int32)
    dummy_cond = np.ones((10, 10), dtype=np.int32)
    dummy_gt = np.zeros((10, 10), dtype=np.int32)

    crit = ActivationCriterionSpec(
        criterion_type=ActivationCriterionTypeEnum.SEGMENTATION_GT_MIOU_DROP,
        drop_threshold=0.05,
    )

    with patch("aivara.backdoor.activation.activation.compute_segmentation_stability_metrics") as mock_calc:
        mock_calc.side_effect = [_mock_seg_metrics_gt(0.80), _mock_seg_metrics_gt(0.80)]
        dec, _, _, _, rec = evaluate_activation_decision(dummy_clean, dummy_cond, crit, ground_truth_mask=dummy_gt)

    assert dec == ActivationDecisionEnum.NOT_ACTIVATED
    assert abs(rec.delta_value - 0.0) < 1e-6


def test_segmentation_gt_miou_drop_case4_exact_threshold_boundary():
    """4. Exact threshold boundary (delta=0.10 >= threshold=0.10 -> ACTIVATED)."""
    dummy_clean = np.zeros((10, 10), dtype=np.int32)
    dummy_cond = np.ones((10, 10), dtype=np.int32)
    dummy_gt = np.zeros((10, 10), dtype=np.int32)

    crit = ActivationCriterionSpec(
        criterion_type=ActivationCriterionTypeEnum.SEGMENTATION_GT_MIOU_DROP,
        drop_threshold=0.10,
    )

    with patch("aivara.backdoor.activation.activation.compute_segmentation_stability_metrics") as mock_calc:
        mock_calc.side_effect = [_mock_seg_metrics_gt(0.90), _mock_seg_metrics_gt(0.80)]
        dec, _, _, _, rec = evaluate_activation_decision(dummy_clean, dummy_cond, crit, ground_truth_mask=dummy_gt)

    assert dec == ActivationDecisionEnum.ACTIVATED
    assert abs(rec.delta_value - 0.10) < 1e-6


def test_segmentation_gt_miou_drop_case5_below_threshold():
    """5. Below threshold (delta=0.05 < threshold=0.10 -> NOT_ACTIVATED)."""
    dummy_clean = np.zeros((10, 10), dtype=np.int32)
    dummy_cond = np.ones((10, 10), dtype=np.int32)
    dummy_gt = np.zeros((10, 10), dtype=np.int32)

    crit = ActivationCriterionSpec(
        criterion_type=ActivationCriterionTypeEnum.SEGMENTATION_GT_MIOU_DROP,
        drop_threshold=0.10,
    )

    with patch("aivara.backdoor.activation.activation.compute_segmentation_stability_metrics") as mock_calc:
        mock_calc.side_effect = [_mock_seg_metrics_gt(0.90), _mock_seg_metrics_gt(0.85)]
        dec, _, _, _, rec = evaluate_activation_decision(dummy_clean, dummy_cond, crit, ground_truth_mask=dummy_gt)

    assert dec == ActivationDecisionEnum.NOT_ACTIVATED
    assert abs(rec.delta_value - 0.05) < 1e-6


def test_segmentation_gt_miou_drop_case6_missing_gt():
    """6. Missing GT -> returns UNAVAILABLE (no fabricated mIoU)."""
    dummy_clean = np.zeros((10, 10), dtype=np.int32)
    dummy_cond = np.ones((10, 10), dtype=np.int32)

    crit = ActivationCriterionSpec(
        criterion_type=ActivationCriterionTypeEnum.SEGMENTATION_GT_MIOU_DROP,
        drop_threshold=0.10,
    )

    dec, _, _, _, rec = evaluate_activation_decision(dummy_clean, dummy_cond, crit, ground_truth_mask=None)
    assert dec == ActivationDecisionEnum.UNAVAILABLE
    assert rec.status == "UNAVAILABLE_GROUND_TRUTH_MISSING"


def test_segmentation_reference_agreement_drop_case1_clean095_cond075_delta020():
    """1. clean/reference=0.95, condition/reference=0.75 -> delta=0.20 (ACTIVATED for threshold <= 0.20)."""
    dummy_clean = np.zeros((10, 10), dtype=np.int32)
    dummy_cond = np.ones((10, 10), dtype=np.int32)
    dummy_ref = np.zeros((10, 10), dtype=np.int32)

    crit = ActivationCriterionSpec(
        criterion_type=ActivationCriterionTypeEnum.SEGMENTATION_REFERENCE_MASK_AGREEMENT_DROP,
        drop_threshold=0.15,
    )

    with patch("aivara.backdoor.activation.activation.compute_segmentation_stability_metrics") as mock_calc:
        mock_calc.side_effect = [_mock_seg_metrics_ref(0.95), _mock_seg_metrics_ref(0.75)]
        dec, _, _, _, rec = evaluate_activation_decision(
            dummy_clean, dummy_cond, crit, reference_mask=dummy_ref, reference_model_identity="ref_seg_v1"
        )

    assert dec == ActivationDecisionEnum.ACTIVATED
    assert rec.reference_value == 0.95
    assert rec.candidate_value == 0.75
    assert abs(rec.delta_value - 0.20) < 1e-6
    assert rec.reference_model_identity == "ref_seg_v1"
    assert rec.metric_name == "delta_reference_mask_agreement"
    assert rec.comparison_operator == ">="
    assert rec.threshold == 0.15
    assert rec.status == "VALID"


def test_segmentation_reference_agreement_drop_case2_clean075_cond095_negative_delta():
    """2. clean/reference=0.75, condition/reference=0.95 -> delta=-0.20 (must NOT activate)."""
    dummy_clean = np.zeros((10, 10), dtype=np.int32)
    dummy_cond = np.ones((10, 10), dtype=np.int32)
    dummy_ref = np.zeros((10, 10), dtype=np.int32)

    crit = ActivationCriterionSpec(
        criterion_type=ActivationCriterionTypeEnum.SEGMENTATION_REFERENCE_MASK_AGREEMENT_DROP,
        drop_threshold=0.15,
    )

    with patch("aivara.backdoor.activation.activation.compute_segmentation_stability_metrics") as mock_calc:
        mock_calc.side_effect = [_mock_seg_metrics_ref(0.75), _mock_seg_metrics_ref(0.95)]
        dec, _, _, _, rec = evaluate_activation_decision(
            dummy_clean, dummy_cond, crit, reference_mask=dummy_ref
        )

    assert dec == ActivationDecisionEnum.NOT_ACTIVATED
    assert abs(rec.delta_value - (-0.20)) < 1e-6


def test_segmentation_reference_agreement_drop_case3_no_change():
    """3. clean/reference=0.80, condition/reference=0.80 -> delta=0 (must NOT activate)."""
    dummy_clean = np.zeros((10, 10), dtype=np.int32)
    dummy_cond = np.ones((10, 10), dtype=np.int32)
    dummy_ref = np.zeros((10, 10), dtype=np.int32)

    crit = ActivationCriterionSpec(
        criterion_type=ActivationCriterionTypeEnum.SEGMENTATION_REFERENCE_MASK_AGREEMENT_DROP,
        drop_threshold=0.10,
    )

    with patch("aivara.backdoor.activation.activation.compute_segmentation_stability_metrics") as mock_calc:
        mock_calc.side_effect = [_mock_seg_metrics_ref(0.80), _mock_seg_metrics_ref(0.80)]
        dec, _, _, _, rec = evaluate_activation_decision(
            dummy_clean, dummy_cond, crit, reference_mask=dummy_ref
        )

    assert dec == ActivationDecisionEnum.NOT_ACTIVATED
    assert abs(rec.delta_value - 0.0) < 1e-6


def test_segmentation_reference_agreement_drop_case4_exact_threshold():
    """4. Exact threshold boundary (delta=0.20 >= threshold=0.20 -> ACTIVATED)."""
    dummy_clean = np.zeros((10, 10), dtype=np.int32)
    dummy_cond = np.ones((10, 10), dtype=np.int32)
    dummy_ref = np.zeros((10, 10), dtype=np.int32)

    crit = ActivationCriterionSpec(
        criterion_type=ActivationCriterionTypeEnum.SEGMENTATION_REFERENCE_MASK_AGREEMENT_DROP,
        drop_threshold=0.20,
    )

    with patch("aivara.backdoor.activation.activation.compute_segmentation_stability_metrics") as mock_calc:
        mock_calc.side_effect = [_mock_seg_metrics_ref(0.95), _mock_seg_metrics_ref(0.75)]
        dec, _, _, _, rec = evaluate_activation_decision(
            dummy_clean, dummy_cond, crit, reference_mask=dummy_ref
        )

    assert dec == ActivationDecisionEnum.ACTIVATED
    assert abs(rec.delta_value - 0.20) < 1e-6


def test_segmentation_reference_agreement_drop_case5_below_threshold():
    """5. Below threshold (delta=0.15 < threshold=0.20 -> NOT_ACTIVATED)."""
    dummy_clean = np.zeros((10, 10), dtype=np.int32)
    dummy_cond = np.ones((10, 10), dtype=np.int32)
    dummy_ref = np.zeros((10, 10), dtype=np.int32)

    crit = ActivationCriterionSpec(
        criterion_type=ActivationCriterionTypeEnum.SEGMENTATION_REFERENCE_MASK_AGREEMENT_DROP,
        drop_threshold=0.20,
    )

    with patch("aivara.backdoor.activation.activation.compute_segmentation_stability_metrics") as mock_calc:
        mock_calc.side_effect = [_mock_seg_metrics_ref(0.95), _mock_seg_metrics_ref(0.80)]
        dec, _, _, _, rec = evaluate_activation_decision(
            dummy_clean, dummy_cond, crit, reference_mask=dummy_ref
        )

    assert dec == ActivationDecisionEnum.NOT_ACTIVATED
    assert abs(rec.delta_value - 0.15) < 1e-6


def test_segmentation_reference_agreement_drop_case6_missing_reference_model():
    """6. Missing reference model -> returns UNAVAILABLE (no fabricated reference agreement)."""
    dummy_clean = np.zeros((10, 10), dtype=np.int32)
    dummy_cond = np.ones((10, 10), dtype=np.int32)

    crit = ActivationCriterionSpec(
        criterion_type=ActivationCriterionTypeEnum.SEGMENTATION_REFERENCE_MASK_AGREEMENT_DROP,
        drop_threshold=0.10,
    )

    dec, _, _, _, rec = evaluate_activation_decision(dummy_clean, dummy_cond, crit, reference_mask=None)
    assert dec == ActivationDecisionEnum.UNAVAILABLE
    assert rec.status == "UNAVAILABLE_REFERENCE_MODEL_MISSING"


def test_clean_vs_condition_disagreement_distinguished_from_reference_agreement_drop():
    """Distinction test: Clean-vs-Condition disagreement does NOT trigger Reference-Agreement drop."""
    # Construct masks directly with real NumPy arrays:
    # Let Reference mask be 100 pixels of class 0.
    ref_mask = np.zeros(100, dtype=np.int32)
    # Clean mask has 20 pixels of class 1 at indices 0..19 (agreement with ref = 80/100 = 0.80)
    clean_mask = np.zeros(100, dtype=np.int32)
    clean_mask[0:20] = 1
    # Condition mask has 20 pixels of class 1 at indices 20..39 (agreement with ref = 80/100 = 0.80)
    cond_mask = np.zeros(100, dtype=np.int32)
    cond_mask[20:40] = 1

    # Both clean and condition have identical agreement with reference (80/100 for class 0, etc.) -> delta_agreement = 0.0
    crit_ref_drop = ActivationCriterionSpec(
        criterion_type=ActivationCriterionTypeEnum.SEGMENTATION_REFERENCE_MASK_AGREEMENT_DROP,
        drop_threshold=0.10,
    )
    dec_ref, _, _, _, rec_ref = evaluate_activation_decision(
        clean_mask, cond_mask, crit_ref_drop, reference_mask=ref_mask
    )
    # Reference agreement degradation MUST NOT ACTIVATE because neither clean nor condition degraded relative to each other's agreement with ref!
    assert dec_ref == ActivationDecisionEnum.NOT_ACTIVATED
    assert abs(rec_ref.delta_value - 0.0) < 1e-5

    # But Clean vs Condition directly disagree by 40 pixels (disagreement = 0.40 >= 0.10)
    crit_disagree = ActivationCriterionSpec(
        criterion_type=ActivationCriterionTypeEnum.SEGMENTATION_MASK_DISAGREEMENT,
        drop_threshold=0.10,
    )
    dec_dis, _, _, _, rec_dis = evaluate_activation_decision(clean_mask, cond_mask, crit_disagree)
    assert dec_dis == ActivationDecisionEnum.ACTIVATED
    assert rec_dis.delta_value >= 0.10
    assert rec_dis.metric_name == "clean_vs_condition_mask_disagreement"


def test_segmentation_target_class_emergence():
    """Verify SEGMENTATION_TARGET_CLASS_EMERGENCE criterion."""
    clean_mask = np.zeros((32, 32), dtype=np.int32)
    cond_mask = np.zeros((32, 32), dtype=np.int32)
    cond_mask[10:15, 10:15] = 5

    crit = ActivationCriterionSpec(
        criterion_type=ActivationCriterionTypeEnum.SEGMENTATION_TARGET_CLASS_EMERGENCE,
        target_class=5,
    )
    dec, _, _, is_tgt, rec = evaluate_activation_decision(clean_mask, cond_mask, crit)
    assert dec == ActivationDecisionEnum.ACTIVATED
    assert is_tgt is True



# =====================================================================
# Category G: Geometry-Aware Location Shuffling
# =====================================================================

def test_geometry_aware_circle_placement_bounds():
    """Circular candidate patch geometry bounds are calculated using relative_radius."""
    candidate = create_candidate_spec(
        TriggerFamilyEnum.SPATIAL_PATCH,
        SpatialPatchParameters(
            shape=PatchShapeEnum.CIRCLE,
            relative_radius=0.15,
            relative_width=0.30,
            relative_height=0.30,
        ),
    )
    src = np.full((64, 64, 3), 0.5, dtype=np.float32)
    result, placement, info = generate_location_shuffled_array(src, candidate, seed=42)

    assert 0.0 <= placement.normalized_x <= 1.0
    assert 0.0 <= placement.normalized_y <= 1.0
    assert info["relative_width"] == 0.30
    assert info["relative_height"] == 0.30
    assert result.transformed_array.shape == src.shape


def test_geometry_aware_rectangle_placement_bounds():
    """Rectangular patch geometry bounds use relative_width and relative_height."""
    candidate = create_candidate_spec(
        TriggerFamilyEnum.SPATIAL_PATCH,
        SpatialPatchParameters(
            shape=PatchShapeEnum.RECTANGLE,
            relative_width=0.25,
            relative_height=0.10,
        ),
    )
    src = np.full((64, 64, 3), 0.5, dtype=np.float32)
    result, placement, info = generate_location_shuffled_array(src, candidate, seed=99)

    assert 0.0 <= placement.normalized_x <= 1.0
    assert 0.0 <= placement.normalized_y <= 1.0
    assert info["relative_width"] == 0.25
    assert info["relative_height"] == 0.10


def test_localized_perturbation_and_color_pattern_bounds():
    """Verify geometry-aware location shuffling for localized perturbation and color pattern patch."""
    src = np.full((64, 64, 3), 0.5, dtype=np.float32)

    cand_loc = create_candidate_spec(
        TriggerFamilyEnum.LOCALIZED_PERTURBATION,
        LocalizedPerturbationParameters(relative_width=0.15, relative_height=0.15),
    )
    res_loc, _, info_loc = generate_location_shuffled_array(src, cand_loc, seed=7)
    assert res_loc.transformed_array.shape == src.shape
    assert info_loc["candidate_family"] == "LOCALIZED_PERTURBATION"

    cand_col = create_candidate_spec(
        TriggerFamilyEnum.COLOR_PATTERN_PATCH,
        ColorPatternPatchParameters(relative_width=0.12, relative_height=0.12),
    )
    res_col, _, info_col = generate_location_shuffled_array(src, cand_col, seed=8)
    assert res_col.transformed_array.shape == src.shape
    assert info_col["candidate_family"] == "COLOR_PATTERN_PATCH"


# =====================================================================
# Category H: Realized RMS Magnitude Matching
# =====================================================================

def test_realized_magnitude_matching_and_metrics():
    """Verify that magnitude matched noise accurately computes and matches realized RMS delta."""
    src = np.full((64, 64, 3), 0.5, dtype=np.float32)
    triggered = src.copy()
    triggered[-10:, -10:, :] = 1.0
    expected_diff = triggered - src
    expected_rms = float(np.sqrt(np.mean(expected_diff ** 2)))

    noise_arr, noise_hash, metrics = generate_magnitude_matched_noise_array(src, triggered, seed=42)

    assert abs(metrics["trigger_perturbation_magnitude"] - expected_rms) < 1e-4
    assert metrics["matching_method"] == "REALIZED_RMS_GAUSSIAN"
    assert metrics["matching_error"] <= metrics["matching_tolerance"]
    assert metrics["status"] == "MATCHED"


def test_magnitude_matched_noise_zero_delta_fallback():
    """When triggered array is identical to source, realized RMS is 0.0."""
    src = np.full((32, 32, 3), 0.5, dtype=np.float32)
    noise_arr, noise_hash, metrics = generate_magnitude_matched_noise_array(src, src, seed=99)
    assert metrics["trigger_perturbation_magnitude"] == 0.0
    assert metrics["control_perturbation_magnitude"] == 0.0
    assert metrics["matching_method"] == "REALIZED_RMS_ZERO"
    assert np.array_equal(noise_arr, src)


# =====================================================================
# Category I: Generic Tensor, Classification, & Incompatible Formats
# =====================================================================

def test_generic_tensor_distance_activation():
    """Verify generic tensor distance activation."""
    clean_tensor = np.zeros((4, 4, 4), dtype=np.float32)
    cond_tensor = np.ones((4, 4, 4), dtype=np.float32)

    crit = ActivationCriterionSpec(
        criterion_type=ActivationCriterionTypeEnum.TENSOR_DISTANCE_THRESHOLD,
        distance_threshold=1.0,
    )
    dec, _, _, _, rec = evaluate_activation_decision(clean_tensor, cond_tensor, crit)
    assert dec == ActivationDecisionEnum.ACTIVATED


def test_classification_confidence_delta_activation():
    """Verify classification CONFIDENCE_DELTA_THRESHOLD activation."""
    clean_out = np.array([0.9, 0.05, 0.05], dtype=np.float32)
    cond_out = np.array([0.5, 0.25, 0.25], dtype=np.float32)

    crit = ActivationCriterionSpec(
        criterion_type=ActivationCriterionTypeEnum.CONFIDENCE_DELTA_THRESHOLD,
        confidence_delta_threshold=0.30,
    )
    dec, pred, conf, _, rec = evaluate_activation_decision(clean_out, cond_out, crit)
    assert dec == ActivationDecisionEnum.ACTIVATED
    assert rec.status == "VALID"


def test_incompatible_format_returns_unavailable():
    """Passing non-dict to detection criterion returns UNAVAILABLE without error."""
    crit = ActivationCriterionSpec(
        criterion_type=ActivationCriterionTypeEnum.DETECTION_COUNT_DELTA,
    )
    dec, _, _, _, rec = evaluate_activation_decision("invalid_clean", "invalid_cond", crit)
    assert dec == ActivationDecisionEnum.UNAVAILABLE
    assert rec.status.startswith("UNAVAILABLE")


# =====================================================================
# Category J: Immutability, Security, Determinism, & Database
# =====================================================================

def test_source_immutability():
    """Source inputs must remain bit-for-bit unchanged before and after evaluation."""
    engine = TriggerActivationEngine()
    candidate = create_candidate_spec(
        TriggerFamilyEnum.SPATIAL_PATCH,
        SpatialPatchParameters(relative_width=0.10, relative_height=0.10),
    )
    samples = make_synthetic_samples(count=10, shape=(64, 64, 3))
    orig_hashes = [compute_input_array_hash(s[1]) for s in samples]

    engine.assess_candidate("proj-immut", "m1", samples, candidate, dummy_classification_model)

    after_hashes = [compute_input_array_hash(s[1]) for s in samples]
    assert orig_hashes == after_hashes


def test_zero_database_schema_changes():
    """Verification that Phase 9.4 introduces zero database schema changes."""
    from aivara.database.connection import Base
    table_names = list(Base.metadata.tables.keys())
    for t in table_names:
        assert not t.startswith("backdoor_activation")
        assert not t.startswith("trigger_activation")


def test_assessment_serialization_roundtrip():
    """Assessment Pydantic model must dump and validate roundtrip identically."""
    engine = TriggerActivationEngine()
    candidate = create_candidate_spec(
        TriggerFamilyEnum.SPATIAL_PATCH,
        SpatialPatchParameters(relative_width=0.10, relative_height=0.10),
    )
    samples = make_synthetic_samples(count=10, shape=(64, 64, 3))
    assessment = engine.assess_candidate("proj-roundtrip", "m1", samples, candidate, dummy_classification_model)

    dumped = assessment.model_dump()
    reloaded = TriggerActivationAssessment.model_validate(dumped)

    assert reloaded.assessment_id == assessment.assessment_id
    assert reloaded.tar == assessment.tar
    assert reloaded.status == assessment.status
    assert reloaded.support_status == assessment.support_status
    assert len(reloaded.paired_observations) == 10


def test_seed_isolation_distinct_conditions():
    """Seeds derived for different conditions on the same sample must differ."""
    seed_shuff = derive_control_seed(
        project_id="proj-1",
        source_input_id="s1",
        source_input_hash="a" * 64,
        candidate_hash="b" * 64,
        condition_type=BackdoorConditionEnum.LOCATION_SHUFFLED.value,
        experiment_id="exp-1",
        sample_index=0,
    )
    seed_noise = derive_control_seed(
        project_id="proj-1",
        source_input_id="s1",
        source_input_hash="a" * 64,
        candidate_hash="b" * 64,
        condition_type=BackdoorConditionEnum.MAGNITUDE_MATCHED_NOISE.value,
        experiment_id="exp-1",
        sample_index=0,
    )
    assert seed_shuff != seed_noise


def test_empty_input_samples_rejected():
    """Empty input sample list must raise InvalidExperimentConfigError."""
    engine = TriggerActivationEngine()
    candidate = create_candidate_spec(
        TriggerFamilyEnum.SPATIAL_PATCH,
        SpatialPatchParameters(relative_width=0.10, relative_height=0.10),
    )
    with pytest.raises(InvalidExperimentConfigError):
        engine.assess_candidate("proj-empty", "m1", [], candidate, dummy_classification_model)


def test_max_evaluation_budget_exceeded_rejected():
    """Exceeding MAX_EVALUATION_SAMPLES budget must raise InvalidExperimentConfigError."""
    engine = TriggerActivationEngine()
    candidate = create_candidate_spec(
        TriggerFamilyEnum.SPATIAL_PATCH,
        SpatialPatchParameters(relative_width=0.10, relative_height=0.10),
    )
    samples = make_synthetic_samples(count=MAX_EVALUATION_SAMPLES + 1, shape=(64, 64, 3))
    with pytest.raises(InvalidExperimentConfigError):
        engine.assess_candidate("proj-overflow", "m1", samples, candidate, dummy_classification_model)


def test_texture_grid_activation():
    """Verify assessment with TEXTURE_GRID candidate."""
    engine = TriggerActivationEngine()
    candidate = create_candidate_spec(
        TriggerFamilyEnum.TEXTURE_GRID,
        TextureGridParameters(primitive=TexturePrimitiveEnum.CHECKER, stride_pixels=8, line_width_pixels=2),
    )
    samples = make_synthetic_samples(count=10, shape=(64, 64, 3))
    assessment = engine.assess_candidate(
        "proj-texture", "m1", samples, candidate, dummy_classification_model
    )
    assert assessment.tar is not None
    assert assessment.candidate_family == TriggerFamilyEnum.TEXTURE_GRID


def test_assessment_idempotency():
    """Re-assessing identical inputs and candidate produces identical assessment_id."""
    engine = TriggerActivationEngine()
    candidate = create_candidate_spec(
        TriggerFamilyEnum.SPATIAL_PATCH,
        SpatialPatchParameters(relative_width=0.10, relative_height=0.10),
    )
    samples1 = make_synthetic_samples(count=10, shape=(64, 64, 3))
    samples2 = make_synthetic_samples(count=10, shape=(64, 64, 3))

    res1 = engine.assess_candidate("proj-idem", "m1", samples1, candidate, dummy_classification_model)
    res2 = engine.assess_candidate("proj-idem", "m1", samples2, candidate, dummy_classification_model)

    assert res1.assessment_id == res2.assessment_id
    assert res1.tar == res2.tar


def test_no_malicious_inference_in_taxonomy():
    """Taxonomy must not contain words like malicious, attacker, backdoor_confirmed, culprit."""
    forbidden = ["malicious", "attacker", "backdoor_confirmed", "culprit", "compromised", "guilty"]
    for status in BackdoorComparisonStatusEnum:
        for f in forbidden:
            assert f not in status.value.lower()
    for dec in ActivationDecisionEnum:
        for f in forbidden:
            assert f not in dec.value.lower()
    for sup in BackdoorSupportStatusEnum:
        for f in forbidden:
            assert f not in sup.value.lower()


def test_source_input_mutation_raises_integrity_error():
    """Mutating the source input array during evaluation must raise SourceInputIntegrityError."""
    def mutating_model(arr: np.ndarray) -> np.ndarray:
        if arr.flags.writeable:
            arr[0, 0, 0] = 999.0
        return np.array([1.0, 0.0], dtype=np.float32)

    engine = TriggerActivationEngine()
    candidate = create_candidate_spec(
        TriggerFamilyEnum.SPATIAL_PATCH,
        SpatialPatchParameters(relative_width=0.10, relative_height=0.10),
    )
    samples = make_synthetic_samples(count=2, shape=(64, 64, 3))
    samples[0][1].flags.writeable = True

    with pytest.raises(SourceInputIntegrityError):
        engine.assess_candidate("proj-mut", "m1", samples, candidate, mutating_model)


def test_reference_model_optional_and_supplied_semantics():
    """Reference model is OPTIONAL_RESERVED when omitted, and executed when supplied."""
    engine = TriggerActivationEngine()
    candidate = create_candidate_spec(
        TriggerFamilyEnum.SPATIAL_PATCH,
        SpatialPatchParameters(relative_width=0.10, relative_height=0.10),
    )
    samples = make_synthetic_samples(count=10, shape=(64, 64, 3))

    res_omitted = engine.assess_candidate("proj-ref1", "m1", samples, candidate, dummy_classification_model)
    assert res_omitted.reference_model_status == "OPTIONAL_RESERVED"
    assert res_omitted.paired_observations[0].reference_model_result is None

    def ref_model(arr):
        return np.array([1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0], dtype=np.float32)

    res_supplied = engine.assess_candidate(
        "proj-ref2", "m1", samples, candidate, dummy_classification_model, reference_model_fn=ref_model
    )
    assert res_supplied.reference_model_status == "IMPLEMENTED_SUPPLIED"
    assert res_supplied.paired_observations[0].reference_model_result is not None


def test_different_blend_modes_activation():
    """Verify activation pipeline with ALPHA_BLEND mode."""
    engine = TriggerActivationEngine()
    candidate = create_candidate_spec(
        TriggerFamilyEnum.SPATIAL_PATCH,
        SpatialPatchParameters(
            relative_width=0.10,
            relative_height=0.10,
            fill_color=[1.0, 1.0, 1.0],
            alpha=0.8,
            blend_mode=BlendModeEnum.ALPHA_BLEND,
        ),
    )
    samples = make_synthetic_samples(count=10, shape=(64, 64, 3))
    assessment = engine.assess_candidate(
        project_id="proj-alpha-blend",
        model_id="mod-01",
        input_samples=samples,
        candidate_spec=candidate,
        model_fn=dummy_classification_model,
    )
    assert assessment.tar == 1.0


def test_project_isolation():
    """Different project_ids must generate completely different experiment and assessment IDs."""
    engine = TriggerActivationEngine()
    candidate = create_candidate_spec(
        TriggerFamilyEnum.SPATIAL_PATCH,
        SpatialPatchParameters(relative_width=0.10, relative_height=0.10),
    )
    samples = make_synthetic_samples(count=5, shape=(64, 64, 3))

    res_p1 = engine.assess_candidate("proj-alpha", "mod-1", samples, candidate, dummy_classification_model)
    res_p2 = engine.assess_candidate("proj-beta", "mod-1", samples, candidate, dummy_classification_model)

    assert res_p1.experiment_id != res_p2.experiment_id
    assert res_p1.assessment_id != res_p2.assessment_id


def test_placement_info_recorded_in_location_shuffled():
    """Verify that placement_info metadata is recorded for location shuffled condition."""
    engine = TriggerActivationEngine()
    candidate = create_candidate_spec(
        TriggerFamilyEnum.SPATIAL_PATCH,
        SpatialPatchParameters(relative_width=0.10, relative_height=0.10),
    )
    samples = make_synthetic_samples(count=3, shape=(64, 64, 3))
    assessment = engine.assess_candidate("proj-place-info", "m1", samples, candidate, dummy_classification_model)
    shuff_res = assessment.paired_observations[0].location_shuffled_result
    assert shuff_res is not None
    assert shuff_res.placement_info is not None
    assert "original_placement" in shuff_res.placement_info
    assert "shuffled_placement" in shuff_res.placement_info


def test_unsupported_layout_string_rejected():
    """Unsupported layout strings must raise UnsupportedInputShapeError."""
    from aivara.backdoor.transformation.exceptions import UnsupportedInputShapeError
    engine = TriggerActivationEngine()
    candidate = create_candidate_spec(
        TriggerFamilyEnum.SPATIAL_PATCH,
        SpatialPatchParameters(relative_width=0.10, relative_height=0.10),
    )
    samples = make_synthetic_samples(count=2, shape=(64, 64, 3))
    with pytest.raises(UnsupportedInputShapeError):
        engine.assess_candidate(
            "proj-bad-layout",
            "m1",
            samples,
            candidate,
            dummy_classification_model,
            input_layout="INVALID_LAYOUT_XYZ",
        )

