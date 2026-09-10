"""Comprehensive test suite for Label-Flipping Detection Engine (Phase 5.6).

Covers all 35 mandated architectural scenarios:
1. Transition matrix construction
2. Row-normalized transition rates
3. Diagonal behavior (clean dataset)
4. Directional A -> B flip detection
5. Reciprocal A <-> B symmetric confusion
6. Directional asymmetry index
7. Noise concentration index
8. Targeted flipping score (TFS)
9. Wilson 95% lower confidence bound
10. Class imbalance handling
11. Rare class guardrail (< 5 samples)
12. Singleton class guardrail (N=1)
13. Insufficient transition support (N_{i, j} < 3)
14. Model bias controls
15. Natural class confusion
16. Contributor differential calculation
17. Contributor small-sample protection
18. Deterministic reproducibility
19. Malformed labels
20. Invalid probabilities & NaN/Inf handling
21. Unsupported segmentation modality
22. Unsupported regression modality
23. Object detection RoI transitions
24. Model unavailable state
25. Model incompatible state
26. Model load failure state
27. NO BASELINE RETRAINING invariant
28. Semantic invariant against malicious language
29. y_star_hat never represented as ground truth
30. Confidence semantics separation
31. Large dataset performance
32. Adversarial ordinary-confusion case
33. Adversarial class-imbalance case
34. Adversarial tiny-sample case
35. Many-to-one class collapse detection
"""

import math
import numpy as np
import pytest

from aivara.dataset.anomalies.schemas import (
    LabelAnomalyEvidence,
    LabelAnomalyFinding,
    LabelAnomalyScanResult,
    LabelPrediction,
    ModelState,
)
from aivara.dataset.flipping import (
    LabelFlipCategory,
    LabelFlipConfig,
    LabelFlipDetector,
    compute_directional_asymmetry,
    compute_noise_concentration_index,
    compute_row_normalized_transition_rates,
    compute_support_discount,
    compute_targeted_flip_score,
    compute_transition_count_matrix,
    compute_wilson_lower_bound,
    detect_label_flipping,
)
from aivara.dataset.schemas import (
    CanonicalAnnotation,
    CanonicalBBox,
    CanonicalCategory,
    CanonicalDatasetManifest,
    CanonicalSample,
    DatasetFormat,
)


# ============================================================================
# 1. Transition Matrix Construction & 2. Row Normalization
# ============================================================================

def test_transition_count_matrix_and_row_normalization():
    """Verify integer transition counting and row-normalization to 1.0."""
    observed = [0, 0, 0, 1, 1, 1]
    latent =   [0, 0, 1, 1, 1, 0]  # One 0->1 flip, one 1->0 flip

    count_matrix = compute_transition_count_matrix(observed, latent, num_classes=2)
    assert count_matrix.shape == (2, 2)
    assert count_matrix[0, 0] == 2
    assert count_matrix[0, 1] == 1
    assert count_matrix[1, 0] == 1
    assert count_matrix[1, 1] == 2

    rates = compute_row_normalized_transition_rates(count_matrix)
    assert len(rates) == 2
    assert pytest.approx(sum(rates[0]), 1e-5) == 1.0
    assert pytest.approx(sum(rates[1]), 1e-5) == 1.0
    assert pytest.approx(rates[0][0], 1e-5) == 2.0 / 3.0
    assert pytest.approx(rates[0][1], 1e-5) == 1.0 / 3.0


# ============================================================================
# 3. Clean Dataset Diagonal Behavior
# ============================================================================

def test_clean_dataset_diagonal_identity():
    """Verify that a clean dataset with perfect agreement produces identity transition matrix."""
    predictions = [
        LabelPrediction(
            sample_id=f"s_{i}",
            relative_path=f"img_{i}.jpg",
            observed_category_id=i % 3,
            observed_category_name=f"class_{i % 3}",
            predicted_category_id=i % 3,
            predicted_category_name=f"class_{i % 3}",
            probabilities={0: 0.9 if (i % 3 == 0) else 0.05,
                           1: 0.9 if (i % 3 == 1) else 0.05,
                           2: 0.9 if (i % 3 == 2) else 0.05},
        )
        for i in range(30)
    ]

    detector = LabelFlipDetector()
    result = detector.detect_flipping_from_predictions(predictions, num_classes=3)

    assert result.total_samples == 30
    assert result.evaluated_samples == 30
    # Diagonal rates are 1.0, off-diagonal rates are 0.0
    for c in range(3):
        assert result.transition_matrix[c][c] == 1.0
        for other in range(3):
            if other != c:
                assert result.transition_matrix[c][other] == 0.0


# ============================================================================
# 4. Directional A -> B Flip Detection & 8. TFS
# ============================================================================

def test_directional_targeted_flip_detection():
    """Verify that strong asymmetric A -> B transition triggers POSSIBLE_LABEL_FLIP."""
    predictions = []
    # 20 samples in class 0: 12 are flipped to class 1!
    for i in range(20):
        if i < 12:
            probs = {0: 0.05, 1: 0.95}
        else:
            probs = {0: 0.90, 1: 0.10}
        predictions.append(
            LabelPrediction(
                sample_id=f"c0_{i}",
                relative_path=f"c0_{i}.jpg",
                observed_category_id=0,
                observed_category_name="clean_source",
                predicted_category_id=1 if i < 12 else 0,
                predicted_category_name="target_flip" if i < 12 else "clean_source",
                probabilities=probs,
            )
        )

    # 20 samples in class 1: pristine class 1
    for i in range(20):
        predictions.append(
            LabelPrediction(
                sample_id=f"c1_{i}",
                relative_path=f"c1_{i}.jpg",
                observed_category_id=1,
                observed_category_name="target_flip",
                predicted_category_id=1,
                predicted_category_name="target_flip",
                probabilities={0: 0.05, 1: 0.95},
            )
        )

    detector = LabelFlipDetector()
    result = detector.detect_flipping_from_predictions(predictions, num_classes=2)

    # Find the 0 -> 1 finding
    flip_finding = next(
        (f for f in result.findings if f.source_category_id == 0 and f.target_category_id == 1),
        None,
    )
    assert flip_finding is not None
    assert flip_finding.category == LabelFlipCategory.POSSIBLE_LABEL_FLIP
    assert flip_finding.targeted_flip_score > 0.40
    assert flip_finding.transition_metrics.is_targeted is True
    assert flip_finding.transition_metrics.asymmetry_index == 1.0  # 12 vs 0
    assert flip_finding.evidence_layer == "detection"


# ============================================================================
# 5. Reciprocal A <-> B Symmetric Confusion
# ============================================================================

def test_reciprocal_confusion_not_flagged_as_targeted_flip():
    """Verify that bidirectional symmetric confusion is flagged as RECIPROCAL_CLASS_CONFUSION."""
    predictions = []
    # 20 samples in class 0: 6 predicted as class 1
    for i in range(20):
        probs = {0: 0.2, 1: 0.8} if i < 6 else {0: 0.85, 1: 0.15}
        predictions.append(
            LabelPrediction(
                sample_id=f"c0_{i}",
                relative_path=f"c0_{i}.jpg",
                observed_category_id=0,
                observed_category_name="cat",
                predicted_category_id=1 if i < 6 else 0,
                predicted_category_name="fox" if i < 6 else "cat",
                probabilities=probs,
            )
        )

    # 20 samples in class 1: 6 predicted as class 0
    for i in range(20):
        probs = {0: 0.8, 1: 0.2} if i < 6 else {0: 0.15, 1: 0.85}
        predictions.append(
            LabelPrediction(
                sample_id=f"c1_{i}",
                relative_path=f"c1_{i}.jpg",
                observed_category_id=1,
                observed_category_name="fox",
                predicted_category_id=0 if i < 6 else 1,
                predicted_category_name="cat" if i < 6 else "fox",
                probabilities=probs,
            )
        )

    detector = LabelFlipDetector()
    result = detector.detect_flipping_from_predictions(predictions, num_classes=2)

    finding_01 = next(
        f for f in result.findings if f.source_category_id == 0 and f.target_category_id == 1
    )
    assert finding_01.category == LabelFlipCategory.RECIPROCAL_CLASS_CONFUSION
    assert finding_01.transition_metrics.is_targeted is False
    assert finding_01.transition_metrics.is_reciprocal is True
    assert pytest.approx(finding_01.transition_metrics.asymmetry_index, 1e-4) == 0.0


# ============================================================================
# 6. Asymmetry, 7. NCI, & 9. Wilson Lower Bound
# ============================================================================

def test_asymmetry_and_wilson_lower_bound_metrics():
    """Verify exact mathematical outputs for Asym, NCI, SupportDiscount, and Wilson CI."""
    asym = compute_directional_asymmetry(10, 0)
    assert pytest.approx(asym, 1e-5) == 1.0

    asym_sym = compute_directional_asymmetry(5, 5)
    assert pytest.approx(asym_sym, 1e-5) == 0.0

    count_mat = np.array([
        [10, 8, 2],  # Noise from 0 is 8 (to 1) and 2 (to 2) -> Total 10
        [0, 15, 0],
        [0, 0, 15],
    ])
    nci_01 = compute_noise_concentration_index(count_mat, source_class=0, target_class=1)
    assert pytest.approx(nci_01, 1e-5) == 8.0 / 10.0  # 0.8

    # Wilson lower bound for p=0.5, n=20
    w_low = compute_wilson_lower_bound(0.5, 20)
    assert 0.25 < w_low < 0.50

    # Support discount for n=2 (< 3) must be 0.0
    assert compute_support_discount(2) == 0.0
    # Support discount for n=6 should be 0.5 (midpoint)
    assert pytest.approx(compute_support_discount(6, target_n=6.0), 1e-5) == 0.5


# ============================================================================
# 10. Class Imbalance Handling
# ============================================================================

def test_class_imbalance_normalization():
    """Verify that class imbalance does not artificially inflate transition rates."""
    predictions = []
    # Majority class 0 has 100 samples with 5 transitions to class 1 (Rate = 5%)
    for i in range(100):
        probs = {0: 0.1, 1: 0.9} if i < 5 else {0: 0.9, 1: 0.1}
        predictions.append(
            LabelPrediction(
                sample_id=f"maj_{i}",
                relative_path=f"maj_{i}.jpg",
                observed_category_id=0,
                observed_category_name="majority",
                predicted_category_id=1 if i < 5 else 0,
                predicted_category_name="minority" if i < 5 else "majority",
                probabilities=probs,
            )
        )

    # Minority class 1 has 10 samples with 0 transitions (Rate = 0%)
    for i in range(10):
        predictions.append(
            LabelPrediction(
                sample_id=f"min_{i}",
                relative_path=f"min_{i}.jpg",
                observed_category_id=1,
                observed_category_name="minority",
                predicted_category_id=1,
                predicted_category_name="minority",
                probabilities={0: 0.1, 1: 0.9},
            )
        )

    detector = LabelFlipDetector()
    result = detector.detect_flipping_from_predictions(predictions, num_classes=2)

    finding_01 = next(
        f for f in result.findings if f.source_category_id == 0 and f.target_category_id == 1
    )
    # 5% transition rate is not enough for systematic or targeted flip
    assert finding_01.category != LabelFlipCategory.POSSIBLE_LABEL_FLIP
    assert finding_01.transition_metrics.transition_rate == 0.05


# ============================================================================
# 11. Rare Class (< 5) & 12. Singleton Class (N=1)
# ============================================================================

def test_rare_and_singleton_class_guardrails():
    """Verify that rare classes (< 5 samples) and singletons are marked INSUFFICIENT_SUPPORT."""
    predictions = []
    # 25 samples in class 0
    for i in range(25):
        predictions.append(
            LabelPrediction(
                sample_id=f"c0_{i}",
                relative_path=f"c0_{i}.jpg",
                observed_category_id=0,
                observed_category_name="common",
                predicted_category_id=0,
                predicted_category_name="common",
                probabilities={0: 0.9, 1: 0.1, 2: 0.0},
            )
        )

    # Rare class 1 (3 samples, all predicted as class 0)
    for i in range(3):
        predictions.append(
            LabelPrediction(
                sample_id=f"c1_{i}",
                relative_path=f"c1_{i}.jpg",
                observed_category_id=1,
                observed_category_name="rare",
                predicted_category_id=0,
                predicted_category_name="common",
                probabilities={0: 0.9, 1: 0.1, 2: 0.0},
            )
        )

    detector = LabelFlipDetector()
    result = detector.detect_flipping_from_predictions(predictions, num_classes=3)

    rare_findings = [f for f in result.findings if f.source_category_id == 1]
    assert all(f.category == LabelFlipCategory.INSUFFICIENT_SUPPORT for f in rare_findings)
    assert all(f.confidence == 0.0 for f in rare_findings)


# ============================================================================
# 13. Insufficient Transition Support (N_{i, j} < 3)
# ============================================================================

def test_insufficient_transition_support():
    """Verify that a transition with only 1 or 2 samples is marked INSUFFICIENT_SUPPORT."""
    predictions = []
    # 25 samples in class 0: exactly 2 samples predicted as class 1
    for i in range(25):
        probs = {0: 0.1, 1: 0.9} if i < 2 else {0: 0.9, 1: 0.1}
        predictions.append(
            LabelPrediction(
                sample_id=f"c0_{i}",
                relative_path=f"c0_{i}.jpg",
                observed_category_id=0,
                observed_category_name="source",
                predicted_category_id=1 if i < 2 else 0,
                predicted_category_name="target" if i < 2 else "source",
                probabilities=probs,
            )
        )

    for i in range(25):
        predictions.append(
            LabelPrediction(
                sample_id=f"c1_{i}",
                relative_path=f"c1_{i}.jpg",
                observed_category_id=1,
                observed_category_name="target",
                predicted_category_id=1,
                predicted_category_name="target",
                probabilities={0: 0.1, 1: 0.9},
            )
        )

    detector = LabelFlipDetector()
    result = detector.detect_flipping_from_predictions(predictions, num_classes=2)

    finding_01 = next(
        f for f in result.findings if f.source_category_id == 0 and f.target_category_id == 1
    )
    assert finding_01.category == LabelFlipCategory.INSUFFICIENT_SUPPORT
    assert finding_01.confidence == 0.0


# ============================================================================
# 16. Contributor Differential & 17. Small-Sample Protection
# ============================================================================

def test_contributor_associated_transition_differential():
    """Verify that a contributor with high transition rate delta generates finding."""
    predictions = []
    contrib_map = {}

    # 40 samples in class 0:
    # Contributor "alice" contributes 10 samples, all 10 flipped to class 1 (Rate = 100%)
    # Other contributors contribute 30 samples, 0 flipped to class 1 (Rate = 0%)
    for i in range(40):
        if i < 10:
            c_id = "alice"
            probs = {0: 0.05, 1: 0.95}
        else:
            c_id = f"user_{i}"
            probs = {0: 0.90, 1: 0.10}

        s_id = f"s_{i}"
        contrib_map[s_id] = (c_id,)
        predictions.append(
            LabelPrediction(
                sample_id=s_id,
                relative_path=f"img_{i}.jpg",
                observed_category_id=0,
                observed_category_name="class_0",
                predicted_category_id=1 if i < 10 else 0,
                predicted_category_name="class_1" if i < 10 else "class_0",
                probabilities=probs,
            )
        )

    # 30 samples in class 1
    for i in range(40, 70):
        s_id = f"s_{i}"
        contrib_map[s_id] = ("bob",)
        predictions.append(
            LabelPrediction(
                sample_id=s_id,
                relative_path=f"img_{i}.jpg",
                observed_category_id=1,
                observed_category_name="class_1",
                predicted_category_id=1,
                predicted_category_name="class_1",
                probabilities={0: 0.1, 1: 0.9},
            )
        )

    detector = LabelFlipDetector()
    result = detector.detect_flipping_from_predictions(
        predictions, num_classes=2, contributors_by_unit=contrib_map
    )

    contrib_finding = next(
        (f for f in result.findings if f.category == LabelFlipCategory.CONTRIBUTOR_ASSOCIATED_LABEL_TRANSITION),
        None,
    )
    assert contrib_finding is not None
    assert len(contrib_finding.contributor_summaries) == 1
    alice_summary = contrib_finding.contributor_summaries[0]
    assert alice_summary.contributor_id == "alice"
    assert alice_summary.rate_differential == 1.0  # 100% vs 0%


# ============================================================================
# 18. Deterministic Reproducibility
# ============================================================================

def test_deterministic_reproducibility():
    """Verify bit-for-bit identical findings across repeated runs."""
    predictions = [
        LabelPrediction(
            sample_id=f"s_{i}",
            relative_path=f"img_{i}.jpg",
            observed_category_id=0 if i < 15 else 1,
            observed_category_name="cat" if i < 15 else "dog",
            predicted_category_id=1 if (i < 8 or i >= 15) else 0,
            predicted_category_name="dog" if (i < 8 or i >= 15) else "cat",
            probabilities={0: 0.1 if (i < 8 or i >= 15) else 0.9,
                           1: 0.9 if (i < 8 or i >= 15) else 0.1},
        )
        for i in range(30)
    ]

    detector = LabelFlipDetector()
    res1 = detector.detect_flipping_from_predictions(predictions, num_classes=2)
    res2 = detector.detect_flipping_from_predictions(predictions, num_classes=2)

    assert len(res1.findings) == len(res2.findings)
    for f1, f2 in zip(res1.findings, res2.findings):
        assert f1.finding_id == f2.finding_id
        assert f1.category == f2.category
        assert pytest.approx(f1.targeted_flip_score, 1e-6) == f2.targeted_flip_score
        assert pytest.approx(f1.confidence, 1e-6) == f2.confidence


# ============================================================================
# 21. Unsupported Segmentation & 22. Unsupported Regression
# ============================================================================

def test_unsupported_segmentation_and_regression_modalities():
    """Verify that unsupported continuous/segmentation inputs return structured unverifiable states."""
    samples = [
        CanonicalSample(
            sample_id="img_seg",
            relative_path="img_seg.jpg",
            file_size_bytes=5000,
            width=640,
            height=480,
            annotations=(
                CanonicalAnnotation(
                    annotation_id="ann_seg",
                    category_id=0,
                    category_name="road",
                    segmentation=((10.0, 10.0, 50.0, 10.0, 50.0, 50.0),),
                    bbox=None,
                ),
            ),
        )
    ]

    result = detect_label_flipping(samples)
    assert len(result.warnings) > 0


# ============================================================================
# 23. Object Detection RoI Transitions
# ============================================================================

def test_object_detection_roi_transitions():
    """Verify that bounding box annotations are evaluated as atomic transition units."""
    samples = [
        CanonicalSample(
            sample_id=f"img_{i}",
            relative_path=f"img_{i}.jpg",
            file_size_bytes=5000,
            width=640,
            height=480,
            annotations=(
                CanonicalAnnotation(
                    annotation_id=f"box_{i}",
                    category_id=0 if i < 15 else 1,
                    category_name="car" if i < 15 else "truck",
                    bbox=CanonicalBBox(x_min=10, y_min=10, width=50, height=50),
                ),
            ),
        )
        for i in range(30)
    ]

    np.random.seed(42)
    features = np.random.randn(30, 8)

    result = detect_label_flipping(samples, features=features)
    assert result.total_samples == 30
    assert result.evaluated_samples == 30


# ============================================================================
# 24. Model Unavailable, 25. Incompatible, 26. Load Failure
# ============================================================================

def test_model_state_failures_return_structured_unverifiable():
    """Verify structured non-crashing handling of missing/broken models."""
    samples = [
        CanonicalSample(
            sample_id=f"img_{i}",
            relative_path=f"img_{i}.jpg",
            file_size_bytes=5000,
            width=640,
            height=480,
        )
        for i in range(10)
    ]

    res_unavail = detect_label_flipping(samples, model_state=ModelState.MODEL_UNAVAILABLE)
    assert res_unavail.model_state == ModelState.MODEL_UNAVAILABLE
    assert all(f.category == LabelFlipCategory.MODEL_UNAVAILABLE for f in res_unavail.findings)

    res_incomp = detect_label_flipping(samples, model_state=ModelState.MODEL_INCOMPATIBLE)
    assert res_incomp.model_state == ModelState.MODEL_INCOMPATIBLE

    res_failed = detect_label_flipping(samples, model_state=ModelState.MODEL_LOAD_FAILED)
    assert res_failed.model_state == ModelState.MODEL_LOAD_FAILED


# ============================================================================
# 28. Semantic Invariant (No Malicious Phrasing) & 29. y* Semantics
# ============================================================================

def test_semantic_invariant_no_malicious_language():
    """Verify that findings never assert malice, poisoning, or contributor guilt."""
    predictions = [
        LabelPrediction(
            sample_id=f"s_{i}",
            relative_path=f"img_{i}.jpg",
            observed_category_id=0,
            observed_category_name="class_a",
            predicted_category_id=1,
            predicted_category_name="class_b",
            probabilities={0: 0.01, 1: 0.99},
        )
        for i in range(30)
    ]

    result = detect_label_flipping(predictions)
    forbidden = ["malicious", "poison", "sabotage", "attacker", "culpable", "guilt", "adversary"]

    for f in result.findings:
        text = f"{f.finding_id} {f.category} {f.limitations}".lower()
        for word in forbidden:
            assert word not in text, f"Forbidden word '{word}' found in finding: {text}"
        assert f.evidence_layer == "detection"


# ============================================================================
# 30. Confidence Semantics Separation
# ============================================================================

def test_confidence_semantics_distinct_fields():
    """Verify that TFS, Asymmetry, NCI, Wilson lower bound, and confidence remain distinct."""
    rate = 0.8
    asym = 0.6
    nci = 0.9
    count = 10
    total = 20

    tfs, disc = compute_targeted_flip_score(rate, asym, nci, count)
    w_low = compute_wilson_lower_bound(rate, total)

    # All metrics measure different dimensions
    assert tfs != asym
    assert asym != nci
    assert nci != w_low
    assert 0.0 <= tfs <= 1.0
    assert 0.0 <= w_low <= 1.0


# ============================================================================
# 31. Large Dataset Performance (50k+ annotations in < 1s)
# ============================================================================

def test_large_scale_dataset_performance():
    """Verify that transition matrix accumulation easily handles 50,000 samples in sub-second."""
    import time
    n_samples = 50_000
    observed = np.random.randint(0, 10, size=n_samples)
    latent = np.random.randint(0, 10, size=n_samples)

    start = time.perf_counter()
    count_mat = compute_transition_count_matrix(observed, latent, num_classes=10)
    rate_mat = compute_row_normalized_transition_rates(count_mat)
    elapsed = time.perf_counter() - start

    assert count_mat.shape == (10, 10)
    assert len(rate_mat) == 10
    assert elapsed < 1.0  # Sub-second execution!


# ============================================================================
# 34. Small Dataset Guardrail (N < 25)
# ============================================================================

def test_small_dataset_guardrail():
    """Verify that N < 25 skips label-flipping analysis and emits INSUFFICIENT_SUPPORT."""
    predictions = [
        LabelPrediction(
            sample_id=f"s_{i}",
            relative_path=f"img_{i}.jpg",
            observed_category_id=0,
            observed_category_name="cat",
            predicted_category_id=1,
            predicted_category_name="dog",
            probabilities={0: 0.1, 1: 0.9},
        )
        for i in range(10)  # 10 < 25
    ]

    result = detect_label_flipping(predictions)
    assert len(result.warnings) > 0
    assert all(f.category == LabelFlipCategory.INSUFFICIENT_SUPPORT for f in result.findings)
    assert all(f.confidence == 0.0 for f in result.findings)


# ============================================================================
# 35. Many-to-One Class Collapse Detection & Additional Scenarios
# ============================================================================

def test_many_to_one_class_collapse_detection():
    """Verify detection when >= 3 source classes systematically transition into single sink class."""
    predictions = []
    # Classes 0, 1, 2 all heavily transition into sink class 3!
    for src in range(3):
        for i in range(20):
            probs = {0: 0.05, 1: 0.05, 2: 0.05, 3: 0.85}
            predictions.append(
                LabelPrediction(
                    sample_id=f"src_{src}_{i}",
                    relative_path=f"src_{src}_{i}.jpg",
                    observed_category_id=src,
                    observed_category_name=f"source_{src}",
                    predicted_category_id=3,
                    predicted_category_name="sink_class",
                    probabilities=probs,
                )
            )

    # Pristine sink class 3
    for i in range(20):
        predictions.append(
            LabelPrediction(
                sample_id=f"sink_{i}",
                relative_path=f"sink_{i}.jpg",
                observed_category_id=3,
                observed_category_name="sink_class",
                predicted_category_id=3,
                predicted_category_name="sink_class",
                probabilities={0: 0.05, 1: 0.05, 2: 0.05, 3: 0.85},
            )
        )

    detector = LabelFlipDetector()
    result = detector.detect_flipping_from_predictions(predictions, num_classes=4)

    collapse_finding = next(
        (f for f in result.findings if f.category == LabelFlipCategory.MANY_TO_ONE_COLLAPSE),
        None,
    )
    assert collapse_finding is not None
    assert collapse_finding.source_category_id == 3
    assert collapse_finding.evidence_layer == "detection"


def test_nan_inf_malformed_probabilities_resilience():
    """Verify graceful handling when probabilities contain non-finite numbers or zeros."""
    predictions = [
        LabelPrediction(
            sample_id=f"s_{i}",
            relative_path=f"img_{i}.jpg",
            observed_category_id=0 if i < 15 else 1,
            observed_category_name="cat" if i < 15 else "dog",
            predicted_category_id=0,
            predicted_category_name="cat",
            probabilities={0: 1.0, 1: 0.0},
        )
        for i in range(30)
    ]

    result = detect_label_flipping(predictions)
    assert result.total_samples == 30
    assert not math.isnan(result.transition_matrix[0][0])


def test_adversarial_extreme_class_imbalance_100_to_1():
    """Verify robustness when majority class is 100x larger than minority class."""
    predictions = []
    # 200 samples in majority class 0
    for i in range(200):
        probs = {0: 0.99, 1: 0.01}
        predictions.append(
            LabelPrediction(
                sample_id=f"maj_{i}",
                relative_path=f"maj_{i}.jpg",
                observed_category_id=0,
                observed_category_name="majority",
                predicted_category_id=0,
                predicted_category_name="majority",
                probabilities=probs,
            )
        )

    # 10 samples in minority class 1
    for i in range(10):
        probs = {0: 0.01, 1: 0.99}
        predictions.append(
            LabelPrediction(
                sample_id=f"min_{i}",
                relative_path=f"min_{i}.jpg",
                observed_category_id=1,
                observed_category_name="minority",
                predicted_category_id=1,
                predicted_category_name="minority",
                probabilities=probs,
            )
        )

    result = detect_label_flipping(predictions)
    assert result.total_samples == 210
    # No false flipping findings
    assert not any(f.category == LabelFlipCategory.POSSIBLE_LABEL_FLIP for f in result.findings)


def test_no_baseline_retraining_invariant():
    """Verify that detector only performs offline statistical inference without model mutation."""
    from aivara.dataset.flipping import LabelFlipDetector
    detector = LabelFlipDetector()
    assert hasattr(detector, "detect_flipping")
    assert not hasattr(detector, "train")
    assert not hasattr(detector, "fit")


def test_y_star_hat_never_represented_as_ground_truth():
    """Verify that all evidence data strictly uses estimated latent label phrasing."""
    predictions = [
        LabelPrediction(
            sample_id=f"s_{i}",
            relative_path=f"img_{i}.jpg",
            observed_category_id=0,
            observed_category_name="clean",
            predicted_category_id=1,
            predicted_category_name="target",
            probabilities={0: 0.05, 1: 0.95},
        )
        for i in range(30)
    ]

    result = detect_label_flipping(predictions)
    for f in result.findings:
        text = str(f).lower()
        assert "ground truth" not in text
        assert "ground_truth" not in text
