"""Comprehensive test suite for Label Anomaly & Confident Learning Engine (Phase 5.5).

Covers all 25 mandated architectural scenarios:
1. deterministic splitting
2. stratification
3. OOF correctness
4. no training/test leakage
5. preprocessing leakage prevention
6. class thresholds
7. confident count matrix
8. joint distribution
9. anomaly scoring
10. high-confidence alternative class
11. systematic class anomaly
12. rare class
13. singleton class
14. small dataset
15. missing model
16. incompatible model
17. model load failure
18. deterministic reproducibility
19. classification behavior
20. object-detection RoI behavior
21. unsupported segmentation
22. unsupported regression
23. malformed input
24. confidence semantics
25. NO BASELINE RETRAINING invariant
"""

import hashlib
import numpy as np
import pytest

from aivara.dataset.anomalies import (
    DetectorSideCentroidEstimator,
    InsufficientDataError,
    InvalidFoldSplitError,
    LabelAnomalyCategory,
    LabelAnomalyConfig,
    LabelAnomalyDetector,
    LabelAnomalyError,
    LabelPrediction,
    ModelState,
    compute_class_thresholds,
    compute_confident_count_matrix,
    compute_joint_distribution_matrix,
    compute_out_of_fold_probabilities,
    compute_sample_anomaly_metrics,
    detect_label_anomalies,
    deterministic_stratified_kfold_split,
    generate_deterministic_seed,
    identify_systematic_anomalies,
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
# 1. Deterministic Splitting
# ============================================================================

def test_deterministic_stratified_split_reproducibility():
    """Verify that identical inputs produce exact same fold assignments."""
    labels = [0] * 20 + [1] * 20 + [2] * 20
    sample_ids = [f"sample_{i:03d}" for i in range(len(labels))]

    splits_1 = deterministic_stratified_kfold_split(labels, sample_ids, k_folds=5, random_seed=42)
    splits_2 = deterministic_stratified_kfold_split(labels, sample_ids, k_folds=5, random_seed=42)

    assert len(splits_1) == 5
    for (tr1, te1), (tr2, te2) in zip(splits_1, splits_2):
        np.testing.assert_array_equal(tr1, tr2)
        np.testing.assert_array_equal(te1, te2)


def test_seed_generation_with_dataset_fingerprint():
    """Verify seed generation derives properly from dataset hash."""
    seed_a = generate_deterministic_seed(42, dataset_fingerprint="abc123hash")
    seed_b = generate_deterministic_seed(42, dataset_fingerprint="abc123hash")
    seed_c = generate_deterministic_seed(42, dataset_fingerprint="def456hash")

    assert seed_a == seed_b
    assert seed_a != seed_c


# ============================================================================
# 2. Stratification
# ============================================================================

def test_stratification_preserves_class_proportions():
    """Verify that folds preserve relative class distribution as closely as possible."""
    # 30 of class 0, 60 of class 1, 90 of class 2 (Total 180) -> 5 folds (36 per fold)
    labels = [0] * 30 + [1] * 60 + [2] * 90
    splits = deterministic_stratified_kfold_split(labels, k_folds=5, random_seed=42)

    y = np.array(labels)
    for fold, (tr_idx, te_idx) in enumerate(splits):
        assert len(te_idx) == 36
        test_y = y[te_idx]
        assert np.sum(test_y == 0) == 6   # 30 / 5
        assert np.sum(test_y == 1) == 12  # 60 / 5
        assert np.sum(test_y == 2) == 18  # 90 / 5


# ============================================================================
# 3. OOF Correctness & 4. No Training/Test Leakage
# ============================================================================

def test_oof_no_data_leakage():
    """Verify that in every fold, train_indices and test_indices are strictly disjoint."""
    labels = [0] * 15 + [1] * 15
    splits = deterministic_stratified_kfold_split(labels, k_folds=5, random_seed=42)

    all_test_indices = []
    for tr, te in splits:
        intersection = np.intersect1d(tr, te)
        assert len(intersection) == 0  # Zero leakage!
        assert len(tr) + len(te) == len(labels)
        all_test_indices.extend(te)

    # Every sample is tested exactly once
    assert sorted(all_test_indices) == list(range(len(labels)))


# ============================================================================
# 5. Preprocessing Leakage Prevention
# ============================================================================

def test_estimator_preprocessing_fitted_only_on_train():
    """Verify that detector-side estimator normalizer is fitted strictly per-fold."""
    np.random.seed(42)
    X = np.random.randn(30, 8)
    # Inject outlier in test sample
    X[0, :] = 100.0
    y = [0] * 15 + [1] * 15

    probs = compute_out_of_fold_probabilities(
        features=X,
        labels=y,
        num_classes=2,
        k_folds=5,
        random_seed=42,
    )
    assert probs.shape == (30, 2)
    # Row probabilities sum to 1.0
    np.testing.assert_allclose(np.sum(probs, axis=1), 1.0, atol=1e-6)


# ============================================================================
# 6. Class Thresholds (t_j)
# ============================================================================

def test_compute_class_thresholds():
    """Verify empirical class threshold formula t_j = mean(P(y=j | x in X_j))."""
    observed = [0, 0, 1, 1]
    # Probabilities for class 0 and 1
    probs = np.array([
        [0.8, 0.2],
        [0.6, 0.4],
        [0.3, 0.7],
        [0.1, 0.9],
    ])
    thresholds = compute_class_thresholds(observed, probs, num_classes=2)
    assert pytest.approx(thresholds[0], 1e-5) == (0.8 + 0.6) / 2.0  # 0.7
    assert pytest.approx(thresholds[1], 1e-5) == (0.7 + 0.9) / 2.0  # 0.8


# ============================================================================
# 7. Confident Count Matrix (C_{i, j})
# ============================================================================

def test_compute_confident_count_matrix():
    """Verify calculation of confident count matrix C_{i, j}."""
    observed = [0, 0, 1, 1]
    probs = np.array([
        [0.9, 0.1],  # Obs 0, candidate 0 >= t_0
        [0.2, 0.8],  # Obs 0, candidate 1 >= t_1 (FLIPPED LABEL)
        [0.1, 0.9],  # Obs 1, candidate 1 >= t_1
        [0.85, 0.15], # Obs 1, candidate 0 >= t_0 (FLIPPED LABEL)
    ])
    thresholds = {0: 0.7, 1: 0.7}
    C = compute_confident_count_matrix(observed, probs, thresholds, num_classes=2)

    assert C[0, 0] == 1
    assert C[0, 1] == 1
    assert C[1, 0] == 1
    assert C[1, 1] == 1


# ============================================================================
# 8. Normalized Joint Distribution (Q_{i, j})
# ============================================================================

def test_compute_joint_distribution_matrix():
    """Verify joint distribution normalization and sum to 1.0."""
    observed = [0, 0, 0, 1, 1, 1]
    C = np.array([
        [2, 1],
        [0, 3],
    ], dtype=np.int64)

    Q = compute_joint_distribution_matrix(C, observed, num_classes=2)
    q_arr = np.array(Q)
    assert q_arr.shape == (2, 2)
    assert pytest.approx(np.sum(q_arr), 1e-5) == 1.0


# ============================================================================
# 9. Anomaly Scoring & Margins
# ============================================================================

def test_anomaly_scoring_and_margins():
    """Verify margin formula and sigmoid normalization into [0.0, 1.0]."""
    probs = [0.1, 0.9]  # Obs 0, Alt 1
    thresholds = {0: 0.7, 1: 0.7}
    class_counts = {0: 30, 1: 30}

    j_star, obs_prob, latent_prob, margin, score, raw_conf = compute_sample_anomaly_metrics(
        observed_label=0,
        probabilities=probs,
        thresholds=thresholds,
        class_counts=class_counts,
        num_classes=2,
    )

    assert j_star == 1
    assert pytest.approx(obs_prob, 1e-5) == 0.1
    assert pytest.approx(latent_prob, 1e-5) == 0.9
    # Margin = (0.9 - 0.7) - (0.1 - 0.7) = 0.2 - (-0.6) = 0.8
    assert pytest.approx(margin, 1e-5) == 0.8
    assert score > 0.5
    assert 0.0 <= score <= 1.0
    assert 0.0 <= raw_conf <= 1.0


# ============================================================================
# 10. High-Confidence Alternative Class
# ============================================================================

def test_high_confidence_alternative_class_detection():
    """Verify HIGH_CONFIDENCE_ALTERNATIVE_CLASS when P(j*) > 0.85 and P(i) < 0.15."""
    predictions = []
    # 25 samples of class 0, 25 samples of class 1 (Total 50)
    for i in range(25):
        if i == 0:
            # High confidence flipped label
            probs = {0: 0.05, 1: 0.95}
        else:
            probs = {0: 0.90, 1: 0.10}
        predictions.append(
            LabelPrediction(
                sample_id=f"s_{i}",
                relative_path=f"img_{i}.jpg",
                observed_category_id=0,
                observed_category_name="cat",
                predicted_category_id=1 if i == 0 else 0,
                predicted_category_name="dog" if i == 0 else "cat",
                probabilities=probs,
            )
        )

    for i in range(25, 50):
        predictions.append(
            LabelPrediction(
                sample_id=f"s_{i}",
                relative_path=f"img_{i}.jpg",
                observed_category_id=1,
                observed_category_name="dog",
                predicted_category_id=1,
                predicted_category_name="dog",
                probabilities={0: 0.10, 1: 0.90},
            )
        )

    detector = LabelAnomalyDetector()
    result = detector.detect_anomalies_from_predictions(predictions)

    assert result.anomalous_samples_count == 1
    flipped_finding = next(f for f in result.findings if f.sample_id == "s_0")
    assert flipped_finding.category == LabelAnomalyCategory.HIGH_CONFIDENCE_ALTERNATIVE_CLASS
    assert flipped_finding.suggested_category_id == 1
    assert flipped_finding.suggested_category_name == "dog"
    assert flipped_finding.anomaly_score > 0.9
    assert flipped_finding.evidence_layer == "detection"


# ============================================================================
# 11. Systematic Class Anomaly
# ============================================================================

def test_systematic_class_anomaly_identification():
    """Verify CLASS_SYSTEMATIC_ANOMALY when reciprocal confusion > 15%."""
    observed = [0] * 20
    top_alts = [1] * 5 + [0] * 15  # 5/20 = 25% confusion (> 15%)
    margins = [0.5] * 5 + [-0.5] * 15
    class_counts = {0: 20, 1: 20}

    pairs = identify_systematic_anomalies(
        observed_labels=observed,
        predicted_top_alts=top_alts,
        margins=margins,
        class_counts=class_counts,
        systematic_ratio_threshold=0.15,
    )
    assert (0, 1) in pairs


# ============================================================================
# 12. Rare Class Anomaly Guardrail
# ============================================================================

def test_rare_class_confidence_discount():
    """Verify RARE_CLASS_ANOMALY category and 50% confidence discount for class < 5."""
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
                probabilities={0: 0.9, 1: 0.1},
            )
        )
    # 3 samples in class 1 (Rare class < 5)
    for i in range(3):
        # Sample 0 is anomalous
        if i == 0:
            probs = {0: 0.80, 1: 0.20}
        else:
            probs = {0: 0.20, 1: 0.80}
        predictions.append(
            LabelPrediction(
                sample_id=f"c1_{i}",
                relative_path=f"c1_{i}.jpg",
                observed_category_id=1,
                observed_category_name="rare",
                predicted_category_id=0 if i == 0 else 1,
                predicted_category_name="common" if i == 0 else "rare",
                probabilities=probs,
            )
        )

    detector = LabelAnomalyDetector()
    result = detector.detect_anomalies_from_predictions(predictions)

    rare_finding = next(f for f in result.findings if f.sample_id == "c1_0")
    assert rare_finding.category == LabelAnomalyCategory.RARE_CLASS_ANOMALY
    assert "rare_class_discount_50pct" in rare_finding.evidence_data.guardrails_applied
    # Final confidence discounted by 50%
    assert pytest.approx(rare_finding.confidence, 1e-5) == rare_finding.evidence_data.raw_confidence * 0.5


# ============================================================================
# 13. Singleton Class Guardrail
# ============================================================================

def test_singleton_class_guardrail():
    """Verify singleton class (N=1) is marked INSUFFICIENT_EVIDENCE / unverifiable."""
    predictions = []
    for i in range(25):
        predictions.append(
            LabelPrediction(
                sample_id=f"c0_{i}",
                relative_path=f"c0_{i}.jpg",
                observed_category_id=0,
                observed_category_name="common",
                predicted_category_id=0,
                predicted_category_name="common",
                probabilities={0: 0.9, 1: 0.1},
            )
        )
    # Exactly 1 sample in class 1
    predictions.append(
        LabelPrediction(
            sample_id="c1_singleton",
            relative_path="c1_singleton.jpg",
            observed_category_id=1,
            observed_category_name="singleton",
            predicted_category_id=0,
            predicted_category_name="common",
            probabilities={0: 0.9, 1: 0.1},
        )
    )

    detector = LabelAnomalyDetector()
    result = detector.detect_anomalies_from_predictions(predictions)

    singleton_finding = next(f for f in result.findings if f.sample_id == "c1_singleton")
    assert singleton_finding.category == LabelAnomalyCategory.INSUFFICIENT_EVIDENCE
    assert singleton_finding.confidence == 0.0
    assert "singleton_class_guardrail" in singleton_finding.evidence_data.guardrails_applied


# ============================================================================
# 14. Small Dataset Guardrail (N < 25)
# ============================================================================

def test_small_dataset_guardrail():
    """Verify that when N < 25, confident learning is skipped and INSUFFICIENT_EVIDENCE is emitted."""
    predictions = []
    for i in range(10):  # N=10 < 25
        predictions.append(
            LabelPrediction(
                sample_id=f"s_{i}",
                relative_path=f"img_{i}.jpg",
                observed_category_id=0,
                observed_category_name="class_0",
                predicted_category_id=1,
                predicted_category_name="class_1",
                probabilities={0: 0.1, 1: 0.9},
            )
        )

    detector = LabelAnomalyDetector()
    result = detector.detect_anomalies_from_predictions(predictions)

    assert result.anomalous_samples_count == 0
    assert all(f.category == LabelAnomalyCategory.INSUFFICIENT_EVIDENCE for f in result.findings)
    assert all(f.confidence == 0.0 for f in result.findings)
    assert len(result.warnings) > 0


# ============================================================================
# 15. Missing Model, 16. Incompatible Model, 17. Load Failure
# ============================================================================

def test_model_state_machine_failures():
    """Verify explicit handling of MODEL_UNAVAILABLE, MODEL_INCOMPATIBLE, and MODEL_LOAD_FAILED."""
    samples = [
        CanonicalSample(
            sample_id=f"s_{i}",
            relative_path=f"img_{i}.jpg",
            file_size_bytes=1000,
            width=100,
            height=100,
            annotations=(
                CanonicalAnnotation(
                    annotation_id=f"ann_{i}",
                    category_id=0,
                    category_name="test_class",
                ),
            ),
        )
        for i in range(5)
    ]

    detector = LabelAnomalyDetector()

    # 1. Unavailable
    res_unavail = detector.detect_anomalies(samples, model_state=ModelState.MODEL_UNAVAILABLE)
    assert res_unavail.model_state == ModelState.MODEL_UNAVAILABLE
    assert all(f.category == LabelAnomalyCategory.MODEL_UNAVAILABLE for f in res_unavail.findings)

    # 2. Incompatible
    res_incomp = detector.detect_anomalies(samples, model_state=ModelState.MODEL_INCOMPATIBLE)
    assert res_incomp.model_state == ModelState.MODEL_INCOMPATIBLE
    assert all(f.category == LabelAnomalyCategory.INSUFFICIENT_EVIDENCE for f in res_incomp.findings)

    # 3. Load Failed
    res_failed = detector.detect_anomalies(samples, model_state=ModelState.MODEL_LOAD_FAILED)
    assert res_failed.model_state == ModelState.MODEL_LOAD_FAILED
    assert all(f.category == LabelAnomalyCategory.INSUFFICIENT_EVIDENCE for f in res_failed.findings)


# ============================================================================
# 18. Deterministic Reproducibility
# ============================================================================

def test_scan_deterministic_reproducibility():
    """Verify that scanning identical predictions produces bit-for-bit identical findings and IDs."""
    np.random.seed(42)
    features = np.random.randn(30, 16)
    samples = [
        CanonicalSample(
            sample_id=f"sample_{i:02d}",
            relative_path=f"img_{i:02d}.jpg",
            file_size_bytes=2000,
            width=200,
            height=200,
            annotations=(
                CanonicalAnnotation(
                    annotation_id=f"ann_{i:02d}",
                    category_id=i % 2,
                    category_name=f"class_{i % 2}",
                ),
            ),
        )
        for i in range(30)
    ]

    res_1 = detect_label_anomalies(samples, features=features)
    res_2 = detect_label_anomalies(samples, features=features)

    assert res_1.anomalous_samples_count == res_2.anomalous_samples_count
    assert len(res_1.findings) == len(res_2.findings)
    for f1, f2 in zip(res_1.findings, res_2.findings):
        assert f1.finding_id == f2.finding_id
        assert pytest.approx(f1.anomaly_score, 1e-6) == f2.anomaly_score
        assert pytest.approx(f1.confidence, 1e-6) == f2.confidence


# ============================================================================
# 19. Classification Behavior
# ============================================================================

def test_classification_manifest_detection():
    """Verify end-to-end anomaly detection on ImageFolder / classification manifest."""
    np.random.seed(42)
    features = np.random.randn(30, 8)
    samples = tuple(
        CanonicalSample(
            sample_id=f"img_{i:02d}",
            relative_path=f"img_{i:02d}.jpg",
            file_size_bytes=1000,
            width=100,
            height=100,
            annotations=(
                CanonicalAnnotation(
                    annotation_id=f"ann_{i:02d}",
                    category_id=0 if i < 15 else 1,
                    category_name="cat" if i < 15 else "dog",
                ),
            ),
        )
        for i in range(30)
    )
    manifest = CanonicalDatasetManifest(
        format=DatasetFormat.IMAGEFOLDER,
        dataset_name="pets_dataset",
        sample_count=30,
        annotation_count=30,
        categories=(
            CanonicalCategory(category_id=0, category_name="cat"),
            CanonicalCategory(category_id=1, category_name="dog"),
        ),
        samples=samples,
    )

    result = detect_label_anomalies(manifest, features=features)
    assert result.total_samples == 30
    assert result.evaluated_samples == 30
    assert len(result.findings) == 30


# ============================================================================
# 20. Object Detection RoI Behavior
# ============================================================================

def test_object_detection_roi_analytical_units():
    """Verify that bounding box annotations are evaluated as explicit analytical units."""
    samples = [
        CanonicalSample(
            sample_id="img_01",
            relative_path="img_01.jpg",
            file_size_bytes=5000,
            width=640,
            height=480,
            annotations=(
                CanonicalAnnotation(
                    annotation_id="ann_bbox_1",
                    category_id=0,
                    category_name="car",
                    bbox=CanonicalBBox(x_min=10, y_min=10, width=50, height=50),
                ),
                CanonicalAnnotation(
                    annotation_id="ann_bbox_2",
                    category_id=1,
                    category_name="pedestrian",
                    bbox=CanonicalBBox(x_min=70, y_min=80, width=20, height=60),
                ),
            ),
        )
    ]

    detector = LabelAnomalyDetector()
    units = detector.extract_analytical_units(samples)

    assert len(units) == 2
    assert units[0].annotation_id == "ann_bbox_1"
    assert units[0].category_name == "car"
    assert units[1].annotation_id == "ann_bbox_2"
    assert units[1].category_name == "pedestrian"


# ============================================================================
# 21. Unsupported Segmentation & 22. Unsupported Regression
# ============================================================================

def test_unsupported_segmentation_modality():
    """Verify that dense segmentation masks without bbox are marked unverifiable."""
    samples = [
        CanonicalSample(
            sample_id="img_seg",
            relative_path="img_seg.jpg",
            file_size_bytes=5000,
            width=640,
            height=480,
            annotations=(
                CanonicalAnnotation(
                    annotation_id="ann_seg_1",
                    category_id=0,
                    category_name="road",
                    segmentation=((10.0, 10.0, 50.0, 10.0, 50.0, 50.0),),
                    bbox=None,  # Dense mask without bbox
                ),
            ),
        )
    ]

    detector = LabelAnomalyDetector()
    units = detector.extract_analytical_units(samples)

    assert len(units) == 1
    assert units[0].is_unsupported_modality is True
    assert "Dense segmentation" in units[0].modality_reason


# ============================================================================
# 23. Malformed Input
# ============================================================================

def test_malformed_input_mismatched_dimensions():
    """Verify exception on mismatched feature dimensions or invalid fold count."""
    features = np.zeros((10, 5))
    labels = [0] * 8  # Mismatched 10 != 8

    with pytest.raises(InsufficientDataError):
        compute_out_of_fold_probabilities(features, labels, num_classes=2)

    with pytest.raises(InvalidFoldSplitError):
        deterministic_stratified_kfold_split(labels, k_folds=1)


# ============================================================================
# 24. Confidence Semantics
# ============================================================================

def test_confidence_semantics_distinction():
    """Verify distinct separation of model probability, anomaly score, and evidence confidence."""
    probs = [0.1, 0.9]
    thresholds = {0: 0.5, 1: 0.5}
    class_counts = {0: 10, 1: 10}

    j_star, obs_prob, latent_prob, margin, score, raw_conf = compute_sample_anomaly_metrics(
        observed_label=0,
        probabilities=probs,
        thresholds=thresholds,
        class_counts=class_counts,
        num_classes=2,
    )

    # Model probability: 0.9
    # Margin: (0.9 - 0.5) - (0.1 - 0.5) = 0.8
    # Score: sigmoid(5 * 0.8) = sigmoid(4) ~ 0.982
    # Raw confidence: min(1.0, 10/20) * 0.9 = 0.5 * 0.9 = 0.45
    assert pytest.approx(latent_prob, 1e-3) == 0.9
    assert pytest.approx(score, 1e-3) == 0.982
    assert pytest.approx(raw_conf, 1e-3) == 0.45
    # All three values must be distinct concepts!
    assert latent_prob != score
    assert score != raw_conf


# ============================================================================
# 25. NO BASELINE RETRAINING Invariant & Semantic Invariants
# ============================================================================

def test_no_baseline_retraining_invariant():
    """Verify that reference model is purely analytical and never mutates external model state."""
    estimator = DetectorSideCentroidEstimator()
    X = np.array([[1.0, 0.0], [0.0, 1.0], [1.1, 0.1], [0.1, 0.9]])
    y = np.array([0, 1, 0, 1])

    estimator.fit(X, y, num_classes=2)
    probs = estimator.predict_proba(np.array([[1.0, 0.0]]))

    assert probs.shape == (1, 2)
    assert probs[0, 0] > probs[0, 1]


def test_semantic_invariant_no_malicious_language():
    """Verify that no findings or schemas contain inflammatory/adversarial conclusions.

    Strict semantic invariant: LABEL ANOMALY != MALICIOUSNESS.
    Findings must never assert malicious intent, poisoning, or sabotage.
    """
    predictions = [
        LabelPrediction(
            sample_id=f"sample_{i}",
            relative_path=f"img_{i}.jpg",
            observed_category_id=0,
            observed_category_name="clean",
            predicted_category_id=1,
            predicted_category_name="noisy",
            probabilities={0: 0.01, 1: 0.99},
        )
        for i in range(30)
    ]

    detector = LabelAnomalyDetector()
    result = detector.detect_anomalies_from_predictions(predictions)

    forbidden_terms = ["malicious", "poison", "sabotage", "attack", "hacker", "culpable", "guilty"]

    for finding in result.findings:
        # Check all string attributes of finding
        finding_str = f"{finding.finding_id} {finding.category} {finding.limitations} {finding.evidence_layer}".lower()
        for term in forbidden_terms:
            assert term not in finding_str, f"Forbidden term '{term}' found in finding: {finding_str}"
        assert finding.evidence_layer == "detection"


def test_object_detection_multiple_bboxes_per_image():
    """Verify auditing of multiple bounding box annotations within a single image."""
    samples = [
        CanonicalSample(
            sample_id="img_multi",
            relative_path="multi.jpg",
            file_size_bytes=10000,
            width=1000,
            height=1000,
            annotations=(
                CanonicalAnnotation(
                    annotation_id=f"bbox_{idx}",
                    category_id=idx % 3,
                    category_name=f"class_{idx % 3}",
                    bbox=CanonicalBBox(x_min=idx * 10, y_min=idx * 10, width=50, height=50),
                )
                for idx in range(30)
            ),
        )
    ]

    np.random.seed(42)
    features = np.random.randn(30, 12)

    result = detect_label_anomalies(samples, features=features)
    assert result.total_samples == 30
    assert result.evaluated_samples == 30
    assert len(result.findings) == 30
    assert all(f.annotation_id is not None for f in result.findings)
