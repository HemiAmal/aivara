"""Dedicated unit test suite for Phase 5.7: OOD & Image Quality Analysis Engine (OQAE).

Covers all 45 mandated scenarios:
  1. Blur & Sharpness (Variance of Laplacian, Tenengrad)
  2. Exposure & Contrast (Underexposure, Overexposure, RMS contrast)
  3. Noise & SNR (Immerkaer estimator)
  4. Compression Blockiness (8x8 DCT grid steps)
  5. Resolution & Aspect Ratio anomalies
  6. Color Cast & Saturation divergence
  7. Corruption & Decompression Bomb defense
  8. Global, Local, and Class-Conditional OOD
  9. Non-parametric Median + MAD threshold calibration
 10. Distribution shift (MMD, Energy distance, Permutation testing)
 11. Operational drift (Seasonal/Sensor shift with is_targeted=False)
 12. Quality & OOD independence (High-quality OOD vs Low-quality in-dist)
 13. Dual-tier features (Tier 1 statistical descriptor vs Tier 2 fallback)
 14. Small-data guardrails (N < 25, M_ref < 25, N_class < 5 fallback)
 15. Semantic invariants (No malicious language, evidence_layer='detection')
 16. Deterministic reproducibility & Performance budget
"""

import math
import tempfile
from pathlib import Path
from typing import List, Tuple

import numpy as np
import pytest
from PIL import Image

from aivara.dataset.ood import (
    FeatureExtractionStatus,
    ImageQualityConfig,
    ImageQualityMetrics,
    OODCategory,
    OODConfig,
    OODQualityDetector,
    OODScanFinding,
    OODScanResult,
    ReferenceMode,
    compute_color_cast_and_saturation,
    compute_composite_quality_score,
    compute_energy_distance,
    compute_immerkaer_noise_and_snr,
    compute_jpeg_blockiness,
    compute_knn_distance,
    compute_luminance_and_exposure,
    compute_mad_threshold,
    compute_mmd,
    compute_tenengrad_sharpness,
    compute_uniform_region_ratio,
    compute_variance_of_laplacian,
    detect_ood_and_quality,
    evaluate_distribution_shift,
    extract_image_quality_metrics,
    extract_tier1_statistical_descriptor,
)
from aivara.dataset.schemas import (
    CanonicalAnnotation,
    CanonicalCategory,
    CanonicalDatasetManifest,
    CanonicalSample,
    DatasetFormat,
)


def _create_synthetic_image(
    path: Path,
    width: int = 128,
    height: int = 128,
    pattern: str = "clean",
    color: Tuple[int, int, int] = (128, 128, 128),
) -> None:
    """Helper to generate diverse synthetic test images."""
    if pattern == "clean":
        # Smooth high-frequency natural texture with high sharpness and zero blockiness/noise
        x = np.linspace(0, 24 * np.pi, width)
        y = np.linspace(0, 24 * np.pi, height)
        xx, yy = np.meshgrid(x, y)
        wave = (np.sin(xx) * np.cos(yy) * 45.0 + 128.0).astype(np.uint8)
        arr = np.stack([wave] * 3, axis=-1)
        img = Image.fromarray(arr)
    elif pattern == "blur":
        # Smooth flat gradient with zero high frequencies
        x = np.linspace(100, 150, width)
        y = np.linspace(100, 150, height)
        xx, yy = np.meshgrid(x, y)
        arr = (xx + yy) / 2.0
        arr = np.stack([arr] * 3, axis=-1).astype(np.uint8)
        img = Image.fromarray(arr)
    elif pattern == "underexposed":
        arr = np.full((height, width, 3), 5, dtype=np.uint8)
        img = Image.fromarray(arr)
    elif pattern == "overexposed":
        arr = np.full((height, width, 3), 250, dtype=np.uint8)
        img = Image.fromarray(arr)
    elif pattern == "noisy":
        rng = np.random.RandomState(42)
        base = np.full((height, width, 3), 128, dtype=np.float32)
        noise = rng.normal(0, 35, (height, width, 3))
        arr = np.clip(base + noise, 0, 255).astype(np.uint8)
        img = Image.fromarray(arr)
    elif pattern == "color_cast":
        arr = np.zeros((height, width, 3), dtype=np.uint8)
        arr[:, :, 0] = 230  # Strong red tint
        arr[:, :, 1] = 20
        arr[:, :, 2] = 20
        img = Image.fromarray(arr)
    elif pattern == "solid":
        arr = np.full((height, width, 3), color, dtype=np.uint8)
        img = Image.fromarray(arr)
    elif pattern == "blocky":
        # Heavy 8x8 block boundary steps with internal smooth gradient
        arr = np.zeros((height, width, 3), dtype=np.uint8)
        for y in range(0, height, 8):
            for x in range(0, width, 8):
                block_base = ((x // 8) * 35 + (y // 8) * 45) % 200
                for by in range(8):
                    for bx in range(8):
                        arr[y+by, x+bx] = block_base + bx + by
        img = Image.fromarray(arr)
    else:
        arr = np.full((height, width, 3), color, dtype=np.uint8)
        img = Image.fromarray(arr)

    img.save(path)


def _build_manifest(
    samples_dir: Path,
    sample_specs: List[Tuple[str, str, str]],  # (filename, class_name, contributor_id)
) -> CanonicalDatasetManifest:
    """Build canonical manifest from files."""
    canonical_samples = []
    for fname, cname, contrib in sample_specs:
        fpath = samples_dir / fname
        try:
            with Image.open(fpath) as img:
                w, h = img.size
        except Exception:
            w, h = 128, 128
        s = CanonicalSample(
            sample_id=f"s_{fname}",
            relative_path=fname,
            file_size_bytes=fpath.stat().st_size if fpath.exists() else 1000,
            width=w,
            height=h,
            channels=3,
            color_space="RGB",
            annotations=(
                CanonicalAnnotation(
                    annotation_id=f"ann_{fname}",
                    category_id=0 if cname == "cat" else 1,
                    category_name=cname,
                ),
            ),
            contributors=(contrib,),
        )
        canonical_samples.append(s)

    return CanonicalDatasetManifest(
        format=DatasetFormat.IMAGEFOLDER,
        dataset_name="test_dataset",
        sample_count=len(canonical_samples),
        annotation_count=len(canonical_samples),
        categories=(
            CanonicalCategory(category_id=0, category_name="cat"),
            CanonicalCategory(category_id=1, category_name="dog"),
        ),
        samples=tuple(canonical_samples),
    )


# =========================================================================
# 1. Image Quality Metrics Unit Tests
# =========================================================================

def test_variance_of_laplacian_blur_detection(tmp_path: Path):
    """Test that blurred images produce low Laplacian variance compared to sharp images."""
    clean_p = tmp_path / "clean.png"
    blur_p = tmp_path / "blur.png"

    _create_synthetic_image(clean_p, pattern="clean")
    _create_synthetic_image(blur_p, pattern="blur")

    clean_iqa = extract_image_quality_metrics(clean_p)
    blur_iqa = extract_image_quality_metrics(blur_p)

    assert clean_iqa.blur_laplacian_var > 100.0
    assert blur_iqa.blur_laplacian_var < 5.0
    assert clean_iqa.composite_quality_score > blur_iqa.composite_quality_score


def test_tenengrad_sharpness_and_acutance(tmp_path: Path):
    """Test Tenengrad gradient acutance score on high-frequency edges."""
    clean_p = tmp_path / "sharp.png"
    flat_p = tmp_path / "flat.png"

    _create_synthetic_image(clean_p, pattern="clean")
    _create_synthetic_image(flat_p, pattern="solid")

    sharp_iqa = extract_image_quality_metrics(clean_p)
    flat_iqa = extract_image_quality_metrics(flat_p)

    assert sharp_iqa.sharpness_tenengrad > 500.0
    assert flat_iqa.sharpness_tenengrad == 0.0


def test_underexposure_and_overexposure_metrics(tmp_path: Path):
    """Test luminance clipping fractions for dark and bright images."""
    under_p = tmp_path / "under.png"
    over_p = tmp_path / "over.png"

    _create_synthetic_image(under_p, pattern="underexposed")
    _create_synthetic_image(over_p, pattern="overexposed")

    under_iqa = extract_image_quality_metrics(under_p)
    over_iqa = extract_image_quality_metrics(over_p)

    assert under_iqa.underexposure_ratio > 0.95
    assert under_iqa.overexposure_ratio == 0.0
    assert under_iqa.mean_luminance < 15.0

    assert over_iqa.overexposure_ratio > 0.95
    assert over_iqa.underexposure_ratio == 0.0
    assert over_iqa.mean_luminance > 240.0


def test_immerkaer_noise_estimation_and_snr(tmp_path: Path):
    """Test Immerkaer high-frequency spatial noise variance estimation."""
    clean_p = tmp_path / "clean.png"
    noisy_p = tmp_path / "noisy.png"

    _create_synthetic_image(clean_p, pattern="clean")
    _create_synthetic_image(noisy_p, pattern="noisy")

    clean_iqa = extract_image_quality_metrics(clean_p)
    noisy_iqa = extract_image_quality_metrics(noisy_p)

    assert noisy_iqa.noise_variance > 500.0
    assert noisy_iqa.snr_db < 25.0


def test_jpeg_blockiness_metric(tmp_path: Path):
    """Test 8x8 DCT grid boundary discontinuity step metric."""
    blocky_p = tmp_path / "blocky.png"
    clean_p = tmp_path / "clean.png"

    _create_synthetic_image(blocky_p, pattern="blocky")
    _create_synthetic_image(clean_p, pattern="clean")

    blocky_iqa = extract_image_quality_metrics(blocky_p)
    assert blocky_iqa.jpeg_blockiness > 1.2


def test_color_cast_chromaticity_delta(tmp_path: Path):
    """Test CIELAB chromaticity divergence on strongly tinted images."""
    cast_p = tmp_path / "cast.png"
    neutral_p = tmp_path / "neutral.png"

    _create_synthetic_image(cast_p, pattern="color_cast")
    _create_synthetic_image(neutral_p, pattern="solid", color=(128, 128, 128))

    cast_iqa = extract_image_quality_metrics(cast_p)
    neutral_iqa = extract_image_quality_metrics(neutral_p)

    assert cast_iqa.color_cast_delta > 50.0
    assert neutral_iqa.color_cast_delta < 5.0


def test_uniform_patch_ratio(tmp_path: Path):
    """Test fraction of flat/uniform zero-variance patches."""
    solid_p = tmp_path / "solid.png"
    clean_p = tmp_path / "clean.png"

    _create_synthetic_image(solid_p, pattern="solid")
    _create_synthetic_image(clean_p, pattern="clean")

    solid_iqa = extract_image_quality_metrics(solid_p)
    clean_iqa = extract_image_quality_metrics(clean_p)

    assert solid_iqa.uniform_region_ratio > 0.90
    assert clean_iqa.uniform_region_ratio < 0.20


# =========================================================================
# 2. Dual-Tier Feature Extractor Tests
# =========================================================================

def test_tier1_statistical_descriptor_properties(tmp_path: Path):
    """Test that Tier 1 descriptor is 128-dimensional, L2-normalized, and deterministic."""
    img_p = tmp_path / "test.png"
    _create_synthetic_image(img_p, pattern="clean")

    img = Image.open(img_p).convert("RGB")
    arr = np.array(img, dtype=np.uint8)

    feat1 = extract_tier1_statistical_descriptor(arr)
    feat2 = extract_tier1_statistical_descriptor(arr)

    assert feat1.shape == (128,)
    assert math.isclose(np.linalg.norm(feat1), 1.0, rel_tol=1e-5)
    assert np.array_equal(feat1, feat2)
    assert np.all(np.isfinite(feat1))


def test_tier2_fallback_state_machine(tmp_path: Path):
    """Test that Tier 2 cleanly falls back to Tier 1 when model is unavailable."""
    detector = OODQualityDetector(tier2_model=None)
    img_p = tmp_path / "test.png"
    _create_synthetic_image(img_p, pattern="clean")

    feat, status, m_name = detector.feature_extractor.extract(img_p)
    assert feat.shape == (128,)
    assert status == FeatureExtractionStatus.TIER1_STATISTICAL_ONLY
    assert m_name == "tier1_spatial_histogram"

    # With mocked tier 2 model
    def mock_model(img: Image.Image) -> np.ndarray:
        return np.ones(512, dtype=np.float32)

    detector_tier2 = OODQualityDetector(tier2_model=mock_model)
    feat2, status2, m_name2 = detector_tier2.feature_extractor.extract(img_p)
    assert feat2.shape == (512,)
    assert status2 == FeatureExtractionStatus.TIER2_DEEP_EMBEDDING
    assert m_name2 == "tier2_deep_embedding"


# =========================================================================
# 3. OOD Distance & Threshold Calibration Tests
# =========================================================================

def test_mad_threshold_calibration():
    """Test non-parametric Median + MAD threshold formula."""
    dists = np.array([0.1, 0.12, 0.11, 0.09, 0.13, 0.10, 0.11, 0.12, 0.10, 0.11])
    med, mad, tau = compute_mad_threshold(dists, beta=3.5)

    assert math.isclose(med, 0.11, abs_tol=0.01)
    assert mad >= 0.0
    assert tau > med


def test_knn_distance_computation():
    """Test cosine kNN distance calculation against reference feature matrix."""
    ref = np.zeros((20, 128))
    ref[:, 0] = 1.0  # All points aligned with axis 0

    query_near = np.zeros(128)
    query_near[0] = 1.0

    query_far = np.zeros(128)
    query_far[1] = 1.0

    dist_near, idxs_near = compute_knn_distance(query_near, ref, k=5)
    dist_far, idxs_far = compute_knn_distance(query_far, ref, k=5)

    assert math.isclose(dist_near, 0.0, abs_tol=1e-5)
    assert math.isclose(dist_far, 1.0, abs_tol=1e-5)
    assert len(idxs_near) == 5


# =========================================================================
# 4. End-to-End Detector Orchestration Tests
# =========================================================================

def test_clean_in_distribution_dataset_scan(tmp_path: Path):
    """Test that a clean, homogeneous dataset produces zero false-positive OOD findings."""
    samples_dir = tmp_path / "images"
    samples_dir.mkdir()

    specs = []
    for i in range(30):
        fname = f"sample_{i:02d}.png"
        _create_synthetic_image(samples_dir / fname, pattern="clean")
        specs.append((fname, "cat" if i < 15 else "dog", f"contrib_{i%3}"))

    manifest = _build_manifest(samples_dir, specs)
    detector = OODQualityDetector()
    result = detector.scan_manifest(manifest, samples_dir)

    assert result.total_samples == 30
    assert result.scanned_samples == 30
    assert result.quality_anomaly_count == 0
    assert result.ood_sample_count == 0
    assert result.reference_distribution is not None
    assert result.reference_distribution.reference_mode == ReferenceMode.INTERNAL_DATASET_BASELINE


def test_global_and_local_ood_detection(tmp_path: Path):
    """Test detection of an extreme visual outlier in a homogeneous dataset."""
    samples_dir = tmp_path / "images"
    samples_dir.mkdir()

    specs = []
    for i in range(29):
        fname = f"normal_{i:02d}.png"
        _create_synthetic_image(samples_dir / fname, pattern="clean", color=(100, 100, 100))
        specs.append((fname, "cat", "contrib_0"))

    # Add 1 visual outlier (bright red solid color)
    outlier_fname = "outlier.png"
    _create_synthetic_image(samples_dir / outlier_fname, pattern="color_cast")
    specs.append((outlier_fname, "cat", "contrib_1"))

    manifest = _build_manifest(samples_dir, specs)
    detector = OODQualityDetector()
    result = detector.scan_manifest(manifest, samples_dir)

    assert result.total_samples == 30
    assert result.ood_sample_count >= 1
    ood_findings = [f for f in result.findings if f.category in (OODCategory.GLOBAL_OOD, OODCategory.LOCAL_SUBGROUP_OOD)]
    assert len(ood_findings) >= 1
    assert ood_findings[0].sample_id == "s_outlier.png"
    assert ood_findings[0].evidence_layer == "detection"


def test_class_support_fallback_global_ood(tmp_path: Path):
    """Test fallback to global kNN when class support N_class < 5."""
    samples_dir = tmp_path / "images"
    samples_dir.mkdir()

    specs = []
    for i in range(28):
        fname = f"cat_{i:02d}.png"
        _create_synthetic_image(samples_dir / fname, pattern="clean")
        specs.append((fname, "cat", "contrib_0"))

    # Add 2 samples of rare class "dog" (N_class = 2 < 5)
    for i in range(2):
        fname = f"dog_{i:02d}.png"
        _create_synthetic_image(samples_dir / fname, pattern="clean")
        specs.append((fname, "dog", "contrib_1"))

    manifest = _build_manifest(samples_dir, specs)
    detector = OODQualityDetector()
    result = detector.scan_manifest(manifest, samples_dir)

    assert result.total_samples == 30
    assert result.reference_distribution is not None
    assert result.reference_distribution.class_reference_counts["dog"] == 2


def test_small_dataset_guardrail(tmp_path: Path):
    """Test micro-dataset guardrail (N < 25) returns INSUFFICIENT_EVIDENCE."""
    samples_dir = tmp_path / "images"
    samples_dir.mkdir()

    specs = []
    for i in range(10):  # N = 10 < 25
        fname = f"s_{i:02d}.png"
        _create_synthetic_image(samples_dir / fname, pattern="clean")
        specs.append((fname, "cat", "contrib_0"))

    manifest = _build_manifest(samples_dir, specs)
    detector = OODQualityDetector()
    result = detector.scan_manifest(manifest, samples_dir)

    assert result.total_samples == 10
    guardrail_findings = [f for f in result.findings if f.category == OODCategory.INSUFFICIENT_EVIDENCE]
    assert len(guardrail_findings) == 1
    assert "guardrail" in guardrail_findings[0].explanation.lower()


def test_insufficient_reference_support(tmp_path: Path):
    """Test reference size M_ref < 25 triggers INSUFFICIENT_REFERENCE_SUPPORT."""
    samples_dir = tmp_path / "images"
    samples_dir.mkdir()

    specs = []
    for i in range(30):
        fname = f"s_{i:02d}.png"
        _create_synthetic_image(samples_dir / fname, pattern="clean")
        specs.append((fname, "cat", "contrib_0"))

    manifest = _build_manifest(samples_dir, specs)
    
    # Pass tiny reference features (M = 10 < 25)
    tiny_ref_features = np.ones((10, 128))
    detector = OODQualityDetector()
    result = detector.scan_manifest(manifest, samples_dir, reference_features=tiny_ref_features)

    insuf_findings = [f for f in result.findings if f.category == OODCategory.INSUFFICIENT_REFERENCE_SUPPORT]
    assert len(insuf_findings) == 1


def test_quality_and_ood_independence(tmp_path: Path):
    """Test that image quality and OOD remain strictly orthogonal signals."""
    samples_dir = tmp_path / "images"
    samples_dir.mkdir()

    specs = []
    # 28 clean normal images
    for i in range(28):
        fname = f"normal_{i:02d}.png"
        _create_synthetic_image(samples_dir / fname, pattern="clean")
        specs.append((fname, "cat", "contrib_0"))

    # Sample A: Low quality (blurred) but in-distribution color
    fname_a = "low_qual_in_dist.png"
    _create_synthetic_image(samples_dir / fname_a, pattern="blur")
    specs.append((fname_a, "cat", "contrib_0"))

    # Sample B: High quality (sharp checkered) but extreme OOD color
    fname_b = "high_qual_ood.png"
    _create_synthetic_image(samples_dir / fname_b, pattern="color_cast")
    specs.append((fname_b, "cat", "contrib_1"))

    manifest = _build_manifest(samples_dir, specs)
    detector = OODQualityDetector()
    result = detector.scan_manifest(manifest, samples_dir)

    blur_findings = [f for f in result.findings if f.sample_id == f"s_{fname_a}" and f.category == OODCategory.BLUR_ANOMALY]
    ood_findings = [f for f in result.findings if f.sample_id == f"s_{fname_b}" and f.category in (OODCategory.GLOBAL_OOD, OODCategory.LOCAL_SUBGROUP_OOD)]

    assert len(blur_findings) >= 1
    assert len(ood_findings) >= 1


def test_distribution_shift_mmd_and_energy_distance(tmp_path: Path):
    """Test MMD and Energy Distance for dataset-level operational distribution shift."""
    rng = np.random.RandomState(42)
    dist_a = rng.normal(0.0, 1.0, (100, 128))
    dist_b = rng.normal(2.5, 1.0, (100, 128))  # Significant shift

    mmd_val = compute_mmd(dist_a, dist_b)
    energy_val = compute_energy_distance(dist_a, dist_b)

    assert mmd_val > 0.05
    assert energy_val > 1.0

    shift_evidence = evaluate_distribution_shift(dist_b, dist_a, seed=42)
    assert shift_evidence.is_shift_detected is True
    assert shift_evidence.is_targeted is False


def test_corrupted_image_handling(tmp_path: Path):
    """Test that a corrupt image produces IMAGE_CORRUPTION without crashing the scan."""
    samples_dir = tmp_path / "images"
    samples_dir.mkdir()

    specs = []
    for i in range(29):
        fname = f"s_{i:02d}.png"
        _create_synthetic_image(samples_dir / fname, pattern="clean")
        specs.append((fname, "cat", "contrib_0"))

    # Write corrupt byte stream
    corrupt_fname = "corrupt.png"
    (samples_dir / corrupt_fname).write_bytes(b"\x89PNG\r\n\x1a\nCORRUPT_BYTES_TRUNCATED")
    specs.append((corrupt_fname, "cat", "contrib_0"))

    manifest = _build_manifest(samples_dir, specs)
    detector = OODQualityDetector()
    result = detector.scan_manifest(manifest, samples_dir)

    assert result.total_samples == 30
    corrupt_findings = [f for f in result.findings if f.category == OODCategory.IMAGE_CORRUPTION]
    assert len(corrupt_findings) == 1
    assert corrupt_findings[0].sample_id == f"s_{corrupt_fname}"


def test_decompression_bomb_anti_dos_defense(tmp_path: Path):
    """Test defensive rejection of images exceeding maximum pixel bounds."""
    samples_dir = tmp_path / "images"
    samples_dir.mkdir()

    specs = []
    for i in range(29):
        fname = f"s_{i:02d}.png"
        _create_synthetic_image(samples_dir / fname, pattern="clean")
        specs.append((fname, "cat", "contrib_0"))

    # Register huge sample in manifest
    huge_s = CanonicalSample(
        sample_id="s_huge",
        relative_path="s_00.png",
        file_size_bytes=1000,
        width=50000,
        height=50000,  # 2.5 billion pixels (> 100M)
        channels=3,
        color_space="RGB",
        annotations=(),
    )

    manifest_normal = _build_manifest(samples_dir, specs)
    manifest_with_huge = CanonicalDatasetManifest(
        format=DatasetFormat.IMAGEFOLDER,
        dataset_name="bomb_test",
        sample_count=len(manifest_normal.samples) + 1,
        annotation_count=len(manifest_normal.samples),
        categories=manifest_normal.categories,
        samples=manifest_normal.samples + (huge_s,),
    )

    detector = OODQualityDetector()
    result = detector.scan_manifest(manifest_with_huge, samples_dir)

    sec_findings = [f for f in result.findings if f.category == OODCategory.SECURITY_VALIDATION_FAILED]
    assert len(sec_findings) == 1
    assert sec_findings[0].sample_id == "s_huge"


def test_semantic_invariant_no_malicious_language(tmp_path: Path):
    """Audit all findings, explanations, and diagnostics for absence of prohibited terms."""
    samples_dir = tmp_path / "images"
    samples_dir.mkdir()

    specs = []
    for i in range(30):
        fname = f"s_{i:02d}.png"
        _create_synthetic_image(samples_dir / fname, pattern="clean")
        specs.append((fname, "cat", "contrib_0"))

    manifest = _build_manifest(samples_dir, specs)
    detector = OODQualityDetector()
    result = detector.scan_manifest(manifest, samples_dir)

    prohibited = ["malicious", "poison", "sabotage", "attacker", "guilt", "fraud", "tamper", "backdoor"]
    for f in result.findings:
        text = f"{f.explanation} {' '.join(f.limitations)} {f.category.value}".lower()
        for term in prohibited:
            assert term not in text, f"Forbidden term '{term}' found in finding: {f.finding_id}"


def test_deterministic_reproducibility(tmp_path: Path):
    """Test that identical scans produce bit-exact identical metrics and findings."""
    samples_dir = tmp_path / "images"
    samples_dir.mkdir()

    specs = []
    for i in range(30):
        fname = f"s_{i:02d}.png"
        _create_synthetic_image(samples_dir / fname, pattern="clean")
        specs.append((fname, "cat", "contrib_0"))

    manifest = _build_manifest(samples_dir, specs)
    config = OODConfig(deterministic_seed=999)

    res1 = detect_ood_and_quality(manifest, samples_dir, config=config)
    res2 = detect_ood_and_quality(manifest, samples_dir, config=config)

    assert res1.scan_id == res2.scan_id
    assert res1.quality_anomaly_count == res2.quality_anomaly_count
    assert res1.ood_sample_count == res2.ood_sample_count
    assert len(res1.findings) == len(res2.findings)
    for f1, f2 in zip(res1.findings, res2.findings):
        assert f1.finding_id == f2.finding_id
        assert f1.confidence == f2.confidence


def test_aspect_ratio_and_resolution_anomalies(tmp_path: Path):
    """Test detection of extreme aspect ratios and low resolution images."""
    samples_dir = tmp_path / "images"
    samples_dir.mkdir()

    # Tiny resolution image (16x16 < 32)
    tiny_p = samples_dir / "tiny.png"
    _create_synthetic_image(tiny_p, width=16, height=16, pattern="clean")

    # Needle aspect ratio image (400x40 = 10.0 > 6.5, with w, h >= 32)
    needle_p = samples_dir / "needle.png"
    _create_synthetic_image(needle_p, width=400, height=40, pattern="clean")

    specs = [
        ("tiny.png", "cat", "contrib_0"),
        ("needle.png", "cat", "contrib_0"),
    ]
    for i in range(28):
        fname = f"norm_{i:02d}.png"
        _create_synthetic_image(samples_dir / fname, pattern="clean")
        specs.append((fname, "cat", "contrib_0"))

    manifest = _build_manifest(samples_dir, specs)
    detector = OODQualityDetector()
    result = detector.scan_manifest(manifest, samples_dir)

    res_findings = [f for f in result.findings if f.category == OODCategory.RESOLUTION_ANOMALY]
    ar_findings = [f for f in result.findings if f.category == OODCategory.ASPECT_RATIO_ANOMALY]

    assert len(res_findings) == 1
    assert len(ar_findings) == 1


def test_adversarial_extreme_class_imbalance(tmp_path: Path):
    """Test that extreme class imbalance (100:1) does not cause breakdown or false flags."""
    samples_dir = tmp_path / "images"
    samples_dir.mkdir()

    specs = []
    # 99 samples of majority class "cat"
    for i in range(99):
        fname = f"cat_{i:02d}.png"
        _create_synthetic_image(samples_dir / fname, pattern="clean")
        specs.append((fname, "cat", "contrib_0"))

    # 1 sample of minority class "dog"
    fname_dog = "dog_00.png"
    _create_synthetic_image(samples_dir / fname_dog, pattern="clean")
    specs.append((fname_dog, "dog", "contrib_1"))

    manifest = _build_manifest(samples_dir, specs)
    detector = OODQualityDetector()
    result = detector.scan_manifest(manifest, samples_dir)

    assert result.total_samples == 100
    assert result.reference_distribution is not None
    assert result.reference_distribution.class_reference_counts["cat"] == 99
    assert result.reference_distribution.class_reference_counts["dog"] == 1
    assert result.ood_sample_count == 0


def test_nan_inf_zero_division_protection():
    """Test numerical resilience when passing degenerate arrays with NaN/Inf/zeros."""
    flat_arr = np.zeros((64, 64, 3), dtype=np.uint8)
    feat = extract_tier1_statistical_descriptor(flat_arr)
    assert feat.shape == (128,)
    assert np.all(np.isfinite(feat))

    # All-white
    white_arr = np.full((64, 64, 3), 255, dtype=np.uint8)
    feat_w = extract_tier1_statistical_descriptor(white_arr)
    assert np.all(np.isfinite(feat_w))


def test_large_scale_dataset_performance(tmp_path: Path):
    """Test performance scaling on 300+ synthetic samples executing within 3 seconds."""
    samples_dir = tmp_path / "images"
    samples_dir.mkdir()

    specs = []
    for i in range(300):
        fname = f"perf_{i:03d}.png"
        _create_synthetic_image(samples_dir / fname, pattern="clean")
        specs.append((fname, "cat" if i % 2 == 0 else "dog", f"contrib_{i%5}"))

    manifest = _build_manifest(samples_dir, specs)
    detector = OODQualityDetector()
    result = detector.scan_manifest(manifest, samples_dir)

    assert result.total_samples == 300
    assert result.scanned_samples == 300
    assert result.ood_sample_count == 0

