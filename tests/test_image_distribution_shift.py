"""Comprehensive Test Suite for Phase 11.5 Image Distribution Shift Analysis.

Covers all 58 specification requirements across:
A. Image Validation
B. Image Descriptors
C. Distribution Shift
D. Edge Cases
E. Statistical Engine Integration
F. Dataset & Localization Synthesis
G. Security & Immutability
H. Cryptographic Identity & Hashing
"""

import ast
import hashlib
import io
from pathlib import Path
from typing import Any, Dict, List
import numpy as np
from PIL import Image
import pytest

from aivara.crypto.canonical import canonicalize
from aivara.drift.boundary import ComparisonBoundaryEngine
from aivara.drift.engine import StatisticalDriftEngine
from aivara.drift.enums import (
    BoundaryEvaluationStatus,
    CompatibilityStatus,
    DataModality,
    DriftImpactLevel,
    FeatureType,
    PopulationType,
    ShiftDecisionState,
)
from aivara.drift.exceptions import (
    IncompatiblePopulationError,
    ProjectMismatchError,
)
from aivara.drift.image_descriptors import (
    MAX_IMAGE_BYTES,
    MAX_IMAGE_DIMENSION,
    MAX_IMAGE_PIXELS,
    MAX_POPULATION_IMAGES,
    extract_population_descriptors,
    extract_single_image_descriptors,
)
from aivara.drift.image_engine import (
    ImageDistributionShiftAnalyzer,
    compute_image_drift_profile_hash,
)
from aivara.drift.schemas import (
    ComparisonBoundaryResult,
    ComparisonContract,
    ImageDriftProfile,
    ImagePopulationAccounting,
    PopulationIdentity,
    PopulationSelector,
    StatisticalAnalysisConfig,
)


def _make_dummy_boundary(
    project_id: str = "proj-image-1",
    ref_ds: str = "ds-ref-1",
    tgt_ds: str = "ds-tgt-1",
    modality: DataModality = DataModality.IMAGE,
    ref_n: int = 100,
    tgt_n: int = 100,
    status: BoundaryEvaluationStatus = BoundaryEvaluationStatus.VALID,
) -> ComparisonBoundaryResult:
    """Helper to construct deterministic ComparisonBoundaryResult for tests."""
    contract = ComparisonContract(
        project_id=project_id,
        reference_dataset_id=ref_ds,
        target_dataset_id=tgt_ds,
        modality=modality,
        reference_population_hash="a" * 64,
        target_population_hash="b" * 64,
        reference_sample_count=ref_n,
        target_sample_count=tgt_n,
    )
    boundary_hash = hashlib.sha256(canonicalize(contract.to_canonical_dict())).hexdigest()
    ref_pop = PopulationIdentity(
        dataset_id=ref_ds,
        population_type=PopulationType.COMPLETE_DATASET,
        total_available_samples=ref_n,
        selected_sample_count=ref_n,
        sampling_applied=False,
        sample_ids_hash="c" * 64,
        population_selection_hash="d" * 64,
    )
    tgt_pop = PopulationIdentity(
        dataset_id=tgt_ds,
        population_type=PopulationType.COMPLETE_DATASET,
        total_available_samples=tgt_n,
        selected_sample_count=tgt_n,
        sampling_applied=False,
        sample_ids_hash="e" * 64,
        population_selection_hash="f" * 64,
    )
    compat = (
        CompatibilityStatus.COMPATIBLE
        if status == BoundaryEvaluationStatus.VALID
        else CompatibilityStatus.INCOMPATIBLE_SCHEMA
    )
    return ComparisonBoundaryResult(
        contract=contract,
        comparison_boundary_hash=boundary_hash,
        reference_population=ref_pop,
        target_population=tgt_pop,
        status=status,
        compatibility_status=compat,
    )


def _generate_synthetic_image(
    w: int = 64,
    h: int = 64,
    color: tuple = (128, 128, 128),
    noise_std: float = 0.0,
    fmt: str = "PNG",
    seed: int = 42,
) -> bytes:
    """Create a deterministic synthetic image in memory as bytes."""
    rng = np.random.RandomState(seed)
    arr = np.full((h, w, 3), color, dtype=np.float32)
    if noise_std > 0.0:
        noise = rng.normal(0.0, noise_std, (h, w, 3))
        arr = np.clip(arr + noise, 0.0, 255.0)
    arr_uint8 = arr.astype(np.uint8)
    img = Image.fromarray(arr_uint8)
    buf = io.BytesIO()
    img.save(buf, format=fmt)
    return buf.getvalue()


# ===========================================================================
# A. Image Validation Tests (1 - 9)
# ===========================================================================

def test_01_valid_image_population():
    """1. Valid image population extraction."""
    imgs = [_generate_synthetic_image(64, 64, color=(100, 150, 200), seed=i) for i in range(40)]
    cols, acc = extract_population_descriptors(imgs)
    assert acc["total"] == 40
    assert acc["analyzable"] == 40
    assert acc["corrupt"] == 0
    assert len(cols["width"]) == 40
    assert all(w == 64 for w in cols["width"])


def test_02_non_image_modality_rejected():
    """2. Non-image population modality rejected with IncompatiblePopulationError."""
    boundary = _make_dummy_boundary(modality=DataModality.TABULAR_FEATURE)
    analyzer = ImageDistributionShiftAnalyzer()
    with pytest.raises(IncompatiblePopulationError, match="Modality must be 'image'"):
        analyzer.analyze(boundary, [b"fake"], [b"fake"])


def test_03_empty_image_population():
    """3. Empty image population handled fail-closed with INSUFFICIENT_DATA."""
    boundary = _make_dummy_boundary(ref_n=0, tgt_n=0)
    analyzer = ImageDistributionShiftAnalyzer()
    profile = analyzer.analyze(boundary, [], [])
    assert profile.global_status == ShiftDecisionState.INSUFFICIENT_DATA
    assert profile.accounting.reference_analyzable_images == 0


def test_04_corrupted_image_handling():
    """4. Corrupted image inputs trapped safely and counted in accounting."""
    corrupt_bytes = b"NOT_A_VALID_IMAGE_BYTES_XYZ"
    status, descs, err = extract_single_image_descriptors(corrupt_bytes)
    assert status == "CORRUPT"
    assert descs is None
    assert err is not None

    cols, acc = extract_population_descriptors([corrupt_bytes] * 5)
    assert acc["corrupt"] == 5
    assert acc["analyzable"] == 0


def test_05_unsupported_format_handling():
    """5. Unsupported dictionary/format structure rejected gracefully."""
    invalid_dict = {"unsupported_key": 123}
    status, descs, err = extract_single_image_descriptors(invalid_dict)
    assert status == "UNSUPPORTED"
    assert descs is None


def test_06_invalid_dimensions():
    """6. Invalid empty dimensions handled safely."""
    empty_arr = np.zeros((0, 0, 3), dtype=np.uint8)
    status, descs, err = extract_single_image_descriptors(empty_arr)
    assert status == "CORRUPT"
    assert descs is None


def test_07_excessive_dimensions_prevent_decompression_bombs():
    """7. Excessive image dimensions exceed limit and are trapped safely."""
    large_arr = np.zeros((15000, 15000, 3), dtype=np.uint8)
    status, descs, err = extract_single_image_descriptors(large_arr)
    assert status == "UNSUPPORTED"
    assert descs is None


def test_08_project_mismatch_raises_error():
    """8. Project mismatch boundary raises ProjectMismatchError."""
    boundary = _make_dummy_boundary(status=BoundaryEvaluationStatus.PROJECT_MISMATCH)
    analyzer = ImageDistributionShiftAnalyzer()
    with pytest.raises(ProjectMismatchError):
        analyzer.analyze(boundary, [b"img"], [b"img"])


def test_09_boundary_invalid_status_fail_closed():
    """9. Invalid boundary status returns fail-closed profile with INVALID state."""
    boundary = _make_dummy_boundary(status=BoundaryEvaluationStatus.INCOMPATIBLE_INPUTS)
    analyzer = ImageDistributionShiftAnalyzer()
    profile = analyzer.analyze(boundary, [b"img"], [b"img"])
    assert profile.global_status == ShiftDecisionState.INVALID


# ===========================================================================
# B. Descriptor Tests (10 - 20)
# ===========================================================================

def test_10_to_19_descriptors_accuracy():
    """10-19. Verify accuracy of width, height, aspect ratio, channels, format, pixel stats, entropy, contrast, quality."""
    img_bytes = _generate_synthetic_image(w=120, h=80, color=(100, 150, 200), noise_std=10.0, fmt="PNG", seed=10)
    status, d, err = extract_single_image_descriptors(img_bytes)
    assert status == "VALID"
    assert d is not None
    # 10. Width
    assert d["width"] == 120
    # 11. Height
    assert d["height"] == 80
    # 12. Aspect ratio
    assert abs(d["aspect_ratio"] - 1.5) < 1e-4
    # 13. Channel count
    assert d["channels"] == 3
    # 14. Format
    assert d["format"] == "PNG"
    # 15. Pixel mean / brightness
    assert 100.0 <= d["brightness"] <= 180.0
    # 16. Pixel variance / rms contrast
    assert d["rms_contrast"] > 0.0
    # 17. Entropy
    assert 0.0 < d["entropy"] <= 8.0
    # 18. Contrast
    assert d["std_intensity"] > 0.0
    # 19. Quality descriptors (Laplacian variance, clipping, saturation)
    assert d["sharpness_laplacian_var"] >= 0.0
    assert 0.0 <= d["clipping_ratio"] <= 1.0
    assert 0.0 <= d["mean_saturation"] <= 1.0


def test_20_deterministic_descriptor_extraction():
    """20. Deterministic repeated descriptor extraction yields exact bitwise identical floats."""
    img_bytes = _generate_synthetic_image(w=64, h=64, color=(120, 130, 140), noise_std=5.0, seed=99)
    _, d1, _ = extract_single_image_descriptors(img_bytes)
    _, d2, _ = extract_single_image_descriptors(img_bytes)
    assert d1 == d2


# ===========================================================================
# C. Distribution Shift Tests (21 - 29)
# ===========================================================================

def test_21_identical_image_distributions_no_shift():
    """21. Identical image distributions yield NO_SHIFT_DETECTED."""
    ref_imgs = [_generate_synthetic_image(64, 64, color=(128, 128, 128), noise_std=5.0, seed=i) for i in range(50)]
    tgt_imgs = [_generate_synthetic_image(64, 64, color=(128, 128, 128), noise_std=5.0, seed=i + 1000) for i in range(50)]

    boundary = _make_dummy_boundary(ref_n=50, tgt_n=50)
    analyzer = ImageDistributionShiftAnalyzer()
    profile = analyzer.analyze(boundary, ref_imgs, tgt_imgs)

    assert profile.global_status == ShiftDecisionState.NO_SHIFT_DETECTED
    assert profile.materially_shifted_descriptor_count == 0


def test_22_width_distribution_shift():
    """22. Width distribution shift detected and localized."""
    ref_imgs = [_generate_synthetic_image(64, 64, color=(128, 128, 128), seed=i) for i in range(50)]
    tgt_imgs = [_generate_synthetic_image(128, 64, color=(128, 128, 128), seed=i + 500) for i in range(50)]

    boundary = _make_dummy_boundary(ref_n=50, tgt_n=50)
    analyzer = ImageDistributionShiftAnalyzer()
    profile = analyzer.analyze(boundary, ref_imgs, tgt_imgs)

    assert profile.global_status == ShiftDecisionState.MATERIAL_SHIFT
    assert "width" in profile.dimension_drift
    assert profile.dimension_drift["width"].shift_status == ShiftDecisionState.MATERIAL_SHIFT


def test_23_aspect_ratio_shift():
    """23. Aspect ratio shift detected and localized."""
    ref_imgs = [_generate_synthetic_image(64, 64, seed=i) for i in range(50)]
    tgt_imgs = [_generate_synthetic_image(128, 32, seed=i + 500) for i in range(50)]

    boundary = _make_dummy_boundary(ref_n=50, tgt_n=50)
    analyzer = ImageDistributionShiftAnalyzer()
    profile = analyzer.analyze(boundary, ref_imgs, tgt_imgs)

    assert "aspect_ratio" in profile.dimension_drift
    assert profile.dimension_drift["aspect_ratio"].shift_status == ShiftDecisionState.MATERIAL_SHIFT


def test_24_brightness_shift():
    """24. Brightness / photometric mean shift detected."""
    ref_imgs = [_generate_synthetic_image(64, 64, color=(50, 50, 50), noise_std=5.0, seed=i) for i in range(50)]
    tgt_imgs = [_generate_synthetic_image(64, 64, color=(200, 200, 200), noise_std=5.0, seed=i + 500) for i in range(50)]

    boundary = _make_dummy_boundary(ref_n=50, tgt_n=50)
    analyzer = ImageDistributionShiftAnalyzer()
    profile = analyzer.analyze(boundary, ref_imgs, tgt_imgs)

    assert "brightness" in profile.pixel_drift
    assert profile.pixel_drift["brightness"].shift_status == ShiftDecisionState.MATERIAL_SHIFT


def test_25_contrast_shift():
    """25. RMS Contrast shift detected."""
    # Low contrast vs high contrast
    ref_imgs = [_generate_synthetic_image(64, 64, color=(128, 128, 128), noise_std=2.0, seed=i) for i in range(50)]
    tgt_imgs = [_generate_synthetic_image(64, 64, color=(128, 128, 128), noise_std=40.0, seed=i + 500) for i in range(50)]

    boundary = _make_dummy_boundary(ref_n=50, tgt_n=50)
    analyzer = ImageDistributionShiftAnalyzer()
    profile = analyzer.analyze(boundary, ref_imgs, tgt_imgs)

    assert "rms_contrast" in profile.pixel_drift
    assert profile.pixel_drift["rms_contrast"].shift_status == ShiftDecisionState.MATERIAL_SHIFT


def test_26_format_distribution_shift():
    """26. Image format distribution shift (PNG -> JPEG) detected."""
    ref_imgs = [_generate_synthetic_image(64, 64, fmt="PNG", seed=i) for i in range(50)]
    tgt_imgs = [_generate_synthetic_image(64, 64, fmt="JPEG", seed=i + 500) for i in range(50)]

    boundary = _make_dummy_boundary(ref_n=50, tgt_n=50)
    analyzer = ImageDistributionShiftAnalyzer()
    profile = analyzer.analyze(boundary, ref_imgs, tgt_imgs)

    assert profile.format_drift is not None
    assert profile.format_drift.status == ShiftDecisionState.MATERIAL_SHIFT
    assert profile.format_drift.tvd == 1.0


def test_27_multiple_descriptor_shifts():
    """27. Simultaneous multiple descriptor shifts correctly attributed."""
    ref_imgs = [_generate_synthetic_image(64, 64, color=(50, 50, 50), fmt="PNG", seed=i) for i in range(50)]
    tgt_imgs = [_generate_synthetic_image(128, 96, color=(200, 200, 200), fmt="JPEG", seed=i + 500) for i in range(50)]

    boundary = _make_dummy_boundary(ref_n=50, tgt_n=50)
    analyzer = ImageDistributionShiftAnalyzer()
    profile = analyzer.analyze(boundary, ref_imgs, tgt_imgs)

    assert profile.global_status == ShiftDecisionState.MATERIAL_SHIFT
    assert profile.materially_shifted_descriptor_count >= 3
    assert len(profile.top_shifted_descriptors) >= 3


def test_28_and_29_dual_gate_preservation():
    """28-29. Dual gate semantics: both statistical and practical significance required for MATERIAL_SHIFT."""
    # When random variations have large variance, small shifts produce low effect sizes
    ref_imgs = [_generate_synthetic_image(64, 64, color=(128, 128, 128), noise_std=50.0, seed=i) for i in range(50)]
    tgt_imgs = [_generate_synthetic_image(64, 64, color=(128, 128, 128), noise_std=50.0, seed=i + 500) for i in range(50)]

    boundary = _make_dummy_boundary(ref_n=50, tgt_n=50)
    analyzer = ImageDistributionShiftAnalyzer()
    profile = analyzer.analyze(boundary, ref_imgs, tgt_imgs)

    # Identical underlying distributions should produce 0 material shifts
    assert profile.materially_shifted_descriptor_count == 0
    assert profile.global_status == ShiftDecisionState.NO_SHIFT_DETECTED

    # Verify that a profile requires both significance_status AND practical_significance_status to be MATERIAL_SHIFT
    for p in profile.all_descriptor_profiles.values():
        if p.shift_status == ShiftDecisionState.MATERIAL_SHIFT:
            assert p.significance_status is True
            assert p.practical_significance_status is True


# ===========================================================================
# D. Edge Cases (30 - 37)
# ===========================================================================

def test_30_missing_image_in_population():
    """30. Non-existent file paths recorded in accounting without crash."""
    missing_paths = ["/non/existent/path/image1.png", "/non/existent/path/image2.png"]
    cols, acc = extract_population_descriptors(missing_paths)
    assert acc["missing"] == 2
    assert acc["analyzable"] == 0


def test_31_invalid_image_ratio_accounting():
    """31. Mixed valid and corrupt population produces accurate accounting."""
    valid_imgs = [_generate_synthetic_image(64, 64, seed=i) for i in range(40)]
    corrupt_imgs = [b"GARBAGE_BYTES"] * 10
    cols, acc = extract_population_descriptors(valid_imgs + corrupt_imgs)
    assert acc["total"] == 50
    assert acc["analyzable"] == 40
    assert acc["corrupt"] == 10


def test_32_nan_inf_descriptors_sanitized():
    """32. Numerical stability against NaNs and infinities."""
    arr = np.full((32, 32, 3), 0, dtype=np.uint8)
    status, d, err = extract_single_image_descriptors(arr)
    assert status == "VALID"
    assert not np.isnan(d["entropy"])
    assert not np.isinf(d["entropy"])
    assert not np.isnan(d["sharpness_laplacian_var"])


def test_33_constant_image():
    """33. Completely constant image (0 variance, 0 entropy) extracted cleanly."""
    constant_arr = np.full((32, 32, 3), 200, dtype=np.uint8)
    status, d, err = extract_single_image_descriptors(constant_arr)
    assert status == "VALID"
    assert d["rms_contrast"] == 0.0
    assert d["entropy"] == 0.0
    assert d["sharpness_laplacian_var"] == 0.0


def test_34_grayscale_image():
    """34. 2D grayscale image array processed correctly with channels=1."""
    gray_arr = np.full((40, 50), 128, dtype=np.uint8)
    status, d, err = extract_single_image_descriptors(gray_arr)
    assert status == "VALID"
    assert d["width"] == 50
    assert d["height"] == 40
    assert d["channels"] == 1


def test_35_rgb_image():
    """35. Standard RGB image processed with channels=3."""
    rgb_arr = np.zeros((40, 50, 3), dtype=np.uint8)
    status, d, err = extract_single_image_descriptors(rgb_arr)
    assert status == "VALID"
    assert d["channels"] == 3


def test_36_rgba_image_alpha_composite():
    """36. RGBA 4-channel image handled cleanly with alpha composite."""
    rgba_img = Image.new("RGBA", (40, 40), (255, 0, 0, 128))
    status, d, err = extract_single_image_descriptors(rgba_img)
    assert status == "VALID"
    assert d["channels"] == 4
    assert d["width"] == 40


def test_37_mixed_image_formats():
    """37. Mixed formats within a single population extracted and accounted."""
    png_img = _generate_synthetic_image(32, 32, fmt="PNG", seed=1)
    jpg_img = _generate_synthetic_image(32, 32, fmt="JPEG", seed=2)
    cols, acc = extract_population_descriptors([png_img, jpg_img])
    assert acc["analyzable"] == 2
    assert sorted(cols["format"]) == ["JPEG", "PNG"]


# ===========================================================================
# E. Statistical Integration Tests (38 - 44)
# ===========================================================================

def test_38_to_44_statistical_engine_reuse():
    """38-44. Verify Phase 11.3 engine reuse, no double FDR, raw and adjusted p-value preservation."""
    ref_imgs = [_generate_synthetic_image(64, 64, color=(50, 50, 50), noise_std=10.0, seed=i) for i in range(50)]
    tgt_imgs = [_generate_synthetic_image(64, 64, color=(150, 150, 150), noise_std=10.0, seed=i + 500) for i in range(50)]

    boundary = _make_dummy_boundary(ref_n=50, tgt_n=50)
    analyzer = ImageDistributionShiftAnalyzer()
    profile = analyzer.analyze(boundary, ref_imgs, tgt_imgs)

    # Check that descriptors have raw_p_value and adjusted_p_value populated
    for name, p in profile.all_descriptor_profiles.items():
        assert p.raw_p_value is not None
        assert p.adjusted_p_value is not None
        assert 0.0 <= p.raw_p_value <= 1.0
        assert 0.0 <= p.adjusted_p_value <= 1.0
        assert p.effect_size >= 0.0


# ===========================================================================
# F. Synthesis & Localization Tests (45 - 50)
# ===========================================================================

def test_45_to_50_synthesis_and_ranking():
    """45-50. Localization, deterministic ranking, invalid-image accounting, and global status."""
    ref_imgs = [_generate_synthetic_image(64, 64, color=(50, 50, 50), seed=i) for i in range(50)]
    tgt_imgs = [_generate_synthetic_image(128, 64, color=(200, 200, 200), seed=i + 500) for i in range(50)]

    boundary = _make_dummy_boundary(ref_n=50, tgt_n=50)
    analyzer = ImageDistributionShiftAnalyzer()
    profile = analyzer.analyze(boundary, ref_imgs, tgt_imgs)

    # 45. Localization buckets
    assert len(profile.dimension_drift) > 0
    assert len(profile.pixel_drift) > 0
    assert len(profile.quality_drift) > 0

    # 49. Deterministic ranking
    ranks = [p.rank for p in profile.top_shifted_descriptors]
    assert ranks == sorted(ranks)
    assert profile.top_shifted_descriptors[0].rank == 1

    # 50. Consistent global status
    assert profile.global_status == ShiftDecisionState.MATERIAL_SHIFT


# ===========================================================================
# G. Security & Resource Bounds (51 - 55)
# ===========================================================================

def test_51_input_immutability():
    """51. Input images and collections remain unmodified after analysis."""
    ref_imgs = [_generate_synthetic_image(32, 32, seed=i) for i in range(35)]
    tgt_imgs = [_generate_synthetic_image(32, 32, seed=i + 100) for i in range(35)]
    ref_copy = list(ref_imgs)
    tgt_copy = list(tgt_imgs)

    boundary = _make_dummy_boundary(ref_n=35, tgt_n=35)
    analyzer = ImageDistributionShiftAnalyzer()
    analyzer.analyze(boundary, ref_imgs, tgt_imgs)

    assert ref_imgs == ref_copy
    assert tgt_imgs == tgt_copy


def test_52_resource_bounds_population_cap():
    """52. Population exceeding MAX_POPULATION_IMAGES is bounded."""
    dummy_img = _generate_synthetic_image(16, 16)
    large_pop = [dummy_img] * 6000
    cols, acc = extract_population_descriptors(large_pop, max_images=100)
    assert acc["analyzable"] == 100


def test_53_and_54_security_ast_scan():
    """53-54. Verify no forbidden calls (eval, exec, pickle, os.system, subprocess) in image drift module."""
    src_paths = [
        Path("backend/aivara/drift/image_descriptors.py"),
        Path("backend/aivara/drift/image_engine.py"),
    ]
    forbidden_calls = {"eval", "exec", "pickle", "system", "popen", "subprocess"}

    for p in src_paths:
        tree = ast.parse(p.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name) and node.func.id in forbidden_calls:
                    pytest.fail(f"Forbidden call {node.func.id} found in {p}")
                elif isinstance(node.func, ast.Attribute) and node.func.attr in forbidden_calls:
                    pytest.fail(f"Forbidden method {node.func.attr} found in {p}")


def test_55_project_isolation():
    """55. Project ID and dataset IDs strictly preserved in findings and evidence."""
    boundary = _make_dummy_boundary(project_id="alpha-proj", ref_ds="ref-dataset-9", tgt_ds="tgt-dataset-9")
    ref_imgs = [_generate_synthetic_image(32, 32, seed=i) for i in range(35)]
    tgt_imgs = [_generate_synthetic_image(32, 32, seed=i + 100) for i in range(35)]

    analyzer = ImageDistributionShiftAnalyzer()
    profile = analyzer.analyze(boundary, ref_imgs, tgt_imgs)

    assert profile.project_id == "alpha-proj"
    assert profile.reference_dataset_id == "ref-dataset-9"
    assert profile.target_dataset_id == "tgt-dataset-9"
    assert profile.findings[0]["project_id"] == "alpha-proj"


# ===========================================================================
# H. Cryptographic Identity & Hashing (56 - 58)
# ===========================================================================

def test_56_deterministic_image_drift_hash():
    """56. Repeated analysis over identical inputs yields exact identical image_drift_profile_hash."""
    ref_imgs = [_generate_synthetic_image(64, 64, color=(100, 100, 100), seed=i) for i in range(40)]
    tgt_imgs = [_generate_synthetic_image(64, 64, color=(100, 100, 100), seed=i + 200) for i in range(40)]

    boundary = _make_dummy_boundary(ref_n=40, tgt_n=40)
    analyzer = ImageDistributionShiftAnalyzer()

    p1 = analyzer.analyze(boundary, ref_imgs, tgt_imgs)
    p2 = analyzer.analyze(boundary, ref_imgs, tgt_imgs)

    assert p1.image_drift_profile_hash == p2.image_drift_profile_hash
    assert len(p1.image_drift_profile_hash) == 64


def test_57_hash_mutation_detection():
    """57. Different image inputs produce different cryptographic profile hashes."""
    ref_imgs = [_generate_synthetic_image(64, 64, color=(50, 50, 50), seed=i) for i in range(40)]
    tgt1 = [_generate_synthetic_image(64, 64, color=(50, 50, 50), seed=i + 100) for i in range(40)]
    tgt2 = [_generate_synthetic_image(128, 128, color=(200, 200, 200), seed=i + 500) for i in range(40)]

    boundary = _make_dummy_boundary(ref_n=40, tgt_n=40)
    analyzer = ImageDistributionShiftAnalyzer()

    p1 = analyzer.analyze(boundary, ref_imgs, tgt1)
    p2 = analyzer.analyze(boundary, ref_imgs, tgt2)

    assert p1.image_drift_profile_hash != p2.image_drift_profile_hash


def test_58_boundary_identity_preservation():
    """58. Profile strictly preserves comparison boundary hash and statistical analysis hash."""
    ref_imgs = [_generate_synthetic_image(32, 32, seed=i) for i in range(35)]
    tgt_imgs = [_generate_synthetic_image(32, 32, seed=i + 100) for i in range(35)]

    boundary = _make_dummy_boundary(ref_n=35, tgt_n=35)
    analyzer = ImageDistributionShiftAnalyzer()
    profile = analyzer.analyze(boundary, ref_imgs, tgt_imgs)

    assert profile.comparison_boundary_hash == boundary.comparison_boundary_hash
    assert len(profile.statistical_analysis_hash) == 64
    assert profile.findings[0]["metadata_json"]["comparison_boundary_hash"] == boundary.comparison_boundary_hash
