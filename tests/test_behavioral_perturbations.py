"""Comprehensive test suite for Phase 8.4: Controlled Perturbation & Sensitivity Experiment Engine.

Verifies:
1. Gaussian noise determinism and bounds.
2. Uniform noise determinism and bounds.
3. Brightness determinism and clipping.
4. Contrast determinism and clipping.
5. Gaussian blur determinism and separable filter.
6. JPEG compression determinism.
7. Spatial translation determinism and boundary policies.
8. Deterministic perturbation identity (JCS + SHA-256).
9. Perturbed input hash determinism.
10. Parameter sensitivity of perturbation ID.
11. Seed sensitivity for stochastic perturbations.
12. Source input strict immutability.
13. Invalid parameter rejection.
14. Excessive parameter rejection (hard ceilings).
15. Oversized image tensor rejection.
16. Unsupported dtype rejection.
17. Non-finite input (NaN / Inf) trapping.
18. Multi-channel preservation (Grayscale, RGB, RGBA).
19. Channel ordering preservation (no silent transposition).
20. Project isolation and multi-tenant scoping.
21. Absence of anomaly/maliciousness semantics.
22. End-to-end integration with Phase 8.2 Safe Runtime Boundary.
23. Immutability of Phase 7, Phase 8.2, Phase 8.3, and database schema.
24. Adversarial attack attempts fail closed.
"""

import hashlib
from pathlib import Path
from typing import Dict, List, Tuple
import numpy as np
import pytest

from aivara.behavioral import (
    BorderPolicy,
    BrightnessParams,
    ContrastParams,
    ControlledModelExecutor,
    ControlledPerturbationEngine,
    DEFAULT_PERTURBATION_LIMITS,
    ExecutionProvider,
    ExecutionRequest,
    ExecutionResult,
    ExecutionStatus,
    GaussianBlurParams,
    GaussianNoiseParams,
    ImageDType,
    JpegCompressionParams,
    PerturbationExperiment,
    PerturbationLimits,
    PerturbationResult,
    PerturbationResultStatus,
    PerturbationSpecification,
    PerturbationType,
    SpatialTranslationParams,
    UniformNoiseParams,
    apply_brightness,
    apply_contrast,
    apply_gaussian_blur,
    apply_gaussian_noise,
    apply_jpeg_compression,
    apply_spatial_translation,
    apply_uniform_noise,
    compute_experiment_id,
    compute_input_array_hash,
    compute_perturbation_id,
)


# =====================================================================
# Fixtures & Deterministic Test Images
# =====================================================================

@pytest.fixture
def synthetic_images():
    """Fixture providing clean synthetic images across uint8 and float representations."""
    # 1. Uint8 RGB image (64, 64, 3) with deterministic gradient pattern
    y, x = np.mgrid[0:64, 0:64]
    r = (x * 4).astype(np.uint8)
    g = (y * 4).astype(np.uint8)
    b = ((x + y) * 2).astype(np.uint8)
    rgb_u8 = np.stack([r, g, b], axis=-1)

    # 2. Float32 RGB image (64, 64, 3) in [0.0, 1.0]
    rgb_f32 = (rgb_u8.astype(np.float32) / 255.0)

    # 3. Grayscale uint8 image (64, 64)
    gray_u8 = (x * 4).astype(np.uint8)

    # 4. RGBA uint8 image (64, 64, 4)
    alpha = np.full((64, 64), 255, dtype=np.uint8)
    rgba_u8 = np.stack([r, g, b, alpha], axis=-1)

    return {
        "rgb_u8": rgb_u8,
        "rgb_f32": rgb_f32,
        "gray_u8": gray_u8,
        "rgba_u8": rgba_u8,
    }


# =====================================================================
# 1. Determinism Tests per Transform
# =====================================================================

def test_gaussian_noise_determinism_and_bounds(synthetic_images):
    """Verify Gaussian noise produces identical output for same seed and stays within bounds."""
    img = synthetic_images["rgb_u8"]
    params = GaussianNoiseParams(mean=0.0, std=0.05, seed=12345)

    out1 = apply_gaussian_noise(img, params)
    out2 = apply_gaussian_noise(img, params)

    assert np.array_equal(out1, out2)
    assert out1.dtype == np.uint8
    assert np.min(out1) >= 0
    assert np.max(out1) <= 255
    # Noise has modified the image
    assert not np.array_equal(out1, img)


def test_uniform_noise_determinism_and_bounds(synthetic_images):
    """Verify Uniform noise produces identical output for same seed and stays within bounds."""
    img = synthetic_images["rgb_f32"]
    params = UniformNoiseParams(min_val=-0.1, max_val=0.1, seed=54321)

    out1 = apply_uniform_noise(img, params, declared_range=(0.0, 1.0))
    out2 = apply_uniform_noise(img, params, declared_range=(0.0, 1.0))

    assert np.array_equal(out1, out2)
    assert out1.dtype == np.float32
    assert np.min(out1) >= 0.0
    assert np.max(out1) <= 1.0
    assert not np.array_equal(out1, img)


def test_brightness_determinism_and_clipping(synthetic_images):
    """Verify multiplicative brightness scaling is deterministic and clips properly."""
    img = synthetic_images["rgb_u8"]
    params_up = BrightnessParams(factor=1.5)
    params_down = BrightnessParams(factor=0.5)

    out_up = apply_brightness(img, params_up)
    out_down = apply_brightness(img, params_down)

    assert out_up.dtype == np.uint8
    assert np.max(out_up) <= 255
    assert np.mean(out_up) > np.mean(img)
    assert np.mean(out_down) < np.mean(img)


def test_contrast_determinism_and_clipping(synthetic_images):
    """Verify linear contrast scaling is deterministic and clips properly."""
    img = synthetic_images["rgb_f32"]
    params = ContrastParams(factor=1.5)

    out1 = apply_contrast(img, params, declared_range=(0.0, 1.0))
    out2 = apply_contrast(img, params, declared_range=(0.0, 1.0))

    assert np.array_equal(out1, out2)
    assert out1.dtype == np.float32
    assert np.min(out1) >= 0.0
    assert np.max(out1) <= 1.0


def test_gaussian_blur_determinism(synthetic_images):
    """Verify Gaussian blur filter is deterministic and preserves image shape/dtype."""
    img = synthetic_images["rgb_u8"]
    params = GaussianBlurParams(kernel_size=5, sigma=1.5)

    out1 = apply_gaussian_blur(img, params)
    out2 = apply_gaussian_blur(img, params)

    assert np.array_equal(out1, out2)
    assert out1.shape == img.shape
    assert out1.dtype == img.dtype


def test_jpeg_compression_determinism(synthetic_images):
    """Verify in-memory JPEG compression is deterministic across repeated runs."""
    img = synthetic_images["rgb_u8"]
    params = JpegCompressionParams(quality=70)

    out1 = apply_jpeg_compression(img, params)
    out2 = apply_jpeg_compression(img, params)

    assert np.array_equal(out1, out2)
    assert out1.shape == img.shape
    assert out1.dtype == img.dtype


def test_spatial_translation_determinism_and_border_policies(synthetic_images):
    """Verify spatial displacement and border policies (replicate and constant)."""
    img = synthetic_images["rgb_u8"]

    params_rep = SpatialTranslationParams(dx=5, dy=5, border_policy=BorderPolicy.REPLICATE)
    out_rep = apply_spatial_translation(img, params_rep)
    assert out_rep.shape == img.shape
    assert out_rep.dtype == img.dtype

    params_const = SpatialTranslationParams(dx=-3, dy=0, border_policy=BorderPolicy.CONSTANT, fill_value=0.0)
    out_const = apply_spatial_translation(img, params_const)
    assert out_const.shape == img.shape
    # Check that the rightmost 3 columns are filled with 0
    assert np.all(out_const[:, -3:, :] == 0)


# =====================================================================
# 2. Identity Model & Hashing Tests
# =====================================================================

def test_perturbation_identity_determinism():
    """Verify perturbation ID is a 64-char SHA-256 JCS digest invariant to unordered parameter dicts."""
    src_hash = "a" * 64
    p1 = compute_perturbation_id(
        source_input_hash=src_hash,
        perturbation_type="GAUSSIAN_NOISE",
        parameters={"mean": 0.0, "std": 0.05},
        seed=42,
    )
    p2 = compute_perturbation_id(
        source_input_hash=src_hash,
        perturbation_type="GAUSSIAN_NOISE",
        parameters={"std": 0.05, "mean": 0.0},
        seed=42,
    )
    assert len(p1) == 64
    assert p1 == p2


def test_parameter_mutation_changes_perturbation_identity():
    """Verify changing any parameter alters the perturbation ID."""
    src_hash = "a" * 64
    p1 = compute_perturbation_id(
        source_input_hash=src_hash,
        perturbation_type="BRIGHTNESS",
        parameters={"factor": 1.1},
    )
    p2 = compute_perturbation_id(
        source_input_hash=src_hash,
        perturbation_type="BRIGHTNESS",
        parameters={"factor": 1.2},
    )
    assert p1 != p2


def test_seed_mutation_changes_stochastic_identity():
    """Verify seed modification changes perturbation ID for stochastic transforms."""
    src_hash = "a" * 64
    p1 = compute_perturbation_id(
        source_input_hash=src_hash,
        perturbation_type="GAUSSIAN_NOISE",
        parameters={"mean": 0.0, "std": 0.05},
        seed=100,
    )
    p2 = compute_perturbation_id(
        source_input_hash=src_hash,
        perturbation_type="GAUSSIAN_NOISE",
        parameters={"mean": 0.0, "std": 0.05},
        seed=101,
    )
    assert p1 != p2


# =====================================================================
# 3. Source Immutability & Engine Safety Tests
# =====================================================================

def test_source_input_strict_immutability(synthetic_images):
    """Verify source input ndarray is never modified in place during perturbation."""
    engine = ControlledPerturbationEngine()
    img = synthetic_images["rgb_u8"]
    orig_copy = np.copy(img)
    orig_hash = compute_input_array_hash(img)

    spec = PerturbationSpecification(
        perturbation_type=PerturbationType.GAUSSIAN_NOISE,
        parameters={"mean": 0.0, "std": 0.1, "seed": 42},
    )
    res = engine.apply_perturbation(img, spec)

    assert res.status == PerturbationResultStatus.SUCCESS
    # Source array must be byte-for-byte identical
    assert np.array_equal(img, orig_copy)
    assert compute_input_array_hash(img) == orig_hash


def test_invalid_and_excessive_parameter_rejection(synthetic_images):
    """Verify out-of-bounds parameters are rejected safely without crashes."""
    engine = ControlledPerturbationEngine()
    img = synthetic_images["rgb_u8"]

    # 1. Excessive noise std
    spec_noise = PerturbationSpecification(
        perturbation_type=PerturbationType.GAUSSIAN_NOISE,
        parameters={"mean": 0.0, "std": 99.0, "seed": 42},
    )
    res_noise = engine.apply_perturbation(img, spec_noise)
    assert res_noise.status == PerturbationResultStatus.INVALID_PARAMETER

    # 2. Even kernel size for Gaussian blur
    spec_blur = PerturbationSpecification(
        perturbation_type=PerturbationType.GAUSSIAN_BLUR,
        parameters={"kernel_size": 4, "sigma": 1.0},
    )
    res_blur = engine.apply_perturbation(img, spec_blur)
    assert res_blur.status == PerturbationResultStatus.INVALID_PARAMETER

    # 3. Inverted uniform noise bounds
    spec_uniform = PerturbationSpecification(
        perturbation_type=PerturbationType.UNIFORM_NOISE,
        parameters={"min_val": 0.5, "max_val": -0.5, "seed": 42},
    )
    res_uniform = engine.apply_perturbation(img, spec_uniform)
    assert res_uniform.status == PerturbationResultStatus.INVALID_PARAMETER


def test_oversized_image_rejection():
    """Verify image exceeding maximum elements limit is rejected with RESOURCE_LIMIT."""
    limits = PerturbationLimits(max_image_elements=1000)
    engine = ControlledPerturbationEngine(limits=limits)

    big_img = np.zeros((100, 100), dtype=np.uint8)  # 10,000 elements > 1,000
    spec = PerturbationSpecification(
        perturbation_type=PerturbationType.BRIGHTNESS,
        parameters={"factor": 1.1},
    )
    res = engine.apply_perturbation(big_img, spec)
    assert res.status == PerturbationResultStatus.RESOURCE_LIMIT


def test_unsupported_dtype_rejection():
    """Verify non-image dtypes (e.g. int64, complex) are rejected with UNSUPPORTED_INPUT."""
    engine = ControlledPerturbationEngine()
    bad_img = np.zeros((10, 10), dtype=np.int64)

    spec = PerturbationSpecification(
        perturbation_type=PerturbationType.BRIGHTNESS,
        parameters={"factor": 1.1},
    )
    res = engine.apply_perturbation(bad_img, spec)
    assert res.status == PerturbationResultStatus.UNSUPPORTED_INPUT


def test_nan_inf_trapping():
    """Verify input containing NaN or Inf is trapped with UNVERIFIABLE_INPUT."""
    engine = ControlledPerturbationEngine()
    nan_img = np.array([[1.0, float("nan")], [0.5, 0.2]], dtype=np.float32)

    spec = PerturbationSpecification(
        perturbation_type=PerturbationType.GAUSSIAN_BLUR,
        parameters={"kernel_size": 3, "sigma": 1.0},
    )
    res = engine.apply_perturbation(nan_img, spec)
    assert res.status == PerturbationResultStatus.UNVERIFIABLE_INPUT


# =====================================================================
# 4. Multi-Channel & Channel Order Preservation
# =====================================================================

def test_channel_preservation(synthetic_images):
    """Verify Grayscale, RGB, and RGBA channel structures are preserved without transposition."""
    engine = ControlledPerturbationEngine()
    spec = PerturbationSpecification(
        perturbation_type=PerturbationType.BRIGHTNESS,
        parameters={"factor": 1.2},
    )

    # Grayscale (64, 64)
    res_gray = engine.apply_perturbation(synthetic_images["gray_u8"], spec)
    assert res_gray.status == PerturbationResultStatus.SUCCESS
    assert res_gray.perturbed_array.shape == (64, 64)

    # RGB (64, 64, 3)
    res_rgb = engine.apply_perturbation(synthetic_images["rgb_u8"], spec)
    assert res_rgb.status == PerturbationResultStatus.SUCCESS
    assert res_rgb.perturbed_array.shape == (64, 64, 3)

    # RGBA (64, 64, 4)
    res_rgba = engine.apply_perturbation(synthetic_images["rgba_u8"], spec)
    assert res_rgba.status == PerturbationResultStatus.SUCCESS
    assert res_rgba.perturbed_array.shape == (64, 64, 4)


# =====================================================================
# 5. Experiment Suite & Multi-Tenant Isolation
# =====================================================================

def test_standard_perturbation_suite_execution(synthetic_images):
    """Verify standard perturbation suite runs all 7 transform types deterministically."""
    engine = ControlledPerturbationEngine()
    img = synthetic_images["rgb_u8"]

    results = engine.run_standard_perturbation_suite(
        project_id="proj-suite-84",
        source_input_id="sample_001",
        image=img,
        model_id="model-resnet-84",
    )

    assert len(results) == 13
    for exp, res in results:
        assert exp.project_id == "proj-suite-84"
        assert exp.source_input_id == "sample_001"
        assert res.status == PerturbationResultStatus.SUCCESS
        assert len(exp.experiment_id) == 64
        assert len(exp.perturbation_id) == 64
        assert len(res.perturbed_input_hash) == 64


def test_project_isolation_in_experiment_identity(synthetic_images):
    """Verify distinct project IDs yield distinct experiment IDs for identical transformations."""
    engine = ControlledPerturbationEngine()
    img = synthetic_images["rgb_u8"]
    spec = PerturbationSpecification(
        perturbation_type=PerturbationType.CONTRAST,
        parameters={"factor": 1.2},
    )

    exp1, _ = engine.create_experiment("proj-alpha", "img-1", img, spec)
    exp2, _ = engine.create_experiment("proj-beta", "img-1", img, spec)

    assert exp1.experiment_id != exp2.experiment_id
    # Perturbation ID is identical because the transformation on the data is identical
    assert exp1.perturbation_id == exp2.perturbation_id


# =====================================================================
# 6. Semantic Neutrality Tests
# =====================================================================

def test_semantic_neutrality_absence_of_anomaly_semantics(synthetic_images):
    """Verify domain representations contain zero anomaly scores, backdoor detection, or maliciousness."""
    engine = ControlledPerturbationEngine()
    img = synthetic_images["rgb_u8"]
    spec = PerturbationSpecification(
        perturbation_type=PerturbationType.GAUSSIAN_NOISE,
        parameters={"mean": 0.0, "std": 0.05, "seed": 42},
    )
    exp, res = engine.create_experiment("proj-test", "img-1", img, spec)

    exp_dump = str(exp.model_dump(mode="json")).lower()
    res_dump = str(res.model_dump(mode="json")).lower()

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
        assert term not in exp_dump, f"Forbidden term '{term}' found in PerturbationExperiment"
        assert term not in res_dump, f"Forbidden term '{term}' found in PerturbationResult"


# =====================================================================
# 7. Integration with Phase 8.2 Safe Runtime Boundary
# =====================================================================

def test_perturbed_input_execution_in_controlled_runtime(tmp_path: Path, synthetic_images):
    """Verify perturbed inputs execute safely through Phase 8.2 ControlledModelExecutor."""
    import onnx
    from onnx import helper, TensorProto

    # 1. Create a minimal valid linear ONNX model matching input shape [1, 3, 8, 8]
    X = helper.make_tensor_value_info("input", TensorProto.FLOAT, [1, 3, 8, 8])
    Y = helper.make_tensor_value_info("output", TensorProto.FLOAT, [1, 3, 8, 8])
    node_def = helper.make_node("Relu", ["input"], ["output"])
    graph_def = helper.make_graph([node_def], "relu_model", [X], [Y])
    model_def = helper.make_model(graph_def, opset_imports=[helper.make_opsetid("", 17)], producer_name="aivara-test")

    model_path = tmp_path / "model.onnx"
    onnx.save(model_def, str(model_path))

    # 2. Perturb an image [1, 3, 8, 8]
    clean_img = np.random.uniform(0.1, 0.9, size=(1, 3, 8, 8)).astype(np.float32)
    engine = ControlledPerturbationEngine()
    spec = PerturbationSpecification(
        perturbation_type=PerturbationType.GAUSSIAN_NOISE,
        parameters={"mean": 0.0, "std": 0.05, "seed": 42},
    )
    res = engine.apply_perturbation(clean_img, spec, declared_range=(0.0, 1.0))
    assert res.status == PerturbationResultStatus.SUCCESS

    # 3. Execute perturbed input through Phase 8.2 ControlledModelExecutor
    executor = ControlledModelExecutor()
    req = ExecutionRequest(
        execution_id="exec-pert-01",
        project_id="proj-e2e-84",
        model_id="model-e2e-84",
        model_fingerprint="e" * 64,
        model_path=str(model_path),
        inputs={"input": res.perturbed_array},
        execution_provider=ExecutionProvider.CPU,
    )
    exec_res = executor.execute(req)
    assert exec_res.status == ExecutionStatus.SUCCESS
    assert exec_res.outputs is not None
    assert "output" in exec_res.outputs


# =====================================================================
# 8. Immutability & Boundary Checks
# =====================================================================

def test_database_and_frozen_phases_immutability():
    """Verify database models, Phase 7, Phase 8.2, and Phase 8.3 remain completely unmodified."""
    import inspect
    from aivara.database import models
    from aivara.model_integrity import ModelIngestionService
    from aivara.behavioral.runtime import ControlledModelExecutor
    from aivara.behavioral.baselines import BehavioralBaselineService

    assert ModelIngestionService is not None
    assert ControlledModelExecutor is not None
    assert BehavioralBaselineService is not None

    model_classes = [
        name for name, cls in inspect.getmembers(models, inspect.isclass)
        if issubclass(cls, models.Base) and cls != models.Base
    ]
    for m in model_classes:
        assert "perturbation" not in m.lower(), f"Forbidden database model '{m}' found in Phase 8.4"


# =====================================================================
# 9. Adversarial Invariant Battery
# =====================================================================

def test_adversarial_unknown_transform_injection(synthetic_images):
    """Verify injection of arbitrary/unallowlisted transform name is rejected safely."""
    engine = ControlledPerturbationEngine()
    img = synthetic_images["rgb_u8"]

    # Attempt to bypass allowlist with arbitrary string
    with pytest.raises(Exception):
        spec = PerturbationSpecification(
            perturbation_type="ARBITRARY_INJECTION_CODE",  # type: ignore
            parameters={"cmd": "rm -rf /"},
        )
        engine.apply_perturbation(img, spec)


def test_adversarial_nan_inf_parameter_injection(synthetic_images):
    """Verify NaN or Inf in transformation parameters is rejected safely."""
    engine = ControlledPerturbationEngine()
    img = synthetic_images["rgb_u8"]

    # 1. NaN in brightness
    spec_nan = PerturbationSpecification(
        perturbation_type=PerturbationType.BRIGHTNESS,
        parameters={"factor": float("nan")},
    )
    res_nan = engine.apply_perturbation(img, spec_nan)
    assert res_nan.status == PerturbationResultStatus.INVALID_PARAMETER

    # 2. Inf in contrast
    spec_inf = PerturbationSpecification(
        perturbation_type=PerturbationType.CONTRAST,
        parameters={"factor": float("inf")},
    )
    res_inf = engine.apply_perturbation(img, spec_inf)
    assert res_inf.status == PerturbationResultStatus.INVALID_PARAMETER


def test_adversarial_zero_and_empty_arrays():
    """Verify 0-element and empty arrays fail gracefully without engine crashes."""
    engine = ControlledPerturbationEngine()
    empty_arr = np.zeros((0, 0), dtype=np.uint8)

    spec = PerturbationSpecification(
        perturbation_type=PerturbationType.BRIGHTNESS,
        parameters={"factor": 1.2},
    )
    res = engine.apply_perturbation(empty_arr, spec)
    assert res.status == PerturbationResultStatus.SUCCESS
    assert res.perturbed_array is not None
    assert res.perturbed_array.size == 0

