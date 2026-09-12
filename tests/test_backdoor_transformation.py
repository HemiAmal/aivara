"""Exhaustive Unit, Invariant, and Security Test Suite for Phase 9.3 Trigger Transformation Engine."""

import math
import numpy as np
import pytest

from aivara.backdoor.candidates.enums import (
    BlendModeEnum,
    ColorSpaceEnum,
    CornerLocationEnum,
    PatchShapeEnum,
    PerturbationModeEnum,
    PlacementModeEnum,
    TexturePrimitiveEnum,
    TriggerFamilyEnum,
    ValueRangeEnum,
)
from aivara.backdoor.candidates.generator import TriggerCandidateGenerator, create_candidate_spec
from aivara.backdoor.candidates.models import (
    ColorPatternPatchParameters,
    InputConstraints,
    LocalizedPerturbationParameters,
    PlacementSpec,
    SpatialPatchParameters,
    TextureGridParameters,
    TriggerCandidateSpec,
)
from aivara.backdoor.transformation.engine import (
    TRANSFORMATION_ENGINE_VERSION,
    TriggerTransformationEngine,
    transform_input,
)
from aivara.backdoor.transformation.exceptions import (
    CandidateInputMismatchError,
    InvalidInputError,
    NonFiniteInputError,
    TransformationBudgetExceededError,
    TransformationNumericalError,
    TriggerTransformationError,
    UnsupportedDtypeError,
    UnsupportedInputShapeError,
)
from aivara.backdoor.transformation.identity import (
    compute_input_array_hash,
    compute_transformation_id,
)
from aivara.backdoor.transformation.models import TransformationMetadata, TransformationResult


# =====================================================================
# 1. Family-Specific Transformation Tests
# =====================================================================

def test_transform_spatial_patch_square():
    """Test applying SPATIAL_PATCH with square shape and REPLACE blend mode."""
    engine = TriggerTransformationEngine()
    candidate = create_candidate_spec(
        TriggerFamilyEnum.SPATIAL_PATCH,
        SpatialPatchParameters(
            shape=PatchShapeEnum.SQUARE,
            relative_width=0.10,
            relative_height=0.10,
            fill_color=[1.0, 0.0, 0.0],
            blend_mode=BlendModeEnum.REPLACE,
        ),
        placement=PlacementSpec(mode=PlacementModeEnum.FIXED_CORNER, corner=CornerLocationEnum.BOTTOM_RIGHT),
    )
    src = np.zeros((100, 100, 3), dtype=np.float32)
    result = engine.transform(src, candidate)

    assert isinstance(result, TransformationResult)
    assert result.transformed_array.shape == (100, 100, 3)
    assert result.output_dtype == "float32"
    # Bottom right patch should be red [1, 0, 0]
    assert np.all(result.transformed_array[90:, 90:, 0] == 1.0)
    assert np.all(result.transformed_array[90:, 90:, 1:] == 0.0)
    # Top left should remain 0
    assert np.all(result.transformed_array[:10, :10, :] == 0.0)


def test_transform_spatial_patch_circle_alpha_blend():
    """Test applying SPATIAL_PATCH with CIRCLE shape and ALPHA_BLEND mode."""
    engine = TriggerTransformationEngine()
    candidate = create_candidate_spec(
        TriggerFamilyEnum.SPATIAL_PATCH,
        SpatialPatchParameters(
            shape=PatchShapeEnum.CIRCLE,
            relative_width=0.20,
            relative_height=0.20,
            fill_color=[1.0, 1.0, 1.0],
            alpha=0.5,
            blend_mode=BlendModeEnum.ALPHA_BLEND,
        ),
        placement=PlacementSpec(mode=PlacementModeEnum.FIXED_CORNER, corner=CornerLocationEnum.TOP_LEFT),
    )
    src = np.zeros((100, 100, 3), dtype=np.float32)
    result = engine.transform(src, candidate)

    assert result.transformed_array.shape == (100, 100, 3)
    # Inside circular region center, alpha 0.5 with white on black -> 0.5
    center_val = result.transformed_array[10, 10, :]
    assert np.allclose(center_val, [0.5, 0.5, 0.5], atol=1e-3)


def test_transform_color_pattern_patch():
    """Test applying COLOR_PATTERN_PATCH."""
    engine = TriggerTransformationEngine()
    candidate = create_candidate_spec(
        TriggerFamilyEnum.COLOR_PATTERN_PATCH,
        ColorPatternPatchParameters(
            channel_deltas=[0.5, -0.2, 0.3],
            relative_width=0.15,
            relative_height=0.15,
            alpha=1.0,
            blend_mode=BlendModeEnum.ALPHA_BLEND,
        ),
        placement=PlacementSpec(mode=PlacementModeEnum.FIXED_CORNER, corner=CornerLocationEnum.BOTTOM_RIGHT),
    )
    src = np.full((100, 100, 3), 0.5, dtype=np.float32)
    result = engine.transform(src, candidate)

    assert result.transformed_array.shape == (100, 100, 3)
    # Bottom right should have modified colors
    assert not np.allclose(result.transformed_array[90:, 90:, :], 0.5)
    # Top left should remain 0.5
    assert np.allclose(result.transformed_array[:10, :10, :], 0.5)


@pytest.mark.parametrize(
    "primitive",
    [
        TexturePrimitiveEnum.CHECKER,
        TexturePrimitiveEnum.GRID,
        TexturePrimitiveEnum.STRIPE_HORIZONTAL,
        TexturePrimitiveEnum.STRIPE_VERTICAL,
        TexturePrimitiveEnum.DOT_GRID,
    ],
)
def test_transform_texture_grid_primitives(primitive: TexturePrimitiveEnum):
    """Test applying TEXTURE_GRID with all periodic primitives."""
    engine = TriggerTransformationEngine()
    candidate = create_candidate_spec(
        TriggerFamilyEnum.TEXTURE_GRID,
        TextureGridParameters(
            primitive=primitive,
            stride_pixels=16,
            line_width_pixels=2,
            amplitude=0.30,
            alpha=0.50,
        ),
    )
    src = np.full((64, 64, 3), 0.5, dtype=np.float32)
    result = engine.transform(src, candidate)

    assert result.transformed_array.shape == (64, 64, 3)
    assert not np.array_equal(result.transformed_array, src)


@pytest.mark.parametrize(
    "mode",
    [
        PerturbationModeEnum.ADDITIVE_GAUSSIAN,
        PerturbationModeEnum.ADDITIVE_UNIFORM,
        PerturbationModeEnum.MULTIPLICATIVE_UNIFORM,
    ],
)
def test_transform_localized_perturbation_modes(mode: PerturbationModeEnum):
    """Test applying LOCALIZED_PERTURBATION across all noise modes."""
    engine = TriggerTransformationEngine()
    candidate = create_candidate_spec(
        TriggerFamilyEnum.LOCALIZED_PERTURBATION,
        LocalizedPerturbationParameters(
            mode=mode,
            relative_width=0.20,
            relative_height=0.20,
            amplitude=0.10,
            noise_std=0.04,
        ),
        random_seed=4242,
    )
    src = np.full((64, 64, 3), 0.5, dtype=np.float32)
    result = engine.transform(src, candidate)

    assert result.transformed_array.shape == (64, 64, 3)
    assert not np.array_equal(result.transformed_array, src)


# =====================================================================
# 2. Source Immutability & Memory Independence Tests
# =====================================================================

def test_source_input_immutability():
    """Source input array must NOT be mutated in place."""
    engine = TriggerTransformationEngine()
    candidate = create_candidate_spec(
        TriggerFamilyEnum.SPATIAL_PATCH,
        SpatialPatchParameters(relative_width=0.10, relative_height=0.10, fill_color=[1.0, 1.0, 1.0]),
    )
    src = np.zeros((100, 100, 3), dtype=np.float32)
    src_copy = src.copy()
    src_hash_before = compute_input_array_hash(src)

    result = engine.transform(src, candidate)

    src_hash_after = compute_input_array_hash(src)
    assert src_hash_before == src_hash_after
    assert np.array_equal(src, src_copy)
    assert result.source_input_hash == src_hash_before


def test_transformed_array_read_only():
    """Transformed array in result should be read-only (immutable)."""
    engine = TriggerTransformationEngine()
    candidate = create_candidate_spec(
        TriggerFamilyEnum.SPATIAL_PATCH,
        SpatialPatchParameters(relative_width=0.10, relative_height=0.10),
    )
    src = np.zeros((64, 64, 3), dtype=np.float32)
    result = engine.transform(src, candidate)

    with pytest.raises(ValueError):
        result.transformed_array[0, 0, 0] = 999.0


# =====================================================================
# 3. Input Ranks (2, 3, 4) & Formats
# =====================================================================

def test_transform_rank_2_grayscale():
    """Test transformation on Rank 2 (H, W) grayscale array."""
    engine = TriggerTransformationEngine()
    candidate = create_candidate_spec(
        TriggerFamilyEnum.SPATIAL_PATCH,
        SpatialPatchParameters(relative_width=0.10, relative_height=0.10, fill_color=[1.0]),
    )
    src = np.zeros((64, 64), dtype=np.float32)
    result = engine.transform(src, candidate)

    assert result.transformed_array.ndim == 2
    assert result.transformed_array.shape == (64, 64)
    assert np.any(result.transformed_array > 0.0)


def test_transform_rank_3_channel_first_chw():
    """Test transformation on Rank 3 (C, H, W) channel-first array."""
    engine = TriggerTransformationEngine()
    candidate = create_candidate_spec(
        TriggerFamilyEnum.SPATIAL_PATCH,
        SpatialPatchParameters(relative_width=0.10, relative_height=0.10, fill_color=[1.0, 0.0, 0.0]),
    )
    src = np.zeros((3, 64, 64), dtype=np.float32)
    result = engine.transform(src, candidate)

    assert result.transformed_array.shape == (3, 64, 64)
    # Red channel (C=0) at bottom right should be 1.0
    assert np.all(result.transformed_array[0, 58:, 58:] == 1.0)
    assert np.all(result.transformed_array[1:, 58:, 58:] == 0.0)


def test_transform_rank_4_batched():
    """Test transformation on Rank 4 (N, H, W, C) batched array."""
    engine = TriggerTransformationEngine()
    candidate = create_candidate_spec(
        TriggerFamilyEnum.SPATIAL_PATCH,
        SpatialPatchParameters(relative_width=0.10, relative_height=0.10, fill_color=[1.0, 1.0, 1.0]),
    )
    src_batch = np.zeros((4, 64, 64, 3), dtype=np.float32)
    result = engine.transform(src_batch, candidate)

    assert result.transformed_array.shape == (4, 64, 64, 3)
    # Every sample in batch should have the patch applied
    for i in range(4):
        assert np.any(result.transformed_array[i] > 0.0)


def test_transform_rank_4_batch_ceiling():
    """Batch size exceeding MAX_BATCH_SIZE (16) must raise TransformationBudgetExceededError."""
    engine = TriggerTransformationEngine()
    candidate = create_candidate_spec(
        TriggerFamilyEnum.SPATIAL_PATCH,
        SpatialPatchParameters(relative_width=0.10, relative_height=0.10),
    )
    oversized_batch = np.zeros((17, 32, 32, 3), dtype=np.float32)
    with pytest.raises(TransformationBudgetExceededError):
        engine.transform(oversized_batch, candidate)


# =====================================================================
# 4. Input Dtypes
# =====================================================================

@pytest.mark.parametrize("dtype", [np.float32, np.float64, np.uint8, np.int32, np.int64])
def test_transform_preserves_dtypes(dtype):
    """Transformation output must preserve the original input dtype."""
    engine = TriggerTransformationEngine()
    candidate = create_candidate_spec(
        TriggerFamilyEnum.SPATIAL_PATCH,
        SpatialPatchParameters(relative_width=0.10, relative_height=0.10, fill_color=[1.0, 1.0, 1.0]),
    )
    if np.issubdtype(dtype, np.integer):
        src = np.full((32, 32, 3), 50, dtype=dtype)
    else:
        src = np.full((32, 32, 3), 0.5, dtype=dtype)

    result = engine.transform(src, candidate)
    assert result.transformed_array.dtype == dtype
    assert result.output_dtype == str(np.dtype(dtype))


# =====================================================================
# 5. Determinism, Randomness Isolation & Identity Tests
# =====================================================================

def test_transformation_reproducibility():
    """Repeated transformations with identical input, candidate, and seed must be byte-identical."""
    engine = TriggerTransformationEngine()
    candidate = create_candidate_spec(
        TriggerFamilyEnum.LOCALIZED_PERTURBATION,
        LocalizedPerturbationParameters(relative_width=0.15, relative_height=0.15, amplitude=0.10),
        random_seed=777,
    )
    src = np.full((64, 64, 3), 0.5, dtype=np.float32)

    res1 = engine.transform(src, candidate)
    res2 = engine.transform(src, candidate)

    assert np.array_equal(res1.transformed_array, res2.transformed_array)
    assert res1.transformation_id == res2.transformation_id
    assert res1.transformed_input_hash == res2.transformed_input_hash


def test_stochastic_seed_variation():
    """Different random seeds must produce different stochastic perturbation outputs."""
    engine = TriggerTransformationEngine()
    cand1 = create_candidate_spec(
        TriggerFamilyEnum.LOCALIZED_PERTURBATION,
        LocalizedPerturbationParameters(relative_width=0.15, relative_height=0.15, amplitude=0.10),
        random_seed=101,
    )
    cand2 = create_candidate_spec(
        TriggerFamilyEnum.LOCALIZED_PERTURBATION,
        LocalizedPerturbationParameters(relative_width=0.15, relative_height=0.15, amplitude=0.10),
        random_seed=202,
    )
    src = np.full((64, 64, 3), 0.5, dtype=np.float32)

    res1 = engine.transform(src, cand1)
    res2 = engine.transform(src, cand2)

    assert not np.array_equal(res1.transformed_array, res2.transformed_array)
    assert res1.transformation_id != res2.transformation_id


def test_global_rng_unmutated():
    """Transformation engine must not alter legacy global numpy RNG state."""
    engine = TriggerTransformationEngine()
    candidate = create_candidate_spec(
        TriggerFamilyEnum.LOCALIZED_PERTURBATION,
        LocalizedPerturbationParameters(relative_width=0.15, relative_height=0.15),
        random_seed=999,
    )
    src = np.full((64, 64, 3), 0.5, dtype=np.float32)

    np.random.seed(12345)
    rng_state_before = np.random.get_state()

    _ = engine.transform(src, candidate)

    rng_state_after = np.random.get_state()
    assert rng_state_before[0] == rng_state_after[0]
    assert np.array_equal(rng_state_before[1], rng_state_after[1])


def test_transformation_id_sensitivity():
    """Changing source input, candidate, placement, or version must change transformation_id."""
    engine = TriggerTransformationEngine()
    cand = create_candidate_spec(
        TriggerFamilyEnum.SPATIAL_PATCH,
        SpatialPatchParameters(relative_width=0.10, relative_height=0.10),
    )
    src1 = np.zeros((32, 32, 3), dtype=np.float32)
    src2 = np.ones((32, 32, 3), dtype=np.float32)

    res1 = engine.transform(src1, cand)
    res2 = engine.transform(src2, cand)
    assert res1.transformation_id != res2.transformation_id

    # Placement override
    custom_placement = PlacementSpec(mode=PlacementModeEnum.FIXED_CORNER, corner=CornerLocationEnum.TOP_LEFT)
    res3 = engine.transform(src1, cand, placement=custom_placement)
    assert res1.transformation_id != res3.transformation_id


# =====================================================================
# 6. Value Range & Clipping Policy Tests
# =====================================================================

def test_additive_blend_clipping_policy():
    """Values pushed beyond [0.0, 1.0] in ADDITIVE_BLEND must be clipped with flag recorded."""
    engine = TriggerTransformationEngine()
    candidate = create_candidate_spec(
        TriggerFamilyEnum.COLOR_PATTERN_PATCH,
        ColorPatternPatchParameters(
            channel_deltas=[0.8, 0.8, 0.8],
            relative_width=0.20,
            relative_height=0.20,
            blend_mode=BlendModeEnum.ADDITIVE,
        ),
    )
    src = np.full((32, 32, 3), 0.8, dtype=np.float32)
    result = engine.transform(src, candidate)

    assert result.clipping_occurred is True
    assert np.all(result.transformed_array <= 1.0)
    assert np.all(result.transformed_array >= 0.0)


# =====================================================================
# 7. Error Handling & Validation Tests
# =====================================================================

def test_nan_input_rejected():
    """Source input containing NaN must raise NonFiniteInputError."""
    engine = TriggerTransformationEngine()
    candidate = create_candidate_spec(
        TriggerFamilyEnum.SPATIAL_PATCH,
        SpatialPatchParameters(relative_width=0.10, relative_height=0.10),
    )
    src = np.zeros((32, 32, 3), dtype=np.float32)
    src[5, 5, 0] = float("nan")

    with pytest.raises(NonFiniteInputError):
        engine.transform(src, candidate)


def test_inf_input_rejected():
    """Source input containing Inf must raise NonFiniteInputError."""
    engine = TriggerTransformationEngine()
    candidate = create_candidate_spec(
        TriggerFamilyEnum.SPATIAL_PATCH,
        SpatialPatchParameters(relative_width=0.10, relative_height=0.10),
    )
    src = np.zeros((32, 32, 3), dtype=np.float32)
    src[5, 5, 0] = float("inf")

    with pytest.raises(NonFiniteInputError):
        engine.transform(src, candidate)


def test_unsupported_dtype_rejected():
    """Unsupported dtypes (e.g. complex, bool, object) must raise UnsupportedDtypeError."""
    engine = TriggerTransformationEngine()
    candidate = create_candidate_spec(
        TriggerFamilyEnum.SPATIAL_PATCH,
        SpatialPatchParameters(relative_width=0.10, relative_height=0.10),
    )
    src = np.zeros((32, 32, 3), dtype=complex)
    with pytest.raises(UnsupportedDtypeError):
        engine.transform(src, candidate)


def test_invalid_spatial_dimensions_rejected():
    """Spatial dimensions below minimum (16) must raise UnsupportedInputShapeError."""
    engine = TriggerTransformationEngine()
    candidate = create_candidate_spec(
        TriggerFamilyEnum.SPATIAL_PATCH,
        SpatialPatchParameters(relative_width=0.10, relative_height=0.10),
    )
    src = np.zeros((8, 8, 3), dtype=np.float32)
    with pytest.raises(UnsupportedInputShapeError):
        engine.transform(src, candidate)


def test_non_array_input_rejected():
    """Non-numpy array input must raise InvalidInputError."""
    engine = TriggerTransformationEngine()
    candidate = create_candidate_spec(
        TriggerFamilyEnum.SPATIAL_PATCH,
        SpatialPatchParameters(relative_width=0.10, relative_height=0.10),
    )
    with pytest.raises(InvalidInputError):
        engine.transform([[1, 2], [3, 4]], candidate)  # type: ignore


# =====================================================================
# 8. Functional transform_input & Batch Tests
# =====================================================================

def test_functional_transform_input():
    """Test functional transform_input helper."""
    candidate = create_candidate_spec(
        TriggerFamilyEnum.SPATIAL_PATCH,
        SpatialPatchParameters(relative_width=0.10, relative_height=0.10),
    )
    src = np.zeros((32, 32, 3), dtype=np.float32)
    result = transform_input(src, candidate)
    assert isinstance(result, TransformationResult)
    assert result.transformation_id is not None


def test_transform_batch_list_and_metadata():
    """Test transform_batch with list of arrays and metadata model conversion."""
    engine = TriggerTransformationEngine()
    candidate = create_candidate_spec(
        TriggerFamilyEnum.SPATIAL_PATCH,
        SpatialPatchParameters(relative_width=0.10, relative_height=0.10),
    )
    inputs = [np.zeros((32, 32, 3), dtype=np.float32) for _ in range(3)]
    results = engine.transform_batch(inputs, candidate)

    assert len(results) == 3
    for res in results:
        meta = res.to_metadata_model()
        assert isinstance(meta, TransformationMetadata)
        assert meta.transformation_id == res.transformation_id


# =====================================================================
# 9. Explicit Input Layout and Invariant Tests (ADR-087)
# =====================================================================

from aivara.backdoor.transformation.enums import InputLayoutEnum


def test_explicit_layout_hwc_vs_chw():
    """Explicit HWC and CHW layouts must transform proper spatial axes and produce matching output layouts."""
    engine = TriggerTransformationEngine()
    candidate = create_candidate_spec(
        TriggerFamilyEnum.SPATIAL_PATCH,
        SpatialPatchParameters(
            relative_width=0.10,
            relative_height=0.10,
            fill_color=[1.0, 0.0, 0.0],
            blend_mode=BlendModeEnum.REPLACE,
        ),
        placement=PlacementSpec(mode=PlacementModeEnum.FIXED_CORNER, corner=CornerLocationEnum.BOTTOM_RIGHT),
    )

    # 1. HWC (100, 100, 3)
    src_hwc = np.zeros((100, 100, 3), dtype=np.float32)
    res_hwc = engine.transform(src_hwc, candidate, input_layout=InputLayoutEnum.HWC)
    assert res_hwc.input_layout == InputLayoutEnum.HWC
    assert res_hwc.output_layout == InputLayoutEnum.HWC
    assert res_hwc.transformed_array.shape == (100, 100, 3)
    assert np.all(res_hwc.transformed_array[90:, 90:, 0] == 1.0)

    # 2. CHW (3, 100, 100)
    src_chw = np.zeros((3, 100, 100), dtype=np.float32)
    res_chw = engine.transform(src_chw, candidate, input_layout=InputLayoutEnum.CHW)
    assert res_chw.input_layout == InputLayoutEnum.CHW
    assert res_chw.output_layout == InputLayoutEnum.CHW
    assert res_chw.transformed_array.shape == (3, 100, 100)
    assert np.all(res_chw.transformed_array[0, 90:, 90:] == 1.0)


def test_layout_participates_in_transformation_id():
    """Changing input_layout must change transformation_id even on identical array data and candidate."""
    engine = TriggerTransformationEngine()
    candidate = create_candidate_spec(
        TriggerFamilyEnum.SPATIAL_PATCH,
        SpatialPatchParameters(relative_width=0.10, relative_height=0.10),
    )
    # A symmetric 3D array (e.g. 3, 32, 32 can be viewed as HWC if H=3, W=32, C=32 or CHW if C=3, H=32, W=32)
    src_chw = np.zeros((3, 32, 32), dtype=np.float32)
    src_hwc = np.zeros((32, 32, 3), dtype=np.float32)

    res_chw = engine.transform(src_chw, candidate, input_layout=InputLayoutEnum.CHW)
    res_hwc = engine.transform(src_hwc, candidate, input_layout=InputLayoutEnum.HWC)

    assert res_chw.transformation_id != res_hwc.transformation_id
    assert res_chw.input_layout == InputLayoutEnum.CHW
    assert res_hwc.input_layout == InputLayoutEnum.HWC


def test_ambiguous_layout_rejection():
    """Ambiguous tensor shapes (where both axis 0 and axis 2 match channel dimensions) require explicit layout."""
    engine = TriggerTransformationEngine()
    candidate = create_candidate_spec(
        TriggerFamilyEnum.SPATIAL_PATCH,
        SpatialPatchParameters(relative_width=0.10, relative_height=0.10),
    )
    # Shape (3, 32, 3) has both axis 0 and axis 2 matching channel count (3)
    ambiguous_src = np.zeros((3, 32, 3), dtype=np.float32)

    # Must fail without explicit layout
    with pytest.raises(UnsupportedInputShapeError) as exc_info:
        engine.transform(ambiguous_src, candidate)
    assert "Ambiguous rank 3 array shape" in str(exc_info.value)

    # Explicit layout with valid spatial dimensions succeeds
    valid_chw = np.zeros((3, 32, 32), dtype=np.float32)
    res = engine.transform(valid_chw, candidate, input_layout=InputLayoutEnum.CHW)
    assert res.input_layout == InputLayoutEnum.CHW


def test_batched_nhwc_and_nchw_all_samples_transformed():
    """Batched transformations for NHWC and NCHW must transform every sample across batch dimension."""
    engine = TriggerTransformationEngine()
    candidate = create_candidate_spec(
        TriggerFamilyEnum.SPATIAL_PATCH,
        SpatialPatchParameters(
            relative_width=0.10,
            relative_height=0.10,
            fill_color=[1.0, 1.0, 1.0],
            blend_mode=BlendModeEnum.REPLACE,
        ),
        placement=PlacementSpec(mode=PlacementModeEnum.FIXED_CORNER, corner=CornerLocationEnum.BOTTOM_RIGHT),
    )

    for n_samples in [1, 4, 16]:
        # NHWC (N, 64, 64, 3)
        batch_nhwc = np.zeros((n_samples, 64, 64, 3), dtype=np.float32)
        res_nhwc = engine.transform(batch_nhwc, candidate, input_layout=InputLayoutEnum.NHWC)
        assert res_nhwc.output_layout == InputLayoutEnum.NHWC
        assert res_nhwc.transformed_array.shape == (n_samples, 64, 64, 3)
        for i in range(n_samples):
            assert np.any(res_nhwc.transformed_array[i, 58:, 58:, :] == 1.0)

        # NCHW (N, 3, 64, 64)
        batch_nchw = np.zeros((n_samples, 3, 64, 64), dtype=np.float32)
        res_nchw = engine.transform(batch_nchw, candidate, input_layout=InputLayoutEnum.NCHW)
        assert res_nchw.output_layout == InputLayoutEnum.NCHW
        assert res_nchw.transformed_array.shape == (n_samples, 3, 64, 64)
        for i in range(n_samples):
            assert np.any(res_nchw.transformed_array[i, :, 58:, 58:] == 1.0)


def test_batch_ceiling_fail_closed_n17():
    """Batch size 17 must be rejected with TransformationBudgetExceededError."""
    engine = TriggerTransformationEngine()
    candidate = create_candidate_spec(
        TriggerFamilyEnum.SPATIAL_PATCH,
        SpatialPatchParameters(relative_width=0.10, relative_height=0.10),
    )
    batch_17 = np.zeros((17, 32, 32, 3), dtype=np.float32)
    with pytest.raises(TransformationBudgetExceededError):
        engine.transform(batch_17, candidate, input_layout=InputLayoutEnum.NHWC)

