"""Exhaustive Unit and Security Test Suite for Phase 9.2 Trigger Candidate Generation."""

import math
import numpy as np
import pytest
from pydantic import ValidationError

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
from aivara.backdoor.candidates.exceptions import (
    BackdoorCandidateError,
    CandidateBudgetExceededError,
    CandidateOutOfBoundsError,
    DuplicateCandidateError,
    InvalidCandidateParameterError,
    InvalidCandidateTypeError,
    InvalidSeedError,
    SecurityValidationError,
)
from aivara.backdoor.candidates.generator import (
    MAX_CANDIDATES,
    TriggerCandidateGenerator,
    create_candidate_spec,
)
from aivara.backdoor.candidates.identity import compute_candidate_identity_hash
from aivara.backdoor.candidates.models import (
    ColorPatternPatchParameters,
    GeneratedPattern,
    InputConstraints,
    LocalizedPerturbationParameters,
    PlacementSpec,
    SpatialPatchParameters,
    TextureGridParameters,
    TriggerCandidateSpec,
)
from aivara.backdoor.candidates.validators import (
    MAX_RELATIVE_HEIGHT,
    MAX_RELATIVE_RADIUS,
    MAX_RELATIVE_WIDTH,
    MIN_RELATIVE_DIMENSION,
    validate_finite_number,
    validate_security_dict,
    validate_security_string,
    validate_seed,
)


# =====================================================================
# 1. Family Specification Tests
# =====================================================================

def test_spatial_patch_spec_valid():
    """Test valid SPATIAL_PATCH candidate specification creation."""
    params = SpatialPatchParameters(
        shape=PatchShapeEnum.SQUARE,
        relative_width=0.10,
        relative_height=0.10,
        fill_color=[1.0, 1.0, 1.0],
        alpha=1.0,
    )
    spec = create_candidate_spec(
        candidate_family=TriggerFamilyEnum.SPATIAL_PATCH,
        parameters=params,
        random_seed=123,
    )
    assert spec.candidate_family == TriggerFamilyEnum.SPATIAL_PATCH
    assert len(spec.candidate_hash) == 64
    assert int(spec.candidate_hash, 16) > 0
    assert spec.parameters["relative_width"] == 0.10


def test_color_pattern_patch_spec_valid():
    """Test valid COLOR_PATTERN_PATCH candidate specification creation."""
    params = ColorPatternPatchParameters(
        color_space=ColorSpaceEnum.RGB,
        channel_deltas=[0.3, -0.2, 0.4],
        relative_width=0.12,
        relative_height=0.12,
        alpha=0.7,
    )
    spec = create_candidate_spec(
        candidate_family=TriggerFamilyEnum.COLOR_PATTERN_PATCH,
        parameters=params,
        random_seed=456,
    )
    assert spec.candidate_family == TriggerFamilyEnum.COLOR_PATTERN_PATCH
    assert len(spec.candidate_hash) == 64
    assert spec.parameters["channel_deltas"] == [0.3, -0.2, 0.4]


def test_texture_grid_spec_valid():
    """Test valid TEXTURE_GRID candidate specification creation."""
    params = TextureGridParameters(
        primitive=TexturePrimitiveEnum.CHECKER,
        stride_pixels=16,
        line_width_pixels=4,
        amplitude=0.3,
        alpha=0.6,
    )
    spec = create_candidate_spec(
        candidate_family=TriggerFamilyEnum.TEXTURE_GRID,
        parameters=params,
        random_seed=789,
    )
    assert spec.candidate_family == TriggerFamilyEnum.TEXTURE_GRID
    assert len(spec.candidate_hash) == 64
    assert spec.parameters["primitive"] == TexturePrimitiveEnum.CHECKER.value


def test_localized_perturbation_spec_valid():
    """Test valid LOCALIZED_PERTURBATION candidate specification creation."""
    params = LocalizedPerturbationParameters(
        mode=PerturbationModeEnum.ADDITIVE_GAUSSIAN,
        relative_width=0.20,
        relative_height=0.20,
        amplitude=0.15,
        noise_std=0.05,
    )
    spec = create_candidate_spec(
        candidate_family=TriggerFamilyEnum.LOCALIZED_PERTURBATION,
        parameters=params,
        random_seed=101112,
    )
    assert spec.candidate_family == TriggerFamilyEnum.LOCALIZED_PERTURBATION
    assert len(spec.candidate_hash) == 64
    assert spec.parameters["amplitude"] == 0.15


# =====================================================================
# 2. Determinism and PCG64 Random State Tests
# =====================================================================

def test_identical_spec_produces_identical_hash():
    """Same canonical parameters, placement, input constraints, and seed must produce identical hash."""
    params = {"relative_width": 0.10, "relative_height": 0.10, "fill_color": [1.0, 0.0, 0.0]}
    spec1 = create_candidate_spec(TriggerFamilyEnum.SPATIAL_PATCH, params, random_seed=42)
    spec2 = create_candidate_spec(TriggerFamilyEnum.SPATIAL_PATCH, params, random_seed=42)
    assert spec1.candidate_hash == spec2.candidate_hash


def test_different_parameters_produce_different_hash():
    """Altering any identity parameter must produce a distinct hash."""
    spec1 = create_candidate_spec(
        TriggerFamilyEnum.SPATIAL_PATCH,
        {"relative_width": 0.10, "relative_height": 0.10, "fill_color": [1.0, 0.0, 0.0]},
        random_seed=42,
    )
    spec2 = create_candidate_spec(
        TriggerFamilyEnum.SPATIAL_PATCH,
        {"relative_width": 0.12, "relative_height": 0.10, "fill_color": [1.0, 0.0, 0.0]},
        random_seed=42,
    )
    assert spec1.candidate_hash != spec2.candidate_hash


def test_different_seed_produces_different_hash():
    """Changing random seed must change candidate identity hash."""
    params = {"relative_width": 0.10, "relative_height": 0.10, "fill_color": [1.0, 0.0, 0.0]}
    spec1 = create_candidate_spec(TriggerFamilyEnum.SPATIAL_PATCH, params, random_seed=42)
    spec2 = create_candidate_spec(TriggerFamilyEnum.SPATIAL_PATCH, params, random_seed=43)
    assert spec1.candidate_hash != spec2.candidate_hash


def test_pcg64_pattern_generation_determinism():
    """Pattern synthesis using PCG64 must produce exact byte-for-byte numerical reproducibility."""
    gen = TriggerCandidateGenerator()
    params = LocalizedPerturbationParameters(
        mode=PerturbationModeEnum.ADDITIVE_GAUSSIAN,
        relative_width=0.25,
        relative_height=0.25,
        amplitude=0.20,
        noise_std=0.08,
    )
    spec = gen.generate_candidate(TriggerFamilyEnum.LOCALIZED_PERTURBATION, params, random_seed=999)

    pattern1 = gen.synthesize_pattern(spec, target_shape=(128, 128, 3))
    pattern2 = gen.synthesize_pattern(spec, target_shape=(128, 128, 3))

    assert np.array_equal(pattern1.pattern_array, pattern2.pattern_array)
    assert np.array_equal(pattern1.mask_array, pattern2.mask_array)


def test_pcg64_no_global_rng_contamination():
    """Mutating Python global or NumPy legacy global RNG must not affect PCG64 synthesis."""
    gen = TriggerCandidateGenerator()
    params = LocalizedPerturbationParameters(
        mode=PerturbationModeEnum.ADDITIVE_GAUSSIAN,
        relative_width=0.20,
        relative_height=0.20,
        amplitude=0.10,
    )
    spec = gen.generate_candidate(TriggerFamilyEnum.LOCALIZED_PERTURBATION, params, random_seed=777)

    # Baseline synthesis
    baseline = gen.synthesize_pattern(spec, target_shape=(64, 64, 3))

    # Contaminate global state
    np.random.seed(12345)
    _ = np.random.randn(100)

    # Re-synthesize
    post_contamination = gen.synthesize_pattern(spec, target_shape=(64, 64, 3))

    assert np.array_equal(baseline.pattern_array, post_contamination.pattern_array)


# =====================================================================
# 3. Immutability Tests
# =====================================================================

def test_candidate_spec_is_immutable():
    """TriggerCandidateSpec must be frozen and reject in-place attribute mutation."""
    spec = create_candidate_spec(
        TriggerFamilyEnum.SPATIAL_PATCH,
        {"relative_width": 0.10, "relative_height": 0.10},
        random_seed=42,
    )
    with pytest.raises(ValidationError):
        spec.schema_version = "2.0.0"

    with pytest.raises(ValidationError):
        spec.random_seed = 99


# =====================================================================
# 4. Resource Bounding and Batch Limits
# =====================================================================

def test_max_candidates_ceiling_enforced():
    """Batch requests exceeding MAX_CANDIDATES (16) must raise CandidateBudgetExceededError."""
    gen = TriggerCandidateGenerator()
    assert MAX_CANDIDATES == 16

    # 17 candidate specs
    excess_specs = [
        {
            "candidate_family": TriggerFamilyEnum.SPATIAL_PATCH,
            "parameters": {"relative_width": 0.05, "relative_height": 0.05},
            "random_seed": i,
        }
        for i in range(17)
    ]

    with pytest.raises(CandidateBudgetExceededError) as exc_info:
        gen.generate_candidates(excess_specs)
    assert "exceeds maximum budget limit (16)" in str(exc_info.value)


def test_standard_grid_count_bounds():
    """Standard grid generator must respect max_candidates bounds."""
    gen = TriggerCandidateGenerator()
    with pytest.raises(CandidateBudgetExceededError):
        gen.generate_standard_grid(TriggerFamilyEnum.SPATIAL_PATCH, count=17)

    with pytest.raises(CandidateBudgetExceededError):
        gen.generate_standard_grid(TriggerFamilyEnum.SPATIAL_PATCH, count=0)


def test_duplicate_candidate_detection():
    """Identical candidate specifications in a batch must trigger DuplicateCandidateError."""
    gen = TriggerCandidateGenerator()
    duplicate_specs = [
        {
            "candidate_family": TriggerFamilyEnum.SPATIAL_PATCH,
            "parameters": {"relative_width": 0.10, "relative_height": 0.10},
            "random_seed": 42,
        },
        {
            "candidate_family": TriggerFamilyEnum.SPATIAL_PATCH,
            "parameters": {"relative_width": 0.10, "relative_height": 0.10},
            "random_seed": 42,
        },
    ]
    with pytest.raises(DuplicateCandidateError) as exc_info:
        gen.generate_candidates(duplicate_specs)
    assert "Duplicate candidate detected" in str(exc_info.value)


def test_deterministic_batch_sorting():
    """Batch generator must return candidates sorted deterministically by candidate_hash."""
    gen = TriggerCandidateGenerator()
    specs = [
        {
            "candidate_family": TriggerFamilyEnum.SPATIAL_PATCH,
            "parameters": {"relative_width": 0.08, "relative_height": 0.08},
            "random_seed": 100 - i,
        }
        for i in range(5)
    ]
    candidates = gen.generate_candidates(specs)
    hashes = [c.candidate_hash for c in candidates]
    assert hashes == sorted(hashes)


# =====================================================================
# 5. Parameter Validation and Boundary Tests
# =====================================================================

def test_relative_dimension_bounds():
    """Dimensions exceeding MAX_RELATIVE_WIDTH / HEIGHT (0.50) or below 0.01 must be rejected."""
    # Exceed width 0.50
    with pytest.raises(InvalidCandidateParameterError):
        create_candidate_spec(
            TriggerFamilyEnum.SPATIAL_PATCH,
            {"relative_width": 0.51, "relative_height": 0.10},
        )

    # Sub-minimum width < 0.01
    with pytest.raises(InvalidCandidateParameterError):
        create_candidate_spec(
            TriggerFamilyEnum.SPATIAL_PATCH,
            {"relative_width": 0.005, "relative_height": 0.10},
        )

    # Circular radius > 0.25
    with pytest.raises(InvalidCandidateParameterError):
        create_candidate_spec(
            TriggerFamilyEnum.SPATIAL_PATCH,
            {"shape": "circle", "relative_radius": 0.30},
        )


def test_nan_and_inf_rejection():
    """NaN or Inf floats must be rejected."""
    with pytest.raises(InvalidCandidateParameterError):
        create_candidate_spec(
            TriggerFamilyEnum.SPATIAL_PATCH,
            {"relative_width": float("nan"), "relative_height": 0.10},
        )

    with pytest.raises(InvalidCandidateParameterError):
        create_candidate_spec(
            TriggerFamilyEnum.SPATIAL_PATCH,
            {"relative_width": float("inf"), "relative_height": 0.10},
        )


def test_invalid_seed_rejection():
    """Seeds out of range [0, 2^32 - 1] or non-integer must be rejected."""
    with pytest.raises(InvalidSeedError):
        create_candidate_spec(
            TriggerFamilyEnum.SPATIAL_PATCH,
            {"relative_width": 0.10, "relative_height": 0.10},
            random_seed=-1,
        )

    with pytest.raises(InvalidSeedError):
        create_candidate_spec(
            TriggerFamilyEnum.SPATIAL_PATCH,
            {"relative_width": 0.10, "relative_height": 0.10},
            random_seed=2**32 + 1,
        )


def test_unsupported_candidate_type():
    """Unsupported or deferred candidate families must raise InvalidCandidateTypeError."""
    with pytest.raises(InvalidCandidateTypeError):
        create_candidate_spec("FOURIER_FREQUENCY_TRIGGER", {"freq": 10})

    with pytest.raises(InvalidCandidateTypeError):
        create_candidate_spec("STYLE_TRANSFER_TRIGGER", {})


# =====================================================================
# 6. Security Validation Tests
# =====================================================================

@pytest.mark.parametrize(
    "malicious_string",
    [
        "__import__('os').system('ls')",
        "eval('1+1')",
        "exec('import sys')",
        "subprocess.Popen(['calc.exe'])",
        "http://attacker.com/trigger.png",
        "https://malicious.site/payload",
        "file:///etc/passwd",
        "../../../../windows/system32",
        "cmd.exe /c dir",
        "powershell -c whoami",
    ],
)
def test_security_injection_strings_rejected(malicious_string: str):
    """Malicious string injection attempts must be rejected with SecurityValidationError."""
    with pytest.raises(SecurityValidationError):
        validate_security_string(malicious_string, "test_field")

    with pytest.raises(SecurityValidationError):
        validate_security_dict({"inject": malicious_string}, "parameters")


def test_target_shape_dimensions_bounded():
    """Synthesizing patterns with excessively large target shapes must fail before allocation."""
    gen = TriggerCandidateGenerator()
    spec = create_candidate_spec(
        TriggerFamilyEnum.SPATIAL_PATCH,
        {"relative_width": 0.10, "relative_height": 0.10},
    )

    # 10000x10000 exceeds max 4096
    with pytest.raises(CandidateOutOfBoundsError):
        gen.synthesize_pattern(spec, target_shape=(10000, 10000, 3))

    # Channel count 10 exceeds max 4
    with pytest.raises(CandidateOutOfBoundsError):
        gen.synthesize_pattern(spec, target_shape=(224, 224, 10))


# =====================================================================
# 7. Pattern Synthesis and Primitive Tests
# =====================================================================

@pytest.mark.parametrize(
    "shape",
    [PatchShapeEnum.SQUARE, PatchShapeEnum.RECTANGLE, PatchShapeEnum.CIRCLE],
)
def test_spatial_patch_all_shapes_synthesis(shape: PatchShapeEnum):
    """Synthesize spatial patch with all supported shapes."""
    gen = TriggerCandidateGenerator()
    params = SpatialPatchParameters(
        shape=shape,
        relative_width=0.15,
        relative_height=0.15,
        fill_color=[0.0, 1.0, 0.0],
        alpha=0.9,
    )
    spec = gen.generate_candidate(TriggerFamilyEnum.SPATIAL_PATCH, params)
    pattern = gen.synthesize_pattern(spec, target_shape=(100, 100, 3))

    assert pattern.pattern_array.shape == (100, 100, 3)
    assert pattern.mask_array.shape == (100, 100)
    assert np.any(pattern.mask_array > 0.0)
    assert np.all(pattern.mask_array <= 1.0)


@pytest.mark.parametrize(
    "corner",
    [
        CornerLocationEnum.BOTTOM_RIGHT,
        CornerLocationEnum.TOP_LEFT,
        CornerLocationEnum.TOP_RIGHT,
        CornerLocationEnum.BOTTOM_LEFT,
        CornerLocationEnum.CENTER,
    ],
)
def test_spatial_patch_all_corners(corner: CornerLocationEnum):
    """Verify placement in all 5 corner locations."""
    gen = TriggerCandidateGenerator()
    params = SpatialPatchParameters(
        relative_width=0.10,
        relative_height=0.10,
    )
    placement = PlacementSpec(mode=PlacementModeEnum.FIXED_CORNER, corner=corner)
    spec = gen.generate_candidate(TriggerFamilyEnum.SPATIAL_PATCH, params, placement=placement)
    pattern = gen.synthesize_pattern(spec, target_shape=(100, 100, 3))
    assert np.sum(pattern.mask_array) > 0


def test_spatial_patch_normalized_position_placement():
    """Verify NORMALIZED_POSITION placement mode."""
    gen = TriggerCandidateGenerator()
    params = SpatialPatchParameters(relative_width=0.10, relative_height=0.10)
    placement = PlacementSpec(
        mode=PlacementModeEnum.NORMALIZED_POSITION,
        normalized_x=0.5,
        normalized_y=0.5,
    )
    spec = gen.generate_candidate(TriggerFamilyEnum.SPATIAL_PATCH, params, placement=placement)
    pattern = gen.synthesize_pattern(spec, target_shape=(100, 100, 3))
    assert pattern.mask_array[50, 50] > 0.0


def test_spatial_patch_grid_cell_placement():
    """Verify GRID_CELL placement mode."""
    gen = TriggerCandidateGenerator()
    params = SpatialPatchParameters(relative_width=0.10, relative_height=0.10)
    placement = PlacementSpec(
        mode=PlacementModeEnum.GRID_CELL,
        grid_row=3,
        grid_col=3,
    )
    spec = gen.generate_candidate(TriggerFamilyEnum.SPATIAL_PATCH, params, placement=placement)
    pattern = gen.synthesize_pattern(spec, target_shape=(128, 128, 3))
    assert np.sum(pattern.mask_array) > 0


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
def test_texture_grid_all_primitives_synthesis(primitive: TexturePrimitiveEnum):
    """Synthesize texture grid with all supported periodic primitives."""
    gen = TriggerCandidateGenerator()
    params = TextureGridParameters(
        primitive=primitive,
        stride_pixels=16,
        line_width_pixels=2,
        amplitude=0.30,
        alpha=0.50,
    )
    spec = gen.generate_candidate(TriggerFamilyEnum.TEXTURE_GRID, params)
    pattern = gen.synthesize_pattern(spec, target_shape=(64, 64, 3))

    assert pattern.pattern_array.shape == (64, 64, 3)
    assert pattern.mask_array.shape == (64, 64)
    assert np.any(pattern.mask_array > 0.0)


@pytest.mark.parametrize(
    "mode",
    [
        PerturbationModeEnum.ADDITIVE_GAUSSIAN,
        PerturbationModeEnum.ADDITIVE_UNIFORM,
        PerturbationModeEnum.MULTIPLICATIVE_UNIFORM,
    ],
)
def test_localized_perturbation_all_modes_synthesis(mode: PerturbationModeEnum):
    """Synthesize localized perturbation with all supported noise modes."""
    gen = TriggerCandidateGenerator()
    params = LocalizedPerturbationParameters(
        mode=mode,
        relative_width=0.20,
        relative_height=0.20,
        amplitude=0.10,
        noise_std=0.04,
    )
    spec = gen.generate_candidate(TriggerFamilyEnum.LOCALIZED_PERTURBATION, params, random_seed=12345)
    pattern = gen.synthesize_pattern(spec, target_shape=(64, 64, 3))

    assert pattern.pattern_array.shape == (64, 64, 3)
    assert pattern.mask_array.shape == (64, 64)
    assert np.any(pattern.mask_array > 0.0)


def test_standard_grid_all_families():
    """Verify standard bounded grid generation for all 4 families."""
    gen = TriggerCandidateGenerator()
    for fam in [
        TriggerFamilyEnum.SPATIAL_PATCH,
        TriggerFamilyEnum.COLOR_PATTERN_PATCH,
        TriggerFamilyEnum.TEXTURE_GRID,
        TriggerFamilyEnum.LOCALIZED_PERTURBATION,
    ]:
        candidates = gen.generate_standard_grid(fam, count=4)
        assert len(candidates) == 4
        # All candidate hashes must be distinct
        hashes = [c.candidate_hash for c in candidates]
        assert len(set(hashes)) == 4
        # Sorted by candidate_hash
        assert hashes == sorted(hashes)


def test_serialization_and_deserialization_roundtrip():
    """Candidate specification model_dump / model_validate roundtrip must preserve identity."""
    spec = create_candidate_spec(
        TriggerFamilyEnum.COLOR_PATTERN_PATCH,
        {"relative_width": 0.12, "relative_height": 0.12, "channel_deltas": [0.2, 0.4, -0.1]},
        random_seed=888,
    )
    dumped = spec.model_dump()
    reloaded = TriggerCandidateSpec.model_validate(dumped)

    assert reloaded.candidate_hash == spec.candidate_hash
    assert reloaded.parameters == spec.parameters
    assert reloaded.candidate_family == spec.candidate_family

