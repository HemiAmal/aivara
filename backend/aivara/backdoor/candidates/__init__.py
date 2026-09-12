"""AIVARA Trigger Candidate Representation & Generation Subsystem (Phase 9.2)."""

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
    InvalidValueRangeError,
    SecurityValidationError,
    UnsupportedCandidateConfigurationError,
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
from aivara.backdoor.candidates.patterns import (
    compute_bounding_box,
    generate_color_pattern_patch,
    generate_localized_perturbation_pattern,
    generate_spatial_patch_pattern,
    generate_texture_grid_pattern,
)
from aivara.backdoor.candidates.validators import (
    MAX_RELATIVE_HEIGHT,
    MAX_RELATIVE_RADIUS,
    MAX_RELATIVE_WIDTH,
    MIN_RELATIVE_DIMENSION,
    MIN_SEED,
    MAX_SEED,
    validate_finite_number,
    validate_normalized_coordinates,
    validate_patch_dimensions,
    validate_security_dict,
    validate_security_string,
    validate_seed,
)

__all__ = [
    # Enums
    "BlendModeEnum",
    "ColorSpaceEnum",
    "CornerLocationEnum",
    "PatchShapeEnum",
    "PerturbationModeEnum",
    "PlacementModeEnum",
    "TexturePrimitiveEnum",
    "TriggerFamilyEnum",
    "ValueRangeEnum",
    # Exceptions
    "BackdoorCandidateError",
    "CandidateBudgetExceededError",
    "CandidateOutOfBoundsError",
    "DuplicateCandidateError",
    "InvalidCandidateParameterError",
    "InvalidCandidateTypeError",
    "InvalidSeedError",
    "InvalidValueRangeError",
    "SecurityValidationError",
    "UnsupportedCandidateConfigurationError",
    # Generator & Methods
    "MAX_CANDIDATES",
    "TriggerCandidateGenerator",
    "create_candidate_spec",
    # Identity
    "compute_candidate_identity_hash",
    # Models
    "SpatialPatchParameters",
    "ColorPatternPatchParameters",
    "TextureGridParameters",
    "LocalizedPerturbationParameters",
    "PlacementSpec",
    "InputConstraints",
    "TriggerCandidateSpec",
    "GeneratedPattern",
    # Patterns
    "compute_bounding_box",
    "generate_spatial_patch_pattern",
    "generate_color_pattern_patch",
    "generate_texture_grid_pattern",
    "generate_localized_perturbation_pattern",
    # Validators
    "MAX_RELATIVE_HEIGHT",
    "MAX_RELATIVE_RADIUS",
    "MAX_RELATIVE_WIDTH",
    "MIN_RELATIVE_DIMENSION",
    "MIN_SEED",
    "MAX_SEED",
    "validate_finite_number",
    "validate_normalized_coordinates",
    "validate_patch_dimensions",
    "validate_security_dict",
    "validate_security_string",
    "validate_seed",
]
