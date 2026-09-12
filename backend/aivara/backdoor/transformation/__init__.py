"""AIVARA Trigger Transformation Engine Subsystem (Phase 9.3)."""

from aivara.backdoor.transformation.blending import apply_blend_and_clip
from aivara.backdoor.transformation.engine import (
    TRANSFORMATION_ENGINE_VERSION,
    TriggerTransformationEngine,
    transform_input,
)
from aivara.backdoor.transformation.enums import InputLayoutEnum
from aivara.backdoor.transformation.exceptions import (
    CandidateInputMismatchError,
    InvalidInputError,
    InvalidPlacementError,
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
from aivara.backdoor.transformation.models import (
    TransformationMetadata,
    TransformationResult,
)
from aivara.backdoor.transformation.validators import (
    MAX_BATCH_SIZE,
    MAX_ELEMENTS_PER_ARRAY,
    MAX_SPATIAL_DIM,
    MIN_SPATIAL_DIM,
    SUPPORTED_CHANNELS,
    SUPPORTED_DTYPES,
    validate_input_array,
)

__all__ = [
    # Enums
    "InputLayoutEnum",
    # Engine & Helpers
    "TRANSFORMATION_ENGINE_VERSION",
    "TriggerTransformationEngine",
    "transform_input",
    # Blending
    "apply_blend_and_clip",
    # Models
    "TransformationMetadata",
    "TransformationResult",
    # Identity
    "compute_input_array_hash",
    "compute_transformation_id",
    # Validators & Constants
    "MAX_BATCH_SIZE",
    "MAX_ELEMENTS_PER_ARRAY",
    "MAX_SPATIAL_DIM",
    "MIN_SPATIAL_DIM",
    "SUPPORTED_CHANNELS",
    "SUPPORTED_DTYPES",
    "validate_input_array",
    # Exceptions
    "CandidateInputMismatchError",
    "InvalidInputError",
    "InvalidPlacementError",
    "NonFiniteInputError",
    "TransformationBudgetExceededError",
    "TransformationNumericalError",
    "TriggerTransformationError",
    "UnsupportedDtypeError",
    "UnsupportedInputShapeError",
]
