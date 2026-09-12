"""AIVARA Backdoor & Trigger Analysis Subsystem (Phase 9).

Provides:
  - Safe, deterministic trigger candidate representation and generation (Phase 9.2)
  - Controlled clean vs triggered evaluation and transformation engine (Phase 9.3)
  - Empirical control comparison and statistical activation analysis (Phase 9.4)
  - Bounded spatial grid localization (Phase 9.5)
  - Cryptographic evidence synthesis and provenance ledger sealing (Phase 9.6)
  - Project-scoped REST APIs, task orchestration, and SSE broadcasting (Phase 9.7)
"""

from __future__ import annotations

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
)
from aivara.backdoor.activation.exceptions import (
    ActivationCriteriaError,
    BackdoorActivationError,
    ConditionGenerationError,
    InvalidExperimentConfigError,
    ModelIntegrityFailureError,
    SourceInputIntegrityError,
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
from aivara.backdoor.transformation.models import (
    TransformationMetadata,
    TransformationResult,
)

__all__ = [
    # Candidate Enums & Models
    "BlendModeEnum",
    "ColorSpaceEnum",
    "CornerLocationEnum",
    "PatchShapeEnum",
    "PerturbationModeEnum",
    "PlacementModeEnum",
    "TexturePrimitiveEnum",
    "TriggerFamilyEnum",
    "ValueRangeEnum",
    "SpatialPatchParameters",
    "ColorPatternPatchParameters",
    "TextureGridParameters",
    "LocalizedPerturbationParameters",
    "PlacementSpec",
    "InputConstraints",
    "TriggerCandidateSpec",
    "GeneratedPattern",
    # Candidate Exceptions & Generator
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
    "MAX_CANDIDATES",
    "TriggerCandidateGenerator",
    "create_candidate_spec",
    # Transformation Enums, Engine & Models
    "InputLayoutEnum",
    "TRANSFORMATION_ENGINE_VERSION",
    "TriggerTransformationEngine",
    "transform_input",
    "TransformationMetadata",
    "TransformationResult",
    "CandidateInputMismatchError",
    "InvalidInputError",
    "InvalidPlacementError",
    "NonFiniteInputError",
    "TransformationBudgetExceededError",
    "TransformationNumericalError",
    "TriggerTransformationError",
    "UnsupportedDtypeError",
    "UnsupportedInputShapeError",
    # Activation Enums, Engine & Models
    "BackdoorConditionEnum",
    "BackdoorComparisonStatusEnum",
    "ActivationCriterionTypeEnum",
    "ActivationDecisionEnum",
    "ACTIVATION_ENGINE_VERSION",
    "MIN_SUPPORT_SAMPLE_COUNT",
    "MAX_EVALUATION_SAMPLES",
    "TriggerActivationEngine",
    "ActivationCriterionSpec",
    "PairedConditionResult",
    "PairedObservation",
    "TriggerActivationAssessment",
    "BackdoorActivationError",
    "InvalidExperimentConfigError",
    "ConditionGenerationError",
    "ActivationCriteriaError",
    "ModelIntegrityFailureError",
    "SourceInputIntegrityError",
]
