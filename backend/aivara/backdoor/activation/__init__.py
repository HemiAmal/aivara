"""AIVARA Trigger Activation & Controlled Comparison Subsystem (Phase 9.4)."""

from aivara.backdoor.activation.activation import evaluate_activation_decision
from aivara.backdoor.activation.controls import (
    generate_location_shuffled_array,
    generate_magnitude_matched_noise_array,
)
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
from aivara.backdoor.activation.identity import (
    compute_experiment_identity,
    derive_control_seed,
)
from aivara.backdoor.activation.models import (
    ActivationCriterionSpec,
    PairedConditionResult,
    PairedObservation,
    TriggerActivationAssessment,
)

__all__ = [
    # Engine & Constants
    "ACTIVATION_ENGINE_VERSION",
    "MIN_SUPPORT_SAMPLE_COUNT",
    "MAX_EVALUATION_SAMPLES",
    "TriggerActivationEngine",
    # Activation & Controls
    "evaluate_activation_decision",
    "generate_location_shuffled_array",
    "generate_magnitude_matched_noise_array",
    # Enums
    "BackdoorConditionEnum",
    "BackdoorComparisonStatusEnum",
    "ActivationCriterionTypeEnum",
    "ActivationDecisionEnum",
    # Exceptions
    "BackdoorActivationError",
    "InvalidExperimentConfigError",
    "ConditionGenerationError",
    "ActivationCriteriaError",
    "ModelIntegrityFailureError",
    "SourceInputIntegrityError",
    # Identity
    "compute_experiment_identity",
    "derive_control_seed",
    # Models
    "ActivationCriterionSpec",
    "PairedConditionResult",
    "PairedObservation",
    "TriggerActivationAssessment",
]
