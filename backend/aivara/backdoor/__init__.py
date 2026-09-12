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

from aivara.backdoor.candidates.enums import (
    BlendModeEnum,
    ColorSpaceEnum,
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

__all__ = [
    "BlendModeEnum",
    "ColorSpaceEnum",
    "PatchShapeEnum",
    "PerturbationModeEnum",
    "PlacementModeEnum",
    "TexturePrimitiveEnum",
    "TriggerFamilyEnum",
    "ValueRangeEnum",
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
    "ColorPatternPatchParameters",
    "GeneratedPattern",
    "InputConstraints",
    "LocalizedPerturbationParameters",
    "PlacementSpec",
    "SpatialPatchParameters",
    "TextureGridParameters",
    "TriggerCandidateSpec",
]
