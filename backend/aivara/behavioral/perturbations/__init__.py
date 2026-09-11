"""AIVARA Controlled Perturbation & Sensitivity Experiment Engine (Phase 8.4)."""

from aivara.behavioral.perturbations.identity import (
    compute_experiment_id,
    compute_input_array_hash,
    compute_perturbation_id,
)
from aivara.behavioral.perturbations.schemas import (
    DEFAULT_PERTURBATION_LIMITS,
    BorderPolicy,
    BrightnessParams,
    ContrastParams,
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
)
from aivara.behavioral.perturbations.service import ControlledPerturbationEngine
from aivara.behavioral.perturbations.transforms import (
    apply_brightness,
    apply_contrast,
    apply_gaussian_blur,
    apply_gaussian_noise,
    apply_jpeg_compression,
    apply_spatial_translation,
    apply_uniform_noise,
)

__all__ = [
    # Schemas & Enums
    "PerturbationType",
    "PerturbationResultStatus",
    "BorderPolicy",
    "ImageDType",
    "PerturbationLimits",
    "DEFAULT_PERTURBATION_LIMITS",
    "GaussianNoiseParams",
    "UniformNoiseParams",
    "BrightnessParams",
    "ContrastParams",
    "GaussianBlurParams",
    "JpegCompressionParams",
    "SpatialTranslationParams",
    "PerturbationSpecification",
    "PerturbationResult",
    "PerturbationExperiment",
    # Service
    "ControlledPerturbationEngine",
    # Identity Functions
    "compute_input_array_hash",
    "compute_perturbation_id",
    "compute_experiment_id",
    # Direct Transforms
    "apply_gaussian_noise",
    "apply_uniform_noise",
    "apply_brightness",
    "apply_contrast",
    "apply_gaussian_blur",
    "apply_jpeg_compression",
    "apply_spatial_translation",
]
