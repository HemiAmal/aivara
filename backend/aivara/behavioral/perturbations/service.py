"""Controlled Perturbation Engine and Experiment Service (Phase 8.4)."""

from __future__ import annotations

from datetime import datetime, timezone
import math
from typing import Any, Dict, List, Optional, Tuple, Union
import numpy as np

from aivara.behavioral.perturbations.identity import (
    compute_experiment_id,
    compute_input_array_hash,
    compute_perturbation_id,
)
from aivara.behavioral.perturbations.schemas import (
    DEFAULT_PERTURBATION_LIMITS,
    BrightnessParams,
    ContrastParams,
    GaussianBlurParams,
    GaussianNoiseParams,
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
from aivara.behavioral.perturbations.transforms import (
    apply_brightness,
    apply_contrast,
    apply_gaussian_blur,
    apply_gaussian_noise,
    apply_jpeg_compression,
    apply_spatial_translation,
    apply_uniform_noise,
)


class ControlledPerturbationEngine:
    """Deterministic, bounded, model-agnostic controlled input perturbation service."""

    def __init__(
        self,
        limits: PerturbationLimits = DEFAULT_PERTURBATION_LIMITS,
        implementation_version: str = "1.0.0",
    ) -> None:
        self.limits = limits
        self.implementation_version = implementation_version

    def apply_perturbation(
        self,
        image: np.ndarray,
        specification: PerturbationSpecification,
        declared_range: Optional[Tuple[float, float]] = None,
    ) -> PerturbationResult:
        """Apply a single controlled perturbation to an input image with strict immutability and bounds enforcement.

        Args:
            image: Source image numpy ndarray (uint8 or floating-point).
            specification: Typed PerturbationSpecification defining transform and parameters.
            declared_range: Optional known value range [min, max] for floating-point inputs.

        Returns:
            Sealed PerturbationResult domain object.
        """
        # 1. Validate Input Structure and Size
        if not isinstance(image, np.ndarray):
            return PerturbationResult(
                status=PerturbationResultStatus.UNSUPPORTED_INPUT,
                perturbation_id="0" * 64,
                source_input_hash="0" * 64,
                error_message=f"Input must be a numpy ndarray, got {type(image)}",
            )

        if image.size > self.limits.max_image_elements:
            return PerturbationResult(
                status=PerturbationResultStatus.RESOURCE_LIMIT,
                perturbation_id="0" * 64,
                source_input_hash="0" * 64,
                error_message=f"Image size {image.size} elements exceeds ceiling {self.limits.max_image_elements}",
            )

        if not (image.dtype == np.uint8 or np.issubdtype(image.dtype, np.floating)):
            return PerturbationResult(
                status=PerturbationResultStatus.UNSUPPORTED_INPUT,
                perturbation_id="0" * 64,
                source_input_hash="0" * 64,
                error_message=f"Unsupported dtype {image.dtype}. Only uint8 and floating-point are supported.",
            )

        # Check for NaN / Inf in source input
        if np.issubdtype(image.dtype, np.floating) and not np.all(np.isfinite(image)):
            return PerturbationResult(
                status=PerturbationResultStatus.UNVERIFIABLE_INPUT,
                perturbation_id="0" * 64,
                source_input_hash="0" * 64,
                error_message="Source input array contains non-finite values (NaN or Inf).",
            )

        # Compute canonical source input hash
        source_input_hash = compute_input_array_hash(image)

        # 2. Validate Parameters Against Schemas & Limits
        p_type = specification.perturbation_type
        raw_params = dict(specification.parameters)
        if specification.seed is not None:
            raw_params["seed"] = specification.seed

        parsed_params: Any = None
        try:
            if p_type == PerturbationType.GAUSSIAN_NOISE:
                parsed_params = GaussianNoiseParams(**raw_params)
                if parsed_params.std > self.limits.max_noise_std:
                    raise ValueError(f"std ({parsed_params.std}) exceeds limit {self.limits.max_noise_std}")
            elif p_type == PerturbationType.UNIFORM_NOISE:
                parsed_params = UniformNoiseParams(**raw_params)
                amp = parsed_params.max_val - parsed_params.min_val
                if amp > self.limits.max_noise_amplitude:
                    raise ValueError(f"Uniform noise amplitude ({amp}) exceeds limit {self.limits.max_noise_amplitude}")
            elif p_type == PerturbationType.BRIGHTNESS:
                parsed_params = BrightnessParams(**raw_params)
                if not (self.limits.min_brightness_factor <= parsed_params.factor <= self.limits.max_brightness_factor):
                    raise ValueError(f"Brightness factor {parsed_params.factor} out of bounds")
            elif p_type == PerturbationType.CONTRAST:
                parsed_params = ContrastParams(**raw_params)
                if not (self.limits.min_contrast_factor <= parsed_params.factor <= self.limits.max_contrast_factor):
                    raise ValueError(f"Contrast factor {parsed_params.factor} out of bounds")
            elif p_type == PerturbationType.GAUSSIAN_BLUR:
                parsed_params = GaussianBlurParams(**raw_params)
                if parsed_params.kernel_size > self.limits.max_blur_kernel_size:
                    raise ValueError(f"kernel_size {parsed_params.kernel_size} exceeds {self.limits.max_blur_kernel_size}")
                if parsed_params.sigma > self.limits.max_blur_sigma:
                    raise ValueError(f"sigma {parsed_params.sigma} exceeds {self.limits.max_blur_sigma}")
            elif p_type == PerturbationType.JPEG_COMPRESSION:
                parsed_params = JpegCompressionParams(**raw_params)
                if not (self.limits.min_jpeg_quality <= parsed_params.quality <= self.limits.max_jpeg_quality):
                    raise ValueError(f"JPEG quality {parsed_params.quality} out of bounds")
            elif p_type == PerturbationType.SPATIAL_TRANSLATION:
                parsed_params = SpatialTranslationParams(**raw_params)
                if abs(parsed_params.dx) > self.limits.max_translation_pixels or abs(parsed_params.dy) > self.limits.max_translation_pixels:
                    raise ValueError(f"Translation offset ({parsed_params.dx}, {parsed_params.dy}) exceeds limit {self.limits.max_translation_pixels}")
            else:
                return PerturbationResult(
                    status=PerturbationResultStatus.INVALID_PARAMETER,
                    perturbation_id="0" * 64,
                    source_input_hash=source_input_hash,
                    error_message=f"Unsupported perturbation type: {p_type}",
                )
        except Exception as e:
            return PerturbationResult(
                status=PerturbationResultStatus.INVALID_PARAMETER,
                perturbation_id="0" * 64,
                source_input_hash=source_input_hash,
                error_message=f"Parameter validation failed: {str(e)}",
            )

        # 3. Deterministic Perturbation ID
        canonical_params = parsed_params.model_dump(mode="json")
        seed_val = canonical_params.get("seed", specification.seed)
        perturbation_id = compute_perturbation_id(
            source_input_hash=source_input_hash,
            perturbation_type=p_type.value,
            parameters=canonical_params,
            seed=seed_val,
            implementation_version=self.implementation_version,
        )

        # 4. Strict Immutability: Deep Copy Input
        image_copy = np.copy(image)
        orig_bytes = image.tobytes()

        # 5. Execute Allowlisted Transformation
        try:
            if p_type == PerturbationType.GAUSSIAN_NOISE:
                out_arr = apply_gaussian_noise(image_copy, parsed_params, declared_range)
            elif p_type == PerturbationType.UNIFORM_NOISE:
                out_arr = apply_uniform_noise(image_copy, parsed_params, declared_range)
            elif p_type == PerturbationType.BRIGHTNESS:
                out_arr = apply_brightness(image_copy, parsed_params, declared_range)
            elif p_type == PerturbationType.CONTRAST:
                out_arr = apply_contrast(image_copy, parsed_params, declared_range)
            elif p_type == PerturbationType.GAUSSIAN_BLUR:
                out_arr = apply_gaussian_blur(image_copy, parsed_params, declared_range)
            elif p_type == PerturbationType.JPEG_COMPRESSION:
                out_arr = apply_jpeg_compression(image_copy, parsed_params, declared_range)
            elif p_type == PerturbationType.SPATIAL_TRANSLATION:
                out_arr = apply_spatial_translation(image_copy, parsed_params, declared_range)
            else:
                raise ValueError(f"Unhandled perturbation type: {p_type}")
        except Exception as e:
            return PerturbationResult(
                status=PerturbationResultStatus.TRANSFORMATION_ERROR,
                perturbation_id=perturbation_id,
                source_input_hash=source_input_hash,
                error_message=f"Transform execution failed: {str(e)}",
            )

        # 6. Verify Source Immutability
        if image.tobytes() != orig_bytes:
            raise RuntimeError("CRITICAL: Source input was modified in-place during perturbation!")

        # 7. Check Numerical Validity of Output
        if np.issubdtype(out_arr.dtype, np.floating) and not np.all(np.isfinite(out_arr)):
            return PerturbationResult(
                status=PerturbationResultStatus.TRANSFORMATION_ERROR,
                perturbation_id=perturbation_id,
                source_input_hash=source_input_hash,
                error_message="Transformation produced non-finite values (NaN / Inf).",
            )

        perturbed_input_hash = compute_input_array_hash(out_arr)

        return PerturbationResult(
            status=PerturbationResultStatus.SUCCESS,
            perturbation_id=perturbation_id,
            source_input_hash=source_input_hash,
            perturbed_input_hash=perturbed_input_hash,
            perturbed_array=out_arr,
            execution_metadata={
                "perturbation_type": p_type.value,
                "implementation_version": self.implementation_version,
            },
        )

    def create_experiment(
        self,
        project_id: str,
        source_input_id: str,
        image: np.ndarray,
        specification: PerturbationSpecification,
        model_id: Optional[str] = None,
        declared_range: Optional[Tuple[float, float]] = None,
    ) -> Tuple[PerturbationExperiment, PerturbationResult]:
        """Create and execute a single controlled perturbation experiment binding domain identities."""
        now_iso = datetime.now(timezone.utc).isoformat()
        res = self.apply_perturbation(image, specification, declared_range=declared_range)

        src_v_min = float(np.min(image)) if image.size > 0 else 0.0
        src_v_max = float(np.max(image)) if image.size > 0 else 0.0

        res_v_min = float(np.min(res.perturbed_array)) if res.perturbed_array is not None and res.perturbed_array.size > 0 else None
        res_v_max = float(np.max(res.perturbed_array)) if res.perturbed_array is not None and res.perturbed_array.size > 0 else None

        exp_id = compute_experiment_id(
            project_id=project_id,
            source_input_id=source_input_id,
            source_input_hash=res.source_input_hash,
            perturbation_id=res.perturbation_id,
            model_id=model_id,
        )

        experiment = PerturbationExperiment(
            experiment_id=exp_id,
            project_id=project_id,
            model_id=model_id,
            source_input_id=source_input_id,
            source_input_hash=res.source_input_hash,
            perturbation_id=res.perturbation_id,
            perturbation_type=specification.perturbation_type,
            parameters=specification.parameters,
            seed=specification.seed,
            implementation_version=self.implementation_version,
            input_shape=list(image.shape),
            input_dtype=str(image.dtype),
            output_shape=list(res.perturbed_array.shape) if res.perturbed_array is not None else None,
            output_dtype=str(res.perturbed_array.dtype) if res.perturbed_array is not None else None,
            source_value_range=[src_v_min, src_v_max],
            result_value_range=[res_v_min, res_v_max] if res_v_min is not None and res_v_max is not None else None,
            status=res.status,
            created_at=now_iso,
        )

        return experiment, res

    def run_standard_perturbation_suite(
        self,
        project_id: str,
        source_input_id: str,
        image: np.ndarray,
        model_id: Optional[str] = None,
        declared_range: Optional[Tuple[float, float]] = None,
        base_seed: int = 42,
    ) -> List[Tuple[PerturbationExperiment, PerturbationResult]]:
        """Run a canonical suite of standard perturbations covering all 7 supported transforms."""
        suite_specs = [
            # Gaussian Noise (light, moderate)
            PerturbationSpecification(
                perturbation_type=PerturbationType.GAUSSIAN_NOISE,
                parameters={"mean": 0.0, "std": 0.02, "seed": base_seed},
                seed=base_seed,
            ),
            PerturbationSpecification(
                perturbation_type=PerturbationType.GAUSSIAN_NOISE,
                parameters={"mean": 0.0, "std": 0.08, "seed": base_seed + 1},
                seed=base_seed + 1,
            ),
            # Uniform Noise
            PerturbationSpecification(
                perturbation_type=PerturbationType.UNIFORM_NOISE,
                parameters={"min_val": -0.05, "max_val": 0.05, "seed": base_seed + 2},
                seed=base_seed + 2,
            ),
            # Brightness (darken, brighten)
            PerturbationSpecification(
                perturbation_type=PerturbationType.BRIGHTNESS,
                parameters={"factor": 0.8},
            ),
            PerturbationSpecification(
                perturbation_type=PerturbationType.BRIGHTNESS,
                parameters={"factor": 1.25},
            ),
            # Contrast (reduce, increase)
            PerturbationSpecification(
                perturbation_type=PerturbationType.CONTRAST,
                parameters={"factor": 0.75},
            ),
            PerturbationSpecification(
                perturbation_type=PerturbationType.CONTRAST,
                parameters={"factor": 1.3},
            ),
            # Gaussian Blur (mild, moderate)
            PerturbationSpecification(
                perturbation_type=PerturbationType.GAUSSIAN_BLUR,
                parameters={"kernel_size": 3, "sigma": 1.0},
            ),
            PerturbationSpecification(
                perturbation_type=PerturbationType.GAUSSIAN_BLUR,
                parameters={"kernel_size": 5, "sigma": 2.0},
            ),
            # JPEG Compression (high quality, moderate compression)
            PerturbationSpecification(
                perturbation_type=PerturbationType.JPEG_COMPRESSION,
                parameters={"quality": 85},
            ),
            PerturbationSpecification(
                perturbation_type=PerturbationType.JPEG_COMPRESSION,
                parameters={"quality": 50},
            ),
            # Spatial Translation (small shifts)
            PerturbationSpecification(
                perturbation_type=PerturbationType.SPATIAL_TRANSLATION,
                parameters={"dx": 2, "dy": 2, "border_policy": "REPLICATE"},
            ),
            PerturbationSpecification(
                perturbation_type=PerturbationType.SPATIAL_TRANSLATION,
                parameters={"dx": -2, "dy": 0, "border_policy": "REPLICATE"},
            ),
        ]

        if len(suite_specs) > self.limits.max_perturbations_per_experiment:
            raise ValueError(f"Suite size {len(suite_specs)} exceeds limit {self.limits.max_perturbations_per_experiment}")

        results: List[Tuple[PerturbationExperiment, PerturbationResult]] = []
        for spec in suite_specs:
            exp, res = self.create_experiment(
                project_id=project_id,
                source_input_id=source_input_id,
                image=image,
                specification=spec,
                model_id=model_id,
                declared_range=declared_range,
            )
            results.append((exp, res))

        return results
