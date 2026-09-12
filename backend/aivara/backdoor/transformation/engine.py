"""Deterministic Trigger Transformation Engine (Phase 9.3)."""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple, Union
import numpy as np

from aivara.backdoor.candidates.enums import (
    BlendModeEnum,
    PerturbationModeEnum,
    TriggerFamilyEnum,
    ValueRangeEnum,
)
from aivara.backdoor.candidates.generator import TriggerCandidateGenerator
from aivara.backdoor.candidates.models import PlacementSpec, TriggerCandidateSpec
from aivara.backdoor.transformation.blending import apply_blend_and_clip
from aivara.backdoor.transformation.enums import InputLayoutEnum
from aivara.backdoor.transformation.exceptions import (
    CandidateInputMismatchError,
    InvalidInputError,
    TriggerTransformationError,
)
from aivara.backdoor.transformation.identity import (
    compute_input_array_hash,
    compute_transformation_id,
)
from aivara.backdoor.transformation.models import (
    TransformationMetadata,
    TransformationResult,
)
from aivara.backdoor.transformation.validators import validate_input_array

TRANSFORMATION_ENGINE_VERSION: str = "1.0.0"


class TriggerTransformationEngine:
    """Deterministic, safe transformation engine for applying trigger candidates to inputs."""

    def __init__(self, version: str = TRANSFORMATION_ENGINE_VERSION) -> None:
        self.version = version
        self._candidate_generator = TriggerCandidateGenerator()

    def transform(
        self,
        input_array: np.ndarray,
        candidate_spec: TriggerCandidateSpec,
        placement: Optional[PlacementSpec] = None,
        input_layout: Optional[Union[InputLayoutEnum, str]] = None,
    ) -> TransformationResult:
        """Apply a trigger candidate to an in-memory input array.

        Guarantees:
          - Source input is never mutated in place.
          - Output layout strictly matches input layout (ADR-087).
          - Transformation identity deterministically binds source hash, candidate hash, placement, input_layout, and version.
        """
        if not isinstance(input_array, np.ndarray):
            raise InvalidInputError(f"Expected numpy.ndarray, got '{type(input_array).__name__}'.")

        # 1. Capture source input hash before any operation
        source_input_hash = compute_input_array_hash(input_array)

        # 2. Validate input array against candidate constraints and resolve layout
        resolved_layout, (H, W), C, N = validate_input_array(
            input_array, candidate_spec, declared_layout=input_layout
        )

        # 3. Resolve effective placement
        effective_placement = placement or candidate_spec.placement

        # 4. Extract blending parameters
        params = candidate_spec.parameters
        raw_blend_mode = params.get("blend_mode", BlendModeEnum.REPLACE)
        blend_mode = (
            raw_blend_mode
            if isinstance(raw_blend_mode, BlendModeEnum)
            else BlendModeEnum(raw_blend_mode)
        )
        alpha = float(params.get("alpha", 1.0))
        value_range = candidate_spec.input_constraints.value_range

        is_multiplicative = False
        if candidate_spec.candidate_family == TriggerFamilyEnum.LOCALIZED_PERTURBATION:
            raw_mode = params.get("mode", PerturbationModeEnum.ADDITIVE_GAUSSIAN)
            pert_mode = (
                raw_mode
                if isinstance(raw_mode, PerturbationModeEnum)
                else PerturbationModeEnum(raw_mode)
            )
            if pert_mode == PerturbationModeEnum.MULTIPLICATIVE_UNIFORM:
                is_multiplicative = True

        # 5. Synthesize trigger pattern for spatial canvas (H, W, C)
        synth_c = max(1, min(4, C))
        synth_spec = candidate_spec
        if placement is not None:
            synth_spec = candidate_spec.model_copy(update={"placement": placement})

        gen_pattern = self._candidate_generator.synthesize_pattern(
            candidate_spec=synth_spec,
            target_shape=(H, W, synth_c),
        )
        pattern_slice = gen_pattern.pattern_array  # (H, W, synth_c)
        mask_slice = gen_pattern.mask_array        # (H, W)

        clipping_occurred = False
        original_dtype = input_array.dtype

        # 6. Apply transformation according to resolved layout
        if resolved_layout == InputLayoutEnum.GRAYSCALE_2D:
            # (H, W) -> expand to (H, W, 1)
            src_3d = input_array[:, :, np.newaxis].astype(np.float32)
            transformed_3d, clip_flag = apply_blend_and_clip(
                source_slice=src_3d,
                pattern_slice=pattern_slice,
                mask_slice=mask_slice,
                blend_mode=blend_mode,
                alpha=alpha,
                value_range=value_range,
                is_multiplicative=is_multiplicative,
            )
            clipping_occurred = clip_flag
            transformed_arr = transformed_3d[:, :, 0].astype(original_dtype)

        elif resolved_layout == InputLayoutEnum.HWC:
            # (H, W, C)
            src_hwc = input_array.astype(np.float32)
            transformed_hwc, clip_flag = apply_blend_and_clip(
                source_slice=src_hwc,
                pattern_slice=pattern_slice,
                mask_slice=mask_slice,
                blend_mode=blend_mode,
                alpha=alpha,
                value_range=value_range,
                is_multiplicative=is_multiplicative,
            )
            clipping_occurred = clip_flag
            transformed_arr = transformed_hwc.astype(original_dtype)

        elif resolved_layout == InputLayoutEnum.CHW:
            # (C, H, W) -> transpose to (H, W, C) for transformation, then restore (C, H, W)
            src_hwc = np.transpose(input_array, (1, 2, 0)).astype(np.float32)
            transformed_hwc, clip_flag = apply_blend_and_clip(
                source_slice=src_hwc,
                pattern_slice=pattern_slice,
                mask_slice=mask_slice,
                blend_mode=blend_mode,
                alpha=alpha,
                value_range=value_range,
                is_multiplicative=is_multiplicative,
            )
            clipping_occurred = clip_flag
            transformed_arr = np.transpose(transformed_hwc, (2, 0, 1)).astype(original_dtype)

        elif resolved_layout == InputLayoutEnum.NHWC:
            # (N, H, W, C)
            N_count = input_array.shape[0]
            transformed_list = []
            for i in range(N_count):
                sample = input_array[i].astype(np.float32)
                transformed_sample, clip_flag = apply_blend_and_clip(
                    source_slice=sample,
                    pattern_slice=pattern_slice,
                    mask_slice=mask_slice,
                    blend_mode=blend_mode,
                    alpha=alpha,
                    value_range=value_range,
                    is_multiplicative=is_multiplicative,
                )
                clipping_occurred = clipping_occurred or clip_flag
                transformed_list.append(transformed_sample.astype(original_dtype))
            transformed_arr = np.stack(transformed_list, axis=0)

        elif resolved_layout == InputLayoutEnum.NCHW:
            # (N, C, H, W)
            N_count = input_array.shape[0]
            transformed_list = []
            for i in range(N_count):
                sample = input_array[i]
                src_hwc = np.transpose(sample, (1, 2, 0)).astype(np.float32)
                transformed_hwc, clip_flag = apply_blend_and_clip(
                    source_slice=src_hwc,
                    pattern_slice=pattern_slice,
                    mask_slice=mask_slice,
                    blend_mode=blend_mode,
                    alpha=alpha,
                    value_range=value_range,
                    is_multiplicative=is_multiplicative,
                )
                clipping_occurred = clipping_occurred or clip_flag
                transformed_sample = np.transpose(transformed_hwc, (2, 0, 1)).astype(original_dtype)
                transformed_list.append(transformed_sample)
            transformed_arr = np.stack(transformed_list, axis=0)
        else:
            raise TriggerTransformationError(f"Unsupported layout {resolved_layout}.")

        # 7. Strictly verify source immutability
        source_after_hash = compute_input_array_hash(input_array)
        if source_after_hash != source_input_hash:
            raise TriggerTransformationError("Critical failure: Source input array was mutated in place.")

        # 8. Compute output hash and transformation identity binding input_layout (ADR-087)
        transformed_input_hash = compute_input_array_hash(transformed_arr)
        transformation_id = compute_transformation_id(
            source_input_hash=source_input_hash,
            candidate_hash=candidate_spec.candidate_hash,
            placement=effective_placement.model_dump(),
            input_layout=resolved_layout,
            transformation_version=self.version,
        )

        metadata_dict = {
            "transformation_id": transformation_id,
            "transformation_version": self.version,
            "candidate_hash": candidate_spec.candidate_hash,
            "candidate_family": candidate_spec.candidate_family.value,
            "source_input_hash": source_input_hash,
            "transformed_input_hash": transformed_input_hash,
            "input_shape": list(input_array.shape),
            "output_shape": list(transformed_arr.shape),
            "input_dtype": str(original_dtype),
            "output_dtype": str(transformed_arr.dtype),
            "input_layout": resolved_layout.value,
            "output_layout": resolved_layout.value,
            "clipping_occurred": clipping_occurred,
            "random_seed": candidate_spec.random_seed,
            "blend_mode": blend_mode.value,
            "alpha": alpha,
        }

        return TransformationResult(
            transformation_id=transformation_id,
            transformation_version=self.version,
            source_input_hash=source_input_hash,
            transformed_input_hash=transformed_input_hash,
            candidate_hash=candidate_spec.candidate_hash,
            candidate_family=candidate_spec.candidate_family,
            input_shape=input_array.shape,
            output_shape=transformed_arr.shape,
            input_dtype=str(original_dtype),
            output_dtype=str(transformed_arr.dtype),
            input_layout=resolved_layout,
            output_layout=resolved_layout,
            placement=effective_placement,
            clipping_occurred=clipping_occurred,
            transformed_array=transformed_arr,
            transformation_metadata=metadata_dict,
        )

    def transform_batch(
        self,
        input_batch: Union[np.ndarray, List[np.ndarray]],
        candidate_spec: TriggerCandidateSpec,
        placement: Optional[PlacementSpec] = None,
        input_layout: Optional[Union[InputLayoutEnum, str]] = None,
    ) -> List[TransformationResult]:
        """Apply a trigger candidate to multiple individual arrays or a batched array."""
        if isinstance(input_batch, np.ndarray) and input_batch.ndim == 4:
            results = []
            N = input_batch.shape[0]
            # When breaking down 4D array into individual samples, resolve 3D layout (NHWC -> HWC, NCHW -> CHW)
            sample_layout: Optional[InputLayoutEnum] = None
            if input_layout is not None:
                parsed_layout = (
                    input_layout
                    if isinstance(input_layout, InputLayoutEnum)
                    else InputLayoutEnum(input_layout.upper())
                )
                sample_layout = InputLayoutEnum.HWC if parsed_layout == InputLayoutEnum.NHWC else InputLayoutEnum.CHW

            for i in range(N):
                results.append(self.transform(input_batch[i], candidate_spec, placement, input_layout=sample_layout))
            return results
        elif isinstance(input_batch, list):
            return [self.transform(arr, candidate_spec, placement, input_layout=input_layout) for arr in input_batch]
        else:
            return [self.transform(input_batch, candidate_spec, placement, input_layout=input_layout)]


def transform_input(
    input_array: np.ndarray,
    candidate_spec: TriggerCandidateSpec,
    placement: Optional[PlacementSpec] = None,
    input_layout: Optional[Union[InputLayoutEnum, str]] = None,
) -> TransformationResult:
    """Convenience functional interface to transform an input array with a trigger candidate."""
    engine = TriggerTransformationEngine()
    return engine.transform(input_array, candidate_spec, placement, input_layout=input_layout)
