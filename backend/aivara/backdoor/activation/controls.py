"""Deterministic Control Condition Generators for Phase 9.4 (ADR-088)."""

from __future__ import annotations

from typing import Any, Dict, Optional, Tuple, Union
import numpy as np

from aivara.backdoor.candidates.enums import PatchShapeEnum, PlacementModeEnum, ValueRangeEnum
from aivara.backdoor.candidates.models import PlacementSpec, TriggerCandidateSpec
from aivara.backdoor.transformation.engine import TriggerTransformationEngine
from aivara.backdoor.transformation.enums import InputLayoutEnum
from aivara.backdoor.transformation.identity import compute_input_array_hash
from aivara.backdoor.transformation.models import TransformationResult


def generate_location_shuffled_array(
    source_array: np.ndarray,
    candidate_spec: TriggerCandidateSpec,
    seed: int,
    input_layout: Optional[Union[InputLayoutEnum, str]] = None,
    engine: Optional[TriggerTransformationEngine] = None,
) -> Tuple[TransformationResult, PlacementSpec, Dict[str, Any]]:
    """Generate location-shuffled control by randomizing placement within valid geometry bounds using PCG64(seed).

    Guarantees:
      - Preserves candidate geometry, pattern, color, and alpha.
      - Restricts randomized placement strictly within valid spatial bounds [0.0, 1.0].
      - Handles square, rectangle, circular/radius, and pattern footprints.
      - Records original and shuffled placement metadata.
    """
    trans_engine = engine or TriggerTransformationEngine()
    rng = np.random.Generator(np.random.PCG64(seed))

    # Extract geometry footprint dimensions
    params = candidate_spec.parameters
    rel_radius = params.get("relative_radius")
    if rel_radius is not None:
        rel_w = float(rel_radius) * 2.0
        rel_h = float(rel_radius) * 2.0
    else:
        rel_w = float(params.get("relative_width", 0.10))
        rel_h = float(params.get("relative_height", 0.10))

    # Bounded spatial domain for normalized position
    # normalized_x and normalized_y span [0.0, 1.0] parameterizing valid offset slack
    shuffled_x = float(rng.uniform(0.0, 1.0))
    shuffled_y = float(rng.uniform(0.0, 1.0))

    shuffled_placement = PlacementSpec(
        mode=PlacementModeEnum.NORMALIZED_POSITION,
        normalized_x=shuffled_x,
        normalized_y=shuffled_y,
    )

    result = trans_engine.transform(
        input_array=source_array,
        candidate_spec=candidate_spec,
        placement=shuffled_placement,
        input_layout=input_layout,
    )

    placement_info: Dict[str, Any] = {
        "original_placement": candidate_spec.placement.model_dump(),
        "shuffled_placement": shuffled_placement.model_dump(),
        "seed": seed,
        "placement_policy_version": "1.0.0",
        "relative_width": rel_w,
        "relative_height": rel_h,
        "candidate_family": candidate_spec.candidate_family.value,
    }

    return result, shuffled_placement, placement_info


def generate_magnitude_matched_noise_array(
    source_array: np.ndarray,
    active_triggered_array: np.ndarray,
    seed: int,
    value_range: ValueRangeEnum = ValueRangeEnum.UNIT_FLOAT,
    matching_tolerance: float = 0.25,
) -> Tuple[np.ndarray, str, Dict[str, Any]]:
    """Generate magnitude-matched noise control matching realized RMS perturbation delta.

    Explicitly computes and matches REALIZED RMS perturbation delta between
    source and active triggered array, avoiding structured trigger patterns.
    """
    # 1. Compute REALIZED RMS perturbation delta of active trigger
    diff_trig = active_triggered_array.astype(np.float64) - source_array.astype(np.float64)
    realized_trigger_rms = float(np.sqrt(np.mean(diff_trig ** 2)))

    # Degenerate case: if trigger has 0 delta, control is identical to source
    if realized_trigger_rms < 1e-9:
        clean_copy = np.ascontiguousarray(source_array.copy())
        clean_copy.flags.writeable = False
        metrics: Dict[str, Any] = {
            "trigger_perturbation_magnitude": 0.0,
            "control_perturbation_magnitude": 0.0,
            "matching_method": "REALIZED_RMS_ZERO",
            "matching_tolerance": matching_tolerance,
            "matching_error": 0.0,
            "deterministic_seed": seed,
            "status": "MATCHED",
        }
        return clean_copy, compute_input_array_hash(clean_copy), metrics

    # 2. Draw Gaussian noise with sigma = realized_trigger_rms
    rng = np.random.Generator(np.random.PCG64(seed))
    noise = rng.normal(loc=0.0, scale=realized_trigger_rms, size=source_array.shape).astype(np.float32)

    # 3. Add to source and clip according to declared value range
    noisy_array = source_array.astype(np.float32) + noise

    if value_range == ValueRangeEnum.UNIT_FLOAT:
        noisy_array = np.clip(noisy_array, 0.0, 1.0)
    elif value_range in (ValueRangeEnum.BYTE_INTEGER, "BYTE_INTEGER", "BYTE_INT"):
        noisy_array = np.clip(noisy_array, 0.0, 255.0)
    elif value_range == ValueRangeEnum.ZERO_CENTERED:
        noisy_array = np.clip(noisy_array, -1.0, 1.0)

    # 4. Compute REALIZED RMS of the resulting noise control
    diff_noise = noisy_array.astype(np.float64) - source_array.astype(np.float64)
    realized_noise_rms = float(np.sqrt(np.mean(diff_noise ** 2)))

    # 5. Iterative scaling correction if clipping reduced realized RMS
    if realized_noise_rms > 1e-9 and abs(realized_noise_rms - realized_trigger_rms) / realized_trigger_rms > 0.05:
        scale_factor = realized_trigger_rms / realized_noise_rms
        noise_adjusted = noise * scale_factor
        noisy_array = source_array.astype(np.float32) + noise_adjusted
        if value_range == ValueRangeEnum.UNIT_FLOAT:
            noisy_array = np.clip(noisy_array, 0.0, 1.0)
        elif value_range in (ValueRangeEnum.BYTE_INTEGER, "BYTE_INTEGER", "BYTE_INT"):
            noisy_array = np.clip(noisy_array, 0.0, 255.0)
        elif value_range == ValueRangeEnum.ZERO_CENTERED:
            noisy_array = np.clip(noisy_array, -1.0, 1.0)
        diff_noise = noisy_array.astype(np.float64) - source_array.astype(np.float64)
        realized_noise_rms = float(np.sqrt(np.mean(diff_noise ** 2)))

    matching_error = float(abs(realized_noise_rms - realized_trigger_rms) / realized_trigger_rms)
    match_status = "MATCHED" if matching_error <= matching_tolerance else "UNAVAILABLE"

    final_arr = np.ascontiguousarray(noisy_array.astype(source_array.dtype))
    final_arr.flags.writeable = False
    noise_hash = compute_input_array_hash(final_arr)

    metrics_dict: Dict[str, Any] = {
        "trigger_perturbation_magnitude": realized_trigger_rms,
        "control_perturbation_magnitude": realized_noise_rms,
        "matching_method": "REALIZED_RMS_GAUSSIAN",
        "matching_tolerance": matching_tolerance,
        "matching_error": matching_error,
        "deterministic_seed": seed,
        "status": match_status,
    }

    return final_arr, noise_hash, metrics_dict
