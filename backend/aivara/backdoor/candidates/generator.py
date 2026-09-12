"""Deterministic Trigger Candidate Generator and Batch Management (Phase 9.2)."""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Set, Tuple, Union
import numpy as np

from aivara.backdoor.candidates.enums import (
    CornerLocationEnum,
    PatchShapeEnum,
    PerturbationModeEnum,
    PlacementModeEnum,
    TexturePrimitiveEnum,
    TriggerFamilyEnum,
)
from aivara.backdoor.candidates.exceptions import (
    BackdoorCandidateError,
    CandidateBudgetExceededError,
    CandidateOutOfBoundsError,
    DuplicateCandidateError,
    InvalidCandidateParameterError,
    InvalidCandidateTypeError,
    SecurityValidationError,
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
    validate_finite_number,
    validate_seed,
)

# Hard limit frozen by Phase 9.1 ADR-064
MAX_CANDIDATES: int = 16

# Supported parameter model mappings
FAMILY_PARAMETER_MODELS = {
    TriggerFamilyEnum.SPATIAL_PATCH: SpatialPatchParameters,
    TriggerFamilyEnum.COLOR_PATTERN_PATCH: ColorPatternPatchParameters,
    TriggerFamilyEnum.TEXTURE_GRID: TextureGridParameters,
    TriggerFamilyEnum.LOCALIZED_PERTURBATION: LocalizedPerturbationParameters,
}


def create_candidate_spec(
    candidate_family: Union[TriggerFamilyEnum, str],
    parameters: Union[Dict[str, Any], SpatialPatchParameters, ColorPatternPatchParameters, TextureGridParameters, LocalizedPerturbationParameters],
    placement: Optional[Union[PlacementSpec, Dict[str, Any]]] = None,
    input_constraints: Optional[Union[InputConstraints, Dict[str, Any]]] = None,
    random_seed: int = 42,
    candidate_id: Optional[str] = None,
    schema_version: str = "1.0.0",
    transformation_version: str = "1.0.0",
) -> TriggerCandidateSpec:
    """Create and validate a single deterministic TriggerCandidateSpec.

    Computes canonical RFC 8785 JCS SHA-256 candidate_hash.
    """
    if isinstance(candidate_family, str):
        try:
            family_enum = TriggerFamilyEnum(candidate_family.upper())
        except ValueError:
            raise InvalidCandidateTypeError(
                f"Unsupported trigger family '{candidate_family}'. "
                f"Supported v1 families: {[f.value for f in TriggerFamilyEnum]}."
            )
    else:
        family_enum = candidate_family

    if family_enum not in FAMILY_PARAMETER_MODELS:
        raise InvalidCandidateTypeError(f"Trigger family '{family_enum}' is not in frozen v1 set.")

    # Validate family parameters using the typed Pydantic parameter model
    param_model_cls = FAMILY_PARAMETER_MODELS[family_enum]
    if isinstance(parameters, dict):
        try:
            validated_params = param_model_cls(**parameters)
        except Exception as e:
            raise InvalidCandidateParameterError(
                f"Parameter validation failed for {family_enum.value}: {e}",
                details={"family": family_enum.value, "error": str(e)},
            ) from e
    elif isinstance(parameters, param_model_cls):
        validated_params = parameters
    else:
        raise InvalidCandidateParameterError(
            f"Expected parameter object of type {param_model_cls.__name__}, got {type(parameters).__name__}."
        )

    # Validate placement
    if placement is None:
        placement_obj = PlacementSpec()
    elif isinstance(placement, dict):
        placement_obj = PlacementSpec(**placement)
    elif isinstance(placement, PlacementSpec):
        placement_obj = placement
    else:
        raise InvalidCandidateParameterError(f"Invalid placement spec type: {type(placement).__name__}.")

    # Validate input constraints
    if input_constraints is None:
        constraints_obj = InputConstraints()
    elif isinstance(input_constraints, dict):
        constraints_obj = InputConstraints(**input_constraints)
    elif isinstance(input_constraints, InputConstraints):
        constraints_obj = input_constraints
    else:
        raise InvalidCandidateParameterError(f"Invalid input_constraints type: {type(input_constraints).__name__}.")

    # Validate seed
    validated_seed = validate_seed(random_seed)

    # Prepare raw dict for identity hash
    params_dict = validated_params.model_dump()
    candidate_data = {
        "schema_version": schema_version,
        "candidate_family": family_enum.value,
        "parameters": params_dict,
        "placement": placement_obj,
        "input_constraints": constraints_obj,
        "random_seed": validated_seed,
        "transformation_version": transformation_version,
    }

    candidate_hash = compute_candidate_identity_hash(candidate_data)

    cid = candidate_id or f"tc-{family_enum.value.lower()[:4]}-{candidate_hash[:12]}"

    return TriggerCandidateSpec(
        schema_version=schema_version,
        candidate_id=cid,
        candidate_family=family_enum,
        parameters=params_dict,
        placement=placement_obj,
        input_constraints=constraints_obj,
        random_seed=validated_seed,
        transformation_version=transformation_version,
        candidate_hash=candidate_hash,
    )


class TriggerCandidateGenerator:
    """Deterministic generator for synthetic trigger candidate specifications and patterns."""

    def __init__(self, max_candidates: int = MAX_CANDIDATES) -> None:
        if max_candidates > MAX_CANDIDATES or max_candidates < 1:
            raise CandidateBudgetExceededError(
                f"Configured max_candidates ({max_candidates}) violates frozen bounds [1, {MAX_CANDIDATES}]."
            )
        self.max_candidates = max_candidates

    def generate_candidate(
        self,
        candidate_family: Union[TriggerFamilyEnum, str],
        parameters: Union[Dict[str, Any], SpatialPatchParameters, ColorPatternPatchParameters, TextureGridParameters, LocalizedPerturbationParameters],
        placement: Optional[Union[PlacementSpec, Dict[str, Any]]] = None,
        input_constraints: Optional[Union[InputConstraints, Dict[str, Any]]] = None,
        random_seed: int = 42,
        candidate_id: Optional[str] = None,
    ) -> TriggerCandidateSpec:
        """Generate and validate a single deterministic TriggerCandidateSpec."""
        return create_candidate_spec(
            candidate_family=candidate_family,
            parameters=parameters,
            placement=placement,
            input_constraints=input_constraints,
            random_seed=random_seed,
            candidate_id=candidate_id,
        )

    def generate_candidates(
        self,
        spec_requests: List[Dict[str, Any]],
    ) -> List[TriggerCandidateSpec]:
        """Validate and create a batch of candidate specifications.

        Enforces:
          1. Batch size <= max_candidates (fail closed if exceeded).
          2. Duplicate detection (reject duplicate candidate hashes).
          3. Deterministic ordering sorted by candidate_hash.
        """
        if len(spec_requests) > self.max_candidates:
            raise CandidateBudgetExceededError(
                f"Requested candidate count ({len(spec_requests)}) exceeds maximum budget limit ({self.max_candidates})."
            )

        candidates: List[TriggerCandidateSpec] = []
        seen_hashes: Set[str] = set()

        for req in spec_requests:
            spec = create_candidate_spec(
                candidate_family=req["candidate_family"],
                parameters=req["parameters"],
                placement=req.get("placement"),
                input_constraints=req.get("input_constraints"),
                random_seed=req.get("random_seed", 42),
                candidate_id=req.get("candidate_id"),
            )
            if spec.candidate_hash in seen_hashes:
                raise DuplicateCandidateError(
                    f"Duplicate candidate detected with identity hash '{spec.candidate_hash}'.",
                    details={"candidate_hash": spec.candidate_hash, "candidate_id": spec.candidate_id},
                )
            seen_hashes.add(spec.candidate_hash)
            candidates.append(spec)

        # Enforce deterministic ordering by candidate_hash
        candidates.sort(key=lambda c: c.candidate_hash)
        return candidates

    def generate_standard_grid(
        self,
        candidate_family: Union[TriggerFamilyEnum, str],
        base_parameters: Optional[Dict[str, Any]] = None,
        base_seed: int = 42,
        count: int = 4,
    ) -> List[TriggerCandidateSpec]:
        """Generate a standard bounded grid of candidates across distinct corners/parameters.

        Bounded by max_candidates <= 16.
        """
        if count > self.max_candidates or count < 1:
            raise CandidateBudgetExceededError(
                f"Requested count ({count}) violates bounds [1, {self.max_candidates}]."
            )

        family = (
            TriggerFamilyEnum(candidate_family.upper())
            if isinstance(candidate_family, str)
            else candidate_family
        )

        corners = [
            CornerLocationEnum.BOTTOM_RIGHT,
            CornerLocationEnum.TOP_LEFT,
            CornerLocationEnum.TOP_RIGHT,
            CornerLocationEnum.BOTTOM_LEFT,
        ]

        specs: List[Dict[str, Any]] = []

        if family == TriggerFamilyEnum.SPATIAL_PATCH:
            for i in range(count):
                corner = corners[i % len(corners)]
                params = dict(base_parameters or {})
                params.setdefault("relative_width", 0.08)
                params.setdefault("relative_height", 0.08)
                params.setdefault("fill_color", [1.0, 1.0, 1.0])
                specs.append({
                    "candidate_family": family,
                    "parameters": params,
                    "placement": {"mode": PlacementModeEnum.FIXED_CORNER, "corner": corner},
                    "random_seed": base_seed + i,
                })

        elif family == TriggerFamilyEnum.COLOR_PATTERN_PATCH:
            for i in range(count):
                corner = corners[i % len(corners)]
                params = dict(base_parameters or {})
                params.setdefault("relative_width", 0.10)
                params.setdefault("relative_height", 0.10)
                params.setdefault("channel_deltas", [0.4 * (1 if i % 2 == 0 else -1), 0.3, -0.3])
                specs.append({
                    "candidate_family": family,
                    "parameters": params,
                    "placement": {"mode": PlacementModeEnum.FIXED_CORNER, "corner": corner},
                    "random_seed": base_seed + i,
                })

        elif family == TriggerFamilyEnum.TEXTURE_GRID:
            primitives = [
                TexturePrimitiveEnum.CHECKER,
                TexturePrimitiveEnum.GRID,
                TexturePrimitiveEnum.STRIPE_HORIZONTAL,
                TexturePrimitiveEnum.STRIPE_VERTICAL,
            ]
            for i in range(count):
                prim = primitives[i % len(primitives)]
                params = dict(base_parameters or {})
                params.setdefault("primitive", prim.value)
                params.setdefault("stride_pixels", 8 * (i + 1))
                params.setdefault("amplitude", 0.20)
                specs.append({
                    "candidate_family": family,
                    "parameters": params,
                    "random_seed": base_seed + i,
                })

        elif family == TriggerFamilyEnum.LOCALIZED_PERTURBATION:
            for i in range(count):
                corner = corners[i % len(corners)]
                params = dict(base_parameters or {})
                params.setdefault("relative_width", 0.15)
                params.setdefault("relative_height", 0.15)
                params.setdefault("amplitude", 0.08)
                params.setdefault("noise_std", 0.04)
                specs.append({
                    "candidate_family": family,
                    "parameters": params,
                    "placement": {"mode": PlacementModeEnum.FIXED_CORNER, "corner": corner},
                    "random_seed": base_seed + (i * 1000),
                })
        else:
            raise InvalidCandidateTypeError(f"Unsupported candidate family: {family}")

        return self.generate_candidates(specs)

    def synthesize_pattern(
        self,
        candidate_spec: TriggerCandidateSpec,
        target_shape: Tuple[int, int, int] = (224, 224, 3),
    ) -> GeneratedPattern:
        """Synthesize concrete numerical pattern and mask arrays from a candidate specification.

        Guarantees deterministic pattern output given (candidate_spec, target_shape).
        """
        # Resource boundary checks on target shape
        if len(target_shape) != 3:
            raise CandidateOutOfBoundsError(
                f"Target shape must be a 3-tuple (H, W, C), got {target_shape}."
            )
        H, W, C = target_shape
        if H < 16 or H > 4096 or W < 16 or W > 4096 or C < 1 or C > 4:
            raise CandidateOutOfBoundsError(
                f"Target dimensions {(H, W, C)} exceed safe computational domain ([16, 4096], [16, 4096], [1, 4])."
            )

        family = candidate_spec.candidate_family
        params_dict = candidate_spec.parameters
        placement = candidate_spec.placement
        seed = candidate_spec.random_seed

        if family == TriggerFamilyEnum.SPATIAL_PATCH:
            params = SpatialPatchParameters(**params_dict)
            pattern, mask = generate_spatial_patch_pattern(params, placement, target_shape)

        elif family == TriggerFamilyEnum.COLOR_PATTERN_PATCH:
            params = ColorPatternPatchParameters(**params_dict)
            pattern, mask = generate_color_pattern_patch(params, placement, target_shape)

        elif family == TriggerFamilyEnum.TEXTURE_GRID:
            params = TextureGridParameters(**params_dict)
            pattern, mask = generate_texture_grid_pattern(params, target_shape)

        elif family == TriggerFamilyEnum.LOCALIZED_PERTURBATION:
            params = LocalizedPerturbationParameters(**params_dict)
            pattern, mask = generate_localized_perturbation_pattern(params, placement, target_shape, seed)

        else:
            raise InvalidCandidateTypeError(f"Unsupported family: {family}")

        return GeneratedPattern(
            candidate_spec=candidate_spec,
            target_shape=target_shape,
            pattern_array=pattern,
            mask_array=mask,
        )
