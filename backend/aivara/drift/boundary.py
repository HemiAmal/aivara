"""Authoritative Reference ↔ Target Comparison Boundary Engine and Identity Derivation."""

from __future__ import annotations

import hashlib
from typing import Any, Dict, List, Optional, Sequence, Tuple

from aivara.crypto.canonical import canonicalize
from aivara.drift.compatibility import (
    compute_feature_descriptor_hash,
    compute_label_descriptor_hash,
    compute_representation_descriptor_hash,
    validate_feature_compatibility,
    validate_image_compatibility,
    validate_label_compatibility,
    validate_representation_compatibility,
)
from aivara.drift.enums import (
    BoundaryEvaluationStatus,
    CompatibilityStatus,
    DataModality,
)
from aivara.drift.exceptions import (
    IncompatiblePopulationError,
    InsufficientDataError,
    InvalidPopulationError,
    ProjectMismatchError,
    ResourceLimitExceededError,
)
from aivara.drift.population import resolve_population_identity
from aivara.drift.schemas import (
    ComparisonBoundaryResult,
    ComparisonContract,
    FeatureSchemaDescriptor,
    ImageSchemaDescriptor,
    LabelSchemaDescriptor,
    PopulationSelector,
    RepresentationDescriptor,
    SamplingConfig,
)


class ComparisonBoundaryEngine:
    """Authoritative engine for establishing, validating, and sealing population comparison boundaries."""

    def __init__(
        self,
        min_sample_size: int = 30,
        max_sample_budget: int = 5000,
        max_feature_dim: int = 4096,
    ) -> None:
        self.min_sample_size = min_sample_size
        self.max_sample_budget = max_sample_budget
        self.max_feature_dim = max_feature_dim

    def compute_boundary_hash(self, contract: ComparisonContract) -> str:
        """Compute cryptographic SHA-256 digest over canonical RFC 8785 comparison contract descriptor."""
        canonical_dict = contract.to_canonical_dict()
        canonical_bytes = canonicalize(canonical_dict)
        return hashlib.sha256(canonical_bytes).hexdigest()

    def establish_boundary(
        self,
        *,
        project_id: str,
        reference_selector: PopulationSelector,
        reference_samples: Sequence[Dict[str, Any]],
        reference_project_id: str,
        target_selector: PopulationSelector,
        target_samples: Sequence[Dict[str, Any]],
        target_project_id: str,
        modality: DataModality = DataModality.IMAGE,
        sampling_config: Optional[SamplingConfig] = None,
        feature_descriptor: Optional[FeatureSchemaDescriptor] = None,
        target_feature_descriptor: Optional[FeatureSchemaDescriptor] = None,
        label_descriptor: Optional[LabelSchemaDescriptor] = None,
        target_label_descriptor: Optional[LabelSchemaDescriptor] = None,
        image_descriptor: Optional[ImageSchemaDescriptor] = None,
        target_image_descriptor: Optional[ImageSchemaDescriptor] = None,
        representation_descriptor: Optional[RepresentationDescriptor] = None,
        target_representation_descriptor: Optional[RepresentationDescriptor] = None,
    ) -> ComparisonBoundaryResult:
        """Establish, validate, and cryptographically seal a comparison boundary."""
        warnings: List[str] = []
        findings: List[Dict[str, Any]] = []

        # 1. Project Isolation Check
        if project_id != reference_project_id or project_id != target_project_id:
            raise ProjectMismatchError(
                f"Project tenant mismatch: request project '{project_id}', "
                f"reference project '{reference_project_id}', target project '{target_project_id}'."
            )

        # 2. Resource Limit Validation on Features
        if feature_descriptor and feature_descriptor.dimensions > self.max_feature_dim:
            raise ResourceLimitExceededError(
                f"Feature dimension ({feature_descriptor.dimensions}) exceeds limit ({self.max_feature_dim})."
            )

        # 3. Resolve Reference Population
        sampling = sampling_config or SamplingConfig(max_samples=self.max_sample_budget)
        _, ref_pop = resolve_population_identity(reference_selector, reference_samples, sampling)

        # 4. Resolve Target Population
        _, target_pop = resolve_population_identity(target_selector, target_samples, sampling)

        # 5. Check Sample Size Floors (N_min = 30)
        overall_status = BoundaryEvaluationStatus.VALID
        if ref_pop.selected_sample_count < self.min_sample_size:
            overall_status = BoundaryEvaluationStatus.INSUFFICIENT_DATA
            warnings.append(
                f"Reference population sample size ({ref_pop.selected_sample_count}) "
                f"is below minimum threshold ({self.min_sample_size})."
            )
            findings.append({
                "finding_type": "insufficient_reference_population",
                "severity": "medium",
                "description": f"Reference sample count {ref_pop.selected_sample_count} < {self.min_sample_size}.",
            })

        if target_pop.selected_sample_count < self.min_sample_size:
            overall_status = BoundaryEvaluationStatus.INSUFFICIENT_DATA
            warnings.append(
                f"Target population sample size ({target_pop.selected_sample_count}) "
                f"is below minimum threshold ({self.min_sample_size})."
            )
            findings.append({
                "finding_type": "insufficient_target_population",
                "severity": "medium",
                "description": f"Target sample count {target_pop.selected_sample_count} < {self.min_sample_size}.",
            })

        # 6. Compatibility Validations
        compat_status = CompatibilityStatus.COMPATIBLE

        # 6a. Tabular features compatibility
        if feature_descriptor and target_feature_descriptor:
            f_status, f_warns = validate_feature_compatibility(feature_descriptor, target_feature_descriptor)
            warnings.extend(f_warns)
            if f_status != CompatibilityStatus.COMPATIBLE:
                compat_status = f_status
                if overall_status == BoundaryEvaluationStatus.VALID:
                    overall_status = BoundaryEvaluationStatus.INCOMPATIBLE_INPUTS

        # 6b. Label schema compatibility
        if label_descriptor and target_label_descriptor:
            l_status, l_warns = validate_label_compatibility(label_descriptor, target_label_descriptor)
            warnings.extend(l_warns)
            if l_status == CompatibilityStatus.UNSEEN_CLASSES_PRESENT:
                findings.append({
                    "finding_type": "unseen_classes_detected",
                    "severity": "low",
                    "description": "; ".join(l_warns),
                })
                # Unseen classes is an informational/compatibility notice, not fatal unless schema broken
                if compat_status == CompatibilityStatus.COMPATIBLE:
                    compat_status = CompatibilityStatus.UNSEEN_CLASSES_PRESENT
            elif l_status != CompatibilityStatus.COMPATIBLE:
                compat_status = l_status
                if overall_status == BoundaryEvaluationStatus.VALID:
                    overall_status = BoundaryEvaluationStatus.INCOMPATIBLE_INPUTS

        # 6c. Image format compatibility
        if image_descriptor and target_image_descriptor:
            img_status, img_warns = validate_image_compatibility(image_descriptor, target_image_descriptor)
            warnings.extend(img_warns)
            if img_status != CompatibilityStatus.COMPATIBLE:
                compat_status = img_status
                if overall_status == BoundaryEvaluationStatus.VALID:
                    overall_status = BoundaryEvaluationStatus.INCOMPATIBLE_INPUTS

        # 6d. Latent representation compatibility
        if representation_descriptor and target_representation_descriptor:
            r_status, r_warns = validate_representation_compatibility(representation_descriptor, target_representation_descriptor)
            warnings.extend(r_warns)
            if r_status != CompatibilityStatus.COMPATIBLE:
                compat_status = r_status
                if overall_status == BoundaryEvaluationStatus.VALID:
                    overall_status = BoundaryEvaluationStatus.INCOMPATIBLE_INPUTS

        # 7. Compute Descriptor Hashes
        feature_hash = compute_feature_descriptor_hash(feature_descriptor)
        label_hash = compute_label_descriptor_hash(label_descriptor)
        rep_hash = compute_representation_descriptor_hash(representation_descriptor)

        # 8. Build Comparison Contract
        contract = ComparisonContract(
            project_id=project_id,
            reference_dataset_id=reference_selector.dataset_id,
            reference_dataset_version_id=reference_selector.dataset_version_id,
            target_dataset_id=target_selector.dataset_id,
            target_dataset_version_id=target_selector.dataset_version_id,
            modality=modality,
            reference_population_hash=ref_pop.population_selection_hash,
            target_population_hash=target_pop.population_selection_hash,
            reference_sample_count=ref_pop.selected_sample_count,
            target_sample_count=target_pop.selected_sample_count,
            sampling_method=sampling.method.value,
            max_samples_budget=sampling.max_samples,
            sampling_seed=sampling.seed,
            feature_descriptor_hash=feature_hash,
            label_descriptor_hash=label_hash,
            representation_descriptor_hash=rep_hash,
        )

        # 9. Compute Boundary Hash
        boundary_hash = self.compute_boundary_hash(contract)

        return ComparisonBoundaryResult(
            contract=contract,
            comparison_boundary_hash=boundary_hash,
            reference_population=ref_pop,
            target_population=target_pop,
            status=overall_status,
            compatibility_status=compat_status,
            warnings=warnings,
            findings=findings,
        )
