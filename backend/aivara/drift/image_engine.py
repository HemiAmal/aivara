"""Authoritative Image Distribution Shift Analysis Engine.

Extracts deterministic structural, photometric, and quality descriptors from image populations,
evaluates statistical two-sample divergence via Phase 11.3 StatisticalDriftEngine,
and synthesizes image-level drift profiles, localization, findings, and cryptographic identities.
"""

from __future__ import annotations

import hashlib
from typing import Any, Dict, List, Optional, Sequence, Tuple

from aivara.crypto.canonical import canonicalize
from aivara.drift.engine import StatisticalDriftEngine
from aivara.drift.enums import (
    BoundaryEvaluationStatus,
    DataModality,
    DriftImpactLevel,
    FeatureDriftCategory,
    FeatureType,
    ShiftDecisionState,
    StatisticalMethod,
)
from aivara.drift.exceptions import (
    DistributionBoundaryError,
    IncompatiblePopulationError,
    ProjectMismatchError,
)
from aivara.drift.image_descriptors import (
    MAX_IMAGE_PIXELS,
    MAX_POPULATION_IMAGES,
    extract_population_descriptors,
)
from aivara.drift.schemas import (
    CategoricalDriftResult,
    ComparisonBoundaryResult,
    FeatureDriftProfile,
    ImageDriftProfile,
    ImagePopulationAccounting,
    StatisticalAnalysisConfig,
    StatisticalAnalysisResult,
)


def compute_image_drift_profile_hash(canonical_dict: Dict[str, Any]) -> str:
    """Compute cryptographic SHA-256 digest over canonical RFC 8785 image drift profile descriptor."""
    canonical_bytes = canonicalize(canonical_dict)
    return hashlib.sha256(canonical_bytes).hexdigest()


# Descriptor categorization mappings
DIMENSION_DESCRIPTORS = {"width", "height", "aspect_ratio", "channels", "file_size_bytes"}
PIXEL_DESCRIPTORS = {
    "mean_intensity",
    "std_intensity",
    "brightness",
    "rms_contrast",
    "r_mean",
    "g_mean",
    "b_mean",
    "r_std",
    "g_std",
    "b_std",
    "mean_saturation",
}
QUALITY_DESCRIPTORS = {"entropy", "sharpness_laplacian_var", "clipping_ratio"}


class ImageDistributionShiftAnalyzer:
    """Authoritative analyzer for image-domain distribution shift analysis."""

    def __init__(
        self,
        statistical_engine: Optional[StatisticalDriftEngine] = None,
        top_k_descriptors: int = 20,
    ) -> None:
        self.statistical_engine = statistical_engine or StatisticalDriftEngine()
        self.top_k_descriptors = top_k_descriptors

    def analyze(
        self,
        boundary_result: ComparisonBoundaryResult,
        reference_images: Sequence[Any],
        target_images: Sequence[Any],
        *,
        config: Optional[StatisticalAnalysisConfig] = None,
        max_images: int = MAX_POPULATION_IMAGES,
        max_pixels: int = MAX_IMAGE_PIXELS,
    ) -> ImageDriftProfile:
        """Perform comprehensive image distribution shift analysis across populations.

        Extracts deterministic descriptors, runs Phase 11.3 statistical engine,
        localizes shifts across dimensions/pixels/quality/format, and generates evidence/findings.
        """
        # 1. Modality & Boundary validation
        contract = boundary_result.contract
        if contract.modality != DataModality.IMAGE:
            raise IncompatiblePopulationError(
                f"Modality must be '{DataModality.IMAGE.value}', found '{contract.modality.value}'."
            )

        if boundary_result.status != BoundaryEvaluationStatus.VALID:
            if boundary_result.status == BoundaryEvaluationStatus.PROJECT_MISMATCH:
                raise ProjectMismatchError("Cannot analyze image drift across mismatched project boundaries.")
            return self._create_fail_closed_profile(
                boundary_result=boundary_result,
                status=ShiftDecisionState.INVALID,
                accounting=ImagePopulationAccounting(
                    reference_total_images=len(reference_images),
                    target_total_images=len(target_images),
                ),
                warnings=[f"Boundary status is {boundary_result.status.value}."],
            )

        active_config = config or self.statistical_engine.default_config
        warnings: List[str] = list(boundary_result.warnings)
        limitations: List[str] = []

        # 2. Extract population descriptors and error accounting
        ref_descriptors, ref_acc = extract_population_descriptors(
            list(reference_images), max_images=max_images, max_pixels=max_pixels
        )
        tgt_descriptors, tgt_acc = extract_population_descriptors(
            list(target_images), max_images=max_images, max_pixels=max_pixels
        )

        accounting = ImagePopulationAccounting(
            reference_total_images=ref_acc["total"],
            reference_analyzable_images=ref_acc["analyzable"],
            reference_corrupt_images=ref_acc["corrupt"],
            reference_unsupported_images=ref_acc["unsupported"],
            reference_missing_images=ref_acc["missing"],
            target_total_images=tgt_acc["total"],
            target_analyzable_images=tgt_acc["analyzable"],
            target_corrupt_images=tgt_acc["corrupt"],
            target_unsupported_images=tgt_acc["unsupported"],
            target_missing_images=tgt_acc["missing"],
        )

        if ref_acc["corrupt"] > 0 or tgt_acc["corrupt"] > 0:
            warnings.append(
                f"Corrupt images detected: {ref_acc['corrupt']} reference, {tgt_acc['corrupt']} target."
            )
        if ref_acc["missing"] > 0 or tgt_acc["missing"] > 0:
            warnings.append(
                f"Missing images detected: {ref_acc['missing']} reference, {tgt_acc['missing']} target."
            )
        if ref_acc["unsupported"] > 0 or tgt_acc["unsupported"] > 0:
            warnings.append(
                f"Unsupported images detected: {ref_acc['unsupported']} reference, {tgt_acc['unsupported']} target."
            )

        # 3. Check for sufficient analyzable samples
        if (
            ref_acc["analyzable"] < active_config.min_sample_size
            or tgt_acc["analyzable"] < active_config.min_sample_size
        ):
            return self._create_fail_closed_profile(
                boundary_result=boundary_result,
                status=ShiftDecisionState.INSUFFICIENT_DATA,
                accounting=accounting,
                warnings=warnings
                + [
                    f"Analyzable image count below minimum {active_config.min_sample_size}: "
                    f"reference={ref_acc['analyzable']}, target={tgt_acc['analyzable']}."
                ],
            )

        # 4. Prepare feature sets for Phase 11.3 statistical evaluation
        # Separate numerical columns from categorical format column
        numerical_ref: Dict[str, Sequence[float]] = {
            k: v for k, v in ref_descriptors.items() if k != "format"
        }
        numerical_tgt: Dict[str, Sequence[float]] = {
            k: v for k, v in tgt_descriptors.items() if k != "format"
        }

        # Format column evaluation
        format_ref = ref_descriptors.get("format", [])
        format_tgt = tgt_descriptors.get("format", [])
        has_format = len(format_ref) > 0 and len(format_tgt) > 0

        # Execute Phase 11.3 Statistical Engine
        statistical_result: StatisticalAnalysisResult = self.statistical_engine.evaluate_boundary(
            boundary_result=boundary_result,
            reference_features=numerical_ref,
            target_features=numerical_tgt,
            reference_labels=format_ref if has_format else None,
            target_labels=format_tgt if has_format else None,
            config=active_config,
        )

        # 5. Extract format drift
        format_drift: Optional[CategoricalDriftResult] = statistical_result.categorical_results.get("class_labels")

        # 6. Profile & localize each numerical image descriptor
        dimension_drift: Dict[str, FeatureDriftProfile] = {}
        pixel_drift: Dict[str, FeatureDriftProfile] = {}
        quality_drift: Dict[str, FeatureDriftProfile] = {}
        all_descriptor_profiles: Dict[str, FeatureDriftProfile] = {}

        for name, fr in statistical_result.feature_results.items():
            impact = self._map_descriptor_impact(fr.status, fr.effect_size)
            f_profile = FeatureDriftProfile(
                schema_version="1.0",
                feature_id=name,
                feature_name=name,
                feature_type=FeatureType.NUMERICAL,
                category=FeatureDriftCategory.COVARIATE_NUMERICAL,
                method=fr.method,
                statistic_value=fr.statistic_value,
                raw_p_value=fr.raw_p_value,
                adjusted_p_value=fr.adjusted_p_value,
                effect_size=fr.effect_size,
                effect_size_metric=fr.effect_size_metric,
                significance_status=fr.is_statistically_significant,
                practical_significance_status=fr.is_practically_significant,
                shift_status=fr.status,
                impact_level=impact,
                rank=1,
                reference_count=fr.reference_sample_count,
                target_count=fr.target_sample_count,
                details=fr.details,
                limitations=[],
            )

            all_descriptor_profiles[name] = f_profile

            if name in DIMENSION_DESCRIPTORS:
                dimension_drift[name] = f_profile
            elif name in PIXEL_DESCRIPTORS:
                pixel_drift[name] = f_profile
            elif name in QUALITY_DESCRIPTORS:
                quality_drift[name] = f_profile

        # 7. Deterministic Ranking
        ranked_profiles = self._rank_descriptors(all_descriptor_profiles)
        top_shifted = [
            p for p in ranked_profiles if p.shift_status != ShiftDecisionState.NO_SHIFT_DETECTED
        ][: self.top_k_descriptors]
        if not top_shifted:
            top_shifted = ranked_profiles[: min(5, len(ranked_profiles))]

        # Re-index all profiles with updated ranks
        updated_profiles_dict = {p.feature_name: p for p in ranked_profiles}
        for k in dimension_drift:
            dimension_drift[k] = updated_profiles_dict[k]
        for k in pixel_drift:
            pixel_drift[k] = updated_profiles_dict[k]
        for k in quality_drift:
            quality_drift[k] = updated_profiles_dict[k]

        # 8. Summary counts and global status
        total_eval = len(all_descriptor_profiles) + (1 if format_drift is not None else 0)
        sig_count = sum(1 for p in ranked_profiles if p.significance_status)
        mat_count = sum(1 for p in ranked_profiles if p.shift_status == ShiftDecisionState.MATERIAL_SHIFT)

        if format_drift:
            if format_drift.is_statistically_significant:
                sig_count += 1
            if format_drift.status == ShiftDecisionState.MATERIAL_SHIFT:
                mat_count += 1

        global_status = statistical_result.global_status

        # 9. Findings and Evidence Synthesis
        findings, evidence_records = self._generate_findings_and_evidence(
            boundary_result=boundary_result,
            statistical_result=statistical_result,
            global_status=global_status,
            accounting=accounting,
            total_evaluated=total_eval,
            sig_count=sig_count,
            mat_count=mat_count,
            top_shifted=top_shifted,
            format_drift=format_drift,
        )

        # 10. Cryptographic Profile Digest
        descriptor_for_hash = {
            "accounting": accounting.to_canonical_dict(),
            "analysis_version": "1.0",
            "comparison_boundary_hash": boundary_result.comparison_boundary_hash,
            "dimension_drift_keys": sorted(dimension_drift.keys()),
            "format_drift_present": format_drift is not None,
            "global_status": global_status.value,
            "materially_shifted_descriptor_count": mat_count,
            "pixel_drift_keys": sorted(pixel_drift.keys()),
            "project_id": contract.project_id,
            "quality_drift_keys": sorted(quality_drift.keys()),
            "reference_dataset_id": contract.reference_dataset_id,
            "schema_version": "1.0",
            "statistical_analysis_hash": statistical_result.analysis_result_hash,
            "statistically_significant_descriptor_count": sig_count,
            "target_dataset_id": contract.target_dataset_id,
            "total_descriptors_evaluated": total_eval,
        }
        profile_hash = compute_image_drift_profile_hash(descriptor_for_hash)

        return ImageDriftProfile(
            schema_version="1.0",
            analysis_version="1.0",
            comparison_boundary_hash=boundary_result.comparison_boundary_hash,
            statistical_analysis_hash=statistical_result.analysis_result_hash,
            image_drift_profile_hash=profile_hash,
            project_id=contract.project_id,
            reference_dataset_id=contract.reference_dataset_id,
            target_dataset_id=contract.target_dataset_id,
            global_status=global_status,
            accounting=accounting,
            format_drift=format_drift,
            dimension_drift=dimension_drift,
            pixel_drift=pixel_drift,
            quality_drift=quality_drift,
            all_descriptor_profiles=updated_profiles_dict,
            top_shifted_descriptors=top_shifted,
            materially_shifted_descriptor_count=mat_count,
            statistically_significant_descriptor_count=sig_count,
            total_descriptors_evaluated=total_eval,
            warnings=sorted(list(set(warnings))),
            limitations=limitations,
            findings=findings,
            evidence_records=evidence_records,
        )

    def _map_descriptor_impact(self, status: ShiftDecisionState, effect_size: float) -> DriftImpactLevel:
        """Map image descriptor shift status and effect size to an operational impact level."""
        if status == ShiftDecisionState.MATERIAL_SHIFT:
            if effect_size >= 0.25:
                return DriftImpactLevel.HIGH
            return DriftImpactLevel.MEDIUM
        elif status == ShiftDecisionState.SIGNIFICANT_SHIFT:
            return DriftImpactLevel.LOW
        elif status == ShiftDecisionState.SHIFT_DETECTED:
            return DriftImpactLevel.MEDIUM
        else:
            return DriftImpactLevel.NEGLIGIBLE

    def _rank_descriptors(self, profiles: Dict[str, FeatureDriftProfile]) -> List[FeatureDriftProfile]:
        """Deterministically rank image descriptor profiles by shift severity, effect size, and name."""
        status_priority = {
            ShiftDecisionState.MATERIAL_SHIFT: 4,
            ShiftDecisionState.SHIFT_DETECTED: 3,
            ShiftDecisionState.SIGNIFICANT_SHIFT: 2,
            ShiftDecisionState.NO_SHIFT_DETECTED: 1,
            ShiftDecisionState.INSUFFICIENT_DATA: 0,
            ShiftDecisionState.UNVERIFIABLE: 0,
            ShiftDecisionState.INVALID: 0,
        }

        sorted_list = sorted(
            profiles.values(),
            key=lambda p: (
                -status_priority.get(p.shift_status, 0),
                -float(p.effect_size),
                p.feature_name,
            ),
        )

        ranked: List[FeatureDriftProfile] = []
        for rank_idx, p in enumerate(sorted_list, start=1):
            ranked.append(p.model_copy(update={"rank": rank_idx}))

        return ranked

    def _create_fail_closed_profile(
        self,
        boundary_result: ComparisonBoundaryResult,
        status: ShiftDecisionState,
        accounting: ImagePopulationAccounting,
        warnings: List[str],
    ) -> ImageDriftProfile:
        """Create a fail-closed image drift profile on invalid boundary or insufficient samples."""
        contract = boundary_result.contract
        dummy_stat_hash = "0" * 64
        descriptor_for_hash = {
            "accounting": accounting.to_canonical_dict(),
            "analysis_version": "1.0",
            "comparison_boundary_hash": boundary_result.comparison_boundary_hash,
            "dimension_drift_keys": [],
            "format_drift_present": False,
            "global_status": status.value,
            "materially_shifted_descriptor_count": 0,
            "pixel_drift_keys": [],
            "project_id": contract.project_id,
            "quality_drift_keys": [],
            "reference_dataset_id": contract.reference_dataset_id,
            "schema_version": "1.0",
            "statistical_analysis_hash": dummy_stat_hash,
            "statistically_significant_descriptor_count": 0,
            "target_dataset_id": contract.target_dataset_id,
            "total_descriptors_evaluated": 0,
        }
        res_hash = compute_image_drift_profile_hash(descriptor_for_hash)

        return ImageDriftProfile(
            schema_version="1.0",
            analysis_version="1.0",
            comparison_boundary_hash=boundary_result.comparison_boundary_hash,
            statistical_analysis_hash=dummy_stat_hash,
            image_drift_profile_hash=res_hash,
            project_id=contract.project_id,
            reference_dataset_id=contract.reference_dataset_id,
            target_dataset_id=contract.target_dataset_id,
            global_status=status,
            accounting=accounting,
            warnings=warnings,
            limitations=["Image distribution shift analysis aborted due to fail-closed state."],
            findings=[],
            evidence_records=[],
        )

    def _generate_findings_and_evidence(
        self,
        boundary_result: ComparisonBoundaryResult,
        statistical_result: StatisticalAnalysisResult,
        global_status: ShiftDecisionState,
        accounting: ImagePopulationAccounting,
        total_evaluated: int,
        sig_count: int,
        mat_count: int,
        top_shifted: List[FeatureDriftProfile],
        format_drift: Optional[CategoricalDriftResult],
    ) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        """Synthesize standard FindingModel and EvidenceModel records without mutating schemas."""
        contract = boundary_result.contract
        findings: List[Dict[str, Any]] = []
        evidence_records: List[Dict[str, Any]] = []

        affected_asset_id = contract.target_dataset_version_id or contract.target_dataset_id
        affected_asset_type = "dataset_version" if contract.target_dataset_version_id else "dataset"

        if global_status == ShiftDecisionState.MATERIAL_SHIFT:
            severity = "high"
            disposition = "review"
            confidence = 0.95
        elif global_status == ShiftDecisionState.SIGNIFICANT_SHIFT:
            severity = "medium"
            disposition = "review"
            confidence = 0.85
        elif global_status == ShiftDecisionState.SHIFT_DETECTED:
            severity = "low"
            disposition = "review"
            confidence = 0.75
        else:
            severity = "info"
            disposition = "accept"
            confidence = 0.99

        top_names = [p.feature_name for p in top_shifted if p.shift_status == ShiftDecisionState.MATERIAL_SHIFT]
        top_summary = f" (Shifted descriptors: {', '.join(top_names[:5])})" if top_names else ""

        finding = {
            "project_id": contract.project_id,
            "engine_id": "image_distribution_shift_analyzer",
            "engine_version": "1.0",
            "evidence_layer": "detection",
            "finding_type": "image_distribution_shift",
            "title": f"Image Distribution Shift Analysis: {global_status.value}",
            "description": (
                f"Image distribution shift analysis evaluated {total_evaluated} image descriptors "
                f"across {accounting.reference_analyzable_images} reference and "
                f"{accounting.target_analyzable_images} target images: {sig_count} statistically significant, "
                f"{mat_count} materially shifted{top_summary}."
            ),
            "severity": severity,
            "confidence": confidence,
            "affected_asset_type": affected_asset_type,
            "affected_asset_id": affected_asset_id,
            "disposition": disposition,
            "analysis_mode": "image_descriptor_two_sample",
            "recommendation": (
                "Review localized physical image shifts (dimensions, brightness, contrast, entropy, format) "
                "and assess downstream visual model robustness. "
                "Note: Image distribution shift measures population divergence and is NOT proof of malicious manipulation, "
                "data poisoning, or model failure."
            ),
            "metadata_json": {
                "comparison_boundary_hash": boundary_result.comparison_boundary_hash,
                "statistical_analysis_hash": statistical_result.analysis_result_hash,
                "global_status": global_status.value,
                "materially_shifted_count": mat_count,
                "statistically_significant_count": sig_count,
                "total_evaluated": total_evaluated,
                "reference_analyzable_images": accounting.reference_analyzable_images,
                "target_analyzable_images": accounting.target_analyzable_images,
                "corrupt_images": accounting.reference_corrupt_images + accounting.target_corrupt_images,
            },
        }
        findings.append(finding)

        evidence_data = {
            "comparison_boundary_hash": boundary_result.comparison_boundary_hash,
            "statistical_analysis_hash": statistical_result.analysis_result_hash,
            "global_status": global_status.value,
            "accounting": accounting.to_canonical_dict(),
            "total_evaluated": total_evaluated,
            "materially_shifted_count": mat_count,
            "statistically_significant_count": sig_count,
            "top_shifted_descriptors": [
                {
                    "name": p.feature_name,
                    "rank": p.rank,
                    "effect_size": p.effect_size,
                    "status": p.shift_status.value,
                    "impact": p.impact_level.value,
                }
                for p in top_shifted
            ],
            "format_drift": (
                {
                    "tvd": format_drift.tvd,
                    "jsd": format_drift.jsd,
                    "status": format_drift.status.value,
                    "unseen_formats": format_drift.unseen_target_classes,
                    "missing_formats": format_drift.missing_target_classes,
                }
                if format_drift is not None
                else None
            ),
        }
        evidence_bytes = canonicalize(evidence_data)
        evidence_hash = hashlib.sha256(evidence_bytes).hexdigest()

        evidence = {
            "evidence_layer": "detection",
            "evidence_type": "image_distribution_shift_evidence",
            "title": "Image Distribution Shift Localization Evidence",
            "description": (
                f"Deterministic image descriptor distribution comparison for boundary "
                f"{boundary_result.comparison_boundary_hash[:16]}."
            ),
            "data_json": evidence_data,
            "confidence": confidence,
            "evidence_hash": evidence_hash,
        }
        evidence_records.append(evidence)

        return findings, evidence_records
