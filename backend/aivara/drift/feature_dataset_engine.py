"""Authoritative Feature & Dataset Drift Analysis Engine.

Synthesizes, localizes, ranks, and attributes distribution shift across
individual numerical features, categorical features, and class labels from Phase 11.3 results.
"""

from __future__ import annotations

import hashlib
from typing import Any, Dict, List, Optional, Sequence, Tuple

from aivara.crypto.canonical import canonicalize
from aivara.drift.enums import (
    BoundaryEvaluationStatus,
    DriftImpactLevel,
    FeatureDriftCategory,
    FeatureType,
    ShiftDecisionState,
    StatisticalMethod,
)
from aivara.drift.exceptions import (
    DistributionBoundaryError,
    ProjectMismatchError,
    ResourceLimitExceededError,
)
from aivara.drift.schemas import (
    ComparisonBoundaryResult,
    DatasetDriftProfile,
    FeatureDriftProfile,
    LabelDriftProfile,
    StatisticalAnalysisResult,
)


def compute_dataset_drift_profile_hash(canonical_dict: Dict[str, Any]) -> str:
    """Compute cryptographic SHA-256 digest over canonical RFC 8785 dataset drift profile descriptor."""
    canonical_bytes = canonicalize(canonical_dict)
    return hashlib.sha256(canonical_bytes).hexdigest()


class FeatureDatasetDriftAnalyzer:
    """Authoritative domain analyzer for feature localization and dataset-level drift synthesis."""

    def __init__(self, top_k_features: int = 20) -> None:
        self.top_k_features = top_k_features

    def analyze(
        self,
        boundary_result: ComparisonBoundaryResult,
        statistical_result: StatisticalAnalysisResult,
        *,
        feature_type_overrides: Optional[Dict[str, FeatureType]] = None,
        untestable_features: Optional[Sequence[str]] = None,
    ) -> DatasetDriftProfile:
        """Perform comprehensive feature-level localization and dataset-level drift synthesis.
        
        Consumes Phase 11.2 boundary and Phase 11.3 statistical analysis results.
        Fails closed on invalid boundaries, project mismatches, or boundary hash divergence.
        """
        # 1. Validate boundary and statistical input contracts
        if boundary_result.status != BoundaryEvaluationStatus.VALID:
            if boundary_result.status == BoundaryEvaluationStatus.PROJECT_MISMATCH:
                raise ProjectMismatchError("Cannot analyze drift across mismatched project boundaries.")
            return self._create_fail_closed_profile(
                boundary_result=boundary_result,
                statistical_result=statistical_result,
                status=ShiftDecisionState.INVALID,
                warnings=[f"Boundary status is {boundary_result.status.value}."],
            )

        if boundary_result.comparison_boundary_hash != statistical_result.comparison_boundary_hash:
            raise DistributionBoundaryError(
                f"Boundary hash mismatch: boundary has {boundary_result.comparison_boundary_hash[:16]}..., "
                f"statistical result has {statistical_result.comparison_boundary_hash[:16]}..."
            )

        if statistical_result.global_status in {
            ShiftDecisionState.INSUFFICIENT_DATA,
            ShiftDecisionState.UNVERIFIABLE,
            ShiftDecisionState.INVALID,
        }:
            return self._create_fail_closed_profile(
                boundary_result=boundary_result,
                statistical_result=statistical_result,
                status=statistical_result.global_status,
                warnings=list(statistical_result.warnings),
            )

        contract = boundary_result.contract
        type_overrides = feature_type_overrides or {}
        untestable_list = sorted(list(untestable_features or []))
        warnings: List[str] = list(statistical_result.warnings)
        limitations: List[str] = list(statistical_result.limitations)

        # 2. Numerical feature localization & profiling
        all_feature_profiles: Dict[str, FeatureDriftProfile] = {}
        affected_numerical: List[str] = []
        affected_categorical: List[str] = []

        for name, fr in statistical_result.feature_results.items():
            f_type = type_overrides.get(name, FeatureType.NUMERICAL)
            impact = self._map_feature_impact(fr.status, fr.effect_size)

            if fr.status in {ShiftDecisionState.MATERIAL_SHIFT, ShiftDecisionState.SHIFT_DETECTED}:
                affected_numerical.append(name)

            f_limitations: List[str] = []
            if fr.reference_sample_count < 50 or fr.target_sample_count < 50:
                f_limitations.append("Moderate sample size; tail sensitivity may be reduced.")

            all_feature_profiles[name] = FeatureDriftProfile(
                schema_version="1.0",
                feature_id=name,
                feature_name=name,
                feature_type=f_type,
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
                rank=1,  # Rank will be computed after collection
                reference_count=fr.reference_sample_count,
                target_count=fr.target_sample_count,
                details=fr.details,
                limitations=f_limitations,
            )

        # 3. Categorical feature localization & Label distribution analysis
        label_drift_profile: Optional[LabelDriftProfile] = None

        for name, cr in statistical_result.categorical_results.items():
            if name == "class_labels":
                label_drift_profile = self._build_label_profile(cr)
            else:
                f_type = type_overrides.get(name, FeatureType.CATEGORICAL)
                impact = self._map_categorical_impact(cr.status, cr.tvd, len(cr.unseen_target_classes))
                if cr.status in {ShiftDecisionState.MATERIAL_SHIFT, ShiftDecisionState.SHIFT_DETECTED}:
                    affected_categorical.append(name)

                all_feature_profiles[name] = FeatureDriftProfile(
                    schema_version="1.0",
                    feature_id=name,
                    feature_name=name,
                    feature_type=f_type,
                    category=FeatureDriftCategory.COVARIATE_CATEGORICAL,
                    method=StatisticalMethod.TOTAL_VARIATION_DISTANCE,
                    statistic_value=cr.tvd,
                    raw_p_value=cr.chi_square_p_value,
                    adjusted_p_value=cr.chi_square_p_value,
                    effect_size=cr.tvd,
                    effect_size_metric="tvd",
                    significance_status=cr.is_statistically_significant,
                    practical_significance_status=cr.is_practically_significant,
                    shift_status=cr.status,
                    impact_level=impact,
                    rank=1,
                    reference_count=cr.details.get("reference_sample_count", 0),
                    target_count=cr.details.get("target_sample_count", 0),
                    details=cr.details,
                    limitations=[],
                )

        # 4. Deterministic Feature Ranking
        ranked_profiles = self._rank_features(all_feature_profiles)
        top_shifted = [p for p in ranked_profiles if p.shift_status != ShiftDecisionState.NO_SHIFT_DETECTED][:self.top_k_features]
        if not top_shifted:
            top_shifted = ranked_profiles[:min(5, len(ranked_profiles))]

        # Re-index all_feature_profiles with updated ranks
        updated_profiles_dict = {p.feature_name: p for p in ranked_profiles}

        # 5. Dataset-level metrics aggregation
        total_numerical = len(statistical_result.feature_results)
        total_categorical = len(statistical_result.categorical_results)
        total_evaluated = total_numerical + total_categorical
        sig_count = sum(1 for p in ranked_profiles if p.significance_status)
        mat_count = sum(1 for p in ranked_profiles if p.shift_status == ShiftDecisionState.MATERIAL_SHIFT)

        if label_drift_profile and label_drift_profile.shift_status == ShiftDecisionState.MATERIAL_SHIFT:
            mat_count += 1
        if label_drift_profile and label_drift_profile.shift_status == ShiftDecisionState.SIGNIFICANT_SHIFT:
            sig_count += 1

        global_status = statistical_result.global_status

        # 6. Generate Findings and Evidence
        findings, evidence_records = self._generate_findings_and_evidence(
            boundary_result=boundary_result,
            statistical_result=statistical_result,
            global_status=global_status,
            total_evaluated=total_evaluated,
            sig_count=sig_count,
            mat_count=mat_count,
            top_shifted=top_shifted,
            label_profile=label_drift_profile,
            untestable_features=untestable_list,
        )

        # 7. Cryptographic Dataset Drift Profile Hash
        descriptor_for_hash = {
            "affected_categorical_features": sorted(affected_categorical),
            "affected_numerical_features": sorted(affected_numerical),
            "analysis_version": "1.0",
            "comparison_boundary_hash": boundary_result.comparison_boundary_hash,
            "global_status": global_status.value,
            "materially_shifted_feature_count": mat_count,
            "project_id": contract.project_id,
            "reference_dataset_id": contract.reference_dataset_id,
            "schema_version": "1.0",
            "statistical_analysis_hash": statistical_result.analysis_result_hash,
            "statistically_significant_feature_count": sig_count,
            "target_dataset_id": contract.target_dataset_id,
            "total_categorical_features": total_categorical,
            "total_features_evaluated": total_evaluated,
            "total_numerical_features": total_numerical,
            "untestable_feature_count": len(untestable_list),
            "untestable_features": sorted(untestable_list),
        }
        profile_hash = compute_dataset_drift_profile_hash(descriptor_for_hash)

        return DatasetDriftProfile(
            schema_version="1.0",
            analysis_version="1.0",
            comparison_boundary_hash=boundary_result.comparison_boundary_hash,
            statistical_analysis_hash=statistical_result.analysis_result_hash,
            dataset_drift_profile_hash=profile_hash,
            project_id=contract.project_id,
            reference_dataset_id=contract.reference_dataset_id,
            target_dataset_id=contract.target_dataset_id,
            global_status=global_status,
            total_features_evaluated=total_evaluated,
            total_numerical_features=total_numerical,
            total_categorical_features=total_categorical,
            statistically_significant_feature_count=sig_count,
            materially_shifted_feature_count=mat_count,
            untestable_feature_count=len(untestable_list),
            affected_numerical_features=sorted(affected_numerical),
            affected_categorical_features=sorted(affected_categorical),
            top_shifted_features=top_shifted,
            all_feature_profiles=updated_profiles_dict,
            label_drift_profile=label_drift_profile,
            untestable_features=untestable_list,
            warnings=sorted(list(set(warnings))),
            limitations=limitations,
            findings=findings,
            evidence_records=evidence_records,
        )

    def _map_feature_impact(self, status: ShiftDecisionState, effect_size: float) -> DriftImpactLevel:
        """Map numerical feature shift status and effect size to an operational impact level."""
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

    def _map_categorical_impact(self, status: ShiftDecisionState, tvd: float, unseen_count: int) -> DriftImpactLevel:
        """Map categorical shift status, TVD, and unseen classes to an operational impact level."""
        if unseen_count > 0:
            return DriftImpactLevel.CRITICAL if unseen_count >= 3 else DriftImpactLevel.HIGH
        if status == ShiftDecisionState.MATERIAL_SHIFT:
            return DriftImpactLevel.HIGH if tvd >= 0.20 else DriftImpactLevel.MEDIUM
        elif status == ShiftDecisionState.SIGNIFICANT_SHIFT:
            return DriftImpactLevel.LOW
        elif status == ShiftDecisionState.SHIFT_DETECTED:
            return DriftImpactLevel.MEDIUM
        else:
            return DriftImpactLevel.NEGLIGIBLE

    def _build_label_profile(self, cr: Any) -> LabelDriftProfile:
        """Construct detailed LabelDriftProfile from categorical evaluation result."""
        # Class imbalance calculation
        target_probs = cr.target_proportions or {}
        is_imbalanced = False
        imbalance_ratio: Optional[float] = None

        if target_probs:
            vals = [v for v in target_probs.values() if v > 0.0]
            if len(vals) > 1:
                max_p = max(vals)
                min_p = min(vals)
                imbalance_ratio = max_p / min_p if min_p > 1e-6 else 100.0
                if imbalance_ratio >= 10.0:
                    is_imbalanced = True

        impact = self._map_categorical_impact(cr.status, cr.tvd, len(cr.unseen_target_classes))

        return LabelDriftProfile(
            schema_version="1.0",
            attribute_name=cr.attribute_name,
            chi_square_statistic=cr.chi_square_statistic,
            chi_square_p_value=cr.chi_square_p_value,
            degrees_of_freedom=cr.degrees_of_freedom,
            tvd=cr.tvd,
            jsd=cr.jsd,
            reference_proportions=cr.reference_proportions,
            target_proportions=cr.target_proportions,
            unseen_classes=cr.unseen_target_classes,
            missing_classes=cr.missing_target_classes,
            is_imbalanced=is_imbalanced,
            imbalance_ratio=imbalance_ratio,
            shift_status=cr.status,
            impact_level=impact,
            details=cr.details,
        )

    def _rank_features(self, profiles: Dict[str, FeatureDriftProfile]) -> List[FeatureDriftProfile]:
        """Deterministically rank feature profiles by shift severity, effect size, and feature name."""
        status_priority = {
            ShiftDecisionState.MATERIAL_SHIFT: 4,
            ShiftDecisionState.SHIFT_DETECTED: 3,
            ShiftDecisionState.SIGNIFICANT_SHIFT: 2,
            ShiftDecisionState.NO_SHIFT_DETECTED: 1,
            ShiftDecisionState.INSUFFICIENT_DATA: 0,
            ShiftDecisionState.UNVERIFIABLE: 0,
            ShiftDecisionState.INVALID: 0,
        }

        # Sort key: priority desc, effect_size desc, feature_name asc
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
            ranked.append(
                p.model_copy(update={"rank": rank_idx})
            )

        return ranked

    def _create_fail_closed_profile(
        self,
        boundary_result: ComparisonBoundaryResult,
        statistical_result: StatisticalAnalysisResult,
        status: ShiftDecisionState,
        warnings: List[str],
    ) -> DatasetDriftProfile:
        """Create fail-closed dataset drift profile on invalid boundary or statistical failure."""
        contract = boundary_result.contract
        descriptor_for_hash = {
            "affected_categorical_features": [],
            "affected_numerical_features": [],
            "analysis_version": "1.0",
            "comparison_boundary_hash": boundary_result.comparison_boundary_hash,
            "global_status": status.value,
            "materially_shifted_feature_count": 0,
            "project_id": contract.project_id,
            "reference_dataset_id": contract.reference_dataset_id,
            "schema_version": "1.0",
            "statistical_analysis_hash": statistical_result.analysis_result_hash,
            "statistically_significant_feature_count": 0,
            "target_dataset_id": contract.target_dataset_id,
            "total_categorical_features": 0,
            "total_features_evaluated": 0,
            "total_numerical_features": 0,
            "untestable_feature_count": 0,
            "untestable_features": [],
        }
        res_hash = compute_dataset_drift_profile_hash(descriptor_for_hash)

        return DatasetDriftProfile(
            schema_version="1.0",
            analysis_version="1.0",
            comparison_boundary_hash=boundary_result.comparison_boundary_hash,
            statistical_analysis_hash=statistical_result.analysis_result_hash,
            dataset_drift_profile_hash=res_hash,
            project_id=contract.project_id,
            reference_dataset_id=contract.reference_dataset_id,
            target_dataset_id=contract.target_dataset_id,
            global_status=status,
            total_features_evaluated=0,
            total_numerical_features=0,
            total_categorical_features=0,
            statistically_significant_feature_count=0,
            materially_shifted_feature_count=0,
            untestable_feature_count=0,
            warnings=warnings,
            limitations=["Analysis aborted due to fail-closed status."],
            findings=[],
            evidence_records=[],
        )

    def _generate_findings_and_evidence(
        self,
        boundary_result: ComparisonBoundaryResult,
        statistical_result: StatisticalAnalysisResult,
        global_status: ShiftDecisionState,
        total_evaluated: int,
        sig_count: int,
        mat_count: int,
        top_shifted: List[FeatureDriftProfile],
        label_profile: Optional[LabelDriftProfile],
        untestable_features: List[str],
    ) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        """Synthesize standard FindingModel and EvidenceModel records without modifying schemas."""
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

        # Dataset-level synthesis finding
        top_names = [p.feature_name for p in top_shifted if p.shift_status == ShiftDecisionState.MATERIAL_SHIFT]
        top_summary = f" (Key shifted dimensions: {', '.join(top_names[:5])})" if top_names else ""

        dataset_finding = {
            "project_id": contract.project_id,
            "engine_id": "feature_dataset_drift_analyzer",
            "engine_version": "1.0",
            "evidence_layer": "detection",
            "finding_type": "feature_dataset_drift",
            "title": f"Feature & Dataset Drift Localization: {global_status.value}",
            "description": (
                f"Feature-level distribution shift attribution evaluated {total_evaluated} dimensions: "
                f"{sig_count} statistically significant after multiple-testing correction, "
                f"{mat_count} meeting material effect size criteria{top_summary}."
            ),
            "severity": severity,
            "confidence": confidence,
            "affected_asset_type": affected_asset_type,
            "affected_asset_id": affected_asset_id,
            "disposition": disposition,
            "analysis_mode": "feature_localization",
            "recommendation": (
                "Review localized feature divergence and evaluate downstream model sensitivity on affected dimensions. "
                "Note: Feature drift reflects population divergence and is not proof of dataset compromise or malicious intent."
            ),
            "metadata_json": {
                "comparison_boundary_hash": boundary_result.comparison_boundary_hash,
                "statistical_analysis_hash": statistical_result.analysis_result_hash,
                "global_status": global_status.value,
                "materially_shifted_count": mat_count,
                "statistically_significant_count": sig_count,
                "total_evaluated": total_evaluated,
                "untestable_feature_count": len(untestable_features),
            },
        }
        findings.append(dataset_finding)

        # Dataset-level evidence record
        evidence_data = {
            "comparison_boundary_hash": boundary_result.comparison_boundary_hash,
            "statistical_analysis_hash": statistical_result.analysis_result_hash,
            "global_status": global_status.value,
            "total_evaluated": total_evaluated,
            "materially_shifted_count": mat_count,
            "statistically_significant_count": sig_count,
            "top_shifted_features": [
                {
                    "name": p.feature_name,
                    "rank": p.rank,
                    "type": p.feature_type.value,
                    "effect_size": p.effect_size,
                    "status": p.shift_status.value,
                    "impact": p.impact_level.value,
                }
                for p in top_shifted
            ],
            "label_drift": (
                {
                    "tvd": label_profile.tvd,
                    "jsd": label_profile.jsd,
                    "status": label_profile.shift_status.value,
                    "unseen_classes": label_profile.unseen_classes,
                    "missing_classes": label_profile.missing_classes,
                    "is_imbalanced": label_profile.is_imbalanced,
                }
                if label_profile is not None
                else None
            ),
            "untestable_features": untestable_features,
        }
        evidence_bytes = canonicalize(evidence_data)
        evidence_hash = hashlib.sha256(evidence_bytes).hexdigest()

        dataset_evidence = {
            "evidence_layer": "detection",
            "evidence_type": "feature_dataset_drift_evidence",
            "title": "Feature & Dataset Drift Localization Evidence",
            "description": (
                f"Feature localization and dataset-level synthesis for comparison boundary "
                f"{boundary_result.comparison_boundary_hash[:16]}."
            ),
            "data_json": evidence_data,
            "confidence": confidence,
            "evidence_hash": evidence_hash,
        }
        evidence_records.append(dataset_evidence)

        return findings, evidence_records
