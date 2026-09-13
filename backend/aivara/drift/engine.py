"""Authoritative Statistical Distribution Shift Engine.

Executes non-parametric two-sample statistical tests, effect size estimation,
Benjamini-Hochberg FDR multiple-testing correction, dual-gate shift evaluation,
and cryptographic analysis identity derivation on a validated ComparisonBoundaryResult.
"""

from __future__ import annotations

import hashlib
import math
from typing import Any, Dict, List, Optional, Sequence, Tuple
import numpy as np

from aivara.crypto.canonical import canonicalize
from aivara.drift.enums import (
    BoundaryEvaluationStatus,
    DataModality,
    MultipleTestingCorrectionMethod,
    ShiftDecisionState,
    StatisticalMethod,
)
from aivara.drift.exceptions import (
    DistributionBoundaryError,
    IncompatiblePopulationError,
    InsufficientDataError,
    InvalidPopulationError,
    ProjectMismatchError,
    ResourceLimitExceededError,
)
from aivara.drift.multiple_testing import (
    apply_benjamini_hochberg,
    apply_multiple_testing_correction,
)
from aivara.drift.schemas import (
    CategoricalDriftResult,
    ComparisonBoundaryResult,
    FeatureDriftResult,
    MultivariateDriftResult,
    StatisticalAnalysisConfig,
    StatisticalAnalysisResult,
)
from aivara.drift.stats_categorical import (
    compute_chi_square_test,
    compute_jensen_shannon_divergence,
    compute_total_variation_distance,
)
from aivara.drift.stats_continuous import (
    compute_psi,
    compute_two_sample_ks,
    compute_wasserstein_1d,
    sanitize_1d_array,
)
from aivara.drift.stats_multivariate import (
    compute_energy_distance,
    compute_kernel_mmd,
    compute_permutation_p_value,
    sanitize_2d_array,
)


def compute_analysis_result_hash(canonical_dict: Dict[str, Any]) -> str:
    """Compute cryptographic SHA-256 digest over canonical RFC 8785 analysis descriptor."""
    canonical_bytes = canonicalize(canonical_dict)
    return hashlib.sha256(canonical_bytes).hexdigest()


class StatisticalDriftEngine:
    """Authoritative Statistical Distribution Shift Engine for population divergence analysis."""

    def __init__(self, default_config: Optional[StatisticalAnalysisConfig] = None) -> None:
        self.default_config = default_config or StatisticalAnalysisConfig()

    def evaluate_boundary(
        self,
        boundary_result: ComparisonBoundaryResult,
        *,
        reference_features: Optional[Dict[str, Sequence[float]]] = None,
        target_features: Optional[Dict[str, Sequence[float]]] = None,
        reference_labels: Optional[Sequence[str]] = None,
        target_labels: Optional[Sequence[str]] = None,
        reference_embeddings: Optional[Sequence[Sequence[float]]] = None,
        target_embeddings: Optional[Sequence[Sequence[float]]] = None,
        config: Optional[StatisticalAnalysisConfig] = None,
    ) -> StatisticalAnalysisResult:
        """Evaluate distribution shift between reference and target populations.
        
        Requires a valid ComparisonBoundaryResult. Fails closed if boundary is invalid.
        """
        active_config = config or self.default_config

        # 1. Validate boundary input
        if boundary_result.status != BoundaryEvaluationStatus.VALID:
            if boundary_result.status == BoundaryEvaluationStatus.PROJECT_MISMATCH:
                raise ProjectMismatchError("Cannot execute statistical analysis across mismatched projects.")
            elif boundary_result.status == BoundaryEvaluationStatus.INSUFFICIENT_DATA:
                return self._create_empty_result(
                    boundary_result=boundary_result,
                    config=active_config,
                    status=ShiftDecisionState.INSUFFICIENT_DATA,
                    warnings=["Boundary status is INSUFFICIENT_DATA."],
                )
            else:
                return self._create_empty_result(
                    boundary_result=boundary_result,
                    config=active_config,
                    status=ShiftDecisionState.INVALID,
                    warnings=[f"Boundary status is {boundary_result.status.value}."],
                )

        contract = boundary_result.contract

        # 2. Check sample counts against minimum thresholds
        if (
            contract.reference_sample_count < active_config.min_sample_size
            or contract.target_sample_count < active_config.min_sample_size
        ):
            return self._create_empty_result(
                boundary_result=boundary_result,
                config=active_config,
                status=ShiftDecisionState.INSUFFICIENT_DATA,
                warnings=[
                    f"Sample count below minimum {active_config.min_sample_size}: "
                    f"reference={contract.reference_sample_count}, target={contract.target_sample_count}."
                ],
            )

        feature_results: Dict[str, FeatureDriftResult] = {}
        categorical_results: Dict[str, CategoricalDriftResult] = {}
        multivariate_results: Optional[MultivariateDriftResult] = None
        warnings: List[str] = list(boundary_result.warnings)
        limitations: List[str] = []

        # 3. Continuous tabular / numeric features evaluation
        if reference_features and target_features:
            feature_results, feature_warnings = self._evaluate_continuous(
                reference_features=reference_features,
                target_features=target_features,
                config=active_config,
            )
            warnings.extend(feature_warnings)

        # 4. Categorical / label distributions evaluation
        if reference_labels is not None and target_labels is not None:
            cat_result, cat_warnings = self._evaluate_categorical(
                attribute_name="class_labels",
                reference_labels=reference_labels,
                target_labels=target_labels,
                config=active_config,
            )
            categorical_results["class_labels"] = cat_result
            warnings.extend(cat_warnings)

        # 5. Multivariate / embedding distribution evaluation
        if reference_embeddings is not None and target_embeddings is not None:
            multivariate_results, multi_warnings = self._evaluate_multivariate(
                reference_embeddings=reference_embeddings,
                target_embeddings=target_embeddings,
                modality=contract.modality,
                config=active_config,
            )
            warnings.extend(multi_warnings)

        # 6. Global aggregation & Dual-Gate decision synthesis
        total_tested = (
            len(feature_results)
            + len(categorical_results)
            + (1 if multivariate_results is not None else 0)
        )

        sig_count = 0
        mat_count = 0

        for fr in feature_results.values():
            if fr.is_statistically_significant:
                sig_count += 1
            if fr.status == ShiftDecisionState.MATERIAL_SHIFT:
                mat_count += 1

        for cr in categorical_results.values():
            if cr.is_statistically_significant:
                sig_count += 1
            if cr.status == ShiftDecisionState.MATERIAL_SHIFT:
                mat_count += 1

        if multivariate_results is not None:
            if multivariate_results.is_statistically_significant:
                sig_count += 1
            if multivariate_results.status == ShiftDecisionState.MATERIAL_SHIFT:
                mat_count += 1

        if mat_count > 0:
            global_status = ShiftDecisionState.MATERIAL_SHIFT
        elif sig_count > 0:
            global_status = ShiftDecisionState.SIGNIFICANT_SHIFT
        elif total_tested == 0:
            global_status = ShiftDecisionState.NO_SHIFT_DETECTED
            limitations.append("No feature, categorical, or embedding representations provided for analysis.")
        else:
            global_status = ShiftDecisionState.NO_SHIFT_DETECTED

        # 7. Generate findings and evidence
        findings, evidence_records = self._generate_findings_and_evidence(
            boundary_result=boundary_result,
            config=active_config,
            global_status=global_status,
            total_tested=total_tested,
            sig_count=sig_count,
            mat_count=mat_count,
            feature_results=feature_results,
            categorical_results=categorical_results,
            multivariate_results=multivariate_results,
        )

        # 8. Compute immutable analysis result identity
        descriptor_for_hash = {
            "analysis_version": active_config.analysis_version,
            "comparison_boundary_hash": boundary_result.comparison_boundary_hash,
            "config": active_config.to_canonical_dict(),
            "global_status": global_status.value,
            "materially_shifted_count": mat_count,
            "schema_version": "1.0",
            "statistically_significant_count": sig_count,
            "total_features_tested": total_tested,
        }
        analysis_result_hash = compute_analysis_result_hash(descriptor_for_hash)

        return StatisticalAnalysisResult(
            schema_version="1.0",
            analysis_version=active_config.analysis_version,
            comparison_boundary_hash=boundary_result.comparison_boundary_hash,
            analysis_result_hash=analysis_result_hash,
            config=active_config,
            global_status=global_status,
            total_features_tested=total_tested,
            statistically_significant_count=sig_count,
            materially_shifted_count=mat_count,
            feature_results=feature_results,
            categorical_results=categorical_results,
            multivariate_results=multivariate_results,
            warnings=sorted(list(set(warnings))),
            limitations=limitations,
            findings=findings,
            evidence_records=evidence_records,
        )

    def _evaluate_continuous(
        self,
        reference_features: Dict[str, Sequence[float]],
        target_features: Dict[str, Sequence[float]],
        config: StatisticalAnalysisConfig,
    ) -> Tuple[Dict[str, FeatureDriftResult], List[str]]:
        """Evaluate continuous features with KS tests, Wasserstein distance, and PSI with BH FDR."""
        feature_names = sorted(list(set(reference_features.keys()) & set(target_features.keys())))
        if len(feature_names) > config.max_features:
            raise ResourceLimitExceededError(
                f"Feature count {len(feature_names)} exceeds limit {config.max_features}."
            )

        raw_p_values: Dict[str, float] = {}
        intermediate: Dict[str, Dict[str, Any]] = {}
        warnings: List[str] = []

        for name in feature_names:
            ref_vals = sanitize_1d_array(reference_features[name])
            target_vals = sanitize_1d_array(target_features[name])

            # KS test
            ks_stat, ks_p_val = compute_two_sample_ks(ref_vals, target_vals)
            # Wasserstein distance W1
            w1 = compute_wasserstein_1d(ref_vals, target_vals)
            # Standardized Wasserstein: W1 / std(ref)
            ref_std = float(np.std(ref_vals))
            w1_norm = (w1 / ref_std) if ref_std > 1e-12 else w1

            # PSI
            psi_val, psi_details = compute_psi(ref_vals, target_vals)

            raw_p_values[name] = ks_p_val
            intermediate[name] = {
                "ks_stat": ks_stat,
                "ks_p_val": ks_p_val,
                "w1": w1,
                "w1_norm": w1_norm,
                "psi": psi_val,
                "psi_details": psi_details,
                "ref_count": len(ref_vals),
                "target_count": len(target_vals),
            }

        # Apply multiple hypothesis testing correction
        corrected_mapping = apply_multiple_testing_correction(
            raw_p_values,
            method=config.correction_method,
            threshold=config.fdr_q_star,
        )

        results: Dict[str, FeatureDriftResult] = {}
        for name in feature_names:
            meta = intermediate[name]
            corr = corrected_mapping.get(name, {})
            q_val = corr.get("adjusted_p_value", meta["ks_p_val"])
            is_stat_sig = corr.get("is_significant", q_val <= config.fdr_q_star)

            # Practical significance gate: PSI >= 0.10 or normalized W1 >= threshold
            is_prac_sig = (
                meta["psi"] >= config.psi_moderate_threshold
                or meta["w1_norm"] >= config.wasserstein_std_threshold
            )

            # Dual-gate decision
            if is_stat_sig and is_prac_sig:
                status = ShiftDecisionState.MATERIAL_SHIFT
            elif is_stat_sig:
                status = ShiftDecisionState.SIGNIFICANT_SHIFT
            elif is_prac_sig:
                status = ShiftDecisionState.SHIFT_DETECTED
            else:
                status = ShiftDecisionState.NO_SHIFT_DETECTED

            results[name] = FeatureDriftResult(
                feature_name=name,
                method=StatisticalMethod.KOLMOGOROV_SMIRNOV_2SAMPLE,
                statistic_value=meta["ks_stat"],
                raw_p_value=meta["ks_p_val"],
                adjusted_p_value=q_val,
                effect_size=meta["psi"],
                effect_size_metric="psi",
                reference_sample_count=meta["ref_count"],
                target_sample_count=meta["target_count"],
                is_statistically_significant=is_stat_sig,
                is_practically_significant=is_prac_sig,
                status=status,
                details={
                    "wasserstein_1d": meta["w1"],
                    "standardized_wasserstein": meta["w1_norm"],
                    "psi": meta["psi"],
                    "psi_bin_count": meta["psi_details"].get("bin_count", 10),
                    "correction_rank": corr.get("rank", 1),
                },
            )

        return results, warnings

    def _evaluate_categorical(
        self,
        attribute_name: str,
        reference_labels: Sequence[str],
        target_labels: Sequence[str],
        config: StatisticalAnalysisConfig,
    ) -> Tuple[CategoricalDriftResult, List[str]]:
        """Evaluate categorical/label distribution drift using TVD, JSD, and Chi-Square."""
        warnings: List[str] = []

        ref_counts: Dict[str, int] = {}
        for item in reference_labels:
            ref_counts[str(item)] = ref_counts.get(str(item), 0) + 1

        target_counts: Dict[str, int] = {}
        for item in target_labels:
            target_counts[str(item)] = target_counts.get(str(item), 0) + 1

        n_ref = len(reference_labels)
        n_target = len(target_labels)

        ref_probs = {c: count / n_ref for c, count in ref_counts.items()}
        target_probs = {c: count / n_target for c, count in target_counts.items()}

        tvd = compute_total_variation_distance(ref_probs, target_probs)
        jsd = compute_jensen_shannon_divergence(ref_probs, target_probs, base=2.0)
        chi2_stat, chi2_p, df, unseen, missing = compute_chi_square_test(ref_counts, target_counts)

        if unseen:
            warnings.append(f"Unseen categories present in target population: {sorted(unseen)}")
        if missing:
            warnings.append(f"Categories missing from target population: {sorted(missing)}")

        is_stat_sig = chi2_p <= config.significance_level
        is_prac_sig = (
            tvd >= config.tvd_material_threshold
            or jsd >= config.jsd_material_threshold
            or len(unseen) > 0
        )

        if is_stat_sig and is_prac_sig:
            status = ShiftDecisionState.MATERIAL_SHIFT
        elif is_stat_sig:
            status = ShiftDecisionState.SIGNIFICANT_SHIFT
        elif is_prac_sig:
            status = ShiftDecisionState.SHIFT_DETECTED
        else:
            status = ShiftDecisionState.NO_SHIFT_DETECTED

        result = CategoricalDriftResult(
            attribute_name=attribute_name,
            chi_square_statistic=chi2_stat,
            chi_square_p_value=chi2_p,
            degrees_of_freedom=df,
            tvd=tvd,
            jsd=jsd,
            reference_proportions=ref_probs,
            target_proportions=target_probs,
            unseen_target_classes=unseen,
            missing_target_classes=missing,
            is_statistically_significant=is_stat_sig,
            is_practically_significant=is_prac_sig,
            status=status,
            details={
                "reference_sample_count": n_ref,
                "target_sample_count": n_target,
                "num_classes": len(set(ref_counts.keys()) | set(target_counts.keys())),
            },
        )
        return result, warnings

    def _evaluate_multivariate(
        self,
        reference_embeddings: Sequence[Sequence[float]],
        target_embeddings: Sequence[Sequence[float]],
        modality: DataModality,
        config: StatisticalAnalysisConfig,
    ) -> Tuple[MultivariateDriftResult, List[str]]:
        """Evaluate multivariate / embedding distribution drift via MMD and Energy Distance."""
        warnings: List[str] = []
        x_mat = sanitize_2d_array(reference_embeddings)
        y_mat = sanitize_2d_array(target_embeddings)

        if x_mat.shape[1] > config.max_features:
            raise ResourceLimitExceededError(
                f"Embedding dimension {x_mat.shape[1]} exceeds max features {config.max_features}."
            )

        # Cap sample size to max_sample_size for quadratic kernel calculations
        if len(x_mat) > config.max_sample_size:
            x_mat = x_mat[:config.max_sample_size]
            warnings.append(f"Subsampled reference embeddings to {config.max_sample_size} for MMD.")
        if len(y_mat) > config.max_sample_size:
            y_mat = y_mat[:config.max_sample_size]
            warnings.append(f"Subsampled target embeddings to {config.max_sample_size} for MMD.")

        mmd_sq, gamma = compute_kernel_mmd(x_mat, y_mat)
        energy_dist = compute_energy_distance(x_mat, y_mat)

        # Deterministic permutation test on MMD
        def mmd_stat_fn(x_sub: np.ndarray, y_sub: np.ndarray) -> float:
            val, _ = compute_kernel_mmd(x_sub, y_sub, gamma=gamma)
            return val

        _, perm_p, _ = compute_permutation_p_value(
            x_mat,
            y_mat,
            stat_fn=mmd_stat_fn,
            num_permutations=config.num_permutations,
            seed=config.seed,
        )

        is_stat_sig = perm_p <= config.significance_level
        is_prac_sig = (
            mmd_sq >= config.mmd_material_threshold
            or energy_dist >= config.energy_material_threshold
        )

        if is_stat_sig and is_prac_sig:
            status = ShiftDecisionState.MATERIAL_SHIFT
        elif is_stat_sig:
            status = ShiftDecisionState.SIGNIFICANT_SHIFT
        elif is_prac_sig:
            status = ShiftDecisionState.SHIFT_DETECTED
        else:
            status = ShiftDecisionState.NO_SHIFT_DETECTED

        result = MultivariateDriftResult(
            modality=modality,
            method=StatisticalMethod.KERNEL_MMD,
            statistic_value=mmd_sq,
            permutation_p_value=perm_p,
            num_permutations=config.num_permutations,
            bandwidth=gamma,
            is_statistically_significant=is_stat_sig,
            is_practically_significant=is_prac_sig,
            status=status,
            details={
                "energy_distance": energy_dist,
                "embedding_dimension": int(x_mat.shape[1]),
                "reference_count": len(x_mat),
                "target_count": len(y_mat),
            },
        )
        return result, warnings

    def _create_empty_result(
        self,
        boundary_result: ComparisonBoundaryResult,
        config: StatisticalAnalysisConfig,
        status: ShiftDecisionState,
        warnings: List[str],
    ) -> StatisticalAnalysisResult:
        """Create a fail-closed / insufficient data result descriptor."""
        descriptor_for_hash = {
            "analysis_version": config.analysis_version,
            "comparison_boundary_hash": boundary_result.comparison_boundary_hash,
            "config": config.to_canonical_dict(),
            "global_status": status.value,
            "materially_shifted_count": 0,
            "schema_version": "1.0",
            "statistically_significant_count": 0,
            "total_features_tested": 0,
        }
        res_hash = compute_analysis_result_hash(descriptor_for_hash)

        return StatisticalAnalysisResult(
            schema_version="1.0",
            analysis_version=config.analysis_version,
            comparison_boundary_hash=boundary_result.comparison_boundary_hash,
            analysis_result_hash=res_hash,
            config=config,
            global_status=status,
            total_features_tested=0,
            statistically_significant_count=0,
            materially_shifted_count=0,
            warnings=warnings,
            limitations=["Analysis aborted due to boundary status or data insufficiency."],
            findings=[],
            evidence_records=[],
        )

    def _generate_findings_and_evidence(
        self,
        boundary_result: ComparisonBoundaryResult,
        config: StatisticalAnalysisConfig,
        global_status: ShiftDecisionState,
        total_tested: int,
        sig_count: int,
        mat_count: int,
        feature_results: Dict[str, FeatureDriftResult],
        categorical_results: Dict[str, CategoricalDriftResult],
        multivariate_results: Optional[MultivariateDriftResult],
    ) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        """Synthesize standard FindingModel and EvidenceModel records without mutating schemas."""
        contract = boundary_result.contract
        findings: List[Dict[str, Any]] = []
        evidence_records: List[Dict[str, Any]] = []

        # Map global status to severity and disposition
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

        affected_asset_id = (
            contract.target_dataset_version_id
            or contract.target_dataset_id
        )
        affected_asset_type = (
            "dataset_version" if contract.target_dataset_version_id else "dataset"
        )

        # Finding record
        finding = {
            "project_id": contract.project_id,
            "engine_id": "statistical_distribution_shift_engine",
            "engine_version": "1.0",
            "evidence_layer": "detection",
            "finding_type": "distribution_shift",
            "title": f"Distribution Shift Evaluation: {global_status.value}",
            "description": (
                f"Statistical two-sample divergence analysis between reference population "
                f"({contract.reference_dataset_id}) and target population "
                f"({contract.target_dataset_id}) concluded with status {global_status.value}. "
                f"Tested {total_tested} units: {sig_count} statistically significant, "
                f"{mat_count} materially shifted under FDR q*={config.fdr_q_star}."
            ),
            "severity": severity,
            "confidence": confidence,
            "affected_asset_type": affected_asset_type,
            "affected_asset_id": affected_asset_id,
            "disposition": disposition,
            "analysis_mode": "statistical_two_sample",
            "recommendation": (
                "Review population divergence metrics and evaluate operational model performance on shifted data. "
                "Note: Distribution shift is objective mathematical divergence, not proof of malicious intent."
            ),
            "metadata_json": {
                "comparison_boundary_hash": boundary_result.comparison_boundary_hash,
                "global_status": global_status.value,
                "total_tested": total_tested,
                "statistically_significant_count": sig_count,
                "materially_shifted_count": mat_count,
                "fdr_q_star": config.fdr_q_star,
                "correction_method": config.correction_method.value,
            },
        }
        findings.append(finding)

        # Evidence record
        evidence_data = {
            "comparison_boundary_hash": boundary_result.comparison_boundary_hash,
            "reference_sample_count": contract.reference_sample_count,
            "target_sample_count": contract.target_sample_count,
            "global_status": global_status.value,
            "features": {
                name: {
                    "statistic": fr.statistic_value,
                    "raw_p_value": fr.raw_p_value,
                    "adjusted_p_value": fr.adjusted_p_value,
                    "effect_size": fr.effect_size,
                    "status": fr.status.value,
                }
                for name, fr in feature_results.items()
            },
            "categorical": {
                name: {
                    "chi2_stat": cr.chi_square_statistic,
                    "p_value": cr.chi_square_p_value,
                    "tvd": cr.tvd,
                    "jsd": cr.jsd,
                    "status": cr.status.value,
                    "unseen_classes": cr.unseen_target_classes,
                }
                for name, cr in categorical_results.items()
            },
            "multivariate": (
                {
                    "mmd_sq": multivariate_results.statistic_value,
                    "permutation_p_value": multivariate_results.permutation_p_value,
                    "status": multivariate_results.status.value,
                }
                if multivariate_results is not None
                else None
            ),
        }
        evidence_bytes = canonicalize(evidence_data)
        evidence_hash = hashlib.sha256(evidence_bytes).hexdigest()

        evidence = {
            "evidence_layer": "detection",
            "evidence_type": "statistical_drift_evidence",
            "title": "Statistical Two-Sample Divergence Evidence",
            "description": (
                f"Detailed two-sample hypothesis tests and effect sizes for comparison boundary "
                f"{boundary_result.comparison_boundary_hash[:16]}."
            ),
            "data_json": evidence_data,
            "confidence": confidence,
            "evidence_hash": evidence_hash,
        }
        evidence_records.append(evidence)

        return findings, evidence_records
