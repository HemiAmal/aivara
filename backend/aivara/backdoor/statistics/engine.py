"""Statistical Trigger Analysis Engine for Phase 9.5 (ADR-089, ADR-090).

Orchestrates deterministic paired permutation testing, exact Clopper-Pearson
confidence intervals, Benjamini-Hochberg candidate-level FDR, Stage 2 promotion
gating, and Holm-Bonferroni spatial grid localization.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Union
import numpy as np

from aivara.backdoor.activation.models import TriggerActivationAssessment
from aivara.backdoor.statistics.budget import compute_budget_accounting, validate_budget_ceiling
from aivara.backdoor.statistics.confidence import clopper_pearson_confidence_interval
from aivara.backdoor.statistics.enums import (
    MultipleTestingMethodEnum,
    StatisticalResultTaxonomyEnum,
    StatisticalSignificanceEnum,
    StatisticalStatusEnum,
)
from aivara.backdoor.statistics.exceptions import (
    BudgetExceededError,
    InsufficientSupportError,
    PairingIntegrityError,
    StatisticalAnalysisError,
)
from aivara.backdoor.statistics.identity import (
    compute_statistical_analysis_id,
    derive_pcg64_seed,
)
from aivara.backdoor.statistics.localization import (
    SpatialLocalizationSummary,
    evaluate_spatial_grid_localization,
)
from aivara.backdoor.statistics.models import (
    CandidateStatisticalSummary,
    ConfidenceIntervalResult,
    InferenceBudgetAccounting,
    PermutationTestResult,
    StatisticalAnalysisAssessment,
)
from aivara.backdoor.statistics.multiple_testing import benjamini_hochberg_fdr
from aivara.backdoor.statistics.policy import evaluate_result_taxonomy
from aivara.backdoor.statistics.promotion import (
    CandidatePromotionAssessment,
    evaluate_stage2_promotion,
)
from aivara.crypto.hashing import hash_canonical_data, sha256_text


class StatisticalAnalysisEngine:
    """Deterministic, pure-analysis statistical significance engine for backdoor trigger evidence."""

    def __init__(
        self,
        permutation_count: int = 1000,
        alpha: float = 0.05,
        confidence_level: float = 0.95,
        enforce_budget_ceiling: bool = True,
    ) -> None:
        if permutation_count <= 0 or permutation_count > 100_000:
            raise StatisticalAnalysisError(f"Permutation count B must be in [1, 100000], got {permutation_count}")
        if alpha <= 0.0 or alpha >= 1.0:
            raise StatisticalAnalysisError(f"Alpha must be in (0, 1), got {alpha}")
        if confidence_level <= 0.0 or confidence_level >= 1.0:
            raise StatisticalAnalysisError(f"Confidence level must be in (0, 1), got {confidence_level}")

        self.permutation_count = permutation_count
        self.alpha = alpha
        self.confidence_level = confidence_level
        self.enforce_budget_ceiling = enforce_budget_ceiling

    def evaluate_assessments(
        self,
        project_id: str,
        activation_assessments: List[TriggerActivationAssessment],
        target_class: Optional[Union[int, str]] = None,
        spatial_localization_data: Optional[Dict[str, List[Dict[str, Any]]]] = None,
        custom_metadata: Optional[Dict[str, Any]] = None,
    ) -> StatisticalAnalysisAssessment:
        """Run complete statistical hypothesis testing and control comparison across candidates.
        
        Args:
            project_id: Valid tenant project identifier.
            activation_assessments: List of Phase 9.4 TriggerActivationAssessment objects.
            target_class: Optional target class for target-conditioned hypothesis testing.
            spatial_localization_data: Optional mapping of candidate_hash -> 64-cell observation dicts.
            custom_metadata: Optional metadata dictionary.
            
        Returns:
            StatisticalAnalysisAssessment containing all deterministic results and provenance.
        """
        if not activation_assessments:
            raise StatisticalAnalysisError("Activation assessments list cannot be empty.")

        # Validate project isolation and extract common metadata
        model_id = activation_assessments[0].model_id
        for ass in activation_assessments:
            if ass.project_id != project_id:
                raise PairingIntegrityError(
                    f"Project isolation violation: expected {project_id}, found {ass.project_id}"
                )
            if ass.model_id != model_id:
                raise PairingIntegrityError(
                    f"Model ID mismatch: expected {model_id}, found {ass.model_id}"
                )

        # Build sample-set canonical hash from all unique sample IDs
        sample_ids = set()
        for ass in activation_assessments:
            for obs in ass.paired_observations:
                sample_ids.add(obs.source_input_id)
        sorted_samples = sorted(list(sample_ids))
        sample_set_hash = hash_canonical_data({"sample_ids": sorted_samples})

        # Calculate budget accounting
        candidate_count = len(activation_assessments)
        stage1_samples = max(ass.sample_count for ass in activation_assessments) if activation_assessments else 50
        
        if self.enforce_budget_ceiling:
            budget_rec = validate_budget_ceiling(
                stage1_samples=stage1_samples,
                stage1_candidates=candidate_count,
            )
        else:
            budget_rec = compute_budget_accounting(
                stage1_samples=stage1_samples,
                stage1_candidates=candidate_count,
            )

        # Canonical analysis identity
        candidate_hashes = sorted([ass.candidate_hash for ass in activation_assessments])
        combined_candidate_hash = sha256_text(",".join(candidate_hashes))
        combined_assessment_id = sha256_text(",".join(sorted([ass.assessment_id for ass in activation_assessments])))

        analysis_id = compute_statistical_analysis_id(
            project_id=project_id,
            candidate_hash=combined_candidate_hash,
            sample_set_hash=sample_set_hash,
            trigger_assessment_id=combined_assessment_id,
            target_class=target_class,
            permutation_count=self.permutation_count,
            rng_algorithm="PCG64",
            alpha=self.alpha,
            confidence_level=self.confidence_level,
            multiple_comparison_method="BENJAMINI_HOCHBERG",
        )

        candidate_raw_results: List[Dict[str, Any]] = []
        raw_p_values: List[Optional[float]] = []
        candidate_keys: List[str] = []

        # Process each candidate independently for Stage 1 hypothesis testing
        for ass in activation_assessments:
            c_hash = ass.candidate_hash
            candidate_keys.append(c_hash)
            n_total = ass.sample_count
            n_eligible = ass.eligible_sample_count

            # Extract paired indicators
            trigger_succ: List[int] = []
            shuff_succ: List[int] = []
            noise_succ: List[int] = []

            for obs in ass.paired_observations:
                # If target_class is evaluated, extract target match indicator
                if target_class is not None:
                    # Only consider samples where clean output != target_class
                    clean_pred = obs.clean_result.prediction_label
                    if clean_pred == target_class:
                        continue  # Ineligible for TSR evaluation

                    trig_m = 1 if (obs.active_trigger_result.is_target_matched is True or obs.active_trigger_result.prediction_label == target_class) else 0
                    
                    shuff_m = 0
                    if obs.location_shuffled_result is not None:
                        shuff_m = 1 if (obs.location_shuffled_result.is_target_matched is True or obs.location_shuffled_result.prediction_label == target_class) else 0

                    noise_m = 0
                    if obs.magnitude_matched_noise_result is not None:
                        noise_m = 1 if (obs.magnitude_matched_noise_result.is_target_matched is True or obs.magnitude_matched_noise_result.prediction_label == target_class) else 0

                    trigger_succ.append(trig_m)
                    shuff_succ.append(shuff_m)
                    noise_succ.append(noise_m)
                else:
                    # Target-free evaluation: indicators represent criterion activation
                    trig_act = 1 if obs.active_trigger_result.activation_decision.value == "ACTIVATED" else 0
                    shuff_act = 1 if (obs.location_shuffled_result and obs.location_shuffled_result.activation_decision.value == "ACTIVATED") else 0
                    noise_act = 1 if (obs.magnitude_matched_noise_result and obs.magnitude_matched_noise_result.activation_decision.value == "ACTIVATED") else 0

                    trigger_succ.append(trig_act)
                    shuff_succ.append(shuff_act)
                    noise_succ.append(noise_act)

            n_eval = len(trigger_succ)
            cand_seed = derive_pcg64_seed(
                statistical_analysis_id=analysis_id,
                experiment_tag="candidate_paired_permutation",
                candidate_hash=c_hash,
            )

            # Insufficient support handling (N < 10)
            if n_eval < 10:
                ci_res = ConfidenceIntervalResult(
                    confidence_level=self.confidence_level,
                    lower_bound=None,
                    upper_bound=None,
                    method="CLOPPER_PEARSON_EXACT",
                    status="INSUFFICIENT_SUPPORT",
                )
                perm_res = PermutationTestResult(
                    permutation_count=self.permutation_count,
                    rng_algorithm="PCG64",
                    seed=cand_seed,
                    t_obs=None,
                    p_value=None,
                    p_value_shuffled=None,
                    p_value_noise=None,
                    significance=StatisticalSignificanceEnum.NOT_EVALUATED,
                    status=StatisticalStatusEnum.INSUFFICIENT_SUPPORT,
                )
                raw_p_values.append(None)
                candidate_raw_results.append({
                    "candidate_hash": c_hash,
                    "sample_count": n_total,
                    "eligible_sample_count": n_eval,
                    "target_class": target_class,
                    "tar": ass.tar,
                    "tsr": None if target_class is None else (sum(trigger_succ) / n_eval if n_eval > 0 else None),
                    "raw_tsr_shuffled": None if target_class is None else (sum(shuff_succ) / n_eval if n_eval > 0 else None),
                    "raw_tsr_noise": None if target_class is None else (sum(noise_succ) / n_eval if n_eval > 0 else None),
                    "control_baseline_tsr": None,
                    "sample_envelope_tsr": None,
                    "delta_separation": None,
                    "confidence_interval": ci_res,
                    "permutation_test": perm_res,
                    "raw_p_value": None,
                    "status": StatisticalStatusEnum.INSUFFICIENT_SUPPORT,
                })
                continue

            # Compute Clopper-Pearson 95% CI on TSR
            k_succ = sum(trigger_succ)
            ci_low, ci_high = clopper_pearson_confidence_interval(
                k=k_succ,
                n=n_eval,
                confidence_level=self.confidence_level,
            )
            ci_res = ConfidenceIntervalResult(
                confidence_level=self.confidence_level,
                lower_bound=ci_low,
                upper_bound=ci_high,
                method="CLOPPER_PEARSON_EXACT",
                status="VALID",
            )

            # Paired permutation test
            perm_dict = from_permutation_to_dict(
                trigger_succ=trigger_succ,
                shuff_succ=shuff_succ,
                noise_succ=noise_succ,
                seed=cand_seed,
                permutation_count=self.permutation_count,
                alpha=self.alpha,
            )

            perm_res = PermutationTestResult(
                permutation_count=self.permutation_count,
                rng_algorithm="PCG64",
                seed=cand_seed,
                t_obs=perm_dict["t_obs"],
                t_obs_shuffled=perm_dict["t_obs_shuffled"],
                t_obs_noise=perm_dict["t_obs_noise"],
                p_value=perm_dict["p_value"],
                p_value_shuffled=perm_dict["p_value_shuffled"],
                p_value_noise=perm_dict["p_value_noise"],
                significance=perm_dict["significance"],
                status=perm_dict["status"],
            )

            raw_p = perm_dict["p_value"]
            raw_p_values.append(raw_p)

            candidate_raw_results.append({
                "candidate_hash": c_hash,
                "sample_count": n_total,
                "eligible_sample_count": n_eval,
                "target_class": target_class,
                "tar": ass.tar,
                "tsr": perm_dict["raw_tsr_trigger"] if target_class is not None else None,
                "raw_tsr_shuffled": perm_dict["raw_tsr_shuffled"] if target_class is not None else None,
                "raw_tsr_noise": perm_dict["raw_tsr_noise"] if target_class is not None else None,
                "control_baseline_tsr": perm_dict["control_baseline_tsr"] if target_class is not None else None,
                "sample_envelope_tsr": perm_dict["sample_envelope_tsr"],
                "delta_separation": perm_dict["delta_separation"] if target_class is not None else None,
                "confidence_interval": ci_res,
                "permutation_test": perm_res,
                "raw_p_value": raw_p,
                "status": StatisticalStatusEnum.COMPLETED,
            })

        # Apply Benjamini-Hochberg FDR across candidates
        bh_results = benjamini_hochberg_fdr(
            p_values=raw_p_values,
            candidate_keys=candidate_keys,
            alpha=self.alpha,
        )

        final_candidate_summaries: List[CandidateStatisticalSummary] = []
        for raw_cand, bh_res in zip(candidate_raw_results, bh_results):
            adj_p = bh_res["adjusted_p_value"]
            fdr_rank = bh_res["rank"]
            is_sig_fdr = bh_res["is_significant"]

            tax_state = evaluate_result_taxonomy(
                sample_count=raw_cand["eligible_sample_count"],
                tar=raw_cand["tar"],
                tsr=raw_cand["tsr"],
                delta_separation=raw_cand["delta_separation"],
                adjusted_p_value=adj_p,
            )

            final_candidate_summaries.append(
                CandidateStatisticalSummary(
                    candidate_hash=raw_cand["candidate_hash"],
                    sample_count=raw_cand["sample_count"],
                    eligible_sample_count=raw_cand["eligible_sample_count"],
                    target_class=raw_cand["target_class"],
                    tar=raw_cand["tar"],
                    tsr=raw_cand["tsr"],
                    raw_tsr_shuffled=raw_cand["raw_tsr_shuffled"],
                    raw_tsr_noise=raw_cand["raw_tsr_noise"],
                    control_baseline_tsr=raw_cand["control_baseline_tsr"],
                    sample_envelope_tsr=raw_cand["sample_envelope_tsr"],
                    delta_separation=raw_cand["delta_separation"],
                    confidence_interval=raw_cand["confidence_interval"],
                    permutation_test=raw_cand["permutation_test"],
                    raw_p_value=raw_cand["raw_p_value"],
                    adjusted_p_value=adj_p,
                    multiple_testing_method=MultipleTestingMethodEnum.BENJAMINI_HOCHBERG,
                    fdr_rank=fdr_rank,
                    is_significant_after_fdr=is_sig_fdr,
                    taxonomy_classification=tax_state,
                    status=raw_cand["status"],
                )
            )

        # Stage 2 candidate promotion gating
        promotion_input = [
            {
                "candidate_hash": c.candidate_hash,
                "tar": c.tar,
                "tsr": c.tsr,
                "delta_separation": c.delta_separation,
                "sample_count": c.eligible_sample_count,
            }
            for c in final_candidate_summaries
        ]
        promotions = evaluate_stage2_promotion(promotion_input)

        # Stage 2 spatial grid localization for promoted candidates (if data provided)
        spatial_summaries: List[SpatialLocalizationSummary] = []
        if spatial_localization_data:
            for prom in promotions:
                if prom.is_promoted and prom.candidate_hash in spatial_localization_data:
                    c_hash = prom.candidate_hash
                    grid_obs = spatial_localization_data[c_hash]
                    loc_summary = evaluate_spatial_grid_localization(
                        candidate_hash=c_hash,
                        statistical_analysis_id=analysis_id,
                        grid_cell_observations=grid_obs,
                        alpha=self.alpha,
                        permutation_count=self.permutation_count,
                    )
                    spatial_summaries.append(loc_summary)

        return StatisticalAnalysisAssessment(
            schema_version="1.0.0",
            statistical_analysis_id=analysis_id,
            project_id=project_id,
            model_id=model_id,
            sample_set_hash=sample_set_hash,
            trigger_assessment_id=combined_assessment_id,
            target_class=target_class,
            permutation_count=self.permutation_count,
            alpha=self.alpha,
            confidence_level=self.confidence_level,
            multiple_comparison_method=MultipleTestingMethodEnum.BENJAMINI_HOCHBERG,
            budget_accounting=budget_rec,
            candidate_summaries=final_candidate_summaries,
            stage2_promotions=promotions,
            spatial_localization_summaries=spatial_summaries,
            assessment_metadata=custom_metadata or {},
        )


def from_permutation_to_dict(
    trigger_succ: List[int],
    shuff_succ: List[int],
    noise_succ: List[int],
    seed: int,
    permutation_count: int,
    alpha: float,
) -> Dict[str, Any]:
    """Helper executing paired permutation test."""
    from aivara.backdoor.statistics.permutation import evaluate_paired_permutation_test
    return evaluate_paired_permutation_test(
        trigger_successes=trigger_succ,
        shuffled_successes=shuff_succ,
        noise_successes=noise_succ,
        seed=seed,
        permutation_count=permutation_count,
        alpha=alpha,
    )
