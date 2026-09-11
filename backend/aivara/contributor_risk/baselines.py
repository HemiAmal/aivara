"""Contextual baseline abstraction and calculation engine for Contributor Risk (Phase 6).

Implements the Leave-One-Out and Class-Conditional Stratified baseline hierarchy (ADR-031).
Eliminates Simpson's Paradox by evaluating contributors against matching task-difficulty strata.
"""

from __future__ import annotations

from typing import Dict, List, Optional
from aivara.contributor_risk.exceptions import InvalidBaselineError
from aivara.contributor_risk.schemas import BaselineType, ContextualBaseline, ContributorRiskConfig


class ContextualBaselineEngine:
    """Engine for computing contextual, LOO, and stratified reference baselines."""

    def __init__(self, config: Optional[ContributorRiskConfig] = None) -> None:
        self.config: ContributorRiskConfig = config or ContributorRiskConfig()

    def compute_leave_one_out_baseline(
        self,
        total_dataset_exposure: float,
        total_dataset_events: float,
        contributor_exposure: float,
        contributor_events: float,
        reference_description: str = "Dataset Leave-One-Out Background Population",
    ) -> ContextualBaseline:
        """Compute global Leave-One-Out (LOO) baseline for target contributor (ADR-031).

        Formula:
          p_LOO = (Total_Events - Contributor_Events) / (Total_Exposure - Contributor_Exposure)
        """
        n_total = max(0.0, float(total_dataset_exposure))
        k_total = max(0.0, float(total_dataset_events))
        n_c = max(0.0, float(contributor_exposure))
        k_c = max(0.0, float(contributor_events))

        n_bg = n_total - n_c
        k_bg = k_total - k_c

        if n_bg <= 0.0:
            # Degenerate case: single contributor comprises the entire dataset
            return ContextualBaseline(
                baseline_type=BaselineType.LEAVE_ONE_OUT,
                baseline_value=0.0,
                support_sample_count=0.0,
                reference_population=reference_description + " (Singleton dataset; no background)",
                is_fallback=True,
                limitations=["No background samples available outside the target contributor."],
            )

        k_bg = max(0.0, min(n_bg, k_bg))
        p_loo = k_bg / n_bg
        p_loo = max(0.0, min(1.0, p_loo))

        return ContextualBaseline(
            baseline_type=BaselineType.LEAVE_ONE_OUT,
            baseline_value=round(p_loo, 6),
            support_sample_count=round(n_bg, 6),
            reference_population=reference_description,
            is_fallback=False,
            limitations=[],
        )

    def compute_class_conditional_baseline(
        self,
        class_total_exposure: float,
        class_total_events: float,
        class_contributor_exposure: float,
        class_contributor_events: float,
        class_name: str,
        class_id: int,
        global_fallback_baseline: Optional[ContextualBaseline] = None,
    ) -> ContextualBaseline:
        """Compute class-conditional LOO baseline to eliminate Simpson's Paradox (ADR-031).

        If class support N_class >= min_class_support (default 10), uses class LOO.
        Otherwise falls back gracefully to global LOO with explicit limitations recorded.
        """
        n_class = max(0.0, float(class_total_exposure))
        k_class = max(0.0, float(class_total_events))
        n_c = max(0.0, float(class_contributor_exposure))
        k_c = max(0.0, float(class_contributor_events))

        n_bg = n_class - n_c
        k_bg = k_class - k_c

        # Guardrail: Check class support threshold
        if n_class < self.config.min_class_support_for_stratification or n_bg <= 0.0:
            if global_fallback_baseline is not None:
                return ContextualBaseline(
                    baseline_type=global_fallback_baseline.baseline_type,
                    baseline_value=global_fallback_baseline.baseline_value,
                    support_sample_count=global_fallback_baseline.support_sample_count,
                    reference_population=f"Global Fallback (Class '{class_name}' support < {self.config.min_class_support_for_stratification})",
                    is_fallback=True,
                    stratum_identifier=f"class_{class_id}:{class_name}",
                    limitations=[
                        f"Fell back to global LOO baseline due to low class support (N_class={n_class:.1f} < {self.config.min_class_support_for_stratification})."
                    ],
                )
            # Degenerate fallback without global baseline
            return ContextualBaseline(
                baseline_type=BaselineType.CLASS_CONDITIONAL,
                baseline_value=0.0,
                support_sample_count=round(max(0.0, n_bg), 6),
                reference_population=f"Class '{class_name}' (Insufficient support)",
                is_fallback=True,
                stratum_identifier=f"class_{class_id}:{class_name}",
                limitations=[f"Insufficient sample support for class '{class_name}'."],
            )

        k_bg = max(0.0, min(n_bg, k_bg))
        p_class_loo = k_bg / n_bg
        p_class_loo = max(0.0, min(1.0, p_class_loo))

        return ContextualBaseline(
            baseline_type=BaselineType.CLASS_CONDITIONAL,
            baseline_value=round(p_class_loo, 6),
            support_sample_count=round(n_bg, 6),
            reference_population=f"Class '{class_name}' (ID {class_id}) LOO Population",
            is_fallback=False,
            stratum_identifier=f"class_{class_id}:{class_name}",
            limitations=[],
        )

    def compute_subgroup_baseline(
        self,
        subgroup_total_exposure: float,
        subgroup_total_events: float,
        subgroup_contributor_exposure: float,
        subgroup_contributor_events: float,
        subgroup_name: str,
        global_fallback_baseline: Optional[ContextualBaseline] = None,
    ) -> ContextualBaseline:
        """Compute domain/sensor subgroup LOO baseline (ADR-031)."""
        n_sub = max(0.0, float(subgroup_total_exposure))
        k_sub = max(0.0, float(subgroup_total_events))
        n_c = max(0.0, float(subgroup_contributor_exposure))
        k_c = max(0.0, float(subgroup_contributor_events))

        n_bg = n_sub - n_c
        k_bg = k_sub - k_c

        if n_sub < self.config.min_class_support_for_stratification or n_bg <= 0.0:
            if global_fallback_baseline is not None:
                return ContextualBaseline(
                    baseline_type=global_fallback_baseline.baseline_type,
                    baseline_value=global_fallback_baseline.baseline_value,
                    support_sample_count=global_fallback_baseline.support_sample_count,
                    reference_population=f"Global Fallback (Subgroup '{subgroup_name}' support < {self.config.min_class_support_for_stratification})",
                    is_fallback=True,
                    stratum_identifier=subgroup_name,
                    limitations=[f"Fell back to global LOO baseline due to low subgroup support for '{subgroup_name}'."],
                )

        k_bg = max(0.0, min(n_bg, k_bg))
        p_sub_loo = max(0.0, min(1.0, k_bg / max(1.0, n_bg)))

        return ContextualBaseline(
            baseline_type=BaselineType.SUBGROUP,
            baseline_value=round(p_sub_loo, 6),
            support_sample_count=round(n_bg, 6),
            reference_population=f"Subgroup '{subgroup_name}' LOO Population",
            is_fallback=False,
            stratum_identifier=subgroup_name,
            limitations=[],
        )
