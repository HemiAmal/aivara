"""Immutable Pydantic Models for Phase 9.5 Statistical Trigger Significance & Control Comparison."""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Union
from pydantic import BaseModel, ConfigDict, Field

from aivara.backdoor.statistics.budget import InferenceBudgetAccounting
from aivara.backdoor.statistics.enums import (
    MultipleTestingMethodEnum,
    StatisticalResultTaxonomyEnum,
    StatisticalSignificanceEnum,
    StatisticalStatusEnum,
)
from aivara.backdoor.statistics.localization import SpatialLocalizationSummary
from aivara.backdoor.statistics.promotion import CandidatePromotionAssessment


class ConfidenceIntervalResult(BaseModel):
    """Exact Clopper-Pearson binomial confidence interval."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    confidence_level: float = Field(0.95, description="Confidence level (e.g. 0.95)")
    lower_bound: Optional[float] = Field(None, ge=0.0, le=1.0, description="Lower bound")
    upper_bound: Optional[float] = Field(None, ge=0.0, le=1.0, description="Upper bound")
    method: str = Field("CLOPPER_PEARSON_EXACT", description="Interval calculation method")
    status: str = Field("VALID", description="Calculation status (VALID, INSUFFICIENT_SUPPORT, etc.)")


class PermutationTestResult(BaseModel):
    """Paired permutation hypothesis test results under Intersection-Union Principle."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    permutation_count: int = Field(1000, description="Permutation iterations B")
    rng_algorithm: str = Field("PCG64", description="RNG bit generator")
    seed: int = Field(..., description="Deterministic 32-bit unsigned seed")
    t_obs: Optional[float] = Field(None, description="Observed statistic delta_sep = TSR(trigger) - max(TSR_shuff, TSR_noise)")
    t_obs_shuffled: Optional[float] = Field(None, description="Observed difference vs location-shuffled control")
    t_obs_noise: Optional[float] = Field(None, description="Observed difference vs magnitude-matched noise control")
    p_value: Optional[float] = Field(None, ge=0.0, le=1.0, description="IUT composite p-value = max(p_shuffled, p_noise)")
    p_value_shuffled: Optional[float] = Field(None, ge=0.0, le=1.0, description="Permutation p-value vs shuffled")
    p_value_noise: Optional[float] = Field(None, ge=0.0, le=1.0, description="Permutation p-value vs noise")
    significance: StatisticalSignificanceEnum = Field(
        StatisticalSignificanceEnum.NOT_EVALUATED, description="Significance decision"
    )
    status: StatisticalStatusEnum = Field(
        StatisticalStatusEnum.COMPLETED, description="Permutation test execution status"
    )


class CandidateStatisticalSummary(BaseModel):
    """Aggregate statistical evaluation summary for a single trigger candidate."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    candidate_hash: str = Field(..., description="Trigger candidate identity hash")
    sample_count: int = Field(..., description="Total evaluated sample count")
    eligible_sample_count: int = Field(..., description="Eligible sample count (clean prediction != target)")
    target_class: Optional[Union[int, str]] = Field(None, description="Target class evaluated")
    tar: Optional[float] = Field(None, description="Trigger Activation Rate")
    tsr: Optional[float] = Field(None, description="Trigger Success Rate")
    raw_tsr_shuffled: Optional[float] = Field(None, description="Raw TSR under location-shuffled control")
    raw_tsr_noise: Optional[float] = Field(None, description="Raw TSR under magnitude-matched noise control")
    control_baseline_tsr: Optional[float] = Field(
        None, description="Control baseline TSR = max(shuffled, noise)"
    )
    sample_envelope_tsr: Optional[float] = Field(
        None, description="Sample-level envelope TSR = mean(max(shuffled_i, noise_i))"
    )
    delta_separation: Optional[float] = Field(
        None, description="Control separation = TSR(trigger) - control_baseline_tsr"
    )
    confidence_interval: ConfidenceIntervalResult = Field(
        default_factory=ConfidenceIntervalResult, description="Clopper-Pearson 95% CI on TSR"
    )
    permutation_test: PermutationTestResult = Field(
        ..., description="Primary paired permutation test result"
    )
    raw_p_value: Optional[float] = Field(None, description="Unadjusted primary p-value")
    adjusted_p_value: Optional[float] = Field(None, description="BH-FDR adjusted p-value across candidates")
    multiple_testing_method: MultipleTestingMethodEnum = Field(
        MultipleTestingMethodEnum.BENJAMINI_HOCHBERG, description="Multiplicity adjustment method"
    )
    fdr_rank: Optional[int] = Field(None, description="FDR candidate rank")
    is_significant_after_fdr: bool = Field(False, description="Whether significant after FDR adjustment")
    taxonomy_classification: StatisticalResultTaxonomyEnum = Field(
        StatisticalResultTaxonomyEnum.NO_TRIGGER_EVIDENCE, description="Evidence taxonomy classification"
    )
    status: StatisticalStatusEnum = Field(
        StatisticalStatusEnum.COMPLETED, description="Candidate evaluation status"
    )


class StatisticalAnalysisAssessment(BaseModel):
    """Aggregate deterministic statistical assessment across evaluated backdoor candidates (ADR-089, ADR-090)."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: str = Field("1.0.0", description="Statistical assessment schema version")
    statistical_analysis_id: str = Field(..., description="Deterministic 64-hex statistical analysis ID")
    project_id: str = Field(..., description="Project identifier")
    model_id: str = Field(..., description="Evaluated model identifier")
    sample_set_hash: str = Field(..., description="SHA-256 hash of evaluated input sample set")
    trigger_assessment_id: str = Field(..., description="Linked Phase 9.4 trigger assessment ID")
    target_class: Optional[Union[int, str]] = Field(None, description="Target class evaluated")
    permutation_count: int = Field(1000, description="Permutation count B")
    alpha: float = Field(0.05, description="Significance alpha threshold")
    confidence_level: float = Field(0.95, description="Confidence interval level")
    multiple_comparison_method: MultipleTestingMethodEnum = Field(
        MultipleTestingMethodEnum.BENJAMINI_HOCHBERG, description="Candidate multiplicity method"
    )
    budget_accounting: InferenceBudgetAccounting = Field(
        ..., description="Inference budget accounting record"
    )
    candidate_summaries: List[CandidateStatisticalSummary] = Field(
        default_factory=list, description="Candidate-level statistical summaries"
    )
    stage2_promotions: List[CandidatePromotionAssessment] = Field(
        default_factory=list, description="Stage 2 promotion eligibility evaluations"
    )
    spatial_localization_summaries: List[SpatialLocalizationSummary] = Field(
        default_factory=list, description="Spatial localization results for promoted candidates"
    )
    assessment_metadata: Dict[str, Any] = Field(
        default_factory=dict, description="Metadata dictionary"
    )
