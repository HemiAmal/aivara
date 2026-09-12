"""Phase 9.5: Statistical Trigger Significance & Control Comparison Module."""

from __future__ import annotations

from aivara.backdoor.statistics.budget import (
    HARD_INFERENCE_CEILING,
    InferenceBudgetAccounting,
    compute_budget_accounting,
    validate_budget_ceiling,
)
from aivara.backdoor.statistics.confidence import (
    clopper_pearson_confidence_interval,
    regularized_incomplete_beta,
)
from aivara.backdoor.statistics.engine import StatisticalAnalysisEngine
from aivara.backdoor.statistics.enums import (
    MultipleTestingMethodEnum,
    StagePromotionStatusEnum,
    StatisticalResultTaxonomyEnum,
    StatisticalSignificanceEnum,
    StatisticalStatusEnum,
)
from aivara.backdoor.statistics.exceptions import (
    BudgetExceededError,
    CandidatePromotionError,
    InsufficientSupportError,
    MultiplicityAdjustmentError,
    PairingIntegrityError,
    StatisticalAnalysisError,
    StatisticalComputationError,
)
from aivara.backdoor.statistics.identity import (
    compute_statistical_analysis_id,
    derive_pcg64_seed,
)
from aivara.backdoor.statistics.localization import (
    GridCellStatisticalResult,
    SpatialLocalizationSummary,
    evaluate_spatial_grid_localization,
)
from aivara.backdoor.statistics.models import (
    CandidateStatisticalSummary,
    ConfidenceIntervalResult,
    PermutationTestResult,
    StatisticalAnalysisAssessment,
)
from aivara.backdoor.statistics.multiple_testing import (
    benjamini_hochberg_fdr,
    holm_bonferroni_step_down,
)
from aivara.backdoor.statistics.permutation import evaluate_paired_permutation_test
from aivara.backdoor.statistics.policy import evaluate_result_taxonomy
from aivara.backdoor.statistics.promotion import (
    CandidatePromotionAssessment,
    evaluate_stage2_promotion,
)

__all__ = [
    "HARD_INFERENCE_CEILING",
    "InferenceBudgetAccounting",
    "compute_budget_accounting",
    "validate_budget_ceiling",
    "clopper_pearson_confidence_interval",
    "regularized_incomplete_beta",
    "StatisticalAnalysisEngine",
    "MultipleTestingMethodEnum",
    "StagePromotionStatusEnum",
    "StatisticalResultTaxonomyEnum",
    "StatisticalSignificanceEnum",
    "StatisticalStatusEnum",
    "BudgetExceededError",
    "CandidatePromotionError",
    "InsufficientSupportError",
    "MultiplicityAdjustmentError",
    "PairingIntegrityError",
    "StatisticalAnalysisError",
    "StatisticalComputationError",
    "compute_statistical_analysis_id",
    "derive_pcg64_seed",
    "GridCellStatisticalResult",
    "SpatialLocalizationSummary",
    "evaluate_spatial_grid_localization",
    "CandidateStatisticalSummary",
    "ConfidenceIntervalResult",
    "PermutationTestResult",
    "StatisticalAnalysisAssessment",
    "benjamini_hochberg_fdr",
    "holm_bonferroni_step_down",
    "evaluate_paired_permutation_test",
    "evaluate_result_taxonomy",
    "CandidatePromotionAssessment",
    "evaluate_stage2_promotion",
]
