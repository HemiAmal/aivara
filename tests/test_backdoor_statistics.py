"""Comprehensive Test Suite for Phase 9.5 Statistical Trigger Significance & Control Comparison."""

from __future__ import annotations

import math
import numpy as np
import pytest

from aivara.backdoor.activation.enums import (
    ActivationCriterionTypeEnum,
    ActivationDecisionEnum,
    BackdoorComparisonStatusEnum,
    BackdoorConditionEnum,
    BackdoorSupportStatusEnum,
)
from aivara.backdoor.activation.models import (
    ActivationCriterionSpec,
    ActivationDecisionRecord,
    PairedConditionResult,
    PairedObservation,
    TriggerActivationAssessment,
)
from aivara.backdoor.candidates.enums import TriggerFamilyEnum
from aivara.backdoor.statistics.budget import (
    HARD_INFERENCE_CEILING,
    InferenceBudgetAccounting,
    compute_budget_accounting,
    validate_budget_ceiling,
)
from aivara.backdoor.statistics.confidence import (
    beta_quantile,
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
    GRID_DIMENSION,
    TOTAL_GRID_CELLS,
    evaluate_spatial_grid_localization,
)
from aivara.backdoor.statistics.multiple_testing import (
    benjamini_hochberg_fdr,
    holm_bonferroni_step_down,
)
from aivara.backdoor.statistics.permutation import evaluate_paired_permutation_test
from aivara.backdoor.statistics.policy import evaluate_result_taxonomy
from aivara.backdoor.statistics.promotion import evaluate_stage2_promotion
from aivara.backdoor.transformation.enums import InputLayoutEnum


# ============================================================================
# 1. Clopper-Pearson Exact Binomial Confidence Interval Tests
# ============================================================================

class TestClopperPearsonConfidenceIntervals:
    """Validation of exact Clopper-Pearson 95% confidence intervals."""

    def test_insufficient_support_n_less_than_10(self):
        """N < 10 must return (None, None) and not fabricate intervals."""
        for n in range(0, 10):
            low, high = clopper_pearson_confidence_interval(k=min(1, n), n=n)
            assert low is None
            assert high is None

    def test_zero_successes_exact_formula(self):
        """k = 0 must give lower = 0.0 and upper = 1 - (alpha/2)^(1/N)."""
        n = 50
        alpha = 0.05
        low, high = clopper_pearson_confidence_interval(k=0, n=n, confidence_level=0.95)
        assert low == 0.0
        expected_high = 1.0 - (alpha / 2.0) ** (1.0 / n)
        assert math.isclose(high, expected_high, rel_tol=1e-9)

    def test_all_successes_exact_formula(self):
        """k = N must give lower = (alpha/2)^(1/N) and upper = 1.0."""
        n = 50
        alpha = 0.05
        low, high = clopper_pearson_confidence_interval(k=50, n=n, confidence_level=0.95)
        expected_low = (alpha / 2.0) ** (1.0 / n)
        assert math.isclose(low, expected_low, rel_tol=1e-9)
        assert high == 1.0

    def test_k_equals_1_and_k_equals_n_minus_1_reference_values(self):
        """k = 1 and k = N - 1 benchmarked against known mathematical reference values."""
        # N = 10, k = 1: [0.00253, 0.44502]
        low_1, high_1 = clopper_pearson_confidence_interval(k=1, n=10, confidence_level=0.95)
        assert math.isclose(low_1, 0.00253, abs_tol=1e-4)
        assert math.isclose(high_1, 0.44502, abs_tol=1e-4)

        # N = 10, k = 9: [0.55498, 0.99747] (symmetry with k = 1)
        low_9, high_9 = clopper_pearson_confidence_interval(k=9, n=10, confidence_level=0.95)
        assert math.isclose(low_9, 1.0 - high_1, abs_tol=1e-4)
        assert math.isclose(high_9, 1.0 - low_1, abs_tol=1e-4)

    def test_sample_scale_progression(self):
        """Test small (N=10), moderate (N=50), and larger (N=500) sample sizes."""
        # Small N = 10, k = 5
        low_10, high_10 = clopper_pearson_confidence_interval(k=5, n=10, confidence_level=0.95)
        assert math.isclose(low_10, 0.18709, abs_tol=1e-3)
        assert math.isclose(high_10, 0.81291, abs_tol=1e-3)

        # Moderate N = 50, k = 25
        low_50, high_50 = clopper_pearson_confidence_interval(k=25, n=50, confidence_level=0.95)
        assert math.isclose(low_50, 0.35526, abs_tol=1e-3)
        assert math.isclose(high_50, 0.64474, abs_tol=1e-3)

        # Larger N = 500, k = 250
        low_500, high_500 = clopper_pearson_confidence_interval(k=250, n=500, confidence_level=0.95)
        assert math.isclose(low_500, 0.45529, abs_tol=1e-3)
        assert math.isclose(high_500, 0.54471, abs_tol=1e-3)

        # Interval width shrinks strictly as N increases for p = 0.5
        assert (high_10 - low_10) > (high_50 - low_50) > (high_500 - low_500)

    def test_strict_monotonicity_in_k(self):
        """As k increases for fixed N, both lower and upper bounds must strictly increase."""
        n = 30
        prev_low = -1.0
        prev_high = -1.0
        for k in range(0, n + 1):
            low, high = clopper_pearson_confidence_interval(k=k, n=n, confidence_level=0.95)
            assert low is not None and high is not None
            assert low <= high
            assert 0.0 <= low <= 1.0
            assert 0.0 <= high <= 1.0
            assert low > prev_low
            assert high > prev_high
            prev_low = low
            prev_high = high

    def test_invalid_arguments(self):
        """Reject invalid successes k > n or negative numbers."""
        with pytest.raises(StatisticalComputationError):
            clopper_pearson_confidence_interval(k=15, n=10)
        with pytest.raises(StatisticalComputationError):
            clopper_pearson_confidence_interval(k=-1, n=10)
        with pytest.raises(StatisticalComputationError):
            clopper_pearson_confidence_interval(k=5, n=10, confidence_level=1.5)


# ============================================================================
# 2. Paired Permutation Test & Control Semantics
# ============================================================================

class TestPairedPermutationTest:
    """Validation of deterministic paired permutation hypothesis testing under Intersection-Union Principle."""

    def test_insufficient_support(self):
        """N < 10 must return INSUFFICIENT_SUPPORT and p_value = None."""
        trig = [1] * 8
        shuff = [0] * 8
        noise = [0] * 8
        res = evaluate_paired_permutation_test(trig, shuff, noise, seed=12345)
        assert res["status"] == StatisticalStatusEnum.INSUFFICIENT_SUPPORT
        assert res["p_value"] is None
        assert res["significance"] == StatisticalSignificanceEnum.NOT_EVALUATED

    def test_perfect_separation_significance(self):
        """When trigger is 100% successful and controls 0%, p-value must be near minimum (1/(B+1))."""
        n = 50
        trig = [1] * n
        shuff = [0] * n
        noise = [0] * n
        seed = 9999
        res = evaluate_paired_permutation_test(trig, shuff, noise, seed=seed, permutation_count=1000)
        assert res["status"] == StatisticalStatusEnum.COMPLETED
        assert res["raw_tsr_trigger"] == 1.0
        assert res["raw_tsr_shuffled"] == 0.0
        assert res["raw_tsr_noise"] == 0.0
        assert res["control_baseline_tsr"] == 0.0
        assert res["delta_separation"] == 1.0
        assert math.isclose(res["p_value"], 1.0 / 1001.0, rel_tol=1e-5)
        assert math.isclose(res["p_value_shuffled"], 1.0 / 1001.0, rel_tol=1e-5)
        assert math.isclose(res["p_value_noise"], 1.0 / 1001.0, rel_tol=1e-5)
        assert res["significance"] == StatisticalSignificanceEnum.SIGNIFICANT

    def test_iut_only_shuffled_significant_yields_non_significant_composite(self):
        """If trigger beats shuffled control but matches noise control, composite p-value must NOT be significant."""
        n = 50
        # Trigger: 40 successes
        trig = [1] * 40 + [0] * 10
        # Shuffled: 5 successes (trigger beats shuffled strongly)
        shuff = [1] * 5 + [0] * 45
        # Noise: 40 successes (trigger equals noise)
        noise = [1] * 40 + [0] * 10
        seed = 5555

        res = evaluate_paired_permutation_test(trig, shuff, noise, seed=seed, permutation_count=1000)
        assert res["p_value_shuffled"] < 0.001
        assert res["p_value_noise"] > 0.40
        # IUT p-value is exactly max(p_shuff, p_noise)
        assert res["p_value"] == max(res["p_value_shuffled"], res["p_value_noise"])
        assert 0.0 <= res["p_value"] <= 1.0
        assert res["significance"] == StatisticalSignificanceEnum.NOT_SIGNIFICANT

    def test_iut_only_noise_significant_yields_non_significant_composite(self):
        """If trigger beats noise control but matches shuffled control, composite p-value must NOT be significant."""
        n = 50
        # Trigger: 40 successes
        trig = [1] * 40 + [0] * 10
        # Shuffled: 40 successes (trigger equals shuffled)
        shuff = [1] * 40 + [0] * 10
        # Noise: 5 successes (trigger beats noise strongly)
        noise = [1] * 5 + [0] * 45
        seed = 6666

        res = evaluate_paired_permutation_test(trig, shuff, noise, seed=seed, permutation_count=1000)
        assert res["p_value_shuffled"] > 0.40
        assert res["p_value_noise"] < 0.001
        # IUT p-value is exactly max(p_shuff, p_noise)
        assert res["p_value"] == max(res["p_value_shuffled"], res["p_value_noise"])
        assert 0.0 <= res["p_value"] <= 1.0
        assert res["significance"] == StatisticalSignificanceEnum.NOT_SIGNIFICANT

    def test_iut_neither_control_significant(self):
        """When neither control is beaten, composite is NOT significant."""
        n = 50
        trig = [1] * 10 + [0] * 40
        shuff = [1] * 20 + [0] * 30
        noise = [1] * 25 + [0] * 25
        seed = 7777

        res = evaluate_paired_permutation_test(trig, shuff, noise, seed=seed, permutation_count=1000)
        assert res["p_value_shuffled"] > 0.50
        assert res["p_value_noise"] > 0.50
        assert res["p_value"] == max(res["p_value_shuffled"], res["p_value_noise"])
        assert 0.0 <= res["p_value"] <= 1.0
        assert res["significance"] == StatisticalSignificanceEnum.NOT_SIGNIFICANT

    def test_zero_separation_no_significance(self):
        """When trigger and controls have identical performance, p-value is large."""
        n = 50
        trig = [1, 0] * 25
        shuff = [1, 0] * 25
        noise = [1, 0] * 25
        seed = 4242
        res = evaluate_paired_permutation_test(trig, shuff, noise, seed=seed, permutation_count=1000)
        assert res["delta_separation"] == 0.0
        assert res["t_obs"] == 0.0
        assert res["p_value"] > 0.40
        assert res["significance"] == StatisticalSignificanceEnum.NOT_SIGNIFICANT

    def test_negative_separation_not_significant(self):
        """When controls outperform the trigger, significance must be NOT_SIGNIFICANT."""
        n = 50
        trig = [0] * n
        shuff = [1] * n
        noise = [1] * n
        seed = 8888
        res = evaluate_paired_permutation_test(trig, shuff, noise, seed=seed, permutation_count=1000)
        assert res["delta_separation"] == -1.0
        assert res["t_obs"] == -1.0
        assert res["significance"] == StatisticalSignificanceEnum.NOT_SIGNIFICANT

    def test_deterministic_rerun(self):
        """Exact same inputs and seed produce bitwise identical p-values and statistics."""
        trig = [1, 1, 1, 1, 1, 0, 0, 1, 1, 0] * 3
        shuff = [0, 0, 1, 0, 0, 0, 0, 1, 0, 0] * 3
        noise = [0, 1, 0, 0, 0, 0, 0, 0, 1, 0] * 3
        seed = 314159

        res1 = evaluate_paired_permutation_test(trig, shuff, noise, seed=seed, permutation_count=1000)
        res2 = evaluate_paired_permutation_test(trig, shuff, noise, seed=seed, permutation_count=1000)

        assert res1["p_value"] == res2["p_value"]
        assert res1["t_obs"] == res2["t_obs"]
        assert res1["delta_separation"] == res2["delta_separation"]

    def test_control_baseline_max_semantics(self):
        """Control baseline is max(TSR_shuff, TSR_noise) and preserved independently."""
        n = 20
        trig = [1] * n
        shuff = [1] * 4 + [0] * 16   # TSR = 0.20
        noise = [1] * 8 + [0] * 12   # TSR = 0.40
        res = evaluate_paired_permutation_test(trig, shuff, noise, seed=123, permutation_count=500)
        assert res["raw_tsr_trigger"] == 1.0
        assert res["raw_tsr_shuffled"] == 0.20
        assert res["raw_tsr_noise"] == 0.40
        assert res["control_baseline_tsr"] == 0.40
        assert res["delta_separation"] == 0.60


# ============================================================================
# 3. Multiple-Testing Adjustments (BH-FDR & Holm-Bonferroni)
# ============================================================================

class TestMultipleTestingAdjustments:
    """Validation of multiplicity corrections."""

    def test_benjamini_hochberg_fdr(self):
        """Verify Benjamini-Hochberg FDR calculation and monotonicity."""
        raw_p = [0.001, 0.010, 0.020, 0.040, 0.500]
        keys = ["c1", "c2", "c3", "c4", "c5"]
        results = benjamini_hochberg_fdr(raw_p, candidate_keys=keys, alpha=0.05)

        assert len(results) == 5
        # For p = [0.001, 0.01, 0.02, 0.04, 0.5], m = 5:
        # q1 = (5/1) * 0.001 = 0.005
        # q2 = (5/2) * 0.01 = 0.025
        # q3 = (5/3) * 0.02 = 0.0333
        # q4 = (5/4) * 0.04 = 0.05
        # q5 = (5/5) * 0.50 = 0.50
        assert math.isclose(results[0]["adjusted_p_value"], 0.005, rel_tol=1e-5)
        assert math.isclose(results[1]["adjusted_p_value"], 0.025, rel_tol=1e-5)
        assert math.isclose(results[2]["adjusted_p_value"], 0.033333, rel_tol=1e-4)
        assert results[0]["is_significant"] is True
        assert results[1]["is_significant"] is True
        assert results[2]["is_significant"] is True
        assert results[4]["is_significant"] is False

    def test_bh_fdr_with_none_entries(self):
        """None entries (insufficient support) are skipped in ranking and adjustment."""
        raw_p = [None, 0.001, None, 0.020]
        results = benjamini_hochberg_fdr(raw_p)
        assert results[0]["adjusted_p_value"] is None
        assert results[0]["is_significant"] is False
        assert results[1]["adjusted_p_value"] is not None
        assert results[2]["adjusted_p_value"] is None

    def test_holm_bonferroni_step_down(self):
        """Verify Holm-Bonferroni FWER step-down correction."""
        raw_p = [0.005, 0.010, 0.020, 0.040]
        results = holm_bonferroni_step_down(raw_p, alpha=0.05)
        assert len(results) == 4
        # m = 4:
        # q1 = (4 - 1 + 1) * 0.005 = 4 * 0.005 = 0.020
        # q2 = (4 - 2 + 1) * 0.010 = 3 * 0.010 = 0.030
        # q3 = (4 - 3 + 1) * 0.020 = 2 * 0.020 = 0.040
        # q4 = (4 - 4 + 1) * 0.040 = 1 * 0.040 = 0.040
        assert math.isclose(results[0]["adjusted_p_value"], 0.020, rel_tol=1e-5)
        assert math.isclose(results[1]["adjusted_p_value"], 0.030, rel_tol=1e-5)
        assert math.isclose(results[2]["adjusted_p_value"], 0.040, rel_tol=1e-5)
        assert math.isclose(results[3]["adjusted_p_value"], 0.040, rel_tol=1e-5)
        for r in results:
            assert r["is_significant"] is True


# ============================================================================
# 4. Stage 2 Candidate Promotion Gating
# ============================================================================

class TestStage2PromotionGating:
    """Validation of Stage 1 -> Stage 2 promotion eligibility rules."""

    def test_qualified_candidates_promotion(self):
        """Candidates meeting TAR >= 0.50, TSR >= 0.50, Sep > 0.20 are promoted up to 2."""
        records = [
            {"candidate_hash": "c1", "tar": 0.80, "tsr": 0.85, "delta_separation": 0.60, "sample_count": 50},
            {"candidate_hash": "c2", "tar": 0.70, "tsr": 0.75, "delta_separation": 0.40, "sample_count": 50},
            {"candidate_hash": "c3", "tar": 0.60, "tsr": 0.65, "delta_separation": 0.30, "sample_count": 50},
        ]
        promotions = evaluate_stage2_promotion(records, max_promoted_candidates=2)
        assert len(promotions) == 3
        # Top 2 promoted by delta_separation DESC
        assert promotions[0].candidate_hash == "c1"
        assert promotions[0].is_promoted is True
        assert promotions[0].status == StagePromotionStatusEnum.PROMOTED
        assert promotions[0].rank == 1

        assert promotions[1].candidate_hash == "c2"
        assert promotions[1].is_promoted is True
        assert promotions[1].status == StagePromotionStatusEnum.PROMOTED
        assert promotions[1].rank == 2

        # 3rd candidate exceeds rank capacity
        assert promotions[2].candidate_hash == "c3"
        assert promotions[2].is_promoted is False
        assert promotions[2].status == StagePromotionStatusEnum.NOT_PROMOTED_RANK_EXCEEDED
        assert promotions[2].rank == 3

    def test_disqualified_by_low_thresholds(self):
        """Test rejection when individual metrics fail thresholds."""
        records = [
            {"candidate_hash": "low_tar", "tar": 0.40, "tsr": 0.80, "delta_separation": 0.50, "sample_count": 50},
            {"candidate_hash": "low_tsr", "tar": 0.80, "tsr": 0.45, "delta_separation": 0.50, "sample_count": 50},
            {"candidate_hash": "low_sep", "tar": 0.80, "tsr": 0.80, "delta_separation": 0.15, "sample_count": 50},
            {"candidate_hash": "no_target", "tar": 0.80, "tsr": None, "delta_separation": 0.50, "sample_count": 50},
            {"candidate_hash": "low_n", "tar": 0.80, "tsr": 0.80, "delta_separation": 0.50, "sample_count": 5},
        ]
        promotions = evaluate_stage2_promotion(records)
        status_map = {p.candidate_hash: p.status for p in promotions}
        assert status_map["low_tar"] == StagePromotionStatusEnum.NOT_PROMOTED_LOW_TAR
        assert status_map["low_tsr"] == StagePromotionStatusEnum.NOT_PROMOTED_LOW_TSR
        assert status_map["low_sep"] == StagePromotionStatusEnum.NOT_PROMOTED_LOW_SEPARATION
        assert status_map["no_target"] == StagePromotionStatusEnum.NOT_APPLICABLE_NO_TARGET
        assert status_map["low_n"] == StagePromotionStatusEnum.INSUFFICIENT_SUPPORT


# ============================================================================
# 5. Spatial Grid Localization
# ============================================================================

class TestSpatialGridLocalization:
    """Validation of 8x8 spatial grid localization with Holm-Bonferroni adjustment."""

    def test_spatial_grid_evaluation_64_cells(self):
        """Ensure 64 cells are evaluated and Holm-Bonferroni is applied."""
        grid_obs = []
        for idx in range(TOTAL_GRID_CELLS):
            if idx == 10:
                # Strong cell: 100% trigger, 0% control
                trig = [1] * 50
                shuff = [0] * 50
                noise = [0] * 50
            else:
                # Noise cell: 0% trigger, 0% control
                trig = [0] * 50
                shuff = [0] * 50
                noise = [0] * 50

            grid_obs.append({
                "cell_index": idx,
                "trigger_successes": trig,
                "shuffled_successes": shuff,
                "noise_successes": noise,
            })

        summary = evaluate_spatial_grid_localization(
            candidate_hash="cand_loc_test",
            statistical_analysis_id="stat_analysis_test_id",
            grid_cell_observations=grid_obs,
            alpha=0.05,
            permutation_count=2000,
        )

        assert summary.total_cells == 64
        assert summary.evaluable_cells == 64
        assert summary.significant_cells >= 1
        assert summary.peak_cell_index == 10
        assert summary.peak_delta_separation == 1.0
        assert summary.cell_results[10].is_significant is True
        assert summary.cell_results[10].grid_row == 1
        assert summary.cell_results[10].grid_col == 2


# ============================================================================
# 6. Budget Accounting & Ceiling Enforcement
# ============================================================================

class TestBudgetAccounting:
    """Validation of inference budgets and 16,000 hard ceiling enforcement."""

    def test_standard_staged_budget_calculation(self):
        """Standard pipeline: Stage 1 (2450) + Stage 2 (1400 + 6400) = 10,250 <= 16,000."""
        budget = compute_budget_accounting()
        assert budget.stage1_inferences == 2450
        assert budget.stage2_expansion_inferences == 1400
        assert budget.stage2_localization_inferences == 6400
        assert budget.total_inferences == 10250
        assert budget.is_within_budget is True

    def test_budget_exceeded_fails_closed(self):
        """Exceeding 16,000 inferences raises BudgetExceededError."""
        with pytest.raises(BudgetExceededError):
            validate_budget_ceiling(
                stage1_samples=500,
                stage1_candidates=32,
            )


# ============================================================================
# 7. Internal Policy Taxonomy Mapping
# ============================================================================

class TestPolicyTaxonomyMapping:
    """Validation of Phase 9.1 non-accusatory result taxonomy classification."""

    def test_strong_trigger_consistency(self):
        """N >= 100, TSR >= 0.90, Sep >= 0.60, p < 0.001 -> STRONG_TRIGGER_CONSISTENCY."""
        tax = evaluate_result_taxonomy(
            sample_count=100,
            tar=0.95,
            tsr=0.92,
            delta_separation=0.65,
            adjusted_p_value=0.0005,
        )
        assert tax == StatisticalResultTaxonomyEnum.STRONG_TRIGGER_CONSISTENCY

    def test_targeted_effect_detected(self):
        """N >= 30, TAR >= 0.70, TSR >= 0.70, Sep >= 0.40, p < 0.05 -> TARGETED_EFFECT_DETECTED."""
        tax = evaluate_result_taxonomy(
            sample_count=30,
            tar=0.75,
            tsr=0.75,
            delta_separation=0.45,
            adjusted_p_value=0.01,
        )
        assert tax == StatisticalResultTaxonomyEnum.TARGETED_EFFECT_DETECTED

    def test_normal_sensitivity_only(self):
        """Trigger active, but separation <= 0.0 -> NORMAL_SENSITIVITY_ONLY."""
        tax = evaluate_result_taxonomy(
            sample_count=50,
            tar=0.80,
            tsr=0.30,
            delta_separation=-0.10,
            adjusted_p_value=0.50,
        )
        assert tax == StatisticalResultTaxonomyEnum.NORMAL_SENSITIVITY_ONLY

    def test_insufficient_support(self):
        """N < 10 -> INSUFFICIENT_SUPPORT."""
        tax = evaluate_result_taxonomy(
            sample_count=8,
            tar=1.0,
            tsr=1.0,
            delta_separation=1.0,
            adjusted_p_value=0.001,
        )
        assert tax == StatisticalResultTaxonomyEnum.INSUFFICIENT_SUPPORT


# ============================================================================
# 8. End-to-End Statistical Analysis Engine
# ============================================================================

class TestStatisticalAnalysisEngineEndToEnd:
    """End-to-end integration test of StatisticalAnalysisEngine."""

    @pytest.fixture
    def mock_activation_assessment(self) -> TriggerActivationAssessment:
        """Create a valid Phase 9.4 TriggerActivationAssessment with 30 samples."""
        n = 30
        paired_obs = []
        for i in range(n):
            # Target class is 1
            # Clean predicts 0
            clean_res = PairedConditionResult(
                condition=BackdoorConditionEnum.CLEAN,
                observation_id=f"clean_{i}",
                transformed_array_hash=f"hash_clean_{i}",
                prediction_label=0,
                activation_decision=ActivationDecisionEnum.NOT_APPLICABLE,
            )
            # Active trigger flips to 1 for 25 out of 30 samples
            trig_pred = 1 if i < 25 else 0
            trig_res = PairedConditionResult(
                condition=BackdoorConditionEnum.ACTIVE_TRIGGER,
                observation_id=f"trig_{i}",
                transformed_array_hash=f"hash_trig_{i}",
                prediction_label=trig_pred,
                is_target_matched=(trig_pred == 1),
                activation_decision=ActivationDecisionEnum.ACTIVATED if trig_pred == 1 else ActivationDecisionEnum.NOT_ACTIVATED,
            )
            # Shuffled control flips to 1 for 2 out of 30 samples
            shuff_pred = 1 if i < 2 else 0
            shuff_res = PairedConditionResult(
                condition=BackdoorConditionEnum.LOCATION_SHUFFLED,
                observation_id=f"shuff_{i}",
                transformed_array_hash=f"hash_shuff_{i}",
                prediction_label=shuff_pred,
                is_target_matched=(shuff_pred == 1),
                activation_decision=ActivationDecisionEnum.ACTIVATED if shuff_pred == 1 else ActivationDecisionEnum.NOT_ACTIVATED,
            )
            # Noise control flips to 1 for 1 out of 30 samples
            noise_pred = 1 if i < 1 else 0
            noise_res = PairedConditionResult(
                condition=BackdoorConditionEnum.MAGNITUDE_MATCHED_NOISE,
                observation_id=f"noise_{i}",
                transformed_array_hash=f"hash_noise_{i}",
                prediction_label=noise_pred,
                is_target_matched=(noise_pred == 1),
                activation_decision=ActivationDecisionEnum.ACTIVATED if noise_pred == 1 else ActivationDecisionEnum.NOT_ACTIVATED,
            )

            paired_obs.append(
                PairedObservation(
                    sample_index=i,
                    source_input_id=f"sample_{i}",
                    source_input_hash=f"src_hash_{i}",
                    candidate_hash="cand_hash_001",
                    input_layout=InputLayoutEnum.CHW,
                    clean_result=clean_res,
                    active_trigger_result=trig_res,
                    location_shuffled_result=shuff_res,
                    magnitude_matched_noise_result=noise_res,
                    target_class=1,
                    is_activated=(trig_pred == 1),
                    is_target_matched=(trig_pred == 1),
                )
            )

        return TriggerActivationAssessment(
            schema_version="1.0.0",
            assessment_id="test_assessment_id_001",
            experiment_id="test_exp_id_001",
            project_id="proj_001",
            model_id="model_001",
            candidate_hash="cand_hash_001",
            candidate_family=TriggerFamilyEnum.SPATIAL_PATCH,
            input_layout=InputLayoutEnum.CHW,
            sample_count=n,
            eligible_sample_count=n,
            activated_sample_count=25,
            target_matched_sample_count=25,
            support_status=BackdoorSupportStatusEnum.SUPPORT_ELIGIBLE,
            is_support_eligible=True,
            tar=25.0 / 30.0,
            tsr=25.0 / 30.0,
            status=BackdoorComparisonStatusEnum.COMPLETED,
            paired_observations=paired_obs,
        )

    def test_engine_orchestration(self, mock_activation_assessment):
        """Validate engine end-to-end processing across candidate assessments."""
        engine = StatisticalAnalysisEngine(permutation_count=1000, alpha=0.05)
        assessment = engine.evaluate_assessments(
            project_id="proj_001",
            activation_assessments=[mock_activation_assessment],
            target_class=1,
        )

        assert assessment.project_id == "proj_001"
        assert assessment.statistical_analysis_id is not None
        assert len(assessment.candidate_summaries) == 1

        cand = assessment.candidate_summaries[0]
        assert cand.sample_count == 30
        assert math.isclose(cand.tsr, 25.0 / 30.0, rel_tol=1e-5)
        assert math.isclose(cand.raw_tsr_shuffled, 2.0 / 30.0, rel_tol=1e-5)
        assert math.isclose(cand.raw_tsr_noise, 1.0 / 30.0, rel_tol=1e-5)
        assert cand.delta_separation > 0.60
        assert cand.raw_p_value is not None
        assert cand.raw_p_value < 0.05
        assert cand.is_significant_after_fdr is True
        assert cand.taxonomy_classification == StatisticalResultTaxonomyEnum.TARGETED_EFFECT_DETECTED

        # Stage 2 promotion check
        assert len(assessment.stage2_promotions) == 1
        assert assessment.stage2_promotions[0].is_promoted is True

    def test_project_isolation_rejection(self, mock_activation_assessment):
        """Cross-project input must raise PairingIntegrityError."""
        engine = StatisticalAnalysisEngine()
        with pytest.raises(PairingIntegrityError):
            engine.evaluate_assessments(
                project_id="other_project_999",
                activation_assessments=[mock_activation_assessment],
            )

    def test_model_id_mismatch_rejection(self, mock_activation_assessment):
        """Mismatched model_id across assessments must raise PairingIntegrityError."""
        ass2 = mock_activation_assessment.model_copy(update={"model_id": "different_model"})
        engine = StatisticalAnalysisEngine()
        with pytest.raises(PairingIntegrityError):
            engine.evaluate_assessments(
                project_id="proj_001",
                activation_assessments=[mock_activation_assessment, ass2],
            )


# ============================================================================
# 9. Edge Cases, Property Invariants & Adversarial Security Tests
# ============================================================================

class TestStatisticalEdgeCasesAndAdversarial:
    """Comprehensive validation of edge cases, properties, and adversarial inputs."""

    def test_edge_case_n_equals_10(self):
        """Boundary test: N = 10 exactly is support-eligible."""
        trig = [1] * 10
        shuff = [0] * 10
        noise = [0] * 10
        res = evaluate_paired_permutation_test(trig, shuff, noise, seed=123, permutation_count=500)
        assert res["status"] == StatisticalStatusEnum.COMPLETED
        assert res["p_value"] is not None

    def test_edge_case_n_equals_0(self):
        """Boundary test: N = 0 returns INSUFFICIENT_SUPPORT."""
        res = evaluate_paired_permutation_test([], [], [], seed=123)
        assert res["status"] == StatisticalStatusEnum.INSUFFICIENT_SUPPORT
        assert res["p_value"] is None

    def test_edge_case_all_successes_all_conditions(self):
        """When all conditions succeed (TSR=1.0 for all), separation = 0.0 and p-value is large."""
        n = 20
        trig = [1] * n
        shuff = [1] * n
        noise = [1] * n
        res = evaluate_paired_permutation_test(trig, shuff, noise, seed=456)
        assert res["delta_separation"] == 0.0
        assert res["t_obs"] == 0.0
        assert res["p_value"] > 0.40
        assert res["significance"] == StatisticalSignificanceEnum.NOT_SIGNIFICANT

    def test_edge_case_all_failures_all_conditions(self):
        """When all conditions fail (TSR=0.0 for all), separation = 0.0 and p-value is 1.0."""
        n = 20
        trig = [0] * n
        shuff = [0] * n
        noise = [0] * n
        res = evaluate_paired_permutation_test(trig, shuff, noise, seed=789)
        assert res["delta_separation"] == 0.0
        assert res["t_obs"] == 0.0
        assert res["p_value"] == 1.0
        assert res["significance"] == StatisticalSignificanceEnum.NOT_SIGNIFICANT

    def test_property_p_value_bounded_in_unit_interval(self):
        """Permutation p-values must strictly reside in [1/(B+1), 1.0]."""
        for count in [100, 500, 1000]:
            res = evaluate_paired_permutation_test([1]*20, [0]*20, [0]*20, seed=42, permutation_count=count)
            p = res["p_value"]
            assert 0.0 < p <= 1.0
            assert p >= (1.0 / (count + 1))

    def test_property_confidence_interval_bounds(self):
        """Clopper-Pearson CI lower <= upper and within [0, 1]."""
        for n in [10, 20, 50, 100]:
            for k in range(0, n + 1, max(1, n // 5)):
                low, high = clopper_pearson_confidence_interval(k=k, n=n)
                assert low is not None and high is not None
                assert 0.0 <= low <= high <= 1.0

    def test_property_multiple_testing_monotonicity(self):
        """BH adjusted p-values must be >= raw p-values and non-decreasing with rank."""
        raw_p = [0.001, 0.004, 0.012, 0.035, 0.090, 0.200, 0.800]
        results = benjamini_hochberg_fdr(raw_p, alpha=0.05)
        adj_p = [r["adjusted_p_value"] for r in results]

        for r, a in zip(raw_p, adj_p):
            assert a >= r

        # Non-decreasing
        for i in range(len(adj_p) - 1):
            assert adj_p[i] <= adj_p[i + 1]

    def test_property_holm_bonferroni_monotonicity(self):
        """Holm-Bonferroni adjusted p-values must be >= raw p-values."""
        raw_p = [0.001, 0.005, 0.010, 0.025, 0.100]
        results = holm_bonferroni_step_down(raw_p, alpha=0.05)
        adj_p = [r["adjusted_p_value"] for r in results]

        for r, a in zip(raw_p, adj_p):
            assert a >= r
        for i in range(len(adj_p) - 1):
            assert adj_p[i] <= adj_p[i + 1]

    def test_adversarial_non_binary_indicators_rejection(self):
        """Non-binary values (e.g. 2, -1, float 0.5) must raise StatisticalComputationError."""
        with pytest.raises(StatisticalComputationError):
            evaluate_paired_permutation_test([2, 0]*10, [0]*20, [0]*20, seed=1)
        with pytest.raises(StatisticalComputationError):
            evaluate_paired_permutation_test([-1, 0]*10, [0]*20, [0]*20, seed=1)

    def test_adversarial_mismatched_lengths_rejection(self):
        """Condition lists of unequal lengths must raise StatisticalComputationError."""
        with pytest.raises(StatisticalComputationError):
            evaluate_paired_permutation_test([1]*20, [0]*19, [0]*20, seed=1)

    def test_adversarial_invalid_permutation_counts(self):
        """Negative, zero, or excessively huge permutation counts must be rejected."""
        with pytest.raises(StatisticalComputationError):
            evaluate_paired_permutation_test([1]*20, [0]*20, [0]*20, seed=1, permutation_count=0)
        with pytest.raises(StatisticalComputationError):
            evaluate_paired_permutation_test([1]*20, [0]*20, [0]*20, seed=1, permutation_count=-100)
        with pytest.raises(StatisticalComputationError):
            evaluate_paired_permutation_test([1]*20, [0]*20, [0]*20, seed=1, permutation_count=200_000)

    def test_adversarial_invalid_alpha(self):
        """Alpha outside (0, 1) must be rejected."""
        with pytest.raises(StatisticalComputationError):
            evaluate_paired_permutation_test([1]*20, [0]*20, [0]*20, seed=1, alpha=0.0)
        with pytest.raises(StatisticalComputationError):
            evaluate_paired_permutation_test([1]*20, [0]*20, [0]*20, seed=1, alpha=1.0)
        with pytest.raises(MultiplicityAdjustmentError):
            benjamini_hochberg_fdr([0.01, 0.02], alpha=-0.05)

    def test_adversarial_tie_breaking_determinism(self):
        """Identical raw p-values must be resolved deterministically using candidate identifiers."""
        raw_p = [0.01, 0.01, 0.01]
        keys = ["cand_c", "cand_a", "cand_b"]
        results = benjamini_hochberg_fdr(raw_p, candidate_keys=keys)
        # Ranks must be assigned deterministically
        assert results[0]["rank"] == 3  # cand_c
        assert results[1]["rank"] == 1  # cand_a
        assert results[2]["rank"] == 2  # cand_b

    def test_adversarial_empty_assessments_engine(self):
        """Engine must reject empty assessment list."""
        engine = StatisticalAnalysisEngine()
        with pytest.raises(StatisticalAnalysisError):
            engine.evaluate_assessments(project_id="proj_01", activation_assessments=[])

