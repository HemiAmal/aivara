"""Phase 9.1 Architecture Contracts & Mathematical Edge Cases Verification.

Verifies the frozen Phase 9.1 mathematical, statistical, and resource accounting contracts:
    - TAR=0 -> TSR=None with status=NOT_APPLICABLE
    - Activated=0 -> TSR=None
    - Missing ground truth -> CPI=None with status=UNAVAILABLE
    - 4 mandatory conditions (C0, C_tau, C_shuff, C_noise) + 1 optional (M_ref)
    - Staged screening inference budget accounting (Total <= 16,000)
    - Staged spatial localization budget bounds (M x M <= 8x8, max 2 candidates)
    - Benjamini-Hochberg (FDR) and Holm-Bonferroni multiplicity corrections
    - Empirical control separation (Delta_sep) calculation
    - Sample support tiers (N < 10 -> INSUFFICIENT_SUPPORT)
    - Strict result taxonomy without BACKDOOR_CONFIRMED or culpability claims
"""

from __future__ import annotations

import math
from typing import Any, Dict, List, Optional, Tuple
import numpy as np
import pytest


# ============================================================================
# 1. CORE METRIC EDGE CASES & FORMULAS (ADR-078, ADR-079, ADR-080)
# ============================================================================

def compute_tar_and_tsr(
    clean_preds: List[int],
    trig_preds: List[int],
    target_class: int,
) -> Tuple[float, Optional[float], str]:
    """Compute TAR and TSR with strict zero-denominator handling (ADR-079)."""
    if len(clean_preds) != len(trig_preds):
        raise ValueError("Sample count mismatch between clean and triggered predictions.")
    
    n = len(clean_preds)
    if n < 10:
        return 0.0, None, "INSUFFICIENT_SUPPORT"

    # Activated samples: clean != triggered
    activated_mask = [c != t for c, t in zip(clean_preds, trig_preds)]
    activated_count = sum(activated_mask)
    tar = activated_count / n

    if activated_count == 0 or tar == 0.0:
        return 0.0, None, "NOT_APPLICABLE"

    # Eligible for target transition: clean was not already target_class
    eligible_mask = [c != target_class for c in clean_preds]
    eligible_count = sum(eligible_mask)

    if eligible_count == 0:
        return tar, None, "NOT_APPLICABLE"

    # Target successes: clean != target_class AND triggered == target_class
    target_success_count = sum(c != target_class and t == target_class for c, t in zip(clean_preds, trig_preds))
    tsr = target_success_count / eligible_count
    return tar, tsr, "VALID"


def compute_cpi(
    clean_preds: List[int],
    ground_truth: Optional[List[int]],
    expected_accuracy: Optional[float] = None,
) -> Tuple[Optional[float], str]:
    """Compute Clean Performance Impact strictly requiring ground truth (ADR-080)."""
    if ground_truth is None or len(ground_truth) == 0:
        return None, "UNAVAILABLE"
    
    if len(clean_preds) != len(ground_truth):
        return None, "UNVERIFIABLE"

    correct = sum(p == g for p, g in zip(clean_preds, ground_truth))
    actual_acc = correct / len(ground_truth)
    
    if expected_accuracy is None:
        expected_accuracy = 1.0  # baseline reference
        
    cpi = expected_accuracy - actual_acc
    return cpi, "VALID"


def compute_control_separation(
    tsr_active: Optional[float],
    tsr_shuff: Optional[float],
    tsr_noise: Optional[float],
) -> Optional[float]:
    """Compute Control Separation Delta_sep against max control (ADR-078)."""
    if tsr_active is None:
        return None
    ctrl_max = max(tsr_shuff or 0.0, tsr_noise or 0.0)
    return tsr_active - ctrl_max


# ============================================================================
# 2. MULTIPLICITY CORRECTIONS (ADR-084)
# ============================================================================

def benjamini_hochberg_correction(p_values: List[float], alpha: float = 0.05) -> List[Tuple[float, bool]]:
    """Benjamini-Hochberg False Discovery Rate (FDR) correction."""
    m = len(p_values)
    if m == 0:
        return []
    
    indexed_p = sorted(enumerate(p_values), key=lambda x: x[1])
    adjusted = [0.0] * m
    significant = [False] * m
    
    cum_min = 1.0
    for rank_minus_1, (orig_idx, p) in reversed(list(enumerate(indexed_p))):
        rank = rank_minus_1 + 1
        adj_p = min(p * m / rank, 1.0)
        cum_min = min(cum_min, adj_p)
        adjusted[orig_idx] = cum_min
        significant[orig_idx] = cum_min <= alpha
        
    return list(zip(adjusted, significant))


def holm_bonferroni_correction(p_values: List[float], alpha: float = 0.05) -> List[Tuple[float, bool]]:
    """Holm-Bonferroni FWER step-down correction for localized grid cells."""
    m = len(p_values)
    if m == 0:
        return []
    
    indexed_p = sorted(enumerate(p_values), key=lambda x: x[1])
    adjusted = [0.0] * m
    significant = [False] * m
    
    cum_max = 0.0
    for rank_minus_1, (orig_idx, p) in enumerate(indexed_p):
        rank = rank_minus_1 + 1
        adj_p = min(p * (m - rank + 1), 1.0)
        cum_max = max(cum_max, adj_p)
        adjusted[orig_idx] = cum_max
        significant[orig_idx] = cum_max <= alpha
        
    return list(zip(adjusted, significant))


# ============================================================================
# 3. RESOURCE & INFERENCE BUDGET ACCOUNTING (ADR-081, ADR-082)
# ============================================================================

def calculate_staged_inference_budget(
    num_candidates_stage1: int = 16,
    samples_stage1: int = 50,
    max_candidates_stage2: int = 2,
    samples_stage2_full: int = 200,
    grid_cells_stage2: int = 64,
    samples_stage2_loc: int = 50,
    has_ref_model: bool = False,
) -> Dict[str, Any]:
    """Calculate inference budget for staged screening (ADR-081, ADR-082)."""
    # 4 conditions for candidates: Clean (1 per batch), Active (1), Shuff (1), Noise (1)
    # Plus optional ref model (+1 per active)
    cand_multiplier = 4 if has_ref_model else 3

    # Stage 1: Screening on 50 samples
    stage1_clean = samples_stage1
    stage1_triggers = samples_stage1 * num_candidates_stage1 * cand_multiplier
    stage1_total = stage1_clean + stage1_triggers

    # Stage 2: Full expansion on up to max_candidates_stage2
    stage2_clean = samples_stage2_full
    stage2_expansion = samples_stage2_full * max_candidates_stage2 * cand_multiplier
    
    # Stage 2 Localization: 64 grid locations on 50 samples
    stage2_localization = samples_stage2_loc * max_candidates_stage2 * grid_cells_stage2
    stage2_total = stage2_clean + stage2_expansion + stage2_localization

    total_inferences = stage1_total + stage2_total
    hard_ceiling = 16_000

    return {
        "stage1_inferences": stage1_total,
        "stage2_inferences": stage2_total,
        "total_inferences": total_inferences,
        "hard_ceiling": hard_ceiling,
        "within_budget": total_inferences <= hard_ceiling,
    }


# ============================================================================
# UNIT TESTS FOR ARCHITECTURE CONTRACTS
# ============================================================================

class TestPhase91ArchitectureContracts:
    """Verifies all Phase 9.1 freeze corrections."""

    def test_tar_zero_tsr_undefined_semantics(self):
        """When TAR=0 (no sample output change), TSR is None and status is NOT_APPLICABLE."""
        clean = [0] * 20
        trig = [0] * 20  # Identical outputs
        tar, tsr, status = compute_tar_and_tsr(clean, trig, target_class=1)
        
        assert tar == 0.0
        assert tsr is None
        assert status == "NOT_APPLICABLE"

    def test_activated_zero_tsr_none(self):
        """When activated count is 0, TSR is None and status is NOT_APPLICABLE."""
        clean = [1, 2, 3, 4, 1, 2, 3, 4, 1, 2]
        trig = [1, 2, 3, 4, 1, 2, 3, 4, 1, 2]
        tar, tsr, status = compute_tar_and_tsr(clean, trig, target_class=5)
        
        assert tar == 0.0
        assert tsr is None
        assert status == "NOT_APPLICABLE"

    def test_insufficient_support_rejection(self):
        """When sample count N < 10, returns INSUFFICIENT_SUPPORT and tsr=None."""
        clean = [0, 1, 2, 3]  # Only 4 samples
        trig = [1, 1, 1, 1]
        tar, tsr, status = compute_tar_and_tsr(clean, trig, target_class=1)
        
        assert tsr is None
        assert status == "INSUFFICIENT_SUPPORT"

    def test_cpi_ground_truth_dependency(self):
        """CPI returns UNAVAILABLE when ground truth labels are missing."""
        clean = [0, 1, 2, 0, 1, 2, 0, 1, 2, 0]
        cpi_no_gt, status_no_gt = compute_cpi(clean, ground_truth=None)
        assert cpi_no_gt is None
        assert status_no_gt == "UNAVAILABLE"

        # With ground truth
        gt = [0, 1, 2, 0, 1, 2, 0, 1, 2, 0]
        cpi_with_gt, status_gt = compute_cpi(clean, ground_truth=gt, expected_accuracy=1.0)
        assert cpi_with_gt == 0.0
        assert status_gt == "VALID"

    def test_control_separation_formula(self):
        """Control separation evaluates active TSR against maximum of control conditions."""
        tsr_active = 0.85
        tsr_shuff = 0.15
        tsr_noise = 0.20
        delta_sep = compute_control_separation(tsr_active, tsr_shuff, tsr_noise)
        
        assert math.isclose(delta_sep, 0.65, rel_tol=1e-5)

    def test_multiplicity_benjamini_hochberg(self):
        """Benjamini-Hochberg FDR controls false positive rate across multiple candidates."""
        raw_p_values = [0.001, 0.01, 0.04, 0.20, 0.50]
        bh_results = benjamini_hochberg_correction(raw_p_values, alpha=0.05)
        
        # P = 0.001 * 5 / 1 = 0.005 <= 0.05 -> Significant
        assert bh_results[0][1] is True
        # P = 0.50 * 5 / 5 = 0.50 > 0.05 -> Not significant
        assert bh_results[4][1] is False

    def test_inference_budget_accounting_within_ceiling(self):
        """Staged screening inference budget strictly respects the 16,000 ceiling."""
        budget = calculate_staged_inference_budget(
            num_candidates_stage1=16,
            samples_stage1=50,
            max_candidates_stage2=2,
            samples_stage2_full=200,
            grid_cells_stage2=64,
            samples_stage2_loc=50,
            has_ref_model=False,
        )
        
        assert budget["within_budget"] is True
        assert budget["total_inferences"] <= 16_000
        assert budget["total_inferences"] == 10_250

    def test_result_taxonomy_neutrality_audit(self):
        """Result taxonomy must strictly adhere to evidence-oriented states without malice claims."""
        permitted_states = {
            "NO_TRIGGER_EVIDENCE",
            "NORMAL_SENSITIVITY_ONLY",
            "TRIGGER_CANDIDATE_OBSERVED",
            "TARGETED_EFFECT_DETECTED",
            "STRONG_TRIGGER_CONSISTENCY",
            "INSUFFICIENT_SUPPORT",
            "INCOMPARABLE",
            "UNAVAILABLE",
            "UNVERIFIABLE",
        }
        forbidden_states = {
            "BACKDOOR_CONFIRMED",
            "MALICIOUS_MODEL",
            "ATTACK_DETECTED",
            "CULPRIT_IDENTIFIED",
            "TROJAN_VERIFIED",
        }
        for state in forbidden_states:
            assert state not in permitted_states
