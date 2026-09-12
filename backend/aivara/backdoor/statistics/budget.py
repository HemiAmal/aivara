"""Inference Budget Accounting and Hard Ceiling Enforcement (ADR-081).

Tracks and enforces frozen inference budget limits across Stage 1 screening,
Stage 2 sample expansion, and Stage 2 spatial grid localization.
"""

from __future__ import annotations

from typing import Any, Dict, Optional
from pydantic import BaseModel, ConfigDict, Field

from aivara.backdoor.statistics.exceptions import BudgetExceededError

HARD_INFERENCE_CEILING: int = 16_000
STAGE1_DEFAULT_MAX_CANDIDATES: int = 16
STAGE1_DEFAULT_SAMPLES: int = 50
STAGE2_DEFAULT_MAX_PROMOTED: int = 2
STAGE2_DEFAULT_EXPANSION_SAMPLES: int = 200
STAGE2_DEFAULT_LOCALIZATION_SAMPLES: int = 50
STAGE2_GRID_CELL_COUNT: int = 64


class InferenceBudgetAccounting(BaseModel):
    """Immutable record of estimated and consumed inference budgets."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    stage1_sample_count: int = Field(50, description="Stage 1 screening sample count")
    stage1_candidate_count: int = Field(16, description="Stage 1 screening candidate count")
    stage1_inferences: int = Field(..., description="Stage 1 inferences (N * (1 + 3 * K1))")
    
    stage2_expansion_samples: int = Field(200, description="Stage 2 full expansion sample count")
    stage2_promoted_candidates: int = Field(2, description="Stage 2 promoted candidate count")
    stage2_expansion_inferences: int = Field(..., description="Stage 2 expansion inferences")
    
    stage2_localization_samples: int = Field(50, description="Stage 2 localization sample count")
    stage2_localization_cells: int = Field(64, description="Spatial grid cell count")
    stage2_localization_inferences: int = Field(..., description="Stage 2 localization inferences")
    
    total_inferences: int = Field(..., description="Sum of all planned/consumed inferences")
    hard_ceiling: int = Field(HARD_INFERENCE_CEILING, description="Hard ceiling limit")
    is_within_budget: bool = Field(True, description="Whether total is within ceiling")


def compute_budget_accounting(
    stage1_samples: int = STAGE1_DEFAULT_SAMPLES,
    stage1_candidates: int = STAGE1_DEFAULT_MAX_CANDIDATES,
    stage2_expansion_samples: int = STAGE2_DEFAULT_EXPANSION_SAMPLES,
    stage2_promoted_candidates: int = STAGE2_DEFAULT_MAX_PROMOTED,
    stage2_loc_samples: int = STAGE2_DEFAULT_LOCALIZATION_SAMPLES,
    stage2_loc_cells: int = STAGE2_GRID_CELL_COUNT,
    hard_ceiling: int = HARD_INFERENCE_CEILING,
) -> InferenceBudgetAccounting:
    """Calculate exact inference budget for multi-stage backdoor analysis.
    
    Stage 1: N_screen * (1 clean + 3 conditions * K1)
    Stage 2 Expansion: N_full * (1 clean + 3 conditions * K2)
    Stage 2 Localization: N_loc * K2 * 64 cells
    """
    if stage1_samples < 0 or stage1_candidates < 0:
        raise BudgetExceededError("Stage 1 sample and candidate counts must be non-negative.")
    if stage2_promoted_candidates < 0 or stage2_promoted_candidates > 2:
        raise BudgetExceededError(f"Stage 2 promoted candidates cannot exceed 2, got {stage2_promoted_candidates}")

    # Stage 1: clean (1) + active/shuffled/noise (3 * K1) per sample
    stage1_inf = stage1_samples * (1 + 3 * stage1_candidates) if stage1_candidates > 0 else 0

    # Stage 2 Expansion: clean (1) + active/shuffled/noise (3 * K2) per sample
    stage2_exp_inf = stage2_expansion_samples * (1 + 3 * stage2_promoted_candidates) if stage2_promoted_candidates > 0 else 0

    # Stage 2 Localization: 64 grid positions per promoted candidate per sample
    stage2_loc_inf = stage2_loc_samples * stage2_promoted_candidates * stage2_loc_cells if stage2_promoted_candidates > 0 else 0

    total_inf = stage1_inf + stage2_exp_inf + stage2_loc_inf
    within_budget = (total_inf <= hard_ceiling)

    return InferenceBudgetAccounting(
        stage1_sample_count=stage1_samples,
        stage1_candidate_count=stage1_candidates,
        stage1_inferences=stage1_inf,
        stage2_expansion_samples=stage2_expansion_samples,
        stage2_promoted_candidates=stage2_promoted_candidates,
        stage2_expansion_inferences=stage2_exp_inf,
        stage2_localization_samples=stage2_loc_samples,
        stage2_localization_cells=stage2_loc_cells,
        stage2_localization_inferences=stage2_loc_inf,
        total_inferences=total_inf,
        hard_ceiling=hard_ceiling,
        is_within_budget=within_budget,
    )


def validate_budget_ceiling(
    stage1_samples: int = STAGE1_DEFAULT_SAMPLES,
    stage1_candidates: int = STAGE1_DEFAULT_MAX_CANDIDATES,
    stage2_expansion_samples: int = STAGE2_DEFAULT_EXPANSION_SAMPLES,
    stage2_promoted_candidates: int = STAGE2_DEFAULT_MAX_PROMOTED,
    stage2_loc_samples: int = STAGE2_DEFAULT_LOCALIZATION_SAMPLES,
    stage2_loc_cells: int = STAGE2_GRID_CELL_COUNT,
    hard_ceiling: int = HARD_INFERENCE_CEILING,
) -> InferenceBudgetAccounting:
    """Validate that planned experiment strictly respects the hard ceiling, failing closed if exceeded."""
    budget = compute_budget_accounting(
        stage1_samples=stage1_samples,
        stage1_candidates=stage1_candidates,
        stage2_expansion_samples=stage2_expansion_samples,
        stage2_promoted_candidates=stage2_promoted_candidates,
        stage2_loc_samples=stage2_loc_samples,
        stage2_loc_cells=stage2_loc_cells,
        hard_ceiling=hard_ceiling,
    )
    if not budget.is_within_budget:
        raise BudgetExceededError(
            f"Planned experiment ({budget.total_inferences} inferences) exceeds hard inference ceiling ({hard_ceiling}). Failing closed."
        )
    return budget
