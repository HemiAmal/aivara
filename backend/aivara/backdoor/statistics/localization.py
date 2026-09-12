"""Spatial Grid Localization Hypothesis Testing (ADR-084).

Evaluates Stage 2 promoted candidates across an 8x8 (64 cell) spatial grid,
applying Holm-Bonferroni step-down correction to control Family-Wise Error Rate (FWER).
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field

from aivara.backdoor.statistics.exceptions import InsufficientSupportError, StatisticalComputationError
from aivara.backdoor.statistics.identity import derive_pcg64_seed
from aivara.backdoor.statistics.multiple_testing import holm_bonferroni_step_down
from aivara.backdoor.statistics.permutation import evaluate_paired_permutation_test

GRID_DIMENSION: int = 8
TOTAL_GRID_CELLS: int = 64


class GridCellStatisticalResult(BaseModel):
    """Statistical evaluation for a single spatial grid cell."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    cell_index: int = Field(..., ge=0, lt=64, description="Flat cell index (0..63)")
    grid_row: int = Field(..., ge=0, lt=8, description="Row index (0..7)")
    grid_col: int = Field(..., ge=0, lt=8, description="Column index (0..7)")
    sample_count: int = Field(..., description="Sample support for this cell")
    tsr: Optional[float] = Field(None, description="Trigger Success Rate at this cell")
    control_tsr: Optional[float] = Field(None, description="Control baseline TSR")
    delta_separation: Optional[float] = Field(None, description="Separation over control")
    raw_p_value: Optional[float] = Field(None, description="Unadjusted permutation p-value")
    adjusted_p_value: Optional[float] = Field(None, description="Holm-Bonferroni adjusted p-value")
    rank: Optional[int] = Field(None, description="Ascending p-value rank (1..64)")
    is_significant: bool = Field(False, description="Significant after Holm-Bonferroni adjustment")


class SpatialLocalizationSummary(BaseModel):
    """Aggregate spatial grid localization result for a promoted candidate."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    candidate_hash: str = Field(..., description="Evaluated candidate identity hash")
    statistical_analysis_id: str = Field(..., description="Canonical statistical analysis ID")
    grid_dimension: int = Field(8, description="Grid dimension (8x8)")
    total_cells: int = Field(64, description="Total grid cells")
    evaluable_cells: int = Field(..., description="Cells with adequate support")
    significant_cells: int = Field(..., description="Cells significant after Holm-Bonferroni")
    peak_cell_index: Optional[int] = Field(None, description="Cell index with highest separation")
    peak_delta_separation: Optional[float] = Field(None, description="Highest separation observed")
    min_adjusted_p_value: Optional[float] = Field(None, description="Lowest adjusted p-value")
    correction_method: str = Field("HOLM_BONFERRONI", description="Applied multiplicity correction")
    alpha: float = Field(0.05, description="FWER alpha threshold")
    cell_results: List[GridCellStatisticalResult] = Field(
        default_factory=list, description="Ordered per-cell evaluation results"
    )


def evaluate_spatial_grid_localization(
    candidate_hash: str,
    statistical_analysis_id: str,
    grid_cell_observations: List[Dict[str, Any]],
    alpha: float = 0.05,
    permutation_count: int = 1000,
) -> SpatialLocalizationSummary:
    """Execute spatial localization analysis over 64 grid cells with Holm-Bonferroni adjustment.
    
    Args:
        candidate_hash: Promoted candidate hash.
        statistical_analysis_id: Canonical statistical analysis identity.
        grid_cell_observations: List of 64 dicts with keys:
            - cell_index (0..63)
            - trigger_successes (List[int])
            - shuffled_successes (List[int])
            - noise_successes (List[int])
        alpha: FWER significance level (default 0.05).
        permutation_count: Number of permutations per cell (default 1000).
        
    Returns:
        SpatialLocalizationSummary with per-cell results and Holm-Bonferroni flags.
    """
    if len(grid_cell_observations) != TOTAL_GRID_CELLS:
        raise StatisticalComputationError(
            f"Expected exactly {TOTAL_GRID_CELLS} grid cells, got {len(grid_cell_observations)}"
        )

    cell_p_values: List[Optional[float]] = []
    cell_keys: List[str] = []
    intermediate_results: List[Dict[str, Any]] = []

    for cell_obs in grid_cell_observations:
        idx = int(cell_obs["cell_index"])
        row = idx // GRID_DIMENSION
        col = idx % GRID_DIMENSION
        trig_succ = cell_obs.get("trigger_successes", [])
        shuff_succ = cell_obs.get("shuffled_successes", [])
        noise_succ = cell_obs.get("noise_successes", [])
        n = len(trig_succ)

        cell_key = f"cell_{idx:02d}"
        cell_keys.append(cell_key)

        if n < 10:
            cell_p_values.append(None)
            intermediate_results.append({
                "cell_index": idx,
                "grid_row": row,
                "grid_col": col,
                "sample_count": n,
                "tsr": None,
                "control_tsr": None,
                "delta_separation": None,
                "raw_p_value": None,
            })
            continue

        # Derive cell-specific seed deterministically
        cell_seed = derive_pcg64_seed(
            statistical_analysis_id=statistical_analysis_id,
            experiment_tag=f"spatial_loc_cell_{idx}",
            candidate_hash=candidate_hash,
        )

        perm_res = evaluate_paired_permutation_test(
            trigger_successes=trig_succ,
            shuffled_successes=shuff_succ,
            noise_successes=noise_succ,
            seed=cell_seed,
            permutation_count=permutation_count,
            alpha=alpha,
        )

        raw_p = perm_res["p_value"]
        cell_p_values.append(raw_p)
        intermediate_results.append({
            "cell_index": idx,
            "grid_row": row,
            "grid_col": col,
            "sample_count": n,
            "tsr": perm_res["raw_tsr_trigger"],
            "control_tsr": perm_res["control_baseline_tsr"],
            "delta_separation": perm_res["delta_separation"],
            "raw_p_value": raw_p,
        })

    # Apply Holm-Bonferroni correction across all 64 grid cells
    adjusted_records = holm_bonferroni_step_down(
        p_values=cell_p_values,
        item_keys=cell_keys,
        alpha=alpha,
    )

    final_cell_results: List[GridCellStatisticalResult] = []
    evaluable_count = 0
    sig_count = 0
    peak_sep: Optional[float] = None
    peak_idx: Optional[int] = None
    min_adj_p: Optional[float] = None

    for inter, adj in zip(intermediate_results, adjusted_records):
        idx = inter["cell_index"]
        raw_p = inter["raw_p_value"]
        adj_p = adj["adjusted_p_value"]
        is_sig = adj["is_significant"]
        rank = adj["rank"]
        sep = inter["delta_separation"]

        if raw_p is not None:
            evaluable_count += 1
            if adj_p is not None:
                if min_adj_p is None or adj_p < min_adj_p:
                    min_adj_p = adj_p
            if sep is not None:
                if peak_sep is None or sep > peak_sep:
                    peak_sep = sep
                    peak_idx = idx
            if is_sig:
                sig_count += 1

        final_cell_results.append(
            GridCellStatisticalResult(
                cell_index=idx,
                grid_row=inter["grid_row"],
                grid_col=inter["grid_col"],
                sample_count=inter["sample_count"],
                tsr=inter["tsr"],
                control_tsr=inter["control_tsr"],
                delta_separation=inter["delta_separation"],
                raw_p_value=raw_p,
                adjusted_p_value=adj_p,
                rank=rank,
                is_significant=is_sig,
            )
        )

    return SpatialLocalizationSummary(
        candidate_hash=candidate_hash,
        statistical_analysis_id=statistical_analysis_id,
        grid_dimension=GRID_DIMENSION,
        total_cells=TOTAL_GRID_CELLS,
        evaluable_cells=evaluable_count,
        significant_cells=sig_count,
        peak_cell_index=peak_idx,
        peak_delta_separation=peak_sep,
        min_adjusted_p_value=min_adj_p,
        correction_method="HOLM_BONFERRONI",
        alpha=alpha,
        cell_results=final_cell_results,
    )
