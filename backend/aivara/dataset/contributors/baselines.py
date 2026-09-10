"""Leave-One-Out (LOO) background baseline and subgroup-aware stratification engine."""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Sequence, Tuple

from aivara.dataset.schemas import CanonicalSample


def compute_leave_one_out_baseline(
    total_anomalies: float,
    total_exposure: float,
    contributor_anomalies: float,
    contributor_exposure: float,
) -> Tuple[float, float, Optional[float]]:
    """Compute Leave-One-Out (LOO) dataset background statistics excluding the contributor.
    
    Formula:
      N_bg = total_exposure - contributor_exposure
      K_bg = total_anomalies - contributor_anomalies
      R_bg = K_bg / N_bg if N_bg > 0 else None
      
    Returns:
      Tuple of (background_count, background_exposure, background_rate).
      When background_exposure <= 0, background_rate is None (INSUFFICIENT_BACKGROUND_SUPPORT).
    """
    bg_exposure = max(0.0, float(total_exposure - contributor_exposure))
    bg_anomalies = max(0.0, float(total_anomalies - contributor_anomalies))

    if bg_exposure <= 0.0:
        return bg_anomalies, 0.0, None

    bg_rate = min(1.0, max(0.0, float(bg_anomalies / bg_exposure)))
    return bg_anomalies, bg_exposure, bg_rate


def compute_subgroup_stratified_rates(
    samples: Sequence[CanonicalSample],
    sample_anomaly_flags: Dict[str, bool],
    attr_map: Dict[str, Dict[str, float]],
    subgroup_extractor: Optional[callable] = None,
) -> Dict[str, Dict[str, Dict[str, float]]]:
    """Compute stratified within-subgroup anomaly rates and subgroup leave-one-out baselines.
    
    Controls for observed subgroup composition (e.g. class, sensor, illumination).
    
    Returns:
      Mapping: contributor_id -> {subgroup_val -> {
          'contributor_count': ...,
          'contributor_exposure': ...,
          'contributor_rate': ...,
          'background_rate': ...,
          'differential': ...,
      }}
    """
    # Default subgroup extractor is primary class name
    if subgroup_extractor is None:
        def _default_subgroup(s: CanonicalSample) -> str:
            if s.annotations and s.annotations[0].category_name:
                return str(s.annotations[0].category_name)
            return str(s.metadata.get("sensor") or s.metadata.get("illumination") or "default_subgroup")
        subgroup_extractor = _default_subgroup

    # 1. Accumulate subgroup totals: subgroup -> (total_anomalies, total_exposure)
    subgroup_totals: Dict[str, Dict[str, float]] = {}
    # contributor -> subgroup -> (anomalies, exposure)
    contributor_subgroups: Dict[str, Dict[str, Dict[str, float]]] = {}

    for s in samples:
        s_id = s.sample_id
        sg_val = subgroup_extractor(s)
        is_anom = sample_anomaly_flags.get(s_id, False)

        c_weights = attr_map.get(s_id, {})
        for c_id, w in c_weights.items():
            if sg_val not in subgroup_totals:
                subgroup_totals[sg_val] = {"anomalies": 0.0, "exposure": 0.0}
            subgroup_totals[sg_val]["exposure"] += w
            if is_anom:
                subgroup_totals[sg_val]["anomalies"] += w

            if c_id not in contributor_subgroups:
                contributor_subgroups[c_id] = {}
            if sg_val not in contributor_subgroups[c_id]:
                contributor_subgroups[c_id][sg_val] = {"anomalies": 0.0, "exposure": 0.0}
            contributor_subgroups[c_id][sg_val]["exposure"] += w
            if is_anom:
                contributor_subgroups[c_id][sg_val]["anomalies"] += w

    # 2. Build final stratified breakdown per contributor
    result: Dict[str, Dict[str, Dict[str, float]]] = {}

    for c_id, sg_dict in contributor_subgroups.items():
        result[c_id] = {}
        for sg_val, c_vals in sg_dict.items():
            c_exp = c_vals["exposure"]
            c_anom = c_vals["anomalies"]
            c_rate = c_anom / c_exp if c_exp > 0 else 0.0

            sg_tot = subgroup_totals.get(sg_val, {"anomalies": 0.0, "exposure": 0.0})
            bg_anom, bg_exp, bg_rate = compute_leave_one_out_baseline(
                total_anomalies=sg_tot["anomalies"],
                total_exposure=sg_tot["exposure"],
                contributor_anomalies=c_anom,
                contributor_exposure=c_exp,
            )

            if bg_rate is None:
                diff = None
                bg_rate_val = None
                status_val = "INSUFFICIENT_BACKGROUND_SUPPORT"
            else:
                diff = float(c_rate - bg_rate)
                bg_rate_val = float(bg_rate)
                status_val = "VALID"

            result[c_id][sg_val] = {
                "contributor_count": float(c_anom),
                "contributor_exposure": float(c_exp),
                "contributor_rate": float(c_rate),
                "background_rate": bg_rate_val,
                "differential": diff,
                "baseline_status": status_val,
            }

    return result
