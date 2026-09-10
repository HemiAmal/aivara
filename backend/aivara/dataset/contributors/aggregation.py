"""Evidence accumulation and profile builder for Contributor Aggregation Engine."""

from __future__ import annotations

import math
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

from aivara.dataset.contributors.attribution import (
    UNATTRIBUTED_KEY,
    build_sample_attribution_map,
    compute_contributor_exposures,
    compute_contributor_sample_counts,
    compute_contributor_shared_counts,
)
from aivara.dataset.contributors.baselines import (
    compute_leave_one_out_baseline,
    compute_subgroup_stratified_rates,
)
from aivara.dataset.contributors.schemas import (
    ContributorAggregationConfig,
    ContributorEvidenceMetric,
    ContributorEvidenceProfile,
)
from aivara.dataset.contributors.statistics import (
    compute_herfindahl_hirschman_index,
    compute_rate_differential_and_se,
    compute_shannon_entropy,
    compute_wilson_confidence_interval,
)
from aivara.dataset.schemas import CanonicalSample


def build_contributor_profiles(
    samples: Sequence[CanonicalSample],
    evidence_by_sample: Dict[str, Set[str]],  # sample_id -> set of metric names present (e.g. {"label_anomaly", "ood"})
    config: Optional[ContributorAggregationConfig] = None,
    subgroup_extractor: Optional[callable] = None,
) -> Tuple[Dict[str, ContributorEvidenceProfile], Dict[str, float]]:
    """Aggregate sample-level evidence into immutable ContributorEvidenceProfiles.
    
    Args:
        samples: Sequence of CanonicalSample objects.
        evidence_by_sample: Mapping of sample_id to set of triggered anomaly metric keys.
        config: Aggregation configuration thresholds.
        subgroup_extractor: Optional callable to extract subgroup domain string from sample.
        
    Returns:
        Tuple of (profiles_dict, anomaly_hhi_dict).
    """
    cfg = config or ContributorAggregationConfig()

    # 1. Attribution Mapping
    attr_map = build_sample_attribution_map(samples)
    exposures = compute_contributor_exposures(attr_map)
    raw_counts = compute_contributor_sample_counts(attr_map)
    shared_counts = compute_contributor_shared_counts(attr_map)

    # 2. Extract unique metric types present across all evidence
    all_metrics: Set[str] = set()
    for m_set in evidence_by_sample.values():
        all_metrics.update(m_set)

    # If no evidence types found, provide standard canonical placeholders
    if not all_metrics:
        all_metrics = {"label_anomaly", "label_flip", "ood", "quality", "duplicate"}

    # Total dataset exposure (sum of weights across all samples == len(samples))
    total_dataset_exposure = float(len(samples))

    # 3. Compute total weighted anomalies per metric across dataset
    dataset_metric_totals: Dict[str, float] = {m: 0.0 for m in all_metrics}
    # contributor -> metric -> weighted anomaly count
    contrib_metric_counts: Dict[str, Dict[str, float]] = {c: {m: 0.0 for m in all_metrics} for c in exposures}

    # contributor -> class -> weighted count
    contrib_class_counts: Dict[str, Dict[str, float]] = {c: {} for c in exposures}

    for s in samples:
        s_id = s.sample_id
        s_metrics = evidence_by_sample.get(s_id, set())
        c_weights = attr_map.get(s_id, {})

        # Primary class
        class_name = s.annotations[0].category_name if s.annotations else "unlabeled"

        for c_id, w in c_weights.items():
            # Accumulate class counts
            contrib_class_counts[c_id][class_name] = contrib_class_counts[c_id].get(class_name, 0.0) + w

            # Accumulate anomalies
            for m in s_metrics:
                dataset_metric_totals[m] = dataset_metric_totals.get(m, 0.0) + w
                contrib_metric_counts[c_id][m] = contrib_metric_counts[c_id].get(m, 0.0) + w

    # 4. Stratified subgroup rates per metric
    metric_subgroup_stratified: Dict[str, Dict[str, Dict[str, Dict[str, float]]]] = {}
    for m in all_metrics:
        sample_flags = {s.sample_id: (m in evidence_by_sample.get(s.sample_id, set())) for s in samples}
        metric_subgroup_stratified[m] = compute_subgroup_stratified_rates(
            samples=samples,
            sample_anomaly_flags=sample_flags,
            attr_map=attr_map,
            subgroup_extractor=subgroup_extractor,
        )

    # 5. Build ContributorEvidenceProfile for each contributor
    profiles: Dict[str, ContributorEvidenceProfile] = {}

    for c_id, exp in exposures.items():
        n_raw = raw_counts.get(c_id, 0)
        n_shared = shared_counts.get(c_id, 0)
        is_sufficient = bool(exp >= cfg.min_contributor_support)

        # Class distribution & Shannon entropy
        c_class_dict = contrib_class_counts.get(c_id, {})
        tot_class_w = sum(c_class_dict.values())
        class_proportions: Dict[str, float] = {}
        if tot_class_w > 0:
            for c_name, c_cnt in c_class_dict.items():
                class_proportions[c_name] = float(c_cnt / tot_class_w)
        class_entropy = compute_shannon_entropy(class_proportions)

        # Metric evaluations
        metrics_dict: Dict[str, ContributorEvidenceMetric] = {}
        diversity_count = 0

        for m in sorted(all_metrics):
            c_anom = contrib_metric_counts[c_id].get(m, 0.0)
            tot_anom = dataset_metric_totals.get(m, 0.0)

            rate, wilson_l, wilson_u = compute_wilson_confidence_interval(
                k=c_anom,
                n=exp,
                confidence=cfg.wilson_confidence,
            )

            # LOO Background
            bg_anom, bg_exp, bg_rate = compute_leave_one_out_baseline(
                total_anomalies=tot_anom,
                total_exposure=total_dataset_exposure,
                contributor_anomalies=c_anom,
                contributor_exposure=exp,
            )

            diff, se = compute_rate_differential_and_se(
                r_c=rate,
                n_c=exp,
                r_bg=bg_rate,
                n_bg=bg_exp,
            )

            baseline_status = "VALID" if (bg_exp > 0.0 and bg_rate is not None) else "INSUFFICIENT_BACKGROUND_SUPPORT"
            share = float(c_anom / tot_anom) if tot_anom > 0 else 0.0

            # Stratified subgroup metrics
            sg_data = metric_subgroup_stratified.get(m, {}).get(c_id, {})

            metrics_dict[m] = ContributorEvidenceMetric(
                metric_name=m,
                contributor_count=float(c_anom),
                contributor_exposure=float(exp),
                contributor_rate=float(rate),
                wilson_lower_bound=float(wilson_l),
                wilson_upper_bound=float(wilson_u),
                background_count=float(bg_anom),
                background_exposure=float(bg_exp),
                background_rate=float(bg_rate) if bg_rate is not None else None,
                rate_differential=float(diff) if diff is not None else None,
                standard_error=float(se) if se is not None else None,
                anomaly_share=float(min(1.0, max(0.0, share))),
                baseline_status=baseline_status,
                subgroup_metrics=sg_data,
            )

            # Diversity count: counts distinct signals with meaningful lower bound or rate
            if is_sufficient and (wilson_l >= cfg.diversity_metric_rate_threshold or (rate > 0.15 and c_anom >= 2.0)):
                diversity_count += 1

        profiles[c_id] = ContributorEvidenceProfile(
            contributor_id=c_id,
            total_samples_contributed=n_raw,
            weighted_sample_exposure=float(exp),
            shared_sample_count=n_shared,
            metrics=metrics_dict,
            class_distribution=class_proportions,
            class_entropy=float(class_entropy),
            evidence_diversity_count=diversity_count,
            is_sufficient_support=is_sufficient,
        )

    # 6. Compute HHI per metric across contributors
    anomaly_hhi: Dict[str, float] = {}
    for m in all_metrics:
        shares = [profiles[c].metrics[m].anomaly_share for c in profiles if m in profiles[c].metrics]
        anomaly_hhi[m] = compute_herfindahl_hirschman_index(shares)

    return profiles, anomaly_hhi
