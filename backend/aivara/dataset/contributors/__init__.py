"""Phase 5.8: Contributor Aggregation Engine (CAE)."""

from aivara.dataset.contributors.aggregation import build_contributor_profiles
from aivara.dataset.contributors.attribution import (
    UNATTRIBUTED_KEY,
    build_sample_attribution_map,
    compute_contributor_exposures,
    compute_contributor_sample_counts,
    compute_contributor_shared_counts,
    normalize_contributor_ids,
)
from aivara.dataset.contributors.baselines import (
    compute_leave_one_out_baseline,
    compute_subgroup_stratified_rates,
)
from aivara.dataset.contributors.detector import (
    ContributorAggregationEngine,
    aggregate_contributor_evidence,
)
from aivara.dataset.contributors.exceptions import (
    ContributorAggregationError,
    InsufficientContributorSupportError,
    InvalidAttributionError,
    InvalidBaselineError,
    MalformedEvidenceError,
)
from aivara.dataset.contributors.schemas import (
    ContributorAggregationConfig,
    ContributorAggregationResult,
    ContributorCategory,
    ContributorEvidenceMetric,
    ContributorEvidenceProfile,
    ContributorScanFinding,
)
from aivara.dataset.contributors.statistics import (
    compute_gini_coefficient,
    compute_herfindahl_hirschman_index,
    compute_rate_differential_and_se,
    compute_shannon_entropy,
    compute_wilson_confidence_interval,
)

__all__ = [
    "ContributorAggregationEngine",
    "aggregate_contributor_evidence",
    "build_contributor_profiles",
    "normalize_contributor_ids",
    "build_sample_attribution_map",
    "compute_contributor_exposures",
    "compute_contributor_sample_counts",
    "compute_contributor_shared_counts",
    "compute_leave_one_out_baseline",
    "compute_subgroup_stratified_rates",
    "compute_wilson_confidence_interval",
    "compute_rate_differential_and_se",
    "compute_shannon_entropy",
    "compute_herfindahl_hirschman_index",
    "compute_gini_coefficient",
    "ContributorCategory",
    "ContributorEvidenceMetric",
    "ContributorEvidenceProfile",
    "ContributorScanFinding",
    "ContributorAggregationConfig",
    "ContributorAggregationResult",
    "ContributorAggregationError",
    "InsufficientContributorSupportError",
    "InvalidAttributionError",
    "InvalidBaselineError",
    "MalformedEvidenceError",
    "UNATTRIBUTED_KEY",
]
