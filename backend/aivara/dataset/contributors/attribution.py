"""Deterministic contributor attribution and fractional weighting engine.

Guarantees:
  1. Equal fractional attribution: w(s, c) = 1/K for K contributors.
  2. Conservation of sample counts: sum_c w(s, c) = 1.0 for every sample.
  3. Safe handling of missing/null/duplicate contributors -> UNATTRIBUTED.
"""

from __future__ import annotations

import math
from typing import Dict, List, Sequence, Set, Tuple

from aivara.dataset.contributors.exceptions import InvalidAttributionError
from aivara.dataset.schemas import CanonicalSample

UNATTRIBUTED_KEY: str = "UNATTRIBUTED"


def normalize_contributor_ids(raw_contributors: Sequence[Any]) -> Tuple[str, ...]:
    """Normalize and deduplicate contributor IDs.
    
    Args:
        raw_contributors: Sequence of raw contributor ID strings or values.
        
    Returns:
        Sorted tuple of non-empty string IDs, or ("UNATTRIBUTED",) if empty.
    """
    if not raw_contributors:
        return (UNATTRIBUTED_KEY,)

    seen: Set[str] = set()
    cleaned: List[str] = []

    for item in raw_contributors:
        if item is None:
            continue
        s_val = str(item).strip()
        if not s_val or s_val.lower() in ("none", "null", "undefined", ""):
            continue
        if s_val not in seen:
            seen.add(s_val)
            cleaned.append(s_val)

    if not cleaned:
        return (UNATTRIBUTED_KEY,)

    # Sort deterministically
    cleaned.sort()
    return tuple(cleaned)


def build_sample_attribution_map(
    samples: Sequence[CanonicalSample],
) -> Dict[str, Dict[str, float]]:
    """Build deterministic fractional attribution map: sample_id -> {contributor_id: weight}.
    
    Invariants enforced:
      - For each sample s, sum_{c} w_{s,c} == 1.0.
      - 0.0 < w_{s,c} <= 1.0.
      - Exactly 1/K for K distinct contributors.
    """
    attr_map: Dict[str, Dict[str, float]] = {}

    for s in samples:
        c_tuple = normalize_contributor_ids(s.contributors)
        k = len(c_tuple)
        if k == 0:
            c_tuple = (UNATTRIBUTED_KEY,)
            k = 1

        weight = 1.0 / float(k)
        weights_dict: Dict[str, float] = {}

        for c_id in c_tuple:
            weights_dict[c_id] = weight

        # Verify conservation invariant
        total_w = sum(weights_dict.values())
        if not math.isclose(total_w, 1.0, rel_tol=1e-5, abs_tol=1e-5):
            raise InvalidAttributionError(
                f"Attribution weights for sample {s.sample_id} do not sum to 1.0 (got {total_w})."
            )

        attr_map[s.sample_id] = weights_dict

    return attr_map


def compute_contributor_exposures(
    attr_map: Dict[str, Dict[str, float]],
) -> Dict[str, float]:
    """Compute total weighted exposure (sum of fractional weights) per contributor."""
    exposures: Dict[str, float] = {}

    for s_id, c_weights in attr_map.items():
        for c_id, w in c_weights.items():
            exposures[c_id] = exposures.get(c_id, 0.0) + w

    return exposures


def compute_contributor_sample_counts(
    attr_map: Dict[str, Dict[str, float]],
) -> Dict[str, int]:
    """Compute raw sample counts (number of samples touched) per contributor."""
    counts: Dict[str, int] = {}

    for s_id, c_weights in attr_map.items():
        for c_id in c_weights:
            counts[c_id] = counts.get(c_id, 0) + 1

    return counts


def compute_contributor_shared_counts(
    attr_map: Dict[str, Dict[str, float]],
) -> Dict[str, int]:
    """Compute number of shared samples (where sample has > 1 contributor) per contributor."""
    shared: Dict[str, int] = {}

    for s_id, c_weights in attr_map.items():
        if len(c_weights) > 1:
            for c_id in c_weights:
                shared[c_id] = shared.get(c_id, 0) + 1

    return shared
