"""Deterministic population selection, filtering, subsampling, and identity hashing."""

from __future__ import annotations

import hashlib
from typing import Any, Dict, List, Optional, Sequence, Tuple
import numpy as np

from aivara.crypto.canonical import canonicalize
from aivara.drift.enums import PopulationType, SamplingMethod
from aivara.drift.exceptions import InvalidPopulationError, ResourceLimitExceededError
from aivara.drift.schemas import PopulationIdentity, PopulationSelector, SamplingConfig


def compute_sample_ids_hash(sample_ids: Sequence[str]) -> str:
    """Compute deterministic SHA-256 digest over sorted sample IDs list."""
    sorted_ids = sorted(list(sample_ids))
    canonical_bytes = canonicalize(sorted_ids)
    return hashlib.sha256(canonical_bytes).hexdigest()


def compute_population_selection_hash(
    dataset_id: str,
    dataset_version_id: Optional[str],
    population_type: PopulationType,
    selector_dict: Dict[str, Any],
    sample_ids_hash: str,
    total_available: int,
    selected_count: int,
    sampling_applied: bool,
) -> str:
    """Compute cryptographic SHA-256 digest over canonical population selection descriptor."""
    descriptor = {
        "dataset_id": dataset_id,
        "dataset_version_id": dataset_version_id or "",
        "population_type": population_type.value,
        "sample_ids_hash": sample_ids_hash,
        "sampling_applied": sampling_applied,
        "selected_count": selected_count,
        "selector_params": {
            "class_filter": sorted(selector_dict.get("class_filter") or []),
            "contributor_id": selector_dict.get("contributor_id") or "",
            "time_end": selector_dict.get("time_end") or "",
            "time_start": selector_dict.get("time_start") or "",
        },
        "total_available": total_available,
    }
    canonical_bytes = canonicalize(descriptor)
    return hashlib.sha256(canonical_bytes).hexdigest()


def filter_sample_records(
    samples: Sequence[Dict[str, Any]],
    selector: PopulationSelector,
) -> List[Dict[str, Any]]:
    """Filter raw sample dictionaries based on PopulationSelector criteria."""
    filtered = []
    
    # Pre-parse class whitelist set if specified
    class_set = set(selector.class_filter) if selector.class_filter else None
    sample_id_set = set(selector.sample_ids) if selector.sample_ids else None

    for sample in samples:
        s_id = str(sample.get("id") or sample.get("sample_id") or "")
        if not s_id:
            continue

        # 1. Explicit sample ID filter
        if sample_id_set is not None and s_id not in sample_id_set:
            continue

        # 2. Contributor filter
        if selector.contributor_id:
            s_contrib = sample.get("contributor_id") or sample.get("metadata_json", {}).get("contributor_id")
            if s_contrib != selector.contributor_id:
                continue

        # 3. Temporal window filter
        if selector.time_start or selector.time_end:
            s_time = sample.get("created_at") or sample.get("timestamp")
            if s_time is not None:
                s_time_str = str(s_time)
                if selector.time_start and s_time_str < selector.time_start:
                    continue
                if selector.time_end and s_time_str > selector.time_end:
                    continue

        # 4. Class label filter
        if class_set is not None:
            label_json = sample.get("label_json") or {}
            category = label_json.get("category") or label_json.get("label") or sample.get("category")
            if category and str(category) not in class_set:
                continue

        filtered.append(sample)

    return filtered


def deterministic_subsample(
    sample_ids: Sequence[str],
    config: SamplingConfig,
    dataset_context_seed: Optional[str] = None,
) -> Tuple[List[str], bool]:
    """Deterministically downsample sample IDs if length exceeds config.max_samples."""
    sorted_unique_ids = sorted(list(set(sample_ids)))
    n_total = len(sorted_unique_ids)

    if n_total <= config.max_samples or config.method == SamplingMethod.NONE:
        return sorted_unique_ids, False

    if config.method == SamplingMethod.HASH_RANKING:
        # Sort by SHA-256(sample_id + salt)
        salt = dataset_context_seed or str(config.seed)
        ranked = sorted(
            sorted_unique_ids,
            key=lambda sid: hashlib.sha256(f"{sid}:{salt}".encode("utf-8")).hexdigest()
        )
        return sorted(ranked[:config.max_samples]), True

    elif config.method == SamplingMethod.DETERMINISTIC_SEEDED:
        # Deterministic seeded selection
        rng = np.random.RandomState(config.seed)
        indices = rng.choice(n_total, size=config.max_samples, replace=False)
        selected = [sorted_unique_ids[i] for i in sorted(indices)]
        return selected, True

    else:
        raise InvalidPopulationError(f"Unsupported sampling method: {config.method}")


def resolve_population_identity(
    selector: PopulationSelector,
    all_candidate_samples: Sequence[Dict[str, Any]],
    sampling_config: Optional[SamplingConfig] = None,
) -> Tuple[List[str], PopulationIdentity]:
    """Authoritative population resolution and identity derivation."""
    sampling = sampling_config or SamplingConfig()

    # 1. Filter candidates
    filtered_samples = filter_sample_records(all_candidate_samples, selector)
    total_available = len(filtered_samples)

    raw_ids = [str(s.get("id") or s.get("sample_id")) for s in filtered_samples]

    # 2. Check upper bounds before downsampling
    if total_available > 1000000:
        raise ResourceLimitExceededError(f"Available population ({total_available}) exceeds safety limit 1,000,000.")

    # 3. Deterministic subsampling
    selected_ids, sampling_applied = deterministic_subsample(
        raw_ids,
        sampling,
        dataset_context_seed=selector.dataset_id,
    )
    selected_count = len(selected_ids)

    # 4. Compute cryptographic hashes
    sample_ids_hash = compute_sample_ids_hash(selected_ids)
    pop_hash = compute_population_selection_hash(
        dataset_id=selector.dataset_id,
        dataset_version_id=selector.dataset_version_id,
        population_type=selector.population_type,
        selector_dict=selector.model_dump(),
        sample_ids_hash=sample_ids_hash,
        total_available=total_available,
        selected_count=selected_count,
        sampling_applied=sampling_applied,
    )

    identity = PopulationIdentity(
        dataset_id=selector.dataset_id,
        dataset_version_id=selector.dataset_version_id,
        population_type=selector.population_type,
        total_available_samples=total_available,
        selected_sample_count=selected_count,
        sampling_applied=sampling_applied,
        sample_ids_hash=sample_ids_hash,
        population_selection_hash=pop_hash,
    )

    return selected_ids, identity
