"""Deterministic cryptographic hashing and identity generation for Phase 8.5 Output Stability."""

from __future__ import annotations

from typing import Any, Dict, Optional
from aivara.crypto.canonical import canonicalize
from aivara.crypto.hashing import sha256_bytes


def compute_comparison_id(
    project_id: str,
    source_observation_id: str,
    target_observation_id: str,
    comparison_type: str,
    task_type: str,
    implementation_version: str = "1.0.0",
) -> str:
    """Compute a deterministic 64-char lowercase SHA-256 JCS digest of the comparison identity."""
    payload = {
        "comparison_type": str(comparison_type),
        "implementation_version": implementation_version,
        "project_id": project_id,
        "source_observation_id": source_observation_id,
        "target_observation_id": target_observation_id,
        "task_type": task_type,
    }
    canonical_bytes = canonicalize(payload)
    return sha256_bytes(canonical_bytes)


def compute_metric_id(
    metric_name: str,
    formula_version: str = "1.0.0",
    parameters: Optional[Dict[str, Any]] = None,
) -> str:
    """Compute a deterministic 64-char lowercase SHA-256 JCS digest of a metric configuration."""
    payload = {
        "formula_version": formula_version,
        "metric_name": metric_name,
        "parameters": parameters or {},
    }
    canonical_bytes = canonicalize(payload)
    return sha256_bytes(canonical_bytes)


def compute_repeatability_analysis_id(
    project_id: str,
    model_id: str,
    model_fingerprint: str,
    repeat_count: int,
    execution_provider: str,
    implementation_version: str = "1.0.0",
) -> str:
    """Compute a deterministic 64-char lowercase SHA-256 JCS digest of a repeatability analysis."""
    payload = {
        "execution_provider": execution_provider,
        "implementation_version": implementation_version,
        "model_fingerprint": model_fingerprint,
        "model_id": model_id,
        "project_id": project_id,
        "repeat_count": repeat_count,
    }
    canonical_bytes = canonicalize(payload)
    return sha256_bytes(canonical_bytes)


def compute_sensitivity_id(
    project_id: str,
    model_id: str,
    source_input_hash: str,
    perturbed_input_hash: str,
    perturbation_id: str,
    implementation_version: str = "1.0.0",
) -> str:
    """Compute a deterministic 64-char lowercase SHA-256 JCS digest of a perturbation sensitivity experiment."""
    payload = {
        "implementation_version": implementation_version,
        "model_id": model_id,
        "perturbation_id": perturbation_id,
        "project_id": project_id,
        "perturbed_input_hash": perturbed_input_hash,
        "source_input_hash": source_input_hash,
    }
    canonical_bytes = canonicalize(payload)
    return sha256_bytes(canonical_bytes)
