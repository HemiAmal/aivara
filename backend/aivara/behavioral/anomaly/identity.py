"""Deterministic cryptographic hashing and identity generation for Phase 8.6 Behavioral Anomaly Detection."""

from __future__ import annotations

from typing import Any, Dict, List
from aivara.crypto.canonical import canonicalize
from aivara.crypto.hashing import sha256_bytes


def compute_anomaly_analysis_id(
    project_id: str,
    model_id: str,
    model_fingerprint: str,
    baseline_id: str,
    observation_id: str,
    task_type: str,
    policy_version: str,
    threshold_policy: Dict[str, Any],
    metrics: List[Dict[str, Any]],
    families: Dict[str, Any],
    overall_status: str,
    support_status: str,
    analysis_version: str = "1.0.0",
) -> str:
    """Compute a deterministic 64-char lowercase SHA-256 JCS digest of the anomaly analysis result."""
    # Ensure canonical deterministic sorting
    sorted_metrics = sorted(metrics, key=lambda m: (m.get("family", ""), m.get("metric_name", "")))
    sorted_families = {k: families[k] for k in sorted(families.keys())}

    payload = {
        "analysis_version": analysis_version,
        "baseline_id": baseline_id,
        "families": sorted_families,
        "metrics": sorted_metrics,
        "model_fingerprint": model_fingerprint,
        "model_id": model_id,
        "observation_id": observation_id,
        "overall_status": overall_status,
        "policy_version": policy_version,
        "project_id": project_id,
        "support_status": support_status,
        "task_type": task_type,
        "threshold_policy": threshold_policy,
    }
    canonical_bytes = canonicalize(payload)
    return sha256_bytes(canonical_bytes)
