"""Deterministic Canonical Behavioral Evidence and Execution Identity Engine (Phase 8.7).

Provides:
  - Canonical RFC 8785 (JCS) serialization and SHA-256 evidence hashing using Phase 4 crypto.
  - Strict exclusion of non-deterministic fields (database UUIDs, wall-clock timestamps, local paths).
  - Explicit sanitization and rejection of non-finite floating-point values (NaN, +Inf, -Inf).
  - Comprehensive ExecutionIdentityHash computation for behavioral scan idempotency.
"""

from __future__ import annotations

import math
import re
from typing import Any, Dict, List, Optional, Union

from aivara.crypto.canonical import canonicalize
from aivara.crypto.hashing import hash_canonical_data, is_valid_sha256
from aivara.domain.schemas import EvidenceLayer
from aivara.behavioral.provenance.enums import BehavioralEvidenceType
from aivara.behavioral.provenance.exceptions import (
    BehavioralEvidenceIdentityError,
    BehavioralExecutionIdentityError,
    NonFiniteValueError,
)
from aivara.behavioral.provenance.schemas import BehavioralEvidenceContent

_SHA256_REGEX = re.compile(r"^[0-9a-f]{64}$")


def is_valid_hash(hash_str: Optional[str]) -> bool:
    """Validate that a string is a 64-character lowercase hex SHA-256 digest."""
    if not hash_str or not isinstance(hash_str, str):
        return False
    return bool(_SHA256_REGEX.match(hash_str.strip().lower()))


def sanitize_numeric_value(val: Any) -> Any:
    """Recursively sanitize numeric values to reject NaN / Infinity and ensure deterministic representation."""
    if isinstance(val, float):
        if math.isnan(val) or math.isinf(val):
            raise NonFiniteValueError(f"Prohibited non-finite floating-point value: {val}")
        return val
    elif isinstance(val, dict):
        return {str(k): sanitize_numeric_value(v) for k, v in sorted(val.items(), key=lambda x: str(x[0]))}
    elif isinstance(val, (list, tuple)):
        return [sanitize_numeric_value(v) for v in val]
    return val


def build_canonical_behavioral_evidence_dict(
    *,
    evidence_layer: Union[EvidenceLayer, str],
    evidence_type: Union[BehavioralEvidenceType, str],
    project_id: str,
    model_id: str,
    model_fingerprint: str,
    task_type: str,
    observation_id: str,
    baseline_id: str,
    baseline_type: str,
    comparison_id: str = "NONE",
    sensitivity_id: str = "NONE",
    anomaly_analysis_id: str = "NONE",
    input_hash: str,
    output_hash: str,
    preprocessing_hash: str = "STANDARD_V1",
    detector_id: str,
    detector_version: str,
    detector_config_hash: str,
    policy_version: str = "1.0.0",
    engine_version: str = "1.0.0",
    result_status: str,
    support_status: str,
    comparability_status: str = "COMPARABLE",
    metrics: Optional[List[Dict[str, Any]]] = None,
    families: Optional[Dict[str, Dict[str, Any]]] = None,
    limitations: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Build normalized dictionary containing exclusively deterministic behavioral evidence identity attributes."""
    if not project_id:
        raise BehavioralEvidenceIdentityError("project_id is required for behavioral evidence identity.")
    if not model_id:
        raise BehavioralEvidenceIdentityError("model_id is required for behavioral evidence identity.")
    if not model_fingerprint:
        raise BehavioralEvidenceIdentityError("model_fingerprint is required for behavioral evidence identity.")
    if not observation_id:
        raise BehavioralEvidenceIdentityError("observation_id is required for behavioral evidence identity.")
    if not baseline_id:
        raise BehavioralEvidenceIdentityError("baseline_id is required for behavioral evidence identity.")
    if not input_hash:
        raise BehavioralEvidenceIdentityError("input_hash is required for behavioral evidence identity.")
    if not output_hash:
        raise BehavioralEvidenceIdentityError("output_hash is required for behavioral evidence identity.")
    if not detector_id:
        raise BehavioralEvidenceIdentityError("detector_id is required for behavioral evidence identity.")
    if not detector_version:
        raise BehavioralEvidenceIdentityError("detector_version is required for behavioral evidence identity.")
    if not detector_config_hash or not is_valid_sha256(detector_config_hash):
        raise BehavioralEvidenceIdentityError(
            f"detector_config_hash must be a valid 64-hex SHA-256 digest, got {detector_config_hash}."
        )

    # Sanitize and sort metrics deterministically by metric_name
    raw_metrics = metrics or []
    sanitized_metrics = []
    for m in raw_metrics:
        sanitized_metrics.append(sanitize_numeric_value(m))
    sorted_metrics = sorted(sanitized_metrics, key=lambda x: str(x.get("metric_name", "")))

    # Sanitize families
    raw_families = families or {}
    sanitized_families = sanitize_numeric_value(raw_families)

    # Sanitize limitations
    raw_limitations = limitations or []
    sorted_limitations = sorted([str(lim) for lim in raw_limitations])

    ev_layer_val = evidence_layer.value if isinstance(evidence_layer, EvidenceLayer) else str(evidence_layer)
    ev_type_val = evidence_type.value if isinstance(evidence_type, BehavioralEvidenceType) else str(evidence_type)

    return {
        "anomaly_analysis_id": str(anomaly_analysis_id).lower() if is_valid_sha256(anomaly_analysis_id) else str(anomaly_analysis_id),
        "baseline_id": str(baseline_id),
        "baseline_type": str(baseline_type),
        "comparability_status": str(comparability_status),
        "comparison_id": str(comparison_id),
        "detector_config_hash": detector_config_hash.lower(),
        "detector_id": str(detector_id),
        "detector_version": str(detector_version),
        "engine_version": str(engine_version),
        "evidence_layer": ev_layer_val,
        "evidence_type": ev_type_val,
        "families": sanitized_families,
        "input_hash": str(input_hash).lower() if is_valid_sha256(input_hash) else str(input_hash),
        "limitations": sorted_limitations,
        "metrics": sorted_metrics,
        "model_fingerprint": str(model_fingerprint).lower() if is_valid_sha256(model_fingerprint) else str(model_fingerprint),
        "model_id": str(model_id),
        "observation_id": str(observation_id),
        "output_hash": str(output_hash).lower() if is_valid_sha256(output_hash) else str(output_hash),
        "policy_version": str(policy_version),
        "preprocessing_hash": str(preprocessing_hash).lower() if is_valid_sha256(preprocessing_hash) else str(preprocessing_hash),
        "project_id": str(project_id),
        "result_status": str(result_status),
        "sensitivity_id": str(sensitivity_id),
        "support_status": str(support_status),
        "task_type": str(task_type),
    }


def compute_behavioral_evidence_hash(
    evidence_data: Union[BehavioralEvidenceContent, Dict[str, Any]]
) -> str:
    """Compute deterministic SHA-256 hash of canonical RFC 8785 serialized behavioral evidence content."""
    if isinstance(evidence_data, BehavioralEvidenceContent):
        raw_dict = evidence_data.model_dump()
    elif isinstance(evidence_data, dict):
        raw_dict = evidence_data
    else:
        raise BehavioralEvidenceIdentityError(f"Unsupported evidence_data type: {type(evidence_data).__name__}")

    canonical_dict = build_canonical_behavioral_evidence_dict(
        evidence_layer=raw_dict["evidence_layer"],
        evidence_type=raw_dict["evidence_type"],
        project_id=raw_dict["project_id"],
        model_id=raw_dict["model_id"],
        model_fingerprint=raw_dict["model_fingerprint"],
        task_type=raw_dict["task_type"],
        observation_id=raw_dict["observation_id"],
        baseline_id=raw_dict["baseline_id"],
        baseline_type=raw_dict["baseline_type"],
        comparison_id=raw_dict.get("comparison_id", "NONE"),
        sensitivity_id=raw_dict.get("sensitivity_id", "NONE"),
        anomaly_analysis_id=raw_dict.get("anomaly_analysis_id", "NONE"),
        input_hash=raw_dict["input_hash"],
        output_hash=raw_dict["output_hash"],
        preprocessing_hash=raw_dict.get("preprocessing_hash", "STANDARD_V1"),
        detector_id=raw_dict["detector_id"],
        detector_version=raw_dict["detector_version"],
        detector_config_hash=raw_dict["detector_config_hash"],
        policy_version=raw_dict.get("policy_version", "1.0.0"),
        engine_version=raw_dict.get("engine_version", "1.0.0"),
        result_status=raw_dict["result_status"],
        support_status=raw_dict["support_status"],
        comparability_status=raw_dict.get("comparability_status", "COMPARABLE"),
        metrics=raw_dict.get("metrics", []),
        families=raw_dict.get("families", {}),
        limitations=raw_dict.get("limitations", []),
    )

    return hash_canonical_data(canonical_dict)


def build_behavioral_execution_payload(
    *,
    project_id: str,
    model_id: str,
    model_fingerprint: str,
    observation_id: str,
    baseline_id: str,
    detector_id: str,
    detector_version: str,
    detector_config_hash: str,
    policy_version: str = "1.0.0",
    engine_version: str = "1.0.0",
    preprocessing_hash: str = "STANDARD_V1",
) -> Dict[str, Any]:
    """Build normalized canonical payload for behavioral execution identity (idempotency key)."""
    if not project_id:
        raise BehavioralExecutionIdentityError("project_id is required for execution identity.")
    if not model_id:
        raise BehavioralExecutionIdentityError("model_id is required for execution identity.")
    if not model_fingerprint:
        raise BehavioralExecutionIdentityError("model_fingerprint is required for execution identity.")
    if not observation_id:
        raise BehavioralExecutionIdentityError("observation_id is required for execution identity.")
    if not baseline_id:
        raise BehavioralExecutionIdentityError("baseline_id is required for execution identity.")
    if not detector_id:
        raise BehavioralExecutionIdentityError("detector_id is required for execution identity.")
    if not detector_version:
        raise BehavioralExecutionIdentityError("detector_version is required for execution identity.")
    if not detector_config_hash or not is_valid_sha256(detector_config_hash):
        raise BehavioralExecutionIdentityError(
            f"detector_config_hash must be a valid 64-hex SHA-256 digest, got {detector_config_hash}."
        )

    return {
        "baseline_id": str(baseline_id),
        "detector_config_hash": detector_config_hash.lower(),
        "detector_id": str(detector_id),
        "detector_version": str(detector_version),
        "engine_version": str(engine_version),
        "model_fingerprint": str(model_fingerprint).lower() if is_valid_sha256(model_fingerprint) else str(model_fingerprint),
        "model_id": str(model_id),
        "observation_id": str(observation_id),
        "policy_version": str(policy_version),
        "preprocessing_hash": str(preprocessing_hash).lower() if is_valid_sha256(preprocessing_hash) else str(preprocessing_hash),
        "project_id": str(project_id),
    }


def compute_behavioral_execution_identity_hash(execution_data: Dict[str, Any]) -> str:
    """Compute deterministic SHA-256 hash of canonical execution identity payload."""
    canonical_dict = build_behavioral_execution_payload(
        project_id=execution_data["project_id"],
        model_id=execution_data["model_id"],
        model_fingerprint=execution_data["model_fingerprint"],
        observation_id=execution_data["observation_id"],
        baseline_id=execution_data["baseline_id"],
        detector_id=execution_data["detector_id"],
        detector_version=execution_data["detector_version"],
        detector_config_hash=execution_data["detector_config_hash"],
        policy_version=execution_data.get("policy_version", "1.0.0"),
        engine_version=execution_data.get("engine_version", "1.0.0"),
        preprocessing_hash=execution_data.get("preprocessing_hash", "STANDARD_V1"),
    )
    return hash_canonical_data(canonical_dict)
