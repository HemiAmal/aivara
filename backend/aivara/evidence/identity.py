"""Deterministic Canonical Evidence and Execution Identity Engine (Phase 5.9).

Provides:
  - Canonical RFC 8785 (JCS) serialization and SHA-256 evidence hashing using Phase 4 crypto.
  - Strict exclusion of non-deterministic fields (database UUIDs, wall-clock timestamps, local paths).
  - Comprehensive ExecutionIdentityHash computation for scan idempotency.
  - Normalization of optional and detector-specific parameters to prevent identity collisions.
"""

from __future__ import annotations

import math
import re
from typing import Any, Dict, List, Optional, Union

from aivara.crypto.canonical import canonicalize
from aivara.crypto.hashing import hash_canonical_data, is_valid_sha256
from aivara.evidence.exceptions import EvidenceIdentityError, ExecutionIdentityError
from aivara.evidence.schemas import EvidenceContent, ExecutionIdentityPayload


# Hex SHA-256 pattern
_SHA256_REGEX = re.compile(r"^[0-9a-f]{64}$")


def is_valid_evidence_hash(hash_str: Optional[str]) -> bool:
    """Validate that a string is a 64-character lowercase hex SHA-256 digest."""
    if not hash_str or not isinstance(hash_str, str):
        return False
    return bool(_SHA256_REGEX.match(hash_str.strip().lower()))


def _sanitize_numeric_value(val: Any) -> Any:
    """Recursively sanitize numeric values to reject NaN / Infinity and ensure JSON compliance."""
    if isinstance(val, float):
        if math.isnan(val) or math.isinf(val):
            raise EvidenceIdentityError(f"Prohibited non-finite floating point value: {val}")
        return val
    elif isinstance(val, dict):
        return {str(k): _sanitize_numeric_value(v) for k, v in val.items()}
    elif isinstance(val, (list, tuple)):
        return [_sanitize_numeric_value(v) for v in val]
    return val


def build_canonical_evidence_content(
    *,
    evidence_layer: str,
    evidence_type: str,
    project_id: str,
    dataset_version_id: str,
    dataset_fingerprint: str,
    target_asset_type: str,
    target_asset_id: str,
    target_asset_hash: str = "NONE",
    detector_id: str,
    detector_version: str,
    detector_config_hash: str,
    model_fingerprint: str = "NONE",
    reference_fingerprint: str = "NONE",
    measurements: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Build a normalized dictionary containing only deterministic evidence identity attributes."""
    if not project_id:
        raise EvidenceIdentityError("project_id is required for evidence identity.")
    if not dataset_version_id:
        raise EvidenceIdentityError("dataset_version_id is required for evidence identity.")
    if not dataset_fingerprint or not is_valid_sha256(dataset_fingerprint):
        raise EvidenceIdentityError(f"dataset_fingerprint must be a valid 64-hex SHA-256 digest, got {dataset_fingerprint}.")
    if not detector_id:
        raise EvidenceIdentityError("detector_id is required for evidence identity.")
    if not detector_version:
        raise EvidenceIdentityError("detector_version is required for evidence identity.")
    if not detector_config_hash or not is_valid_sha256(detector_config_hash):
        raise EvidenceIdentityError(f"detector_config_hash must be a valid 64-hex SHA-256 digest, got {detector_config_hash}.")

    meas = measurements if measurements is not None else {}
    sanitized_meas = _sanitize_numeric_value(meas)

    return {
        "dataset_fingerprint": dataset_fingerprint.lower(),
        "dataset_version_id": str(dataset_version_id),
        "detector_config_hash": detector_config_hash.lower(),
        "detector_id": str(detector_id),
        "detector_version": str(detector_version),
        "evidence_layer": str(evidence_layer),
        "evidence_type": str(evidence_type),
        "measurements": sanitized_meas,
        "model_fingerprint": str(model_fingerprint).lower() if model_fingerprint and is_valid_sha256(model_fingerprint) else str(model_fingerprint),
        "project_id": str(project_id),
        "reference_fingerprint": str(reference_fingerprint).lower() if reference_fingerprint and is_valid_sha256(reference_fingerprint) else str(reference_fingerprint),
        "target_asset_hash": str(target_asset_hash).lower() if target_asset_hash and is_valid_sha256(target_asset_hash) else str(target_asset_hash),
        "target_asset_id": str(target_asset_id),
        "target_asset_type": str(target_asset_type),
    }


def compute_evidence_hash(evidence_data: Union[EvidenceContent, Dict[str, Any]]) -> str:
    """Compute deterministic SHA-256 hash of canonical RFC 8785 serialized evidence content.

    Excludes wall-clock timestamps, local file paths, database primary keys, and mutable state.
    """
    if isinstance(evidence_data, EvidenceContent):
        raw_dict = evidence_data.model_dump()
    elif isinstance(evidence_data, dict):
        raw_dict = evidence_data
    else:
        raise EvidenceIdentityError(f"Unsupported evidence_data type: {type(evidence_data).__name__}")

    # Build canonical content dict to filter out any excluded fields (such as 'id', 'created_at', etc.)
    canonical_dict = build_canonical_evidence_content(
        evidence_layer=raw_dict.get("evidence_layer", "detection"),
        evidence_type=raw_dict["evidence_type"],
        project_id=raw_dict["project_id"],
        dataset_version_id=raw_dict["dataset_version_id"],
        dataset_fingerprint=raw_dict["dataset_fingerprint"],
        target_asset_type=raw_dict["target_asset_type"],
        target_asset_id=raw_dict["target_asset_id"],
        target_asset_hash=raw_dict.get("target_asset_hash", "NONE"),
        detector_id=raw_dict["detector_id"],
        detector_version=raw_dict["detector_version"],
        detector_config_hash=raw_dict["detector_config_hash"],
        model_fingerprint=raw_dict.get("model_fingerprint", "NONE"),
        reference_fingerprint=raw_dict.get("reference_fingerprint", "NONE"),
        measurements=raw_dict.get("measurements", {}),
    )

    return hash_canonical_data(canonical_dict)


def build_canonical_execution_payload(
    *,
    project_id: str,
    dataset_version_id: str,
    dataset_fingerprint: str,
    detector_id: str,
    detector_version: str,
    engine_version: str,
    policy_version: str = "DEFAULT",
    preprocessing_hash: str = "STANDARD_V1",
    model_id: str = "NONE",
    model_fingerprint: str = "NONE",
    model_version: str = "NONE",
    reference_dataset_id: str = "NONE",
    reference_dataset_fingerprint: str = "NONE",
    detector_config_hash: str,
) -> Dict[str, Any]:
    """Build normalized canonical payload for detector execution identity."""
    if not project_id:
        raise ExecutionIdentityError("project_id is required for execution identity.")
    if not dataset_version_id:
        raise ExecutionIdentityError("dataset_version_id is required for execution identity.")
    if not dataset_fingerprint or not is_valid_sha256(dataset_fingerprint):
        raise ExecutionIdentityError(f"dataset_fingerprint must be a valid 64-hex SHA-256 digest, got {dataset_fingerprint}.")
    if not detector_id:
        raise ExecutionIdentityError("detector_id is required for execution identity.")
    if not detector_version:
        raise ExecutionIdentityError("detector_version is required for execution identity.")
    if not engine_version:
        raise ExecutionIdentityError("engine_version is required for execution identity.")
    if not detector_config_hash or not is_valid_sha256(detector_config_hash):
        raise ExecutionIdentityError(f"detector_config_hash must be a valid 64-hex SHA-256 digest, got {detector_config_hash}.")

    return {
        "dataset_fingerprint": dataset_fingerprint.lower(),
        "dataset_version_id": str(dataset_version_id),
        "detector_config_hash": detector_config_hash.lower(),
        "detector_id": str(detector_id),
        "detector_version": str(detector_version),
        "engine_version": str(engine_version),
        "model_fingerprint": str(model_fingerprint).lower() if model_fingerprint and is_valid_sha256(model_fingerprint) else str(model_fingerprint),
        "model_id": str(model_id),
        "model_version": str(model_version),
        "policy_version": str(policy_version),
        "preprocessing_hash": str(preprocessing_hash).lower() if preprocessing_hash and is_valid_sha256(preprocessing_hash) else str(preprocessing_hash),
        "project_id": str(project_id),
        "reference_dataset_fingerprint": str(reference_dataset_fingerprint).lower() if reference_dataset_fingerprint and is_valid_sha256(reference_dataset_fingerprint) else str(reference_dataset_fingerprint),
        "reference_dataset_id": str(reference_dataset_id),
    }


def compute_execution_identity_hash(execution_data: Union[ExecutionIdentityPayload, Dict[str, Any]]) -> str:
    """Compute deterministic SHA-256 hash of canonical execution identity payload for idempotency."""
    if isinstance(execution_data, ExecutionIdentityPayload):
        raw_dict = execution_data.model_dump()
    elif isinstance(execution_data, dict):
        raw_dict = execution_data
    else:
        raise ExecutionIdentityError(f"Unsupported execution_data type: {type(execution_data).__name__}")

    canonical_dict = build_canonical_execution_payload(
        project_id=raw_dict["project_id"],
        dataset_version_id=raw_dict["dataset_version_id"],
        dataset_fingerprint=raw_dict["dataset_fingerprint"],
        detector_id=raw_dict["detector_id"],
        detector_version=raw_dict["detector_version"],
        engine_version=raw_dict["engine_version"],
        policy_version=raw_dict.get("policy_version", "DEFAULT"),
        preprocessing_hash=raw_dict.get("preprocessing_hash", "STANDARD_V1"),
        model_id=raw_dict.get("model_id", "NONE"),
        model_fingerprint=raw_dict.get("model_fingerprint", "NONE"),
        model_version=raw_dict.get("model_version", "NONE"),
        reference_dataset_id=raw_dict.get("reference_dataset_id", "NONE"),
        reference_dataset_fingerprint=raw_dict.get("reference_dataset_fingerprint", "NONE"),
        detector_config_hash=raw_dict["detector_config_hash"],
    )

    return hash_canonical_data(canonical_dict)
