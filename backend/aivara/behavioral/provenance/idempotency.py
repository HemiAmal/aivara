"""Behavioral Scan and Evidence Idempotency Engine (Phase 8.7).

Provides:
  - Resolution of duplicate analytical requests to existing findings and sealed evidence.
  - Distinction between legitimate analytical re-execution (idempotent hit) and cryptographic provenance replay.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional, Tuple
from sqlalchemy.orm import Session

from aivara.database.models import FindingModel, ProvenanceRecordModel
from aivara.domain.schemas import ProvenanceRecordRead
from aivara.evidence.schemas import ScanExecutionStatus
from aivara.behavioral.provenance.enums import BehavioralFindingType
from aivara.behavioral.provenance.identity import (
    build_behavioral_execution_payload,
    compute_behavioral_execution_identity_hash,
)

logger = logging.getLogger("aivara.behavioral.provenance.idempotency")


def resolve_idempotent_behavioral_scan(
    db: Session,
    *,
    project_id: str,
    model_id: str,
    model_fingerprint: str,
    observation_id: str,
    baseline_id: str,
    detector_id: str = "behavioral_anomaly_detector",
    detector_version: str = "1.0.0",
    detector_config_hash: str = "0" * 64,
    policy_version: str = "1.0.0",
    engine_version: str = "1.0.0",
    preprocessing_hash: str = "STANDARD_V1",
) -> Optional[Tuple[FindingModel, Optional[ProvenanceRecordRead]]]:
    """Check if an identical analytical execution was previously recorded and return the existing Finding."""
    exec_payload = {
        "project_id": project_id,
        "model_id": model_id,
        "model_fingerprint": model_fingerprint,
        "observation_id": observation_id,
        "baseline_id": baseline_id,
        "detector_id": detector_id,
        "detector_version": detector_version,
        "detector_config_hash": detector_config_hash,
        "policy_version": policy_version,
        "engine_version": engine_version,
        "preprocessing_hash": preprocessing_hash,
    }
    exec_hash = compute_behavioral_execution_identity_hash(exec_payload)

    existing_findings = (
        db.query(FindingModel)
        .filter(
            FindingModel.project_id == project_id,
            FindingModel.affected_asset_id == model_id,
            FindingModel.finding_type == BehavioralFindingType.BEHAVIORAL_ANOMALY.value,
        )
        .all()
    )

    for f in existing_findings:
        meta = f.metadata_json or {}
        if meta.get("execution_identity_hash") == exec_hash:
            prov_record: Optional[ProvenanceRecordRead] = None
            prov_id = meta.get("provenance_record_id")
            if prov_id:
                prov_model = db.query(ProvenanceRecordModel).filter_by(id=prov_id).first()
                if prov_model:
                    prov_record = ProvenanceRecordRead.model_validate(prov_model)
            return f, prov_record

    return None
