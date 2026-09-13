"""Service layer for Phase 10.12 Comprehensive Inference Verification."""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional, Union
from sqlalchemy.orm import Session

from aivara.core.exceptions import NotFoundException
from aivara.crypto.keys import KeyManager
from aivara.database.models import EvidenceModel, FindingModel, ProvenanceRecordModel
from aivara.domain.schemas import ProvenanceRecordRead
from aivara.inference.composite_binding.models import InferenceBinding
from aivara.inference.comprehensive.engine import ComprehensiveInferenceVerifier
from aivara.inference.comprehensive.models import ComprehensiveInferenceVerificationResult
from aivara.inference.enums import InferenceIntegrityStatus
from aivara.inference.evidence.models import InferenceEvidence
from aivara.inference.evidence.service import InferenceEvidenceService
from aivara.inference.exceptions import InferenceRecordNotFoundError, InferenceRecordProjectMismatchError
from aivara.inference.records.models import InferenceRecord
from aivara.inference.records.repository import InferenceRecordRepository
from aivara.inference.records.service import InferenceRecordService
from aivara.inference.replay.service import InferenceReplayService
from aivara.services.audit_service import AuditService
from aivara.services.provenance_service import ProvenanceService

logger = logging.getLogger("aivara.inference.comprehensive.service")


class ComprehensiveInferenceService:
    """Orchestration service for comprehensive multi-layer inference integrity verification."""

    def __init__(
        self,
        db: Optional[Session] = None,
        key_manager: Optional[KeyManager] = None,
        record_service: Optional[InferenceRecordService] = None,
        evidence_service: Optional[InferenceEvidenceService] = None,
        provenance_service: Optional[ProvenanceService] = None,
        replay_service: Optional[InferenceReplayService] = None,
        audit_service: Optional[AuditService] = None,
    ) -> None:
        self.db = db
        self.key_manager = key_manager
        self.audit_service = audit_service or (AuditService(db) if db is not None else None)
        self.provenance_service = provenance_service or (
            ProvenanceService(db=db, key_manager=key_manager, audit_service=self.audit_service)
            if db is not None
            else None
        )
        self.record_service = record_service or (InferenceRecordService(db) if db is not None else None)
        self.evidence_service = evidence_service or (
            InferenceEvidenceService(
                db=db,
                key_manager=key_manager,
                audit_service=self.audit_service,
                provenance_service=self.provenance_service,
            )
            if db is not None
            else None
        )
        self.replay_service = replay_service or InferenceReplayService()

    def verify_stored_record(
        self,
        project_id: str,
        record_id: str,
    ) -> ComprehensiveInferenceVerificationResult:
        """Retrieve and comprehensively verify an immutable sealed inference record and all linked artifacts."""
        if self.db is None:
            raise RuntimeError("Database session required to verify stored inference record.")

        repo = InferenceRecordRepository(self.db)
        db_rec = repo.get_by_id(record_id, project_id=project_id)
        if db_rec is None:
            # Check for project isolation
            any_rec = repo.get_by_id(record_id)
            if any_rec is not None:
                raise InferenceRecordProjectMismatchError(
                    f"Inference record '{record_id}' belongs to project '{any_rec.project_id}', not '{project_id}'.",
                    details={"record_id": record_id, "project_id": project_id},
                )
            raise NotFoundException(f"Inference record '{record_id}' not found for project '{project_id}'.")

        domain_rec = repo.to_domain(db_rec)
        binding = domain_rec.binding

        # Retrieve linked evidence if available
        linked_evidence: Optional[InferenceEvidence] = None
        evidence_rows = (
            self.db.query(EvidenceModel)
            .join(FindingModel, EvidenceModel.finding_id == FindingModel.id)
            .filter(FindingModel.project_id == project_id)
            .all()
        )
        for ev in evidence_rows:
            data = ev.data_json or {}
            if data.get("record_id") == record_id or data.get("inference_record_id") == record_id:
                try:
                    linked_evidence = InferenceEvidence.model_validate(data)
                    break
                except Exception:
                    pass

        # Retrieve linked provenance if available
        linked_prov: Optional[ProvenanceRecordRead] = None
        prov_rows = (
            self.db.query(ProvenanceRecordModel)
            .filter(
                ProvenanceRecordModel.project_id == project_id,
                ProvenanceRecordModel.record_type == "INFERENCE_TRANSACTION_ASSURANCE",
            )
            .all()
        )
        for p in prov_rows:
            meta = p.metadata_json or {}
            if (
                meta.get("record_id") == record_id
                or meta.get("inference_record_id") == record_id
                or meta.get("record_integrity_hash") == domain_rec.record_integrity_hash
            ):
                linked_prov = ProvenanceRecordRead.model_validate(p)
                break

        return ComprehensiveInferenceVerifier.verify(
            project_id=project_id,
            record=domain_rec,
            binding=binding,
            evidence=linked_evidence,
            provenance=linked_prov,
        )
