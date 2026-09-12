"""Orchestration service for Phase 10.10 Evidence & Provenance Binding."""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional, Tuple, Union
from sqlalchemy.orm import Session

from aivara.crypto.canonical import format_canonical_datetime
from datetime import datetime, timezone
from sqlalchemy import desc

from aivara.crypto.chain import (
    ChainRecord,
    create_genesis_record,
    generate_nonce,
)
from aivara.crypto.hashing import hash_provenance_payload
from aivara.crypto.signing import sign_hash
from aivara.database.models import FindingModel, ProjectModel, ProvenanceRecordModel
from aivara.domain.schemas import ProvenanceRecordCreate, ProvenanceRecordRead
from aivara.evidence.binding import EvidenceFindingBinder
from aivara.evidence.exceptions import CrossProjectContaminationError
from aivara.evidence.provenance import ProvenanceBindingAdapter
from aivara.evidence.validators import validate_project_isolation
from aivara.inference.composite_binding.models import InferenceBinding
from aivara.inference.evidence.engine import (
    build_inference_provenance_payload,
    create_inference_evidence,
    create_phase5_evidence_and_finding_payloads,
    verify_inference_evidence,
)
from aivara.inference.evidence.models import (
    InferenceEvidence,
    InferenceEvidenceVerificationResult,
)
from aivara.inference.records.models import InferenceRecord
from aivara.inference.replay.models import ReplayVerificationResult
from aivara.services.audit_service import AuditService
from aivara.services.provenance_service import ProvenanceService

logger = logging.getLogger("aivara.inference.evidence")


class InferenceEvidenceService:
    """Orchestration service binding inference transactions into Phase 5 evidence and Phase 4 provenance."""

    def __init__(
        self,
        db: Optional[Session] = None,
        key_manager: Optional[KeyManager] = None,
        audit_service: Optional[AuditService] = None,
        provenance_service: Optional[ProvenanceService] = None,
    ) -> None:
        self.db = db
        self.key_manager = key_manager
        self.audit_service = audit_service or (AuditService(db) if db is not None else None)
        self.provenance_service = provenance_service or (
            ProvenanceService(db=db, key_manager=key_manager, audit_service=self.audit_service)
            if db is not None
            else None
        )
        self.binder = EvidenceFindingBinder(db=db) if db is not None else None
        self.provenance_adapter = (
            ProvenanceBindingAdapter(
                db=db,
                key_manager=key_manager,
                audit_service=self.audit_service,
                provenance_service=self.provenance_service,
            )
            if db is not None
            else None
        )

    def generate_inference_evidence(
        self,
        *,
        record: InferenceRecord,
        binding: Optional[InferenceBinding] = None,
        replay_result: Optional[ReplayVerificationResult] = None,
        expected_project_id: Optional[str] = None,
        created_at: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> InferenceEvidence:
        """Pure in-memory construction of immutable InferenceEvidence (offline-safe)."""
        if expected_project_id is not None:
            validate_project_isolation(
                expected_project_id,
                record.project_id,
                entity_name="InferenceRecord",
            )

        return create_inference_evidence(
            record=record,
            binding=binding,
            replay_result=replay_result,
            created_at=created_at,
            metadata=metadata,
        )

    def seal_and_bind_evidence(
        self,
        *,
        record: InferenceRecord,
        binding: Optional[InferenceBinding] = None,
        replay_result: Optional[ReplayVerificationResult] = None,
        signer_key_id: Optional[str] = None,
        key_handle: Optional[Any] = None,
        audit_run_id: Optional[str] = None,
        actor: str = "AIVARA_INFERENCE_ASSURANCE_ENGINE",
        expected_project_id: Optional[str] = None,
    ) -> Tuple[InferenceEvidence, Optional[ProvenanceRecordRead], Optional[FindingModel]]:
        """Synthesize Phase 5 finding and seal into Phase 4 cryptographic provenance ledger.

        Requires an active database session.
        """
        if self.db is None or self.provenance_service is None or self.binder is None:
            raise RuntimeError("Database session and ProvenanceService required to seal evidence.")

        if expected_project_id is not None:
            validate_project_isolation(
                expected_project_id,
                record.project_id,
                entity_name="InferenceRecord",
            )

        # 1. Generate unsealed evidence
        evidence = self.generate_inference_evidence(
            record=record,
            binding=binding,
            replay_result=replay_result,
            expected_project_id=expected_project_id,
        )

        # 2. Build canonical provenance payload
        prov_payload = build_inference_provenance_payload(evidence)

        # 3. Resolve latest provenance record to maintain hash chain
        latest_rec = (
            self.db.query(ProvenanceRecordModel)
            .filter(ProvenanceRecordModel.project_id == record.project_id)
            .order_by(desc(ProvenanceRecordModel.sequence_number))
            .first()
        )
        if latest_rec is None:
            # Anchor with genesis record
            genesis = create_genesis_record(
                project_id=record.project_id,
                signer_key_id=signer_key_id or (key_handle.key_id if key_handle else None),
            )
            self.provenance_service.record_provenance_event(genesis)
            next_seq = 1
            prev_hash = genesis.record_hash
        else:
            next_seq = latest_rec.sequence_number + 1
            prev_hash = latest_rec.record_hash

        nonce = generate_nonce()
        timestamp = format_canonical_datetime(datetime.now(timezone.utc))
        resolved_signer_key_id = signer_key_id or (key_handle.key_id if key_handle else ("0" * 64))

        rec_hash = hash_provenance_payload(
            record_type="INFERENCE_TRANSACTION_ASSURANCE",
            project_id=record.project_id,
            actor=actor,
            action="VERIFY_INFERENCE_INTEGRITY",
            sequence_number=next_seq,
            nonce=nonce,
            timestamp=timestamp,
            signer_key_id=resolved_signer_key_id,
            target_type="model",
            target_id=evidence.model_id,
            input_hash=evidence.input_canonical_hash,
            output_hash=evidence.raw_output_hash,
            model_id=evidence.model_id,
            previous_record_hash=prev_hash,
            metadata_json=prov_payload,
        )

        sig = None
        if key_handle is not None:
            sig_res = sign_hash(rec_hash, key_handle)
            sig = sig_res.signature

        chain_record = ChainRecord(
            project_id=record.project_id,
            sequence_number=next_seq,
            nonce=nonce,
            previous_record_hash=prev_hash,
            record_hash=rec_hash,
            signer_key_id=resolved_signer_key_id,
            record_type="INFERENCE_TRANSACTION_ASSURANCE",
            actor=actor,
            action="VERIFY_INFERENCE_INTEGRITY",
            timestamp=timestamp,
            target_type="model",
            target_id=evidence.model_id,
            input_hash=evidence.input_canonical_hash,
            output_hash=evidence.raw_output_hash,
            model_id=evidence.model_id,
            metadata_json=prov_payload,
            signature=sig,
        )

        # Persist via Phase 4 ProvenanceService
        prov_record = self.provenance_service.record_provenance_event(chain_record)

        # 4. Update evidence with provenance link
        prov_created_at = (
            format_canonical_datetime(prov_record.created_at)
            if isinstance(prov_record.created_at, datetime)
            else str(prov_record.created_at)
        )
        sealed_evidence = create_inference_evidence(
            record=record,
            binding=binding,
            replay_result=replay_result,
            provenance_record_id=prov_record.id,
            provenance_record_hash=prov_record.record_hash,
            created_at=prov_created_at,
        )


        # 5. Synthesize Phase 5 Finding and Evidence rows
        ev_payload, finding_payload = create_phase5_evidence_and_finding_payloads(
            sealed_evidence,
            audit_run_id=audit_run_id,
        )
        persisted_finding = self.binder.synthesize_finding(finding_payload)

        return sealed_evidence, prov_record, persisted_finding



    def verify_evidence(
        self,
        evidence: InferenceEvidence,
        *,
        record: Optional[InferenceRecord] = None,
        binding: Optional[InferenceBinding] = None,
        replay_result: Optional[ReplayVerificationResult] = None,
        expected_project_id: Optional[str] = None,
    ) -> InferenceEvidenceVerificationResult:
        """Verify complete inference evidence and provenance chain."""
        return verify_inference_evidence(
            evidence,
            record=record,
            binding=binding,
            replay_result=replay_result,
            expected_project_id=expected_project_id,
        )
