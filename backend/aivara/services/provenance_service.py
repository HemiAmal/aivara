"""Provenance service with persistent, concurrency-safe replay protection (Phase 4.11).

Provides:
  - Persistent provenance record lifecycle management.
  - Advisory and authoritative database-enforced replay detection.
  - Restart safety: replay detection survives application restarts by querying authoritative DB.
  - Concurrency safety: database uniqueness constraints prevent races, rolling back cleanly.
  - Safe error translation: maps database IntegrityError to structured replay errors
    (DuplicateNonceError, DuplicateSequenceError, DuplicateRecordError, ReplayDetectedError)
    while passing unrelated database integrity errors through.
"""

import logging
from typing import Any, Dict, List, Optional, Sequence, Union

from sqlalchemy import desc
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from aivara.core.exceptions import NotFoundException, ValidationException
from aivara.crypto.audit import (
    AuditEventType,
    AuditOutcome,
)
from aivara.crypto.chain import (
    ChainRecord,
    DuplicateNonceError,
    DuplicateRecordError,
    DuplicateSequenceError,
    InvalidNonceError,
    InvalidSequenceError,
    ReplayDetectedError,
    validate_nonce,
)
from aivara.crypto.keys import KeyManager
from aivara.crypto.replay import (
    ReplayAssessment,
    ReplayType,
    classify_integrity_error,
    raise_replay_error,
)
from aivara.crypto.tamper_detection import (
    ChainTamperAssessment,
    TamperAssessment,
    assess_chain_tampering as assess_chain_tampering_fn,
    assess_record_tampering as assess_record_tampering_fn,
)
from aivara.crypto.verification import (
    FailureCode,
    UnifiedChainVerificationResult,
    UnifiedVerificationResult,
    verify_provenance_chain,
    verify_record,
)
from aivara.database.models import ProvenanceRecordModel
from aivara.domain.schemas import (
    ProvenanceRecordCreate,
    ProvenanceRecordRead,
)
from aivara.services.audit_service import AuditService

logger = logging.getLogger("aivara.services.provenance")


class ProvenanceService:
    """Service managing persistent provenance records and replay detection."""

    def __init__(
        self,
        db: Session,
        key_manager: Optional[KeyManager] = None,
        audit_service: Optional[AuditService] = None,
    ) -> None:
        """Initialize ProvenanceService with a SQLAlchemy session and optional KeyManager.

        Args:
            db: Active SQLAlchemy database session.
            key_manager: Optional KeyManager instance for resolving public keys.
            audit_service: Optional AuditService instance. Defaults to AuditService(db).
        """
        self.db = db
        self.key_manager = key_manager
        self.audit_service = audit_service or AuditService(db)
        self.last_audit_error: Optional[str] = None

    def check_replay(
        self,
        project_id: str,
        *,
        sequence_number: Optional[int] = None,
        nonce: Optional[str] = None,
        record_hash: Optional[str] = None,
    ) -> ReplayAssessment:
        """Advisory query to evaluate whether a record would conflict with existing records.

        Note: Application-level check alone is not sufficient under concurrency.
        The database unique constraints are authoritative.

        Args:
            project_id: Target project identifier.
            sequence_number: Sequence number to test.
            nonce: Nonce to test.
            record_hash: Record hash to test.

        Returns:
            ReplayAssessment indicating whether a replay condition was detected.
        """
        # 1. Check duplicate nonce
        if nonce is not None:
            existing_nonce = (
                self.db.query(ProvenanceRecordModel.id)
                .filter(
                    ProvenanceRecordModel.project_id == project_id,
                    ProvenanceRecordModel.nonce == nonce,
                )
                .first()
            )
            if existing_nonce:
                return ReplayAssessment(
                    replay_detected=True,
                    replay_type=ReplayType.DUPLICATE_NONCE,
                    project_id=project_id,
                    sequence_number=sequence_number,
                    nonce=nonce,
                    record_hash=record_hash,
                    conflicting_record_id=str(existing_nonce[0]),
                    reason=f"Replay detected: duplicate nonce '{nonce}' already accepted in project '{project_id}'.",
                )

        # 2. Check duplicate sequence number
        if sequence_number is not None:
            existing_seq = (
                self.db.query(ProvenanceRecordModel.id)
                .filter(
                    ProvenanceRecordModel.project_id == project_id,
                    ProvenanceRecordModel.sequence_number == sequence_number,
                )
                .first()
            )
            if existing_seq:
                return ReplayAssessment(
                    replay_detected=True,
                    replay_type=ReplayType.DUPLICATE_SEQUENCE,
                    project_id=project_id,
                    sequence_number=sequence_number,
                    nonce=nonce,
                    record_hash=record_hash,
                    conflicting_record_id=str(existing_seq[0]),
                    reason=f"Replay detected: sequence number {sequence_number} already exists in project '{project_id}'.",
                )

        # 3. Check duplicate record hash
        if record_hash is not None:
            existing_hash = (
                self.db.query(ProvenanceRecordModel.id)
                .filter(
                    ProvenanceRecordModel.project_id == project_id,
                    ProvenanceRecordModel.record_hash == record_hash,
                )
                .first()
            )
            if existing_hash:
                return ReplayAssessment(
                    replay_detected=True,
                    replay_type=ReplayType.DUPLICATE_RECORD,
                    project_id=project_id,
                    sequence_number=sequence_number,
                    nonce=nonce,
                    record_hash=record_hash,
                    conflicting_record_id=str(existing_hash[0]),
                    reason=f"Replay detected: duplicate record hash '{record_hash}' already exists in project '{project_id}'.",
                )

        return ReplayAssessment(
            replay_detected=False,
            replay_type=ReplayType.NONE,
            project_id=project_id,
            sequence_number=sequence_number,
            nonce=nonce,
            record_hash=record_hash,
            reason="No replay detected.",
        )

    def record_provenance_event(
        self,
        record_data: Union[ProvenanceRecordCreate, ChainRecord, Dict[str, Any]],
        *,
        verify_first: bool = False,
        key_manager: Optional[KeyManager] = None,
    ) -> ProvenanceRecordRead:
        """Atomically persist a provenance record with database-authoritative replay protection.

        Args:
            record_data: ProvenanceRecordCreate, ChainRecord, or dict containing record fields.
            verify_first: If True, executes cryptographic verification prior to persistence.
            key_manager: KeyManager for resolving public keys if verify_first=True.

        Returns:
            ProvenanceRecordRead representing the persisted record.

        Raises:
            DuplicateNonceError: If nonce was already accepted in the project.
            DuplicateSequenceError: If sequence number was already accepted in the project.
            DuplicateRecordError: If record hash was already accepted in the project.
            ReplayDetectedError: If another uniqueness conflict is detected.
            InvalidNonceError: If nonce format is invalid.
            InvalidSequenceError: If sequence number is negative or invalid.
            IntegrityError: If an unrelated database integrity violation occurred (e.g. invalid FK).
        """
        # Normalize fields to dict
        if isinstance(record_data, ChainRecord):
            raw = record_data.model_dump()
        elif isinstance(record_data, ProvenanceRecordCreate):
            raw = record_data.model_dump()
        elif isinstance(record_data, dict):
            raw = dict(record_data)
        else:
            raise TypeError(f"Unsupported record_data type: {type(record_data).__name__}")

        project_id = raw.get("project_id")
        if not project_id or not isinstance(project_id, str):
            raise ValueError("project_id is required and must be a string.")

        nonce = raw.get("nonce")
        if nonce is not None:
            validate_nonce(nonce)

        seq = raw.get("sequence_number")
        if seq is not None:
            if not isinstance(seq, int) or seq < 0:
                raise InvalidSequenceError(f"Sequence number must be non-negative integer, got {seq}.")

        rec_hash = raw.get("record_hash")

        # Cryptographic verification if requested
        if verify_first:
            res = verify_record(
                raw,
                key_manager=key_manager,
                allow_unsigned=True,
                expected_project_id=project_id,
            )
            # Replay failures during verification
            for f in res.failures:
                if f.code in (
                    FailureCode.DUPLICATE_NONCE,
                    FailureCode.DUPLICATE_SEQUENCE,
                    FailureCode.DUPLICATE_RECORD,
                    FailureCode.REPLAY_DETECTED,
                ):
                    assessment = ReplayAssessment(
                        replay_detected=True,
                        replay_type=ReplayType(f.code.value) if f.code.value in ReplayType._value2member_map_ else ReplayType.REPLAY_DETECTED,
                        project_id=project_id,
                        sequence_number=seq,
                        nonce=nonce,
                        record_hash=rec_hash,
                        reason=f.message,
                    )
                    self.audit_service.record_replay_rejected(
                        project_id=project_id,
                        actor=raw.get("actor", "system"),
                        reason=f.message,
                        replay_type=assessment.replay_type.value,
                        sequence_number=seq,
                        nonce=nonce,
                        record_hash=rec_hash,
                    )
                    raise_replay_error(assessment)

        # Advisory check
        advisory = self.check_replay(
            project_id=project_id,
            sequence_number=seq,
            nonce=nonce,
            record_hash=rec_hash,
        )
        if advisory.replay_detected:
            self.audit_service.record_replay_rejected(
                project_id=project_id,
                actor=raw.get("actor", "system"),
                target_id=advisory.conflicting_record_id,
                reason=advisory.reason,
                replay_type=advisory.replay_type.value,
                sequence_number=seq,
                nonce=nonce,
                record_hash=rec_hash,
            )
            raise_replay_error(advisory)

        # Construct SQLAlchemy model
        model = ProvenanceRecordModel(
            project_id=project_id,
            record_type=raw.get("record_type", "EVENT"),
            actor=raw.get("actor", "system"),
            action=raw.get("action", "record"),
            target_type=raw.get("target_type"),
            target_id=raw.get("target_id"),
            input_hash=raw.get("input_hash"),
            output_hash=raw.get("output_hash"),
            metadata_json=raw.get("metadata_json") or {},
            signature=raw.get("signature"),
            signer_key_id=raw.get("signer_key_id"),
            nonce=nonce,
            previous_record_hash=raw.get("previous_record_hash"),
            record_hash=rec_hash,
            sequence_number=seq,
            blockchain_tx_id=raw.get("blockchain_tx_id"),
        )

        # Atomic insertion with rollback and error classification
        try:
            self.db.add(model)
            self.db.commit()
            self.db.refresh(model)
            res = ProvenanceRecordRead.model_validate(model)
            # Observable audit logging on business success
            try:
                self.audit_service.record_event(
                    project_id=project_id,
                    event_type=AuditEventType.PROVENANCE_RECORDED,
                    actor=model.actor or "system",
                    action=model.action or "RECORD_PROVENANCE",
                    target_type="PROVENANCE_RECORD",
                    target_id=model.id,
                    outcome=AuditOutcome.SUCCESS,
                    description=f"Provenance record {model.sequence_number} recorded successfully.",
                    metadata_json={
                        "sequence_number": model.sequence_number,
                        "record_hash": model.record_hash,
                        "nonce": model.nonce,
                    },
                )
            except Exception as audit_exc:
                self.last_audit_error = str(audit_exc)
                logger.error(
                    "CRITICAL_SECURITY_CONDITION: Business operation succeeded but audit logging failed for project '%s': %s",
                    project_id,
                    audit_exc,
                )
            return res
        except IntegrityError as exc:
            self.db.rollback()
            is_replay, r_type, reason, conf_id = classify_integrity_error(
                exc=exc,
                project_id=project_id,
                sequence_number=seq,
                nonce=nonce,
                record_hash=rec_hash,
                db=self.db,
            )
            if is_replay:
                assessment = ReplayAssessment(
                    replay_detected=True,
                    replay_type=r_type,
                    project_id=project_id,
                    sequence_number=seq,
                    nonce=nonce,
                    record_hash=rec_hash,
                    conflicting_record_id=conf_id,
                    reason=reason,
                )
                # Independent transaction: audit survives failed business transaction rollback
                self.audit_service.record_replay_rejected(
                    project_id=project_id,
                    actor=raw.get("actor", "system"),
                    target_id=conf_id,
                    reason=reason,
                    replay_type=r_type.value,
                    sequence_number=seq,
                    nonce=nonce,
                    record_hash=rec_hash,
                )
                raise_replay_error(assessment)
            # Unrelated database error (e.g. foreign key failure) — do NOT classify as replay
            raise exc

    def get_record(self, record_id: str) -> Optional[ProvenanceRecordRead]:
        """Fetch a provenance record by its primary key ID."""
        record = self.db.query(ProvenanceRecordModel).filter(ProvenanceRecordModel.id == record_id).first()
        if not record:
            return None
        return ProvenanceRecordRead.model_validate(record)

    def get_record_by_sequence(self, project_id: str, sequence_number: int) -> Optional[ProvenanceRecordRead]:
        """Fetch a provenance record by project and sequence number."""
        record = (
            self.db.query(ProvenanceRecordModel)
            .filter(
                ProvenanceRecordModel.project_id == project_id,
                ProvenanceRecordModel.sequence_number == sequence_number,
            )
            .first()
        )
        if not record:
            return None
        return ProvenanceRecordRead.model_validate(record)

    def get_record_by_hash(self, project_id: str, record_hash: str) -> Optional[ProvenanceRecordRead]:
        """Fetch a provenance record by project and record hash."""
        record = (
            self.db.query(ProvenanceRecordModel)
            .filter(
                ProvenanceRecordModel.project_id == project_id,
                ProvenanceRecordModel.record_hash == record_hash,
            )
            .first()
        )
        if not record:
            return None
        return ProvenanceRecordRead.model_validate(record)

    def get_record_by_nonce(self, project_id: str, nonce: str) -> Optional[ProvenanceRecordRead]:
        """Fetch a provenance record by project and nonce."""
        record = (
            self.db.query(ProvenanceRecordModel)
            .filter(
                ProvenanceRecordModel.project_id == project_id,
                ProvenanceRecordModel.nonce == nonce,
            )
            .first()
        )
        if not record:
            return None
        return ProvenanceRecordRead.model_validate(record)

    def list_records(
        self,
        project_id: str,
        *,
        limit: int = 100,
        offset: int = 0,
    ) -> List[ProvenanceRecordRead]:
        """List provenance records for a project ordered by sequence number ascending."""
        records = (
            self.db.query(ProvenanceRecordModel)
            .filter(ProvenanceRecordModel.project_id == project_id)
            .order_by(ProvenanceRecordModel.sequence_number.asc())
            .offset(offset)
            .limit(limit)
            .all()
        )
        return [ProvenanceRecordRead.model_validate(r) for r in records]

    def get_latest_record(self, project_id: str) -> Optional[ProvenanceRecordRead]:
        """Fetch the highest sequence number provenance record in a project."""
        record = (
            self.db.query(ProvenanceRecordModel)
            .filter(ProvenanceRecordModel.project_id == project_id)
            .order_by(desc(ProvenanceRecordModel.sequence_number))
            .first()
        )
        if not record:
            return None
        return ProvenanceRecordRead.model_validate(record)

    def verify_record(
        self,
        record: Optional[Union[Dict[str, Any], ChainRecord, ProvenanceRecordRead]] = None,
        *,
        record_id: Optional[str] = None,
        expected_project_id: Optional[str] = None,
        expected_sequence: Optional[int] = None,
        expected_previous_record_hash: Optional[str] = None,
        allow_unsigned: bool = True,
    ) -> UnifiedVerificationResult:
        """Cryptographically verify a provenance record, supplied directly or loaded by ID.

        Args:
            record: Optional in-memory provenance record payload.
            record_id: Optional database ID to load record from database.
            expected_project_id: Optional expected project ID to validate against.
            expected_sequence: Optional expected sequence number to validate against.
            expected_previous_record_hash: Optional expected previous hash to validate against.
            allow_unsigned: Whether unsigned records are permitted without failure.

        Returns:
            UnifiedVerificationResult containing diagnostic evaluation across all layers.

        Raises:
            NotFoundException: If record_id is specified but does not exist in DB.
            ValidationException: If neither record nor record_id is provided.
        """
        if record is None and record_id is not None:
            db_record = self.get_record(record_id)
            if not db_record:
                raise NotFoundException(f"Provenance record '{record_id}' not found.")
            target_data = db_record.model_dump()
        elif record is not None:
            if hasattr(record, "model_dump"):
                target_data = record.model_dump()
            elif isinstance(record, dict):
                target_data = dict(record)
            else:
                target_data = dict(record)
        else:
            raise ValidationException("Either 'record' payload or 'record_id' must be provided for verification.")

        v_result = verify_record(
            record=target_data,
            key_manager=self.key_manager,
            allow_unsigned=allow_unsigned,
            expected_project_id=expected_project_id,
            expected_sequence=expected_sequence,
            expected_previous_record_hash=expected_previous_record_hash,
        )
        pid = expected_project_id or (isinstance(target_data, dict) and target_data.get("project_id"))
        if pid:
            try:
                self.audit_service.record_event(
                    project_id=pid,
                    event_type=AuditEventType.PROVENANCE_VERIFICATION,
                    actor="verifier",
                    action="VERIFY_PROVENANCE_RECORD",
                    target_type="PROVENANCE_RECORD",
                    target_id=target_data.get("id"),
                    outcome=AuditOutcome.SUCCESS if v_result.overall_valid else AuditOutcome.FAILURE,
                    description="Provenance record verification executed.",
                    metadata_json={
                        "valid": v_result.overall_valid,
                        "failure_count": len(v_result.failures),
                    },
                )
            except Exception as audit_exc:
                self.last_audit_error = str(audit_exc)
                logger.error("Audit logging failed during verify_record: %s", audit_exc)
        return v_result

    def verify_chain(
        self,
        *,
        project_id: Optional[str] = None,
        records: Optional[Sequence[Union[Dict[str, Any], ChainRecord, ProvenanceRecordRead]]] = None,
        allow_unsigned: bool = True,
    ) -> UnifiedChainVerificationResult:
        """Cryptographically verify a provenance chain, supplied directly or loaded from DB.

        Args:
            project_id: Optional project identifier to load chain from DB (or enforce).
            records: Optional in-memory sequence of provenance records.
            allow_unsigned: Whether unsigned records are permitted without failure.

        Returns:
            UnifiedChainVerificationResult containing full chain diagnostic evaluation.

        Raises:
            ValidationException: If neither records nor project_id is provided.
        """
        if records is not None:
            target_records = [
                r.model_dump() if hasattr(r, "model_dump") else dict(r) for r in records
            ]
        elif project_id is not None:
            db_records = self.list_records(project_id, limit=10000)
            target_records = [r.model_dump() for r in db_records]
        else:
            raise ValidationException("Either 'records' or 'project_id' must be provided for chain verification.")

        chain_result = verify_provenance_chain(
            records=target_records,
            expected_project_id=project_id,
            key_manager=self.key_manager,
            allow_unsigned=allow_unsigned,
        )
        pid = project_id or (target_records and target_records[0].get("project_id"))
        if pid:
            try:
                self.audit_service.record_event(
                    project_id=pid,
                    event_type=AuditEventType.CHAIN_VERIFICATION,
                    actor="verifier",
                    action="VERIFY_PROVENANCE_CHAIN",
                    target_type="PROVENANCE_CHAIN",
                    target_id=pid,
                    outcome=AuditOutcome.SUCCESS if chain_result.overall_valid else AuditOutcome.FAILURE,
                    description="Provenance chain verification executed.",
                    metadata_json={
                        "chain_valid": chain_result.chain_valid,
                        "records_verified": chain_result.records_verified_count,
                    },
                )
            except Exception as audit_exc:
                self.last_audit_error = str(audit_exc)
                logger.error("Audit logging failed during verify_chain: %s", audit_exc)
        return chain_result

    def assess_record_tampering(
        self,
        record: Optional[Union[Dict[str, Any], ChainRecord, ProvenanceRecordRead]] = None,
        *,
        record_id: Optional[str] = None,
        expected_project_id: Optional[str] = None,
        allow_unsigned: bool = True,
    ) -> TamperAssessment:
        """Assess cryptographic tampering on a single record by verifying it and classifying findings.

        Args:
            record: Optional in-memory record payload.
            record_id: Optional database ID to load record from DB.
            expected_project_id: Optional expected project ID.
            allow_unsigned: Whether unsigned records are permitted without failure.

        Returns:
            TamperAssessment detailing tampering status, confidence, severity, and findings.
        """
        v_res = self.verify_record(
            record=record,
            record_id=record_id,
            expected_project_id=expected_project_id,
            allow_unsigned=allow_unsigned,
        )
        return assess_record_tampering_fn(v_res)

    def assess_chain_tampering(
        self,
        *,
        project_id: Optional[str] = None,
        records: Optional[Sequence[Union[Dict[str, Any], ChainRecord, ProvenanceRecordRead]]] = None,
        allow_unsigned: bool = True,
    ) -> ChainTamperAssessment:
        """Assess cryptographic tampering across an entire chain.

        Args:
            project_id: Optional project identifier to load chain from DB.
            records: Optional in-memory sequence of records.
            allow_unsigned: Whether unsigned records are permitted.

        Returns:
            ChainTamperAssessment detailing chain-wide tampering status and findings.
        """
        chain_res = self.verify_chain(
            project_id=project_id,
            records=records,
            allow_unsigned=allow_unsigned,
        )
        return assess_chain_tampering_fn(chain_res)
