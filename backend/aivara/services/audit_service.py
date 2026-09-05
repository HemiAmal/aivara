"""Tamper-Evident Audit Service for AIVARA (Phase 4.13).

Provides:
  - Atomic persistence of hash-linked audit records in project-scoped chains.
  - Concurrency-safe, deterministic genesis initialization.
  - Independent transactional logging for replay rejections.
  - Audit chain verification and tamper detection.
  - Strict immutability enforcement (no update or delete operations).
  - Explicit non-recursive boundary: never logs its own internal operations.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple, Union

from sqlalchemy import desc
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker

from aivara.core.exceptions import AivaraException
from aivara.crypto.audit import (
    AUDIT_GENESIS_ACTION,
    AUDIT_GENESIS_ACTOR,
    AUDIT_GENESIS_DESCRIPTION,
    AUDIT_GENESIS_EVENT_TYPE,
    AUDIT_GENESIS_METADATA,
    AUDIT_GENESIS_OUTCOME,
    AUDIT_GENESIS_PREVIOUS_HASH,
    AUDIT_GENESIS_SEQUENCE,
    AUDIT_GENESIS_TARGET_TYPE,
    AUDIT_GENESIS_TIMESTAMP,
    AuditEventType,
    AuditOutcome,
    AuditVerificationResult,
    create_audit_genesis_payload,
    format_canonical_datetime,
    hash_audit_payload,
    verify_audit_chain,
)
from aivara.database.connection import SessionLocal
from aivara.database.models import AuditEventModel, AuditImmutabilityError
from aivara.domain.schemas import AuditEventRead

logger = logging.getLogger("aivara.services.audit")


class AuditServiceError(AivaraException):
    """Base exception for audit service failures."""

    def __init__(self, message: str, code: str = "AUDIT_SERVICE_ERROR", details: Optional[Any] = None) -> None:
        super().__init__(message, code=code, details=details)


class AuditEventNotFoundError(AuditServiceError):
    """Raised when a requested audit event is not found."""

    def __init__(self, event_id: str) -> None:
        super().__init__(f"Audit event with ID '{event_id}' not found.", code="AUDIT_NOT_FOUND")


class AuditSequenceCollisionError(AuditServiceError):
    """Raised when concurrent audit event creation collides on sequence or hash."""

    def __init__(self, message: str) -> None:
        super().__init__(message, code="AUDIT_SEQUENCE_COLLISION")


class AuditService:
    """Service managing cryptographically tamper-evident audit chains."""

    def __init__(self, db: Session) -> None:
        """Initialize AuditService with an active database session.

        Args:
            db: SQLAlchemy database session.
        """
        self.db = db

    # =========================================================================
    # Genesis & Chain Management
    # =========================================================================

    def _ensure_genesis(self, project_id: str) -> AuditEventModel:
        """Ensure the project's audit chain has an initialized genesis anchor at sequence 0.

        Concurrency-safe: Catches duplicate sequence collisions if another worker
        initializes the genesis record concurrently.
        """
        existing_genesis = (
            self.db.query(AuditEventModel)
            .filter(
                AuditEventModel.project_id == project_id,
                AuditEventModel.sequence_number == AUDIT_GENESIS_SEQUENCE,
            )
            .first()
        )
        if existing_genesis:
            return existing_genesis

        # Build deterministic genesis payload
        gen_payload = create_audit_genesis_payload(project_id)
        genesis_model = AuditEventModel(
            project_id=project_id,
            event_type=gen_payload["event_type"],
            actor=gen_payload["actor"],
            action=gen_payload["action"],
            target_type=gen_payload["target_type"],
            target_id=gen_payload["target_id"],
            outcome=gen_payload["outcome"],
            description=gen_payload["description"],
            metadata_json=gen_payload["metadata_json"],
            sequence_number=gen_payload["sequence_number"],
            previous_event_hash=gen_payload["previous_event_hash"],
            event_hash=gen_payload["event_hash"],
            created_at=datetime.fromisoformat(AUDIT_GENESIS_TIMESTAMP.replace("Z", "+00:00")),
        )

        try:
            self.db.add(genesis_model)
            self.db.commit()
            self.db.refresh(genesis_model)
            return genesis_model
        except IntegrityError:
            self.db.rollback()
            # Concurrent insert won the race; query the committed genesis record
            existing_after_race = (
                self.db.query(AuditEventModel)
                .filter(
                    AuditEventModel.project_id == project_id,
                    AuditEventModel.sequence_number == AUDIT_GENESIS_SEQUENCE,
                )
                .first()
            )
            if existing_after_race:
                return existing_after_race
            raise AuditServiceError(f"Failed to initialize or resolve audit genesis for project '{project_id}'.")

    # =========================================================================
    # Event Recording (Observer Boundary)
    # =========================================================================

    def record_event(
        self,
        *,
        project_id: str,
        event_type: Union[AuditEventType, str],
        actor: str = "system",
        action: Optional[str] = None,
        target_type: Optional[str] = None,
        target_id: Optional[str] = None,
        outcome: Union[AuditOutcome, str] = AuditOutcome.SUCCESS,
        description: Optional[str] = None,
        metadata_json: Optional[Dict[str, Any]] = None,
        timestamp: Optional[Union[str, datetime]] = None,
    ) -> AuditEventRead:
        """Atomically record a security-relevant event into the project's audit chain.

        Strict non-recursive invariant: This method never emits secondary audit events.
        """
        if not project_id or not isinstance(project_id, str):
            raise ValueError("project_id must be a non-empty string.")

        e_type = event_type.value if isinstance(event_type, AuditEventType) else str(event_type)
        e_outcome = outcome.value if isinstance(outcome, AuditOutcome) else str(outcome)
        meta = metadata_json if metadata_json is not None else {}

        # 1. Ensure genesis record exists at sequence 0
        self._ensure_genesis(project_id)

        # 2. Query latest event in the project chain
        latest = (
            self.db.query(AuditEventModel)
            .filter(AuditEventModel.project_id == project_id)
            .order_by(desc(AuditEventModel.sequence_number))
            .first()
        )

        if latest is None:
            # Fallback if genesis just committed
            latest = self._ensure_genesis(project_id)

        next_seq = (latest.sequence_number or 0) + 1
        prev_hash = latest.event_hash or AUDIT_GENESIS_PREVIOUS_HASH

        # 3. Resolve timestamp
        if timestamp is None:
            now_dt = datetime.now(timezone.utc)
            ts_str = format_canonical_datetime(now_dt)
        elif isinstance(timestamp, datetime):
            now_dt = timestamp
            ts_str = format_canonical_datetime(timestamp)
        elif isinstance(timestamp, str):
            ts_str = timestamp
            try:
                now_dt = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
            except ValueError:
                now_dt = datetime.now(timezone.utc)
        else:
            raise TypeError(f"Invalid timestamp type: {type(timestamp).__name__}")

        # 4. Compute deterministic event hash over exact 13 fields
        e_hash = hash_audit_payload(
            project_id=project_id,
            event_type=e_type,
            actor=actor,
            action=action,
            target_type=target_type,
            target_id=target_id,
            outcome=e_outcome,
            description=description,
            sequence_number=next_seq,
            previous_event_hash=prev_hash,
            timestamp=ts_str,
            metadata=meta,
        )

        # 5. Build model and persist atomically
        model = AuditEventModel(
            project_id=project_id,
            event_type=e_type,
            actor=actor,
            action=action,
            target_type=target_type,
            target_id=target_id,
            outcome=e_outcome,
            description=description,
            metadata_json=meta,
            sequence_number=next_seq,
            previous_event_hash=prev_hash,
            event_hash=e_hash,
            created_at=now_dt,
        )

        try:
            self.db.add(model)
            self.db.commit()
            self.db.refresh(model)
            return AuditEventRead.model_validate(model)
        except IntegrityError as exc:
            self.db.rollback()
            raise AuditSequenceCollisionError(
                f"Audit sequence collision at sequence {next_seq} for project '{project_id}': {exc}"
            )

    # =========================================================================
    # Independent Transaction Replay Logging
    # =========================================================================

    def record_replay_rejected(
        self,
        *,
        project_id: str,
        actor: str = "system",
        target_id: Optional[str] = None,
        reason: str,
        replay_type: str,
        sequence_number: Optional[int] = None,
        nonce: Optional[str] = None,
        record_hash: Optional[str] = None,
    ) -> Optional[AuditEventRead]:
        """Record a PROVENANCE_REPLAY_REJECTED event in an independent transaction.

        Guarantees that a failed primary business transaction (which rolled back)
        does not discard the security audit record proving a replay attack was attempted.
        """
        # Create an independent database session bound to the same engine as self.db
        bind = self.db.get_bind()
        session_factory = sessionmaker(autocommit=False, autoflush=False, bind=bind)
        independent_db = session_factory()
        try:
            independent_service = AuditService(independent_db)
            meta = {
                "replay_type": replay_type,
                "sequence_number": sequence_number,
                "nonce": nonce,
                "record_hash": record_hash,
            }
            return independent_service.record_event(
                project_id=project_id,
                event_type=AuditEventType.PROVENANCE_REPLAY_REJECTED,
                actor=actor,
                action="REJECT_PROVENANCE_REPLAY",
                target_type="PROVENANCE_RECORD",
                target_id=target_id,
                outcome=AuditOutcome.REJECTED,
                description=reason,
                metadata_json=meta,
            )
        except Exception as exc:
            logger.error("Failed to record replay rejection audit event: %s", exc)
            return None
        finally:
            independent_db.close()

    # =========================================================================
    # Immutability Enforcement (No Updates or Deletes)
    # =========================================================================

    def update_event(self, *args, **kwargs) -> None:
        """Explicitly forbidden: audit events are cryptographically immutable."""
        raise AuditImmutabilityError("Audit events are immutable and cannot be updated.")

    def delete_event(self, *args, **kwargs) -> None:
        """Explicitly forbidden: audit events are cryptographically immutable."""
        raise AuditImmutabilityError("Audit events are immutable and cannot be deleted.")

    # =========================================================================
    # Query Operations (Read-Only)
    # =========================================================================

    def get_event(self, event_id: str) -> Optional[AuditEventRead]:
        """Retrieve a single audit event by primary key UUID."""
        model = self.db.query(AuditEventModel).filter(AuditEventModel.id == event_id).first()
        if not model:
            return None
        return AuditEventRead.model_validate(model)

    def list_events(
        self,
        project_id: Optional[str] = None,
        skip: int = 0,
        limit: int = 100,
    ) -> List[AuditEventRead]:
        """List audit events ordered by creation time / sequence."""
        query = self.db.query(AuditEventModel)
        if project_id:
            query = query.filter(AuditEventModel.project_id == project_id)
        query = query.order_by(AuditEventModel.sequence_number.asc()).offset(skip).limit(limit)
        return [AuditEventRead.model_validate(m) for m in query.all()]

    def get_chain(self, project_id: str) -> List[AuditEventRead]:
        """Retrieve the complete, ordered audit chain for a project."""
        models = (
            self.db.query(AuditEventModel)
            .filter(AuditEventModel.project_id == project_id)
            .order_by(AuditEventModel.sequence_number.asc())
            .all()
        )
        return [AuditEventRead.model_validate(m) for m in models]

    # =========================================================================
    # Cryptographic Verification
    # =========================================================================

    def verify_chain(
        self,
        project_id: str,
        events: Optional[List[Dict[str, Any]]] = None,
    ) -> AuditVerificationResult:
        """Cryptographically verify the audit chain for a project.

        If caller supplies `events`, verifies that specific array;
        otherwise loads the project's persistent audit events from SQLite.
        """
        if events is not None:
            return verify_audit_chain(events, expected_project_id=project_id)

        # Load persisted chain from database
        models = (
            self.db.query(AuditEventModel)
            .filter(AuditEventModel.project_id == project_id)
            .order_by(AuditEventModel.sequence_number.asc())
            .all()
        )
        return verify_audit_chain(models, expected_project_id=project_id)
