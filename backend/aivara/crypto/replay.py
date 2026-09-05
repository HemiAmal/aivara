"""Persistent Replay Detection Domain Model and Classification Engine (Phase 4.11).

Provides:
  - Structured ReplayAssessment model.
  - ReplayType enumeration aligned with established failure taxonomy.
  - Replay classification and translation of database IntegrityErrors.
  - Clean separation between replay (submission of previously accepted valid events)
    and tampering (cryptographic integrity violations).
"""

from __future__ import annotations

import re
from enum import Enum
from typing import Any, Optional, Tuple, Union

from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from aivara.crypto.chain import (
    DuplicateNonceError,
    DuplicateRecordError,
    DuplicateSequenceError,
    ReplayDetectedError,
)


class ReplayType(str, Enum):
    """Taxonomy of replay detection classifications."""

    NONE = "NONE"
    DUPLICATE_NONCE = "DUPLICATE_NONCE"
    DUPLICATE_SEQUENCE = "DUPLICATE_SEQUENCE"
    DUPLICATE_RECORD = "DUPLICATE_RECORD"
    REPLAY_DETECTED = "REPLAY_DETECTED"


class ReplayAssessment(BaseModel):
    """Structured, safe diagnostic assessment of a replay detection check.

    Contains no secrets or private key material.
    """

    model_config = ConfigDict(frozen=True)

    replay_detected: bool = Field(..., description="Whether a replay condition was detected")
    replay_type: ReplayType = Field(default=ReplayType.NONE, description="Specific replay classification")
    project_id: Optional[str] = Field(None, description="Project identifier")
    sequence_number: Optional[int] = Field(None, description="Conflicting sequence number if applicable")
    nonce: Optional[str] = Field(None, description="Conflicting nonce if applicable")
    record_hash: Optional[str] = Field(None, description="Conflicting record hash if applicable")
    conflicting_record_id: Optional[str] = Field(
        None, description="Identifier of the conflicting existing record, if safely available"
    )
    reason: Optional[str] = Field(None, description="Human-readable explanation of the assessment")


def classify_integrity_error(
    exc: IntegrityError,
    project_id: Optional[str] = None,
    sequence_number: Optional[int] = None,
    nonce: Optional[str] = None,
    record_hash: Optional[str] = None,
    db: Optional[Session] = None,
) -> Tuple[bool, ReplayType, str, Optional[str]]:
    """Analyze a database IntegrityError to determine if it is a provenance replay condition.

    Distinguishes unique constraint violations (replay) on (project_id, sequence),
    (project_id, nonce), or (project_id, record_hash) from unrelated database errors
    (e.g., foreign key violations, NOT NULL violations).

    Args:
        exc: The caught SQLAlchemy IntegrityError.
        project_id: Target project ID.
        sequence_number: Sequence number being inserted.
        nonce: Nonce being inserted.
        record_hash: Record hash being inserted.
        db: Optional active DB session to inspect existing rows.

    Returns:
        Tuple of:
          - is_replay (bool): True if error represents a replay.
          - replay_type (ReplayType): Classified duplicate category.
          - reason (str): Human-readable diagnosis.
          - conflicting_id (Optional[str]): ID of conflicting row if found.
    """
    orig_msg = str(getattr(exc, "orig", exc)).lower()

    # Foreign key violations are NOT replay conditions
    if "foreign key" in orig_msg:
        return (
            False,
            ReplayType.NONE,
            f"Database foreign key constraint violation: {exc}",
            None,
        )

    # Check for NOT NULL violations
    if "not null" in orig_msg:
        return (
            False,
            ReplayType.NONE,
            f"Database NOT NULL constraint violation: {exc}",
            None,
        )

    # 1. Inspect error string for direct column or index clues
    # Check sequence conflict
    if "sequence" in orig_msg:
        conflicting_id = None
        if db is not None and project_id is not None and sequence_number is not None:
            conflicting_id = _lookup_conflicting_id(db, project_id=project_id, sequence_number=sequence_number)
        return (
            True,
            ReplayType.DUPLICATE_SEQUENCE,
            f"Replay detected: sequence number {sequence_number} already exists in project '{project_id}'.",
            conflicting_id,
        )

    # Check nonce conflict
    if "nonce" in orig_msg:
        conflicting_id = None
        if db is not None and project_id is not None and nonce is not None:
            conflicting_id = _lookup_conflicting_id(db, project_id=project_id, nonce=nonce)
        return (
            True,
            ReplayType.DUPLICATE_NONCE,
            f"Replay detected: duplicate nonce '{nonce}' already accepted in project '{project_id}'.",
            conflicting_id,
        )

    # Check record_hash conflict
    if "record_hash" in orig_msg:
        conflicting_id = None
        if db is not None and project_id is not None and record_hash is not None:
            conflicting_id = _lookup_conflicting_id(db, project_id=project_id, record_hash=record_hash)
        return (
            True,
            ReplayType.DUPLICATE_RECORD,
            f"Replay detected: duplicate record hash '{record_hash}' already exists in project '{project_id}'.",
            conflicting_id,
        )

    # 2. If SQLite generic "UNIQUE constraint failed", use secondary DB lookup or parameters
    if "unique" in orig_msg:
        if db is not None and project_id is not None:
            # Check nonce first
            if nonce is not None:
                cid = _lookup_conflicting_id(db, project_id=project_id, nonce=nonce)
                if cid:
                    return (
                        True,
                        ReplayType.DUPLICATE_NONCE,
                        f"Replay detected: duplicate nonce '{nonce}' in project '{project_id}'.",
                        cid,
                    )
            # Check sequence
            if sequence_number is not None:
                cid = _lookup_conflicting_id(db, project_id=project_id, sequence_number=sequence_number)
                if cid:
                    return (
                        True,
                        ReplayType.DUPLICATE_SEQUENCE,
                        f"Replay detected: duplicate sequence {sequence_number} in project '{project_id}'.",
                        cid,
                    )
            # Check record hash
            if record_hash is not None:
                cid = _lookup_conflicting_id(db, project_id=project_id, record_hash=record_hash)
                if cid:
                    return (
                        True,
                        ReplayType.DUPLICATE_RECORD,
                        f"Replay detected: duplicate record hash '{record_hash}' in project '{project_id}'.",
                        cid,
                    )

        # Fallback generic unique replay
        return (
            True,
            ReplayType.REPLAY_DETECTED,
            f"Replay detected: unique constraint violation on provenance record for project '{project_id}'.",
            None,
        )

    # Unrecognized database integrity error
    return (
        False,
        ReplayType.NONE,
        f"Database integrity error: {exc}",
        None,
    )


def _lookup_conflicting_id(
    db: Session,
    project_id: str,
    sequence_number: Optional[int] = None,
    nonce: Optional[str] = None,
    record_hash: Optional[str] = None,
) -> Optional[str]:
    """Safely query conflicting record ID without throwing exceptions."""
    try:
        from aivara.database.models import ProvenanceRecordModel

        query = db.query(ProvenanceRecordModel.id).filter(
            ProvenanceRecordModel.project_id == project_id
        )
        if nonce is not None:
            query = query.filter(ProvenanceRecordModel.nonce == nonce)
        elif sequence_number is not None:
            query = query.filter(ProvenanceRecordModel.sequence_number == sequence_number)
        elif record_hash is not None:
            query = query.filter(ProvenanceRecordModel.record_hash == record_hash)
        else:
            return None

        result = query.first()
        return str(result[0]) if result else None
    except Exception:
        return None


def raise_replay_error(assessment: ReplayAssessment) -> None:
    """Raise the appropriate structured exception corresponding to a ReplayAssessment.

    Args:
        assessment: ReplayAssessment containing diagnostic details.

    Raises:
        DuplicateNonceError: For DUPLICATE_NONCE.
        DuplicateSequenceError: For DUPLICATE_SEQUENCE.
        DuplicateRecordError: For DUPLICATE_RECORD.
        ReplayDetectedError: For other/generic REPLAY_DETECTED.
    """
    msg = assessment.reason or "Replay detected."
    details = assessment.model_dump()

    if assessment.replay_type == ReplayType.DUPLICATE_NONCE:
        raise DuplicateNonceError(msg, details=details)
    elif assessment.replay_type == ReplayType.DUPLICATE_SEQUENCE:
        raise DuplicateSequenceError(msg, details=details)
    elif assessment.replay_type == ReplayType.DUPLICATE_RECORD:
        raise DuplicateRecordError(msg, details=details)
    else:
        raise ReplayDetectedError(msg, details=details)
