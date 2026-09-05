"""Cryptographically Tamper-Evident Audit Logging Engine for AIVARA (Phase 4.13).

Provides:
  - Controlled security event taxonomy (AuditEventType, AuditOutcome, AuditFailureCode).
  - Strict canonical serialization (RFC 8785) and SHA-256 hashing for audit records.
  - Deterministic project-scoped audit genesis anchor.
  - Audit chain verification and tamper detection distinguishing AUDIT_INTEGRITY_VIOLATION
    from UNVERIFIABLE_INPUT.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Sequence, Union

from pydantic import BaseModel, ConfigDict, Field

from aivara.core.exceptions import AivaraException
from aivara.crypto.canonical import (
    CANONICAL_SCHEMA_VERSION,
    CanonicalizationError,
    canonicalize,
    format_canonical_datetime,
    validate_canonical_data,
)
from aivara.crypto.hashing import is_valid_sha256, secure_compare_hashes, sha256_bytes


# =====================================================================
# Constants & Defaults
# =====================================================================

AUDIT_SCHEMA_VERSION: str = CANONICAL_SCHEMA_VERSION
AUDIT_GENESIS_SEQUENCE: int = 0
AUDIT_GENESIS_PREVIOUS_HASH: str = "0" * 64
AUDIT_GENESIS_EVENT_TYPE: str = "AUDIT_GENESIS"
AUDIT_GENESIS_ACTOR: str = "AIVARA_SYSTEM"
AUDIT_GENESIS_ACTION: str = "INITIALIZE_AUDIT_CHAIN"
AUDIT_GENESIS_TARGET_TYPE: str = "AUDIT_CHAIN"
AUDIT_GENESIS_OUTCOME: str = "SUCCESS"
AUDIT_GENESIS_DESCRIPTION: str = "Deterministic audit chain genesis record initialized."
AUDIT_GENESIS_TIMESTAMP: str = "1970-01-01T00:00:00Z"
AUDIT_GENESIS_METADATA: Dict[str, Any] = {"audit_genesis": True}


# =====================================================================
# Taxonomy Enums
# =====================================================================


class AuditEventType(str, Enum):
    """Controlled taxonomy of security-relevant audit events."""

    AUDIT_GENESIS = "AUDIT_GENESIS"
    PROVENANCE_RECORDED = "PROVENANCE_RECORDED"
    PROVENANCE_REPLAY_REJECTED = "PROVENANCE_REPLAY_REJECTED"
    PROVENANCE_VERIFICATION = "PROVENANCE_VERIFICATION"
    TAMPER_ASSESSMENT = "TAMPER_ASSESSMENT"
    CHAIN_VERIFICATION = "CHAIN_VERIFICATION"
    AUTHENTICITY_UNAVAILABLE = "AUTHENTICITY_UNAVAILABLE"
    SECURITY_CONFIG_CHANGED = "SECURITY_CONFIG_CHANGED"


class AuditOutcome(str, Enum):
    """Objective outcome of an audited operation."""

    SUCCESS = "SUCCESS"
    REJECTED = "REJECTED"
    FAILURE = "FAILURE"
    WARNING = "WARNING"


class AuditFailureCode(str, Enum):
    """Deterministic failure codes for audit chain verification."""

    EVENT_HASH_MISMATCH = "EVENT_HASH_MISMATCH"
    BROKEN_AUDIT_CHAIN = "BROKEN_AUDIT_CHAIN"
    INVALID_AUDIT_SEQUENCE = "INVALID_AUDIT_SEQUENCE"
    SEQUENCE_GAP = "SEQUENCE_GAP"
    DUPLICATE_AUDIT_SEQUENCE = "DUPLICATE_AUDIT_SEQUENCE"
    DUPLICATE_AUDIT_HASH = "DUPLICATE_AUDIT_HASH"
    GENESIS_TAMPERING = "GENESIS_TAMPERING"
    MALFORMED_AUDIT_INPUT = "MALFORMED_AUDIT_INPUT"
    PROJECT_MISMATCH = "PROJECT_MISMATCH"


class AuditVerificationStatus(str, Enum):
    """High-level classification of audit verification results."""

    VALID = "VALID"
    AUDIT_INTEGRITY_VIOLATION = "AUDIT_INTEGRITY_VIOLATION"
    UNVERIFIABLE_INPUT = "UNVERIFIABLE_INPUT"


# Failure codes that establish deterministic cryptographic tampering
AUDIT_INTEGRITY_VIOLATION_CODES = {
    AuditFailureCode.EVENT_HASH_MISMATCH,
    AuditFailureCode.BROKEN_AUDIT_CHAIN,
    AuditFailureCode.SEQUENCE_GAP,
    AuditFailureCode.DUPLICATE_AUDIT_SEQUENCE,
    AuditFailureCode.DUPLICATE_AUDIT_HASH,
    AuditFailureCode.GENESIS_TAMPERING,
    AuditFailureCode.PROJECT_MISMATCH,
}


# =====================================================================
# Canonical Serialization & Hashing
# =====================================================================


def canonicalize_audit_payload(
    *,
    project_id: str,
    event_type: str,
    actor: str,
    action: Optional[str] = None,
    target_type: Optional[str] = None,
    target_id: Optional[str] = None,
    outcome: Optional[str] = "SUCCESS",
    description: Optional[str] = None,
    sequence_number: int,
    previous_event_hash: Optional[str] = None,
    timestamp: Union[str, datetime],
    metadata: Optional[Dict[str, Any]] = None,
    schema_version: str = AUDIT_SCHEMA_VERSION,
) -> bytes:
    """Canonicalize an explicit audit payload according to RFC 8785 (JCS).

    Binds strictly and exclusively the 13 defined protected audit fields:
      - project_id
      - event_type
      - actor
      - action
      - target_type
      - target_id
      - outcome
      - description
      - sequence_number
      - previous_event_hash
      - timestamp
      - metadata
      - schema_version

    No arbitrary ORM attributes, __dict__, or dynamic fields may enter.
    Null fields are explicitly retained as null.
    """
    if schema_version != AUDIT_SCHEMA_VERSION:
        raise ValueError(f"Unsupported audit schema version '{schema_version}'.")

    if not project_id or not isinstance(project_id, str):
        raise ValueError("project_id must be a non-empty string.")
    if not event_type or not isinstance(event_type, str):
        raise ValueError("event_type must be a non-empty string.")
    if not actor or not isinstance(actor, str):
        raise ValueError("actor must be a non-empty string.")
    if not isinstance(sequence_number, int) or sequence_number < 0:
        raise ValueError(f"sequence_number must be a non-negative integer, got {sequence_number}.")

    # Format timestamp deterministically
    if isinstance(timestamp, datetime):
        ts_str = format_canonical_datetime(timestamp)
    elif isinstance(timestamp, str):
        ts_str = timestamp
    else:
        raise TypeError(f"timestamp must be ISO 8601 string or datetime, got {type(timestamp).__name__}.")

    # Canonicalize metadata dictionary safely
    meta_dict = metadata if metadata is not None else {}
    if not isinstance(meta_dict, dict):
        raise TypeError(f"metadata must be a dictionary, got {type(meta_dict).__name__}.")
    validate_canonical_data(meta_dict)

    # Construct strict dictionary
    payload: Dict[str, Any] = {
        "_schema_version": schema_version,
        "action": action,
        "actor": actor,
        "description": description,
        "event_type": event_type,
        "metadata": meta_dict,
        "outcome": outcome,
        "previous_event_hash": previous_event_hash,
        "project_id": project_id,
        "sequence_number": sequence_number,
        "target_id": target_id,
        "target_type": target_type,
        "timestamp": ts_str,
    }

    validate_canonical_data(payload)
    return canonicalize(payload)


def hash_audit_payload(
    *,
    project_id: str,
    event_type: str,
    actor: str,
    action: Optional[str] = None,
    target_type: Optional[str] = None,
    target_id: Optional[str] = None,
    outcome: Optional[str] = "SUCCESS",
    description: Optional[str] = None,
    sequence_number: int,
    previous_event_hash: Optional[str] = None,
    timestamp: Union[str, datetime],
    metadata: Optional[Dict[str, Any]] = None,
    schema_version: str = AUDIT_SCHEMA_VERSION,
) -> str:
    """Compute the deterministic 64-character lowercase hex SHA-256 digest of an audit payload."""
    canonical_bytes = canonicalize_audit_payload(
        project_id=project_id,
        event_type=event_type,
        actor=actor,
        action=action,
        target_type=target_type,
        target_id=target_id,
        outcome=outcome,
        description=description,
        sequence_number=sequence_number,
        previous_event_hash=previous_event_hash,
        timestamp=timestamp,
        metadata=metadata,
        schema_version=schema_version,
    )
    return sha256_bytes(canonical_bytes)


# =====================================================================
# Deterministic Genesis Factory
# =====================================================================


def compute_audit_genesis_hash(project_id: str) -> str:
    """Deterministically compute the SHA-256 event_hash for a project's audit genesis anchor."""
    return hash_audit_payload(
        project_id=project_id,
        event_type=AUDIT_GENESIS_EVENT_TYPE,
        actor=AUDIT_GENESIS_ACTOR,
        action=AUDIT_GENESIS_ACTION,
        target_type=AUDIT_GENESIS_TARGET_TYPE,
        target_id=project_id,
        outcome=AUDIT_GENESIS_OUTCOME,
        description=AUDIT_GENESIS_DESCRIPTION,
        sequence_number=AUDIT_GENESIS_SEQUENCE,
        previous_event_hash=AUDIT_GENESIS_PREVIOUS_HASH,
        timestamp=AUDIT_GENESIS_TIMESTAMP,
        metadata=AUDIT_GENESIS_METADATA,
        schema_version=AUDIT_SCHEMA_VERSION,
    )


def create_audit_genesis_payload(project_id: str) -> Dict[str, Any]:
    """Return a dictionary representing the deterministic genesis audit event."""
    event_hash = compute_audit_genesis_hash(project_id)
    return {
        "project_id": project_id,
        "event_type": AUDIT_GENESIS_EVENT_TYPE,
        "actor": AUDIT_GENESIS_ACTOR,
        "action": AUDIT_GENESIS_ACTION,
        "target_type": AUDIT_GENESIS_TARGET_TYPE,
        "target_id": project_id,
        "outcome": AUDIT_GENESIS_OUTCOME,
        "description": AUDIT_GENESIS_DESCRIPTION,
        "sequence_number": AUDIT_GENESIS_SEQUENCE,
        "previous_event_hash": AUDIT_GENESIS_PREVIOUS_HASH,
        "event_hash": event_hash,
        "metadata_json": AUDIT_GENESIS_METADATA,
        "created_at": AUDIT_GENESIS_TIMESTAMP,
    }


# =====================================================================
# In-Memory Diagnostic & Verification Models
# =====================================================================


class AuditVerificationFailure(BaseModel):
    """Structured detail for an individual audit verification failure."""

    model_config = ConfigDict(frozen=True)

    code: AuditFailureCode = Field(..., description="Machine-readable failure code")
    message: str = Field(..., description="Human-readable objective diagnostic statement")
    sequence_number: Optional[int] = Field(None, description="Sequence number affected")
    event_id: Optional[str] = Field(None, description="Event ID if available")
    expected: Optional[str] = Field(None, description="Expected cryptographic value")
    observed: Optional[str] = Field(None, description="Observed cryptographic value")


class AuditVerificationResult(BaseModel):
    """Complete cryptographic diagnostic report for an audit chain verification."""

    model_config = ConfigDict(frozen=True)

    valid: bool = Field(..., description="True only if all cryptographic checks pass")
    chain_valid: bool = Field(..., description="True if chain continuity and genesis are intact")
    checked_events: int = Field(default=0, description="Total events verified")
    status: AuditVerificationStatus = Field(..., description="High-level classification")
    failures: List[AuditVerificationFailure] = Field(default_factory=list, description="All detected failures")
    warnings: List[str] = Field(default_factory=list, description="Non-fatal operational warnings")
    project_id: Optional[str] = Field(None, description="Project context verified")


# =====================================================================
# Audit Event & Chain Verification Engine
# =====================================================================


def _extract_event_dict(event: Any) -> Dict[str, Any]:
    """Safely convert ORM model, Pydantic model, or dict into a standard dictionary."""
    if isinstance(event, dict):
        return dict(event)
    elif hasattr(event, "model_dump"):
        return event.model_dump()
    elif hasattr(event, "__dict__"):
        # ORM model: extract known columns without SQLAlchemy internal state
        return {
            "id": getattr(event, "id", None),
            "project_id": getattr(event, "project_id", None),
            "event_type": getattr(event, "event_type", None),
            "actor": getattr(event, "actor", None),
            "action": getattr(event, "action", None),
            "target_type": getattr(event, "target_type", None),
            "target_id": getattr(event, "target_id", None),
            "outcome": getattr(event, "outcome", None),
            "description": getattr(event, "description", None),
            "metadata_json": getattr(event, "metadata_json", None) or {},
            "sequence_number": getattr(event, "sequence_number", None),
            "previous_event_hash": getattr(event, "previous_event_hash", None),
            "event_hash": getattr(event, "event_hash", None),
            "created_at": getattr(event, "created_at", None),
        }
    raise TypeError(f"Cannot extract event dictionary from {type(event).__name__}")


def verify_audit_event(
    event: Any,
    expected_sequence: Optional[int] = None,
    expected_previous_hash: Optional[str] = None,
    expected_project_id: Optional[str] = None,
) -> List[AuditVerificationFailure]:
    """Verify cryptographic integrity of a single audit event record.

    Checks:
      1. Structural presence of required fields.
      2. Project consistency against expected_project_id.
      3. Sequence number matches expected_sequence.
      4. Previous event hash matches expected_previous_hash.
      5. Canonical recomputation of SHA-256 event_hash matches stored event_hash.
    """
    failures: List[AuditVerificationFailure] = []

    try:
        raw = _extract_event_dict(event)
    except Exception as exc:
        failures.append(
            AuditVerificationFailure(
                code=AuditFailureCode.MALFORMED_AUDIT_INPUT,
                message=f"Audit event structure is unparseable: {exc}",
            )
        )
        return failures

    event_id = raw.get("id")
    project_id = raw.get("project_id")
    seq = raw.get("sequence_number")
    stored_hash = raw.get("event_hash")
    prev_hash = raw.get("previous_event_hash")
    ts = raw.get("created_at") or raw.get("timestamp")

    # Format timestamp string if datetime
    if isinstance(ts, datetime):
        ts_str = format_canonical_datetime(ts)
    elif isinstance(ts, str):
        ts_str = ts
    else:
        ts_str = AUDIT_GENESIS_TIMESTAMP

    # 1. Project check
    if expected_project_id is not None and project_id != expected_project_id:
        failures.append(
            AuditVerificationFailure(
                code=AuditFailureCode.PROJECT_MISMATCH,
                message=f"Event project_id '{project_id}' does not match expected '{expected_project_id}'.",
                sequence_number=seq,
                event_id=event_id,
                expected=expected_project_id,
                observed=project_id,
            )
        )

    # 2. Sequence check
    if expected_sequence is not None:
        if seq != expected_sequence:
            failures.append(
                AuditVerificationFailure(
                    code=AuditFailureCode.INVALID_AUDIT_SEQUENCE,
                    message=f"Event sequence {seq} does not match expected sequence {expected_sequence}.",
                    sequence_number=seq,
                    event_id=event_id,
                    expected=str(expected_sequence),
                    observed=str(seq),
                )
            )

    # 3. Previous hash check
    if expected_previous_hash is not None:
        if not prev_hash or not secure_compare_hashes(prev_hash, expected_previous_hash):
            failures.append(
                AuditVerificationFailure(
                    code=AuditFailureCode.BROKEN_AUDIT_CHAIN,
                    message=f"previous_event_hash '{prev_hash}' does not link to preceding event hash '{expected_previous_hash}'.",
                    sequence_number=seq,
                    event_id=event_id,
                    expected=expected_previous_hash,
                    observed=prev_hash,
                )
            )

    # 4. Canonical event hash integrity check
    if not stored_hash or not is_valid_sha256(stored_hash):
        failures.append(
            AuditVerificationFailure(
                code=AuditFailureCode.MALFORMED_AUDIT_INPUT,
                message=f"Stored event_hash '{stored_hash}' is missing or not a valid 64-character SHA-256 hex string.",
                sequence_number=seq,
                event_id=event_id,
                observed=stored_hash,
            )
        )
    else:
        try:
            meta = raw.get("metadata_json") or raw.get("metadata") or {}
            computed_hash = hash_audit_payload(
                project_id=project_id or "",
                event_type=raw.get("event_type", ""),
                actor=raw.get("actor", ""),
                action=raw.get("action"),
                target_type=raw.get("target_type"),
                target_id=raw.get("target_id"),
                outcome=raw.get("outcome", "SUCCESS"),
                description=raw.get("description"),
                sequence_number=seq if isinstance(seq, int) else 0,
                previous_event_hash=prev_hash,
                timestamp=ts_str,
                metadata=meta,
            )
            if not secure_compare_hashes(stored_hash, computed_hash):
                failures.append(
                    AuditVerificationFailure(
                        code=AuditFailureCode.EVENT_HASH_MISMATCH,
                        message=f"Audit event payload discrepancy at sequence {seq}: stored hash does not match computed hash.",
                        sequence_number=seq,
                        event_id=event_id,
                        expected=computed_hash,
                        observed=stored_hash,
                    )
                )
        except Exception as exc:
            failures.append(
                AuditVerificationFailure(
                    code=AuditFailureCode.MALFORMED_AUDIT_INPUT,
                    message=f"Failed to canonicalize audit event payload: {exc}",
                    sequence_number=seq,
                    event_id=event_id,
                )
            )

    return failures


def verify_audit_chain(
    events: Sequence[Any],
    expected_project_id: Optional[str] = None,
) -> AuditVerificationResult:
    """Verify an entire ordered sequence of audit events for a project.

    Verifies:
      1. Non-empty sequence.
      2. Deterministic genesis anchor at sequence 0.
      3. Gapless monotonic sequence numbers (0, 1, 2, 3...).
      4. Continuous previous-event hash linkage (event[N].prev == event[N-1].hash).
      5. Canonical SHA-256 event hash integrity for every event.
      6. No duplicate sequences or duplicate event hashes.

    Distinguishes AUDIT_INTEGRITY_VIOLATION from UNVERIFIABLE_INPUT.
    Preserves all detected failures without masking.
    """
    if not events or len(events) == 0:
        return AuditVerificationResult(
            valid=False,
            chain_valid=False,
            checked_events=0,
            status=AuditVerificationStatus.AUDIT_INTEGRITY_VIOLATION,
            failures=[
                AuditVerificationFailure(
                    code=AuditFailureCode.BROKEN_AUDIT_CHAIN,
                    message="Audit chain is empty: no genesis anchor or events present.",
                )
            ],
            project_id=expected_project_id,
        )

    failures: List[AuditVerificationFailure] = []
    warnings: List[str] = []

    # Extract first event and resolve project context
    try:
        first_raw = _extract_event_dict(events[0])
    except Exception as exc:
        return AuditVerificationResult(
            valid=False,
            chain_valid=False,
            checked_events=0,
            status=AuditVerificationStatus.UNVERIFIABLE_INPUT,
            failures=[
                AuditVerificationFailure(
                    code=AuditFailureCode.MALFORMED_AUDIT_INPUT,
                    message=f"Initial audit event is unparseable: {exc}",
                )
            ],
            project_id=expected_project_id,
        )

    pid = expected_project_id or first_raw.get("project_id")

    seen_sequences: set[int] = set()
    seen_hashes: set[str] = set()
    prev_hash = AUDIT_GENESIS_PREVIOUS_HASH
    checked_count = 0

    for idx, ev in enumerate(events):
        try:
            raw = _extract_event_dict(ev)
        except Exception as exc:
            failures.append(
                AuditVerificationFailure(
                    code=AuditFailureCode.MALFORMED_AUDIT_INPUT,
                    message=f"Event at index {idx} is malformed: {exc}",
                )
            )
            continue

        seq = raw.get("sequence_number")
        e_hash = raw.get("event_hash")
        e_id = raw.get("id")

        # Check required structural presence
        if not raw.get("event_type") or raw.get("previous_event_hash") is None:
            failures.append(
                AuditVerificationFailure(
                    code=AuditFailureCode.MALFORMED_AUDIT_INPUT,
                    message=f"Audit event at index {idx} is missing required fields (event_type or previous_event_hash).",
                    sequence_number=seq,
                    event_id=e_id,
                )
            )
            continue

        # Genesis anchor check at sequence 0
        if idx == 0:
            if seq != AUDIT_GENESIS_SEQUENCE:
                failures.append(
                    AuditVerificationFailure(
                        code=AuditFailureCode.GENESIS_TAMPERING,
                        message=f"Audit chain must start with genesis sequence 0, observed {seq}.",
                        sequence_number=seq,
                        event_id=e_id,
                        expected=str(AUDIT_GENESIS_SEQUENCE),
                        observed=str(seq),
                    )
                )
            if raw.get("previous_event_hash") != AUDIT_GENESIS_PREVIOUS_HASH:
                failures.append(
                    AuditVerificationFailure(
                        code=AuditFailureCode.GENESIS_TAMPERING,
                        message="Genesis previous_event_hash must be 64 zeros.",
                        sequence_number=seq,
                        event_id=e_id,
                        expected=AUDIT_GENESIS_PREVIOUS_HASH,
                        observed=raw.get("previous_event_hash"),
                    )
                )

        # Duplicate sequence detection
        if seq is not None and isinstance(seq, int):
            if seq in seen_sequences:
                failures.append(
                    AuditVerificationFailure(
                        code=AuditFailureCode.DUPLICATE_AUDIT_SEQUENCE,
                        message=f"Duplicate audit sequence number {seq} detected in chain.",
                        sequence_number=seq,
                        event_id=e_id,
                    )
                )
            seen_sequences.add(seq)

            # Monotonic sequence gap check
            if seq != idx:
                failures.append(
                    AuditVerificationFailure(
                        code=AuditFailureCode.SEQUENCE_GAP,
                        message=f"Sequence gap or ordering anomaly at index {idx}: expected sequence {idx}, observed {seq}.",
                        sequence_number=seq,
                        event_id=e_id,
                        expected=str(idx),
                        observed=str(seq),
                    )
                )

        # Duplicate hash detection
        if e_hash:
            if e_hash in seen_hashes:
                failures.append(
                    AuditVerificationFailure(
                        code=AuditFailureCode.DUPLICATE_AUDIT_HASH,
                        message=f"Duplicate audit event_hash '{e_hash}' detected in chain.",
                        sequence_number=seq,
                        event_id=e_id,
                    )
                )
            seen_hashes.add(e_hash)

        # Individual event cryptographic verification
        event_failures = verify_audit_event(
            raw,
            expected_sequence=idx,
            expected_previous_hash=prev_hash,
            expected_project_id=pid,
        )
        failures.extend(event_failures)

        # Next event in chain expects current event's hash
        prev_hash = e_hash if e_hash else prev_hash
        checked_count += 1

    # Determine status
    is_valid = len(failures) == 0
    chain_valid = is_valid

    if is_valid:
        status = AuditVerificationStatus.VALID
    else:
        has_integrity = any(f.code in AUDIT_INTEGRITY_VIOLATION_CODES for f in failures)
        if has_integrity:
            status = AuditVerificationStatus.AUDIT_INTEGRITY_VIOLATION
        else:
            status = AuditVerificationStatus.UNVERIFIABLE_INPUT

    return AuditVerificationResult(
        valid=is_valid,
        chain_valid=chain_valid,
        checked_events=checked_count,
        status=status,
        failures=failures,
        warnings=warnings,
        project_id=pid,
    )
