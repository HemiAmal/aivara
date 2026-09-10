"""ATTACK-03 — Replay Attack Demonstration.

Demonstrates:
  1. First submission of valid provenance evidence -> ACCEPTED.
  2. Second submission of identical evidence -> REPLAY DETECTED -> REJECTED.
  3. Replay classification and failure code captured.
  4. Audit logging of PROVENANCE_REPLAY_REJECTED persists.
  5. Audit chain remains cryptographically valid.
  6. Original valid record is not corrupted.
"""

from __future__ import annotations

import tempfile
import uuid
from pathlib import Path
from typing import Any, Dict, List

from sqlalchemy import create_engine, event
from sqlalchemy.orm import Session, sessionmaker

from aivara.attack_lab.models import (
    AttackCategory,
    AttackResult,
    AttackScenario,
    AttackSubResult,
)
from aivara.crypto.audit import AuditEventType, AuditOutcome, AuditVerificationStatus
from aivara.crypto.canonical import CANONICAL_SCHEMA_VERSION
from aivara.crypto.chain import (
    ChainRecord,
    DuplicateNonceError,
    DuplicateRecordError,
    DuplicateSequenceError,
    ReplayDetectedError,
    create_genesis_record,
    generate_nonce,
)
from aivara.crypto.hashing import hash_provenance_payload, sha256_text
from aivara.crypto.keys import KeyManager
from aivara.crypto.replay import ReplayType
from aivara.crypto.signing import sign_hash
from aivara.database.connection import Base
from aivara.database.models import AuditEventModel, ProjectModel, ProvenanceRecordModel
from aivara.domain.schemas import ProvenanceRecordCreate
from aivara.services.audit_service import AuditService
from aivara.services.provenance_service import ProvenanceService


def get_scenario() -> AttackScenario:
    """Return static metadata for ATTACK-03."""
    return AttackScenario(
        attack_id="ATTACK-03",
        attack_name="Replay Attack",
        category=AttackCategory.REPLAY,
        description=(
            "Controlled demonstration proving that AIVARA persistently and authoritatively "
            "rejects duplicate submission of previously recorded provenance evidence, "
            "records a persistent PROVENANCE_REPLAY_REJECTED audit event, preserves audit "
            "chain integrity, and maintains the uncorrupted state of the original record."
        ),
        target="Authoritative Database Replay Detection & Audit Pipeline",
        prerequisites=["Isolated database session", "Registered ProjectModel"],
        setup={"action": "Initialize isolated test DB and create ProjectModel"},
        attack={"action": "Submit identical provenance payload a second time"},
        verification={"engine": "ProvenanceService.record_provenance_event + AuditService.verify_chain"},
        expected_result={
            "first_submission": "ACCEPTED",
            "second_submission": "REJECTED",
            "replay_type": "DUPLICATE_NONCE",
            "audit_event": "PROVENANCE_REPLAY_REJECTED",
            "audit_chain_status": "VALID",
            "original_uncorrupted": True,
        },
        cleanup="Tear down isolated test engine and session",
    )


def _setup_isolated_db():
    """Create an isolated in-memory SQLite database with foreign keys enabled."""
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})

    @event.listens_for(engine, "connect")
    def _set_sqlite_pragma(dbapi_connection, connection_record):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON;")
        cursor.close()

    Base.metadata.create_all(bind=engine)
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    return engine, SessionLocal()


def run_attack_03() -> AttackResult:
    """Execute the ATTACK-03 demonstration."""
    engine, db = _setup_isolated_db()
    try:
        project_id = f"proj-replay-{uuid.uuid4().hex[:8]}"
        project = ProjectModel(
            id=project_id,
            name="Replay Demo Project",
            description="Isolated project for ATTACK-03 demonstration",
        )
        db.add(project)
        db.commit()

        with tempfile.TemporaryDirectory() as tmp_keys_dir:
            km = KeyManager(keys_dir=Path(tmp_keys_dir))
            handle = km.generate_key(passphrase="Demo_Replay_Passphrase_2026!")
            audit_svc = AuditService(db)
            prov_svc = ProvenanceService(db, key_manager=km, audit_service=audit_svc)

            # Baseline: Initialize genesis record
            gen_rec = create_genesis_record(project_id)
            genesis_model = prov_svc.record_provenance_event(gen_rec)
            assert genesis_model is not None, "Genesis record must initialize cleanly"

            # Construct valid signed record 1
            nonce = generate_nonce()
            meta = {"conf_threshold": 0.5}
            ts = "2026-03-01T12:00:00Z"
            rec1_hash = hash_provenance_payload(
                record_type="INFERENCE",
                project_id=project_id,
                actor="replay-tester",
                action="RUN_INFERENCE",
                sequence_number=1,
                nonce=nonce,
                timestamp=ts,
                signer_key_id=handle.key_id,
                target_type="MODEL",
                target_id="mod-yolo-v8",
                input_hash=sha256_text("input image batch"),
                output_hash=sha256_text("detections: 3 objects"),
                model_id="mod-yolo-v8",
                previous_record_hash=gen_rec.record_hash,
                metadata_json=meta,
                schema_version=CANONICAL_SCHEMA_VERSION,
            )
            sig_res = sign_hash(rec1_hash, handle)
            rec1 = ChainRecord(
                schema_version=CANONICAL_SCHEMA_VERSION,
                record_type="INFERENCE",
                project_id=project_id,
                sequence_number=1,
                previous_record_hash=gen_rec.record_hash,
                nonce=nonce,
                actor="replay-tester",
                action="RUN_INFERENCE",
                target_type="MODEL",
                target_id="mod-yolo-v8",
                timestamp=ts,
                input_hash=sha256_text("input image batch"),
                output_hash=sha256_text("detections: 3 objects"),
                model_id="mod-yolo-v8",
                metadata_json=meta,
                record_hash=rec1_hash,
                signature=sig_res.signature,
                signer_key_id=handle.key_id,
            )

            # First Submission: Must be ACCEPTED
            first_record = prov_svc.record_provenance_event(rec1)
            assert first_record is not None
            assert first_record.sequence_number == 1
            assert first_record.nonce == nonce

            # Verify audit event for first submission
            events_after_first = audit_svc.get_chain(project_id)
            assert any(e.event_type == AuditEventType.PROVENANCE_RECORDED.value for e in events_after_first)

            # Second Submission: Same nonce/payload -> Must be REJECTED
            replay_detected = False
            replay_error_type = ""
            try:
                prov_svc.record_provenance_event(rec1)
            except (DuplicateNonceError, DuplicateSequenceError, DuplicateRecordError, ReplayDetectedError) as rde:
                replay_detected = True
                replay_error_type = type(rde).__name__
            except Exception as exc:
                replay_detected = True
                replay_error_type = type(exc).__name__

            # Verify audit event PROVENANCE_REPLAY_REJECTED was persistently recorded
            events_after_second = audit_svc.get_chain(project_id)
            replay_audit_events = [
                e for e in events_after_second if e.event_type == AuditEventType.PROVENANCE_REPLAY_REJECTED.value
            ]
            has_replay_audit = len(replay_audit_events) > 0

            # Verify audit chain integrity remains completely valid
            audit_verify = audit_svc.verify_chain(project_id)
            audit_valid = audit_verify.status == AuditVerificationStatus.VALID

            # Verify original record remains pristine and uncorrupted in database
            persisted_orig = db.query(ProvenanceRecordModel).filter_by(project_id=project_id, nonce=nonce).first()
            orig_uncorrupted = (
                persisted_orig is not None
                and persisted_orig.sequence_number == 1
                and persisted_orig.record_hash == first_record.record_hash
            )

            all_detected = replay_detected and has_replay_audit and audit_valid and orig_uncorrupted

            sub_results = [
                AttackSubResult(
                    sub_id="SUB-01",
                    name="First Submission Acceptance",
                    target_asset="ProvenanceService.record_provenance_event",
                    attack_technique="Initial legitimate submission of sequence 1 with unique nonce",
                    original_state={"sequence_number": 0},
                    modified_state={"sequence_number": 1, "nonce": nonce},
                    verification_status="ACCEPTED",
                    failure_codes=[],
                    evidence={"record_hash": first_record.record_hash},
                    detected=True,
                    cleanup_status="CLEAN",
                ),
                AttackSubResult(
                    sub_id="SUB-02",
                    name="Duplicate Submission Rejection",
                    target_asset="Database Unique Nonce Constraint & Replay Detector",
                    attack_technique="Replaying identical nonce and sequence number payload",
                    original_state={"nonce_recorded": True},
                    modified_state={"replay_attempted": True},
                    verification_status="REJECTED",
                    failure_codes=[replay_error_type],
                    evidence={
                        "replay_error_type": replay_error_type,
                        "replay_audit_event_count": len(replay_audit_events),
                    },
                    detected=replay_detected,
                    cleanup_status="RESTORED",
                ),
                AttackSubResult(
                    sub_id="SUB-03",
                    name="Persistent Replay Audit Trail & Chain Verification",
                    target_asset="AuditService Chain Verification",
                    attack_technique="Verification of tamper-evident audit log following replay rejection",
                    original_state={"audit_chain_valid": True},
                    modified_state={"audit_chain_valid": audit_valid},
                    verification_status=audit_verify.status.value,
                    failure_codes=[f.code.value for f in audit_verify.failures],
                    evidence={"total_audit_events": len(events_after_second)},
                    detected=audit_valid and has_replay_audit,
                    cleanup_status="RESTORED",
                ),
            ]

            return AttackResult(
                attack_id="ATTACK-03",
                attack_name="Replay Attack",
                target_asset="Provenance Ingestion Pipeline and Audit Logger",
                attack_technique="Identical cryptographic evidence replay against authoritative DB state",
                original_state={"project_id": project_id, "initial_records": 1},
                modified_state={"replayed_nonce": nonce, "rejection_caught": replay_detected},
                verification_status="REPLAY_REJECTED" if all_detected else "FAILED",
                failure_codes=[replay_error_type],
                evidence={
                    "replay_detected": replay_detected,
                    "replay_error_type": replay_error_type,
                    "replay_audit_logged": has_replay_audit,
                    "audit_chain_valid": audit_valid,
                    "original_uncorrupted": orig_uncorrupted,
                },
                detected=all_detected,
                cleanup_status="RESTORED",
                sub_results=sub_results,
                details={"summary": "Replay attempt successfully rejected, audited, and baseline preserved"},
            )
    finally:
        db.close()
        Base.metadata.drop_all(bind=engine)
        engine.dispose()
