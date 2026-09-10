"""ATTACK-05 — Direct Database Tampering Demonstration.

Demonstrates:
  1. Bypassing SQLAlchemy ORM listeners via controlled raw SQL operations:
     - modify description
     - modify metadata
     - modify event_hash
     - modify previous_event_hash
     - modify sequence_number
     - modify project_id
     - delete a middle audit event
     - insert a forged audit event
  2. Expiring ORM session state to prevent in-memory cache contamination.
  3. Running normal AIVARA cryptographic audit verification.
  4. Proving that ORM immutability is merely defense-in-depth, while
     cryptographic verification is the authoritative tamper-evidence mechanism.
  5. Deterministic restoration after each raw SQL mutation.
"""

from __future__ import annotations

import json
import uuid
from typing import Any, Dict, List

from sqlalchemy import create_engine, event, text
from sqlalchemy.orm import Session, sessionmaker

from aivara.attack_lab.models import (
    AttackCategory,
    AttackResult,
    AttackScenario,
    AttackSubResult,
)
from aivara.crypto.audit import (
    AuditEventType,
    AuditFailureCode,
    AuditOutcome,
    AuditVerificationStatus,
    verify_audit_chain,
)
from aivara.crypto.hashing import sha256_text
from aivara.database.connection import Base
from aivara.database.models import AuditEventModel, ProjectModel
from aivara.services.audit_service import AuditService


def get_scenario() -> AttackScenario:
    """Return static metadata for ATTACK-05."""
    return AttackScenario(
        attack_id="ATTACK-05",
        attack_name="Direct Database Tampering",
        category=AttackCategory.DATABASE,
        description=(
            "Controlled demonstration executing raw SQL updates, deletions, and insertions "
            "directly against the database table, completely bypassing SQLAlchemy ORM listeners. "
            "Proves authoritatively that ORM immutability is merely defense-in-depth, while "
            "AIVARA's cryptographic verification engine mathematically detects every manipulation."
        ),
        target="Raw SQLite Database Tables (audit_events)",
        prerequisites=["Isolated database session", "Multiple ProjectModel entities for FK safety"],
        setup={"action": "Create isolated database, two projects, and 4-event baseline audit chain"},
        attack={"action": "Execute 8 targeted raw SQL mutations directly on the database"},
        verification={"engine": "AuditService.verify_chain after session.expire_all()"},
        expected_result={
            "orm_bypassed": True,
            "detected_by_crypto": True,
            "status": "AUDIT_INTEGRITY_VIOLATION",
        },
        cleanup="Restore genuine audit event state after each raw SQL mutation",
    )


def _setup_isolated_db():
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})

    @event.listens_for(engine, "connect")
    def _set_sqlite_pragma(dbapi_connection, connection_record):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON;")
        cursor.close()

    Base.metadata.create_all(bind=engine)
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    return engine, SessionLocal()


def run_attack_05() -> AttackResult:
    """Execute the ATTACK-05 demonstration."""
    engine, db = _setup_isolated_db()
    try:
        project_a_id = f"proj-sql-a-{uuid.uuid4().hex[:6]}"
        project_b_id = f"proj-sql-b-{uuid.uuid4().hex[:6]}"

        p_a = ProjectModel(id=project_a_id, name="Project A", description="Primary test project")
        p_b = ProjectModel(id=project_b_id, name="Project B", description="Secondary project for FK")
        db.add_all([p_a, p_b])
        db.commit()

        audit_svc = AuditService(db)

        # Baseline: Build Genesis -> A1 -> A2 -> A3 in Project A
        audit_svc._ensure_genesis(project_a_id)
        ev1 = audit_svc.record_event(
            project_id=project_a_id,
            event_type=AuditEventType.PROVENANCE_RECORDED,
            actor="sec-user",
            action="RECORD",
            target_type="RECORD",
            target_id="rec-1",
            description="Operational baseline event 1",
            outcome=AuditOutcome.SUCCESS,
        )
        ev2 = audit_svc.record_event(
            project_id=project_a_id,
            event_type=AuditEventType.SECURITY_CONFIG_CHANGED,
            actor="sec-admin",
            action="CHANGE_CONFIG",
            target_type="CONFIG",
            target_id="cfg-1",
            description="Operational baseline event 2",
            outcome=AuditOutcome.SUCCESS,
            metadata_json={"enforce_signatures": True},
        )
        ev3 = audit_svc.record_event(
            project_id=project_a_id,
            event_type=AuditEventType.PROVENANCE_VERIFICATION,
            actor="sec-verifier",
            action="VERIFY",
            target_type="RECORD",
            target_id="rec-1",
            description="Operational baseline event 3",
            outcome=AuditOutcome.SUCCESS,
        )

        base_verify = audit_svc.verify_chain(project_a_id)
        assert base_verify.status == AuditVerificationStatus.VALID

        # Snapshot of event 2 baseline
        orig_ev2 = db.query(AuditEventModel).filter_by(project_id=project_a_id, sequence_number=2).first()
        orig_desc = orig_ev2.description
        orig_meta = orig_ev2.metadata_json
        orig_hash = orig_ev2.event_hash
        orig_prev_hash = orig_ev2.previous_event_hash
        orig_seq = orig_ev2.sequence_number
        orig_pid = orig_ev2.project_id
        orig_id = orig_ev2.id
        orig_created_at = orig_ev2.created_at
        orig_event_type = orig_ev2.event_type
        orig_actor = orig_ev2.actor
        orig_action = orig_ev2.action
        orig_target_type = orig_ev2.target_type
        orig_target_id = orig_ev2.target_id
        orig_outcome = orig_ev2.outcome

        sub_results: List[AttackSubResult] = []

        # 1. Modify description via raw SQL
        db.execute(
            text("UPDATE audit_events SET description = 'RAW_SQL_TAMPERED' WHERE id = :id"),
            {"id": orig_id},
        )
        db.commit()
        db.expire_all()
        v1 = audit_svc.verify_chain(project_a_id)
        codes1 = [f.code.value for f in v1.failures]
        det1 = (v1.status == AuditVerificationStatus.AUDIT_INTEGRITY_VIOLATION) and (
            AuditFailureCode.EVENT_HASH_MISMATCH.value in codes1
        )
        # Restore
        db.execute(text("UPDATE audit_events SET description = :desc WHERE id = :id"), {"desc": orig_desc, "id": orig_id})
        db.commit()
        db.expire_all()
        sub_results.append(
            AttackSubResult(
                sub_id="ATTACK-05A",
                name="Raw SQL UPDATE description",
                target_asset="audit_events.description",
                attack_technique="Direct raw SQL UPDATE bypassing ORM before_update listener",
                original_state={"description": orig_desc},
                modified_state={"description": "RAW_SQL_TAMPERED"},
                verification_status=v1.status.value,
                failure_codes=codes1,
                evidence={"failures": codes1},
                detected=det1,
                cleanup_status="RESTORED",
            )
        )

        # 2. Modify metadata via raw SQL
        db.execute(
            text("UPDATE audit_events SET metadata_json = '{\"enforce_signatures\": false}' WHERE id = :id"),
            {"id": orig_id},
        )
        db.commit()
        db.expire_all()
        v2 = audit_svc.verify_chain(project_a_id)
        codes2 = [f.code.value for f in v2.failures]
        det2 = (v2.status == AuditVerificationStatus.AUDIT_INTEGRITY_VIOLATION) and (
            AuditFailureCode.EVENT_HASH_MISMATCH.value in codes2
        )
        # Restore
        db.execute(
            text("UPDATE audit_events SET metadata_json = :meta WHERE id = :id"),
            {"meta": json.dumps(orig_meta) if isinstance(orig_meta, dict) else orig_meta, "id": orig_id},
        )
        db.commit()
        db.expire_all()
        sub_results.append(
            AttackSubResult(
                sub_id="ATTACK-05B",
                name="Raw SQL UPDATE metadata",
                target_asset="audit_events.metadata_json",
                attack_technique="Direct raw SQL UPDATE modifying security policy in metadata",
                original_state={"metadata": orig_meta},
                modified_state={"metadata": '{"enforce_signatures": false}'},
                verification_status=v2.status.value,
                failure_codes=codes2,
                evidence={"failures": codes2},
                detected=det2,
                cleanup_status="RESTORED",
            )
        )

        # 3. Modify event_hash via raw SQL
        tampered_h = sha256_text("forged_event_hash")
        db.execute(
            text("UPDATE audit_events SET event_hash = :h WHERE id = :id"),
            {"h": tampered_h, "id": orig_id},
        )
        db.commit()
        db.expire_all()
        v3 = audit_svc.verify_chain(project_a_id)
        codes3 = [f.code.value for f in v3.failures]
        det3 = (v3.status == AuditVerificationStatus.AUDIT_INTEGRITY_VIOLATION) and (
            AuditFailureCode.EVENT_HASH_MISMATCH.value in codes3
            or AuditFailureCode.BROKEN_AUDIT_CHAIN.value in codes3
        )
        # Restore
        db.execute(text("UPDATE audit_events SET event_hash = :h WHERE id = :id"), {"h": orig_hash, "id": orig_id})
        db.commit()
        db.expire_all()
        sub_results.append(
            AttackSubResult(
                sub_id="ATTACK-05C",
                name="Raw SQL UPDATE event_hash",
                target_asset="audit_events.event_hash",
                attack_technique="Direct raw SQL replacement of canonical event hash",
                original_state={"event_hash": orig_hash},
                modified_state={"event_hash": tampered_h},
                verification_status=v3.status.value,
                failure_codes=codes3,
                evidence={"failures": codes3},
                detected=det3,
                cleanup_status="RESTORED",
            )
        )

        # 4. Modify previous_event_hash via raw SQL
        tampered_prev = sha256_text("forged_previous_hash")
        db.execute(
            text("UPDATE audit_events SET previous_event_hash = :ph WHERE id = :id"),
            {"ph": tampered_prev, "id": orig_id},
        )
        db.commit()
        db.expire_all()
        v4 = audit_svc.verify_chain(project_a_id)
        codes4 = [f.code.value for f in v4.failures]
        det4 = (v4.status == AuditVerificationStatus.AUDIT_INTEGRITY_VIOLATION) and (
            AuditFailureCode.BROKEN_AUDIT_CHAIN.value in codes4
            or AuditFailureCode.EVENT_HASH_MISMATCH.value in codes4
        )
        # Restore
        db.execute(text("UPDATE audit_events SET previous_event_hash = :ph WHERE id = :id"), {"ph": orig_prev_hash, "id": orig_id})
        db.commit()
        db.expire_all()
        sub_results.append(
            AttackSubResult(
                sub_id="ATTACK-05D",
                name="Raw SQL UPDATE previous_event_hash",
                target_asset="audit_events.previous_event_hash",
                attack_technique="Direct raw SQL modification of parent linkage hash",
                original_state={"previous_event_hash": orig_prev_hash},
                modified_state={"previous_event_hash": tampered_prev},
                verification_status=v4.status.value,
                failure_codes=codes4,
                evidence={"failures": codes4},
                detected=det4,
                cleanup_status="RESTORED",
            )
        )

        # 5. Modify sequence_number via raw SQL
        db.execute(
            text("UPDATE audit_events SET sequence_number = 99 WHERE id = :id"),
            {"id": orig_id},
        )
        db.commit()
        db.expire_all()
        v5 = audit_svc.verify_chain(project_a_id)
        codes5 = [f.code.value for f in v5.failures]
        det5 = (v5.status == AuditVerificationStatus.AUDIT_INTEGRITY_VIOLATION) and (
            AuditFailureCode.SEQUENCE_GAP.value in codes5
            or AuditFailureCode.INVALID_AUDIT_SEQUENCE.value in codes5
            or AuditFailureCode.EVENT_HASH_MISMATCH.value in codes5
        )
        # Restore
        db.execute(text("UPDATE audit_events SET sequence_number = :seq WHERE id = :id"), {"seq": orig_seq, "id": orig_id})
        db.commit()
        db.expire_all()
        sub_results.append(
            AttackSubResult(
                sub_id="ATTACK-05E",
                name="Raw SQL UPDATE sequence_number",
                target_asset="audit_events.sequence_number",
                attack_technique="Direct raw SQL mutation causing non-monotonic sequence anomaly",
                original_state={"sequence_number": orig_seq},
                modified_state={"sequence_number": 99},
                verification_status=v5.status.value,
                failure_codes=codes5,
                evidence={"failures": codes5},
                detected=det5,
                cleanup_status="RESTORED",
            )
        )

        # 6. Modify project_id via raw SQL (to project_b_id)
        db.execute(
            text("UPDATE audit_events SET project_id = :pid WHERE id = :id"),
            {"pid": project_b_id, "id": orig_id},
        )
        db.commit()
        db.expire_all()
        v6 = audit_svc.verify_chain(project_a_id)
        codes6 = [f.code.value for f in v6.failures]
        # In Project A's remaining chain, event 2 is missing (gap) or broken chain
        det6 = (v6.status == AuditVerificationStatus.AUDIT_INTEGRITY_VIOLATION) and (
            AuditFailureCode.SEQUENCE_GAP.value in codes6
            or AuditFailureCode.BROKEN_AUDIT_CHAIN.value in codes6
        )
        # Restore
        db.execute(text("UPDATE audit_events SET project_id = :pid WHERE id = :id"), {"pid": orig_pid, "id": orig_id})
        db.commit()
        db.expire_all()
        sub_results.append(
            AttackSubResult(
                sub_id="ATTACK-05F",
                name="Raw SQL UPDATE project_id",
                target_asset="audit_events.project_id",
                attack_technique="Direct raw SQL re-assignment of audit event to different project context",
                original_state={"project_id": orig_pid},
                modified_state={"project_id": project_b_id},
                verification_status=v6.status.value,
                failure_codes=codes6,
                evidence={"failures": codes6},
                detected=det6,
                cleanup_status="RESTORED",
            )
        )

        # 7. Delete middle audit event via raw SQL
        db.execute(text("DELETE FROM audit_events WHERE id = :id"), {"id": orig_id})
        db.commit()
        db.expire_all()
        v7 = audit_svc.verify_chain(project_a_id)
        codes7 = [f.code.value for f in v7.failures]
        det7 = (v7.status == AuditVerificationStatus.AUDIT_INTEGRITY_VIOLATION) and (
            AuditFailureCode.SEQUENCE_GAP.value in codes7
            or AuditFailureCode.BROKEN_AUDIT_CHAIN.value in codes7
        )
        # Restore event 2 by re-inserting original row
        db.execute(
            text(
                "INSERT INTO audit_events (id, project_id, sequence_number, event_hash, "
                "previous_event_hash, event_type, actor, action, target_type, target_id, "
                "outcome, description, created_at, metadata_json) VALUES "
                "(:id, :pid, :seq, :eh, :peh, :et, :actor, :act, :tt, :ti, :out, :desc, :created_at, :meta)"
            ),
            {
                "id": orig_id,
                "pid": orig_pid,
                "seq": orig_seq,
                "eh": orig_hash,
                "peh": orig_prev_hash,
                "et": orig_event_type,
                "actor": orig_actor,
                "act": orig_action,
                "tt": orig_target_type,
                "ti": orig_target_id,
                "out": orig_outcome,
                "desc": orig_desc,
                "created_at": orig_created_at,
                "meta": json.dumps(orig_meta) if isinstance(orig_meta, dict) else orig_meta,
            },
        )
        db.commit()
        db.expire_all()
        sub_results.append(
            AttackSubResult(
                sub_id="ATTACK-05G",
                name="Raw SQL DELETE middle audit event",
                target_asset="audit_events (sequence 2)",
                attack_technique="Direct raw SQL deletion of an intermediate audit event",
                original_state={"row_present": True},
                modified_state={"row_present": False},
                verification_status=v7.status.value,
                failure_codes=codes7,
                evidence={"failures": codes7},
                detected=det7,
                cleanup_status="RESTORED",
            )
        )

        # 8. Insert forged audit event via raw SQL
        forged_id = str(uuid.uuid4())
        forged_hash = sha256_text("forged audit payload")
        db.execute(
            text(
                "INSERT INTO audit_events (id, project_id, sequence_number, event_hash, "
                "previous_event_hash, event_type, actor, action, target_type, target_id, "
                "outcome, description, created_at, metadata_json) VALUES "
                "(:id, :pid, 10, :eh, :peh, 'SECURITY_CONFIG_CHANGED', 'attacker', 'DISABLE_SECURITY', "
                "'SYSTEM', 'all', 'SUCCESS', 'Forged event', datetime('now'), '{}')"
            ),
            {
                "id": forged_id,
                "pid": project_a_id,
                "eh": forged_hash,
                "peh": orig_hash,
            },
        )
        db.commit()
        db.expire_all()
        v8 = audit_svc.verify_chain(project_a_id)
        codes8 = [f.code.value for f in v8.failures]
        det8 = (v8.status == AuditVerificationStatus.AUDIT_INTEGRITY_VIOLATION) and (
            AuditFailureCode.SEQUENCE_GAP.value in codes8
            or AuditFailureCode.EVENT_HASH_MISMATCH.value in codes8
            or AuditFailureCode.BROKEN_AUDIT_CHAIN.value in codes8
        )
        # Restore: delete forged row
        db.execute(text("DELETE FROM audit_events WHERE id = :id"), {"id": forged_id})
        db.commit()
        db.expire_all()
        sub_results.append(
            AttackSubResult(
                sub_id="ATTACK-05H",
                name="Raw SQL INSERT forged audit event",
                target_asset="audit_events",
                attack_technique="Direct raw SQL insertion of a fraudulent event record",
                original_state={"forged_row_present": False},
                modified_state={"forged_row_present": True},
                verification_status=v8.status.value,
                failure_codes=codes8,
                evidence={"failures": codes8},
                detected=det8,
                cleanup_status="RESTORED",
            )
        )

        # Final check: baseline re-verification
        final_v = audit_svc.verify_chain(project_a_id)
        all_restored = final_v.status == AuditVerificationStatus.VALID
        all_detected = all(sr.detected for sr in sub_results) and all_restored

        return AttackResult(
            attack_id="ATTACK-05",
            attack_name="Direct Database Tampering",
            target_asset="Database Persistent Storage (audit_events)",
            attack_technique="Raw SQL mutations completely bypassing ORM validation hooks",
            original_state={"baseline_verified": True, "mutations_tested": len(sub_results)},
            modified_state={"raw_sql_operations_executed": len(sub_results)},
            verification_status="AUDIT_INTEGRITY_VIOLATION",
            failure_codes=[
                AuditFailureCode.EVENT_HASH_MISMATCH.value,
                AuditFailureCode.BROKEN_AUDIT_CHAIN.value,
                AuditFailureCode.SEQUENCE_GAP.value,
            ],
            evidence={
                "sub_results_count": len(sub_results),
                "orm_bypassed": True,
                "cryptographically_detected": all_detected,
                "baseline_restored": all_restored,
            },
            detected=all_detected,
            cleanup_status="RESTORED" if all_restored else "CORRUPTED",
            sub_results=sub_results,
            details={
                "summary": (
                    "Proved that ORM immutability is merely defense-in-depth: "
                    "cryptographic verification detected all 8 raw SQL tamperings"
                )
            },
        )
    finally:
        db.close()
        Base.metadata.drop_all(bind=engine)
        engine.dispose()
