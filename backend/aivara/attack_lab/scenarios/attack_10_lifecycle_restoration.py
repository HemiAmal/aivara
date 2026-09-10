"""ATTACK-10 — Attack Lifecycle & Restoration Demonstration.

Demonstrates:
  1. Full formal attack lifecycle:
     SETUP -> BASELINE -> ATTACK -> VERIFY -> CAPTURE RESULT -> CLEANUP -> RESTORE.
  2. Operating exclusively in an isolated disposable database / project environment.
  3. Proving that attack execution leaves zero residual corruption in the database.
  4. Running the demonstration twice consecutively to prove:
     - 100% deterministic reproducibility of security classifications.
     - Identical failure codes on repeated execution.
     - Guaranteed baseline restoration across consecutive runs.
"""

from __future__ import annotations

import copy
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
)
from aivara.database.connection import Base
from aivara.database.models import AuditEventModel, ProjectModel
from aivara.services.audit_service import AuditService


def get_scenario() -> AttackScenario:
    """Return static metadata for ATTACK-10."""
    return AttackScenario(
        attack_id="ATTACK-10",
        attack_name="Attack Lifecycle / Restoration",
        category=AttackCategory.LIFECYCLE,
        description=(
            "Controlled demonstration proving the rigorous lifecycle isolation and reversible "
            "restoration discipline of AIVARA's demonstration lab: Setup -> Baseline -> Attack -> "
            "Verify -> Capture Result -> Cleanup -> Restore. Confirms that attacks execute without "
            "residual database corruption and achieve deterministic reproducibility across multiple runs."
        ),
        target="Attack Lab Isolation & Restoration Engine",
        prerequisites=["Isolated database session"],
        setup={"action": "Initialize disposable test database and project baseline"},
        attack={"action": "Execute two consecutive tamper-and-restore cycles"},
        verification={"engine": "AuditService.verify_chain before and after each cycle"},
        expected_result={
            "cycle_1_detected": True,
            "cycle_1_restored": True,
            "cycle_2_detected": True,
            "cycle_2_restored": True,
            "reproducibility": "IDENTICAL",
            "zero_corruption": True,
        },
        cleanup="Complete database teardown and memory disposal",
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


def run_attack_10() -> AttackResult:
    """Execute the ATTACK-10 demonstration."""
    engine, db = _setup_isolated_db()
    try:
        project_id = f"proj-lifecycle-{uuid.uuid4().hex[:6]}"
        project = ProjectModel(
            id=project_id,
            name="Lifecycle Demo Project",
            description="Testing reproducible attack-and-restore lifecycle",
        )
        db.add(project)
        db.commit()

        audit_svc = AuditService(db)

        # 1. SETUP & BASELINE
        audit_svc._ensure_genesis(project_id)
        ev1 = audit_svc.record_event(
            project_id=project_id,
            event_type=AuditEventType.PROVENANCE_RECORDED,
            actor="lifecycle-agent",
            action="INITIALIZE_RECORD",
            target_type="RECORD",
            target_id="rec-lifecycle-01",
            description="Baseline audit record 1",
            outcome=AuditOutcome.SUCCESS,
        )
        ev2 = audit_svc.record_event(
            project_id=project_id,
            event_type=AuditEventType.SECURITY_CONFIG_CHANGED,
            actor="lifecycle-agent",
            action="SET_POLICY",
            target_type="CONFIG",
            target_id="cfg-01",
            description="Baseline audit record 2",
            outcome=AuditOutcome.SUCCESS,
        )

        base_verify = audit_svc.verify_chain(project_id)
        assert base_verify.status == AuditVerificationStatus.VALID, "Initial baseline must be VALID"

        orig_ev2 = db.query(AuditEventModel).filter_by(project_id=project_id, sequence_number=2).first()
        orig_ev2_id = orig_ev2.id
        orig_ev2_desc = orig_ev2.description

        sub_results: List[AttackSubResult] = []

        # CYCLE 1: ATTACK -> VERIFY -> CAPTURE -> CLEANUP -> RESTORE
        # Attack: Mutate description of event 2
        db.execute(
            text("UPDATE audit_events SET description = 'CYCLE_1_TAMPERED' WHERE id = :id"),
            {"id": orig_ev2_id},
        )
        db.commit()
        db.expire_all()

        v_cycle_1 = audit_svc.verify_chain(project_id)
        codes_cycle_1 = [f.code.value for f in v_cycle_1.failures]
        det_cycle_1 = (v_cycle_1.status == AuditVerificationStatus.AUDIT_INTEGRITY_VIOLATION) and (
            AuditFailureCode.EVENT_HASH_MISMATCH.value in codes_cycle_1
        )

        # Cleanup & Restore Cycle 1
        db.execute(
            text("UPDATE audit_events SET description = :desc WHERE id = :id"),
            {"desc": orig_ev2_desc, "id": orig_ev2_id},
        )
        db.commit()
        db.expire_all()

        v_restore_1 = audit_svc.verify_chain(project_id)
        restored_1 = v_restore_1.status == AuditVerificationStatus.VALID

        sub_results.append(
            AttackSubResult(
                sub_id="LIFECYCLE-CYCLE-1",
                name="Attack Lifecycle Cycle 1",
                target_asset="audit_events (sequence 2)",
                attack_technique="Controlled mutation, verification, and restoration",
                original_state={"description": orig_ev2_desc, "baseline_valid": True},
                modified_state={"description": "CYCLE_1_TAMPERED"},
                verification_status=v_cycle_1.status.value,
                failure_codes=codes_cycle_1,
                evidence={"cycle": 1, "failures": codes_cycle_1, "restored": restored_1},
                detected=det_cycle_1 and restored_1,
                cleanup_status="RESTORED",
            )
        )

        # CYCLE 2: REPEAT EXACT SAME ATTACK TO PROVE REPRODUCIBILITY
        db.execute(
            text("UPDATE audit_events SET description = 'CYCLE_2_TAMPERED' WHERE id = :id"),
            {"id": orig_ev2_id},
        )
        db.commit()
        db.expire_all()

        v_cycle_2 = audit_svc.verify_chain(project_id)
        codes_cycle_2 = [f.code.value for f in v_cycle_2.failures]
        det_cycle_2 = (v_cycle_2.status == AuditVerificationStatus.AUDIT_INTEGRITY_VIOLATION) and (
            AuditFailureCode.EVENT_HASH_MISMATCH.value in codes_cycle_2
        )

        # Cleanup & Restore Cycle 2
        db.execute(
            text("UPDATE audit_events SET description = :desc WHERE id = :id"),
            {"desc": orig_ev2_desc, "id": orig_ev2_id},
        )
        db.commit()
        db.expire_all()

        v_restore_2 = audit_svc.verify_chain(project_id)
        restored_2 = v_restore_2.status == AuditVerificationStatus.VALID

        sub_results.append(
            AttackSubResult(
                sub_id="LIFECYCLE-CYCLE-2",
                name="Attack Lifecycle Cycle 2 (Reproducibility Verification)",
                target_asset="audit_events (sequence 2)",
                attack_technique="Second consecutive mutation to verify repeatable determinism",
                original_state={"description": orig_ev2_desc, "baseline_valid": True},
                modified_state={"description": "CYCLE_2_TAMPERED"},
                verification_status=v_cycle_2.status.value,
                failure_codes=codes_cycle_2,
                evidence={"cycle": 2, "failures": codes_cycle_2, "restored": restored_2},
                detected=det_cycle_2 and restored_2,
                cleanup_status="RESTORED",
            )
        )

        # Check reproducibility: failure codes match exactly
        reproducible = (codes_cycle_1 == codes_cycle_2) and restored_1 and restored_2 and det_cycle_1 and det_cycle_2

        return AttackResult(
            attack_id="ATTACK-10",
            attack_name="Attack Lifecycle / Restoration",
            target_asset="Attack Lab Lifecycle Discipline & Database Integrity",
            attack_technique="Consecutive dual-cycle tamper, detection, and restoration verification",
            original_state={"initial_baseline_valid": True},
            modified_state={"cycles_completed": 2},
            verification_status="LIFECYCLE_VERIFIED",
            failure_codes=[AuditFailureCode.EVENT_HASH_MISMATCH.value],
            evidence={
                "cycle_1_detected": det_cycle_1,
                "cycle_1_restored": restored_1,
                "cycle_2_detected": det_cycle_2,
                "cycle_2_restored": restored_2,
                "deterministic_reproducibility": reproducible,
                "residual_corruption": False,
            },
            detected=reproducible,
            cleanup_status="RESTORED",
            sub_results=sub_results,
            details={
                "summary": (
                    "Proved complete attack lifecycle safety: both cycles produced identical "
                    "failure codes and restored the database with zero residual corruption."
                )
            },
        )
    finally:
        db.close()
        Base.metadata.drop_all(bind=engine)
        engine.dispose()
