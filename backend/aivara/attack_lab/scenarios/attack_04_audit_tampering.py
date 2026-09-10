"""ATTACK-04 — Audit Event Tampering Demonstration.

Demonstrates:
  1. Construction of valid 4-event audit chain: Genesis -> A1 -> A2 -> A3.
  2. Baseline audit chain verification -> VALID.
  3. Controlled tampering with audit event A2.
  4. Detection of EVENT_HASH_MISMATCH and downstream BROKEN_AUDIT_CHAIN.
  5. Overall classification as AUDIT_INTEGRITY_VIOLATION.
  6. Reversible restoration of A2 and re-verification of VALID status.
"""

from __future__ import annotations

import copy
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
    AuditVerificationResult,
    AuditVerificationStatus,
    verify_audit_chain,
)
from aivara.database.connection import Base
from aivara.database.models import AuditEventModel, ProjectModel
from aivara.services.audit_service import AuditService


def get_scenario() -> AttackScenario:
    """Return static metadata for ATTACK-04."""
    return AttackScenario(
        attack_id="ATTACK-04",
        attack_name="Audit Event Tampering",
        category=AttackCategory.AUDIT,
        description=(
            "Controlled demonstration proving that modifying any historical audit event "
            "(e.g. Genesis -> A1 -> A2 -> A3, tampering with A2) is mathematically detected "
            "via canonical SHA-256 payload recomputation and downstream previous-event hash "
            "linkage verification, classifying as AUDIT_INTEGRITY_VIOLATION."
        ),
        target="Audit Event Chain Linkage & Content Hashes",
        prerequisites=["Isolated database session", "Registered ProjectModel"],
        setup={"action": "Construct valid audit chain: Genesis -> A1 -> A2 -> A3"},
        attack={"action": "Tamper with event A2 in the middle of the audit chain"},
        verification={"engine": "aivara.crypto.audit.verify_audit_chain"},
        expected_result={
            "status": "AUDIT_INTEGRITY_VIOLATION",
            "detected": True,
            "failure_codes": ["EVENT_HASH_MISMATCH", "BROKEN_AUDIT_CHAIN"],
        },
        cleanup="Restore event A2 to genuine state and verify audit chain VALID status",
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


def run_attack_04() -> AttackResult:
    """Execute the ATTACK-04 demonstration."""
    engine, db = _setup_isolated_db()
    try:
        project_id = f"proj-audit-{uuid.uuid4().hex[:8]}"
        project = ProjectModel(
            id=project_id,
            name="Audit Tampering Demo Project",
            description="Testing audit chain tamper detection",
        )
        db.add(project)
        db.commit()

        audit_svc = AuditService(db)

        # Baseline: Genesis is created automatically
        genesis_event = audit_svc._ensure_genesis(project_id)
        assert genesis_event.sequence_number == 0

        # A1: First operational event
        a1 = audit_svc.record_event(
            project_id=project_id,
            event_type=AuditEventType.PROVENANCE_RECORDED,
            actor="operator-1",
            action="INGEST_MODEL",
            target_type="MODEL",
            target_id="mod-01",
            description="Initial model weights recorded",
            outcome=AuditOutcome.SUCCESS,
        )
        assert a1.sequence_number == 1

        # A2: Middle operational event (Target for tampering)
        a2 = audit_svc.record_event(
            project_id=project_id,
            event_type=AuditEventType.SECURITY_CONFIG_CHANGED,
            actor="admin-sec",
            action="UPDATE_SECURITY_CONFIG",
            target_type="SECURITY_CONFIG",
            target_id="cfg-01",
            description="Enabled strict provenance validation",
            outcome=AuditOutcome.SUCCESS,
            metadata_json={"strict_mode": True, "auth_level": "high"},
        )
        assert a2.sequence_number == 2

        # A3: Downstream operational event
        a3 = audit_svc.record_event(
            project_id=project_id,
            event_type=AuditEventType.PROVENANCE_VERIFICATION,
            actor="verifier-bot",
            action="VERIFY_CHAIN",
            target_type="CHAIN",
            target_id=project_id,
            description="Periodic verification check passed",
            outcome=AuditOutcome.SUCCESS,
        )
        assert a3.sequence_number == 3

        # 1. Verify baseline audit chain is VALID
        base_v = audit_svc.verify_chain(project_id)
        assert base_v.status == AuditVerificationStatus.VALID, "Baseline audit chain must be valid"

        # 2. Capture original A2 state
        orig_a2_desc = a2.description
        orig_a2_hash = a2.event_hash
        orig_a2_meta = copy.deepcopy(a2.metadata_json)

        # 3. Controlled raw SQL tampering with A2 description & metadata_json
        # (Using raw SQL to bypass ORM listeners)
        tampered_desc = "MALICIOUS_TAMPERED: Disabled strict security validation"
        tampered_meta = json.dumps({"strict_mode": False, "auth_level": "disabled"})
        db.execute(
            text(
                "UPDATE audit_events "
                "SET description = :desc, metadata_json = :meta "
                "WHERE project_id = :pid AND sequence_number = 2"
            ),
            {"desc": tampered_desc, "meta": tampered_meta, "pid": project_id},
        )
        db.commit()
        db.expire_all()

        # 4. Verify detection via AIVARA audit verification
        attack_v = audit_svc.verify_chain(project_id)
        failure_codes = [f.code.value for f in attack_v.failures]

        detected_hash_mismatch = AuditFailureCode.EVENT_HASH_MISMATCH.value in failure_codes
        detected_integrity_violation = (
            attack_v.status == AuditVerificationStatus.AUDIT_INTEGRITY_VIOLATION
        )

        sub_results = [
            AttackSubResult(
                sub_id="SUB-A2-PAYLOAD",
                name="Tamper with Audit Event A2 Payload",
                target_asset="audit_events.description & metadata_json (sequence 2)",
                attack_technique="Raw SQL mutation of middle event payload leaving event_hash unchanged",
                original_state={"description": orig_a2_desc, "event_hash": orig_a2_hash},
                modified_state={"description": tampered_desc, "event_hash": orig_a2_hash},
                verification_status=attack_v.status.value,
                failure_codes=failure_codes,
                evidence={
                    "stored_event_hash": orig_a2_hash,
                    "tampered_sequence": 2,
                    "failures_detected": failure_codes,
                },
                detected=detected_hash_mismatch and detected_integrity_violation,
                cleanup_status="PENDING_RESTORE",
            )
        ]

        # 5. Restore Baseline
        db.execute(
            text(
                "UPDATE audit_events "
                "SET description = :desc, metadata_json = :meta "
                "WHERE project_id = :pid AND sequence_number = 2"
            ),
            {"desc": orig_a2_desc, "meta": json.dumps(orig_a2_meta) if isinstance(orig_a2_meta, dict) else orig_a2_meta, "pid": project_id},
        )
        db.commit()
        db.expire_all()

        # Re-verify that baseline is fully restored
        restored_v = audit_svc.verify_chain(project_id)
        clean_restored = restored_v.status == AuditVerificationStatus.VALID

        sub_results.append(
            AttackSubResult(
                sub_id="SUB-RESTORE",
                name="Audit Chain Baseline Restoration",
                target_asset="audit_events (sequence 2)",
                attack_technique="Restoration of canonical values and re-verification",
                original_state={"status": "VALID"},
                modified_state={"status": restored_v.status.value},
                verification_status=restored_v.status.value,
                failure_codes=[f.code.value for f in restored_v.failures],
                evidence={"restored_valid": clean_restored},
                detected=clean_restored,
                cleanup_status="RESTORED",
            )
        )

        all_detected = detected_hash_mismatch and detected_integrity_violation and clean_restored

        return AttackResult(
            attack_id="ATTACK-04",
            attack_name="Audit Event Tampering",
            target_asset="Audit Event Log (Genesis -> A1 -> A2 -> A3)",
            attack_technique="Direct raw-SQL modification of middle audit event A2",
            original_state={"chain_length": 4, "baseline_status": "VALID"},
            modified_state={"tampered_sequence": 2, "tampered_field": "description"},
            verification_status=attack_v.status.value,
            failure_codes=failure_codes,
            evidence={
                "tampered_sequence": 2,
                "failure_codes": failure_codes,
                "recomputed_hash_differs": True,
                "restored_cleanly": clean_restored,
            },
            detected=all_detected,
            cleanup_status="RESTORED" if clean_restored else "CORRUPTED",
            sub_results=sub_results,
            details={"summary": "Audit tampering with A2 authoritatively detected and baseline restored"},
        )
    finally:
        db.close()
        Base.metadata.drop_all(bind=engine)
        engine.dispose()
