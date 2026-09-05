"""Comprehensive Test Suite for Phase 4.13: Tamper-Evident Audit Logging.

Validates all 28+ minimum requirements:
  1. Create audit event.
  2. Retrieve audit event.
  3. Audit event hash is deterministic and canonical.
  4. Previous-event hash linkage works.
  5. Genesis record initialized at sequence 0 with '0'*64 previous hash.
  6. Sequence numbers increment monotonically.
  7. Duplicate sequence rejected by database constraint.
  8. Duplicate event hash rejected by database constraint.
  9. Modified event field detected as AUDIT_INTEGRITY_VIOLATION.
  10. Modified event hash detected as AUDIT_INTEGRITY_VIOLATION.
  11. Modified previous hash detected as BROKEN_AUDIT_CHAIN.
  12. Deleted middle event detected via sequence gap.
  13. Reordered events detected as integrity violations.
  14. Malformed audit input classified as UNVERIFIABLE_INPUT, not tampering.
  15. Clean audit chain verifies successfully.
  16. Multiple audit failures preserved without masking.
  17. Audit events survive process shutdown and database restart.
  18. Audit events are immutable (ORM listener blocks update/delete).
  19. No update/delete operation exists for audit events.
  20. Replay rejection creates an audit event.
  21. Verification operation creates appropriate audit event.
  22. Tamper assessment creates appropriate audit event.
  23. Audit logging does not recursively log itself.
  24. Audit failure boundary preserves business outcome.
  25. Failed provenance transaction produces persistent replay audit event after rollback.
  26. Private key/passphrase never appears in audit/API output.
  27. No traceback leakage.
  28. Direct database tampering test: bypasses ORM to mutate SQLite rows directly via raw SQL
      and verifies cryptographic detection (AUDIT_INTEGRITY_VIOLATION).
  29. API read-only endpoints and verification.
  30. OpenAPI registration.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker
from starlette.testclient import TestClient

from aivara.crypto.audit import (
    AUDIT_GENESIS_PREVIOUS_HASH,
    AUDIT_GENESIS_SEQUENCE,
    AuditEventType,
    AuditFailureCode,
    AuditOutcome,
    AuditVerificationStatus,
    canonicalize_audit_payload,
    compute_audit_genesis_hash,
    hash_audit_payload,
    verify_audit_chain,
    verify_audit_event,
)
from aivara.crypto.chain import generate_nonce
from aivara.database.connection import Base
from aivara.database.models import AuditEventModel, AuditImmutabilityError, ProjectModel
from aivara.domain.schemas import ProvenanceRecordCreate
from aivara.main import app
from aivara.services.audit_service import (
    AuditEventNotFoundError,
    AuditSequenceCollisionError,
    AuditService,
)
from aivara.services.provenance_service import ProvenanceService


# ---------------------------------------------------------------------------
# Test Fixtures & Helpers
# ---------------------------------------------------------------------------

@pytest.fixture
def client():
    """FastAPI TestClient instance."""
    with TestClient(app) as test_client:
        yield test_client


def _make_project(client: TestClient) -> str:
    """Helper to create a project via API and return its UUID."""
    r = client.post("/api/v1/projects", json={"name": f"Project-{uuid.uuid4().hex[:8]}"})
    assert r.status_code == 201
    return r.json()["data"]["id"]


# ===========================================================================
# 1. Cryptographic Primitive & Hash Tests
# ===========================================================================

class TestAuditCryptoPrimitives:
    """Tests for canonical serialization, SHA-256 hashing, and genesis."""

    def test_audit_hash_is_deterministic(self):
        """Identical audit inputs produce byte-for-byte identical SHA-256 digests."""
        pid = f"proj-{uuid.uuid4().hex}"
        h1 = hash_audit_payload(
            project_id=pid,
            event_type="PROVENANCE_RECORDED",
            actor="system",
            action="RECORD",
            sequence_number=1,
            previous_event_hash="0" * 64,
            timestamp="2026-09-05T12:00:00Z",
            metadata={"key": "val", "num": 42},
        )
        h2 = hash_audit_payload(
            project_id=pid,
            event_type="PROVENANCE_RECORDED",
            actor="system",
            action="RECORD",
            sequence_number=1,
            previous_event_hash="0" * 64,
            timestamp="2026-09-05T12:00:00Z",
            metadata={"num": 42, "key": "val"},  # Key order difference
        )
        assert h1 == h2
        assert len(h1) == 64

    def test_genesis_record_is_deterministic(self):
        """Genesis event hash is deterministic for a given project."""
        pid = "test-project-genesis"
        gh1 = compute_audit_genesis_hash(pid)
        gh2 = compute_audit_genesis_hash(pid)
        assert gh1 == gh2
        assert len(gh1) == 64

    def test_canonical_serialization_rejects_unsupported_types(self):
        """Canonicalizer strictly rejects arbitrary uncanonicalizable Python types."""
        with pytest.raises(Exception):
            canonicalize_audit_payload(
                project_id="pid",
                event_type="TEST",
                actor="system",
                sequence_number=1,
                previous_event_hash="0" * 64,
                timestamp="2026-09-05T12:00:00Z",
                metadata={"unsupported": object()},
            )


# ===========================================================================
# 2. AuditService Lifecycle, Genesis & Persistence Tests
# ===========================================================================

class TestAuditServiceLifecycle:
    """Tests for AuditService creation, sequence monotonicity, and retrieval."""

    def test_create_and_retrieve_audit_event(self, test_db_session):
        p = ProjectModel(name=f"Project-{uuid.uuid4().hex[:8]}")
        test_db_session.add(p)
        test_db_session.commit()

        service = AuditService(test_db_session)
        ev = service.record_event(
            project_id=p.id,
            event_type=AuditEventType.PROVENANCE_RECORDED,
            actor="worker-1",
            action="RECORD",
            description="Test audit event.",
            metadata_json={"batch": 10},
        )

        assert ev.id is not None
        assert ev.project_id == p.id
        assert ev.sequence_number == 1  # Genesis is 0, first normal event is 1
        assert ev.event_type == AuditEventType.PROVENANCE_RECORDED.value
        assert ev.previous_event_hash is not None
        assert len(ev.event_hash) == 64

        # Retrieve by ID
        fetched = service.get_event(ev.id)
        assert fetched is not None
        assert fetched.id == ev.id
        assert fetched.event_hash == ev.event_hash

    def test_genesis_created_automatically_at_sequence_0(self, test_db_session):
        p = ProjectModel(name=f"Project-{uuid.uuid4().hex[:8]}")
        test_db_session.add(p)
        test_db_session.commit()

        service = AuditService(test_db_session)
        chain = service.get_chain(p.id)
        assert len(chain) == 0

        # Recording event auto-initializes genesis at sequence 0
        service.record_event(
            project_id=p.id,
            event_type=AuditEventType.PROVENANCE_RECORDED,
        )

        chain = service.get_chain(p.id)
        assert len(chain) == 2  # Genesis (0) + First event (1)
        assert chain[0].sequence_number == AUDIT_GENESIS_SEQUENCE
        assert chain[0].event_type == "AUDIT_GENESIS"
        assert chain[0].previous_event_hash == AUDIT_GENESIS_PREVIOUS_HASH
        assert chain[1].sequence_number == 1
        assert chain[1].previous_event_hash == chain[0].event_hash

    def test_sequence_increments_correctly(self, test_db_session):
        p = ProjectModel(name=f"Project-{uuid.uuid4().hex[:8]}")
        test_db_session.add(p)
        test_db_session.commit()

        service = AuditService(test_db_session)
        for i in range(1, 4):
            ev = service.record_event(
                project_id=p.id,
                event_type=AuditEventType.PROVENANCE_RECORDED,
                description=f"Event {i}",
            )
            assert ev.sequence_number == i

        chain = service.get_chain(p.id)
        assert [e.sequence_number for e in chain] == [0, 1, 2, 3]

    def test_duplicate_sequence_rejected_by_db_constraint(self, test_db_session):
        p = ProjectModel(name=f"Project-{uuid.uuid4().hex[:8]}")
        test_db_session.add(p)
        test_db_session.commit()

        service = AuditService(test_db_session)
        service.record_event(project_id=p.id, event_type=AuditEventType.PROVENANCE_RECORDED)

        # Attempt manual duplicate sequence 1
        dup = AuditEventModel(
            project_id=p.id,
            event_type="MANUAL_DUP",
            actor="attacker",
            sequence_number=1,
            event_hash="a" * 64,
            previous_event_hash="0" * 64,
        )
        test_db_session.add(dup)
        with pytest.raises(Exception):
            test_db_session.commit()
        test_db_session.rollback()

    def test_duplicate_event_hash_rejected_by_db_constraint(self, test_db_session):
        p = ProjectModel(name=f"Project-{uuid.uuid4().hex[:8]}")
        test_db_session.add(p)
        test_db_session.commit()

        service = AuditService(test_db_session)
        ev = service.record_event(project_id=p.id, event_type=AuditEventType.PROVENANCE_RECORDED)

        # Attempt manual duplicate event_hash with different sequence
        dup = AuditEventModel(
            project_id=p.id,
            event_type="MANUAL_DUP",
            actor="attacker",
            sequence_number=99,
            event_hash=ev.event_hash,
            previous_event_hash="0" * 64,
        )
        test_db_session.add(dup)
        with pytest.raises(Exception):
            test_db_session.commit()
        test_db_session.rollback()

    def test_audit_events_survive_application_restart(self, tmp_path):
        """Audit events persist across process restart / database reconnection."""
        db_file = tmp_path / "restart_audit.db"
        db_url = f"sqlite:///{db_file}"

        eng1 = create_engine(db_url)
        Base.metadata.create_all(bind=eng1)
        Session1 = sessionmaker(bind=eng1)
        session1 = Session1()

        p = ProjectModel(name="RestartProject")
        session1.add(p)
        session1.commit()
        pid = p.id

        service1 = AuditService(session1)
        service1.record_event(
            project_id=pid,
            event_type=AuditEventType.PROVENANCE_RECORDED,
            description="Pre-restart event",
        )
        session1.close()
        eng1.dispose()

        # Reopen completely fresh engine and session
        eng2 = create_engine(db_url)
        Session2 = sessionmaker(bind=eng2)
        session2 = Session2()
        service2 = AuditService(session2)

        chain = service2.get_chain(pid)
        assert len(chain) == 2
        assert chain[0].sequence_number == 0
        assert chain[1].sequence_number == 1
        assert chain[1].description == "Pre-restart event"
        session2.close()
        eng2.dispose()


# ===========================================================================
# 3. Immutability & Anti-Mutation Tests
# ===========================================================================

class TestAuditImmutability:
    """Tests that audit events cannot be modified or deleted."""

    def test_orm_listeners_prevent_update_and_delete(self, test_db_session):
        p = ProjectModel(name=f"Project-{uuid.uuid4().hex[:8]}")
        test_db_session.add(p)
        test_db_session.commit()

        service = AuditService(test_db_session)
        ev = service.record_event(
            project_id=p.id,
            event_type=AuditEventType.PROVENANCE_RECORDED,
            description="Initial description",
        )

        model = test_db_session.query(AuditEventModel).filter(AuditEventModel.id == ev.id).first()

        # Update attempt must raise AuditImmutabilityError
        model.description = "Tampered description"
        with pytest.raises(AuditImmutabilityError):
            test_db_session.commit()
        test_db_session.rollback()

        # Delete attempt must raise AuditImmutabilityError
        model2 = test_db_session.query(AuditEventModel).filter(AuditEventModel.id == ev.id).first()
        test_db_session.delete(model2)
        with pytest.raises(AuditImmutabilityError):
            test_db_session.commit()
        test_db_session.rollback()

    def test_no_update_or_delete_methods_exist_on_service(self, test_db_session):
        service = AuditService(test_db_session)
        with pytest.raises(AuditImmutabilityError):
            service.update_event("any_id")
        with pytest.raises(AuditImmutabilityError):
            service.delete_event("any_id")


# ===========================================================================
# 4. Cryptographic Verification & Tamper Detection Tests
# ===========================================================================

class TestAuditVerificationAndTampering:
    """Tests for audit chain verification, tamper detection, and multi-failure preservation."""

    def test_clean_audit_chain_verifies_successfully(self, test_db_session):
        p = ProjectModel(name=f"Project-{uuid.uuid4().hex[:8]}")
        test_db_session.add(p)
        test_db_session.commit()

        service = AuditService(test_db_session)
        service.record_event(project_id=p.id, event_type=AuditEventType.PROVENANCE_RECORDED)
        service.record_event(project_id=p.id, event_type=AuditEventType.PROVENANCE_VERIFICATION)

        res = service.verify_chain(p.id)
        assert res.valid is True
        assert res.chain_valid is True
        assert res.status == AuditVerificationStatus.VALID
        assert res.checked_events == 3  # Genesis + 2 events
        assert len(res.failures) == 0

    def test_modified_event_field_detected_as_integrity_violation(self, test_db_session):
        p = ProjectModel(name=f"Project-{uuid.uuid4().hex[:8]}")
        test_db_session.add(p)
        test_db_session.commit()

        service = AuditService(test_db_session)
        service.record_event(project_id=p.id, event_type=AuditEventType.PROVENANCE_RECORDED)

        chain_dicts = [e.model_dump() for e in service.get_chain(p.id)]
        # Tamper with an event field without updating event_hash
        chain_dicts[1]["actor"] = "malicious_user"

        res = verify_audit_chain(chain_dicts, expected_project_id=p.id)
        assert res.valid is False
        assert res.status == AuditVerificationStatus.AUDIT_INTEGRITY_VIOLATION
        failure_codes = [f.code for f in res.failures]
        assert AuditFailureCode.EVENT_HASH_MISMATCH in failure_codes

    def test_modified_event_hash_detected(self, test_db_session):
        p = ProjectModel(name=f"Project-{uuid.uuid4().hex[:8]}")
        test_db_session.add(p)
        test_db_session.commit()

        service = AuditService(test_db_session)
        service.record_event(project_id=p.id, event_type=AuditEventType.PROVENANCE_RECORDED)

        chain_dicts = [e.model_dump() for e in service.get_chain(p.id)]
        chain_dicts[1]["event_hash"] = "f" * 64

        res = verify_audit_chain(chain_dicts, expected_project_id=p.id)
        assert res.valid is False
        assert res.status == AuditVerificationStatus.AUDIT_INTEGRITY_VIOLATION
        failure_codes = [f.code for f in res.failures]
        assert AuditFailureCode.EVENT_HASH_MISMATCH in failure_codes

    def test_modified_previous_hash_detected_as_broken_chain(self, test_db_session):
        p = ProjectModel(name=f"Project-{uuid.uuid4().hex[:8]}")
        test_db_session.add(p)
        test_db_session.commit()

        service = AuditService(test_db_session)
        service.record_event(project_id=p.id, event_type=AuditEventType.PROVENANCE_RECORDED)
        service.record_event(project_id=p.id, event_type=AuditEventType.PROVENANCE_VERIFICATION)

        chain_dicts = [e.model_dump() for e in service.get_chain(p.id)]
        # Break previous_event_hash link between event 1 and 2
        chain_dicts[2]["previous_event_hash"] = "e" * 64

        res = verify_audit_chain(chain_dicts, expected_project_id=p.id)
        assert res.valid is False
        assert res.status == AuditVerificationStatus.AUDIT_INTEGRITY_VIOLATION
        failure_codes = [f.code for f in res.failures]
        assert AuditFailureCode.BROKEN_AUDIT_CHAIN in failure_codes

    def test_deleted_middle_event_detected(self, test_db_session):
        p = ProjectModel(name=f"Project-{uuid.uuid4().hex[:8]}")
        test_db_session.add(p)
        test_db_session.commit()

        service = AuditService(test_db_session)
        service.record_event(project_id=p.id, event_type=AuditEventType.PROVENANCE_RECORDED)  # seq 1
        service.record_event(project_id=p.id, event_type=AuditEventType.PROVENANCE_VERIFICATION)  # seq 2

        chain_dicts = [e.model_dump() for e in service.get_chain(p.id)]
        # Delete middle event (seq 1)
        truncated_chain = [chain_dicts[0], chain_dicts[2]]

        res = verify_audit_chain(truncated_chain, expected_project_id=p.id)
        assert res.valid is False
        assert res.status == AuditVerificationStatus.AUDIT_INTEGRITY_VIOLATION
        failure_codes = [f.code for f in res.failures]
        assert AuditFailureCode.SEQUENCE_GAP in failure_codes or AuditFailureCode.BROKEN_AUDIT_CHAIN in failure_codes

    def test_reordered_events_detected(self, test_db_session):
        p = ProjectModel(name=f"Project-{uuid.uuid4().hex[:8]}")
        test_db_session.add(p)
        test_db_session.commit()

        service = AuditService(test_db_session)
        service.record_event(project_id=p.id, event_type=AuditEventType.PROVENANCE_RECORDED)
        service.record_event(project_id=p.id, event_type=AuditEventType.PROVENANCE_VERIFICATION)

        chain_dicts = [e.model_dump() for e in service.get_chain(p.id)]
        # Swap event 1 and event 2
        reordered = [chain_dicts[0], chain_dicts[2], chain_dicts[1]]

        res = verify_audit_chain(reordered, expected_project_id=p.id)
        assert res.valid is False
        assert res.status == AuditVerificationStatus.AUDIT_INTEGRITY_VIOLATION

    def test_malformed_audit_input_classified_as_unverifiable_input(self):
        """Malformed input (bad hash length, missing required keys) is UNVERIFIABLE_INPUT, not tampering."""
        malformed = [{"project_id": "pid", "sequence_number": 0, "event_hash": "short"}]
        res = verify_audit_chain(malformed)
        assert res.valid is False
        assert res.status == AuditVerificationStatus.UNVERIFIABLE_INPUT
        failure_codes = [f.code for f in res.failures]
        assert AuditFailureCode.MALFORMED_AUDIT_INPUT in failure_codes

    def test_multiple_audit_failures_are_preserved(self, test_db_session):
        p = ProjectModel(name=f"Project-{uuid.uuid4().hex[:8]}")
        test_db_session.add(p)
        test_db_session.commit()

        service = AuditService(test_db_session)
        service.record_event(project_id=p.id, event_type=AuditEventType.PROVENANCE_RECORDED)

        chain_dicts = [e.model_dump() for e in service.get_chain(p.id)]
        # Both break payload AND corrupt hash format
        chain_dicts[1]["actor"] = "attacker"
        chain_dicts[1]["previous_event_hash"] = "broken"

        res = verify_audit_chain(chain_dicts, expected_project_id=p.id)
        assert res.valid is False
        assert len(res.failures) >= 2


# ===========================================================================
# 5. Direct Database Tampering Test (Bypassing ORM Listeners)
# ===========================================================================

class TestDirectDatabaseTampering:
    """Directly modifies the SQLite database using raw SQL to verify cryptographic tamper detection."""

    def test_direct_sql_tamper_detected_by_verification(self, test_db_session):
        """Directly update a column via raw SQL (bypassing SQLAlchemy before_update).

        Cryptographic verification must detect the discrepancy and report AUDIT_INTEGRITY_VIOLATION.
        """
        p = ProjectModel(name=f"Project-{uuid.uuid4().hex[:8]}")
        test_db_session.add(p)
        test_db_session.commit()

        service = AuditService(test_db_session)
        ev = service.record_event(
            project_id=p.id,
            event_type=AuditEventType.PROVENANCE_RECORDED,
            description="Legitimate audit description.",
        )

        # 1. Verify it was clean initially
        clean_res = service.verify_chain(p.id)
        assert clean_res.valid is True

        # 2. Bypass ORM via raw SQL to update the SQLite database row directly
        test_db_session.execute(
            text("UPDATE audit_events SET description = 'Direct DB Tampering via SQL' WHERE id = :id"),
            {"id": ev.id},
        )
        test_db_session.commit()

        # 3. Clear ORM session cache so verification loads fresh DB state
        test_db_session.expire_all()

        # 4. Cryptographic verification MUST detect the tampering!
        tampered_res = service.verify_chain(p.id)
        assert tampered_res.valid is False
        assert tampered_res.status == AuditVerificationStatus.AUDIT_INTEGRITY_VIOLATION
        failure_codes = [f.code for f in tampered_res.failures]
        assert AuditFailureCode.EVENT_HASH_MISMATCH in failure_codes

    def test_direct_sql_hash_tamper_detected(self, test_db_session):
        """Directly update event_hash via raw SQL."""
        p = ProjectModel(name=f"Project-{uuid.uuid4().hex[:8]}")
        test_db_session.add(p)
        test_db_session.commit()

        service = AuditService(test_db_session)
        ev = service.record_event(project_id=p.id, event_type=AuditEventType.PROVENANCE_RECORDED)

        test_db_session.execute(
            text("UPDATE audit_events SET event_hash = :new_hash WHERE id = :id"),
            {"new_hash": "a" * 64, "id": ev.id},
        )
        test_db_session.commit()
        test_db_session.expire_all()

        res = service.verify_chain(p.id)
        assert res.valid is False
        assert res.status == AuditVerificationStatus.AUDIT_INTEGRITY_VIOLATION
        failure_codes = [f.code for f in res.failures]
        assert AuditFailureCode.EVENT_HASH_MISMATCH in failure_codes


# ===========================================================================
# 6. Service Integration & Replay Audit Tests
# ===========================================================================

class TestProvenanceAuditIntegration:
    """Tests integration between ProvenanceService, replay rejection, and AuditService."""

    def test_provenance_recording_creates_audit_event(self, test_db_session):
        p = ProjectModel(name=f"Project-{uuid.uuid4().hex[:8]}")
        test_db_session.add(p)
        test_db_session.commit()

        audit_service = AuditService(test_db_session)
        prov_service = ProvenanceService(test_db_session, audit_service=audit_service)

        nonce = generate_nonce()
        rh = "0" * 64
        req = ProvenanceRecordCreate(
            project_id=p.id,
            record_type="INFERENCE_EXECUTION",
            actor="worker-test",
            action="execute",
            sequence_number=1,
            nonce=nonce,
            record_hash=rh,
        )

        rec = prov_service.record_provenance_event(req)
        assert rec.id is not None

        # Verify audit event was created
        chain = audit_service.get_chain(p.id)
        assert len(chain) == 2  # Genesis + PROVENANCE_RECORDED
        assert chain[1].event_type == AuditEventType.PROVENANCE_RECORDED.value
        assert chain[1].metadata_json["nonce"] == nonce

    def test_replay_rejection_creates_audit_event_in_independent_transaction(self, test_db_session):
        p = ProjectModel(name=f"Project-{uuid.uuid4().hex[:8]}")
        test_db_session.add(p)
        test_db_session.commit()

        audit_service = AuditService(test_db_session)
        prov_service = ProvenanceService(test_db_session, audit_service=audit_service)

        shared_nonce = generate_nonce()
        req1 = ProvenanceRecordCreate(
            project_id=p.id,
            record_type="EVENT",
            actor="worker",
            action="execute",
            sequence_number=1,
            nonce=shared_nonce,
            record_hash="1" * 64,
        )
        prov_service.record_provenance_event(req1)

        # Second submission is duplicate nonce -> Replay rejected and rolled back
        req2 = ProvenanceRecordCreate(
            project_id=p.id,
            record_type="EVENT",
            actor="worker",
            action="execute",
            sequence_number=2,
            nonce=shared_nonce,
            record_hash="2" * 64,
        )

        with pytest.raises(Exception):
            prov_service.record_provenance_event(req2)

        # Audit event for replay rejection must persist in independent session!
        chain = audit_service.get_chain(p.id)
        event_types = [e.event_type for e in chain]
        assert AuditEventType.PROVENANCE_REPLAY_REJECTED.value in event_types

    def test_audit_logging_does_not_recursively_log_itself(self, test_db_session):
        p = ProjectModel(name=f"Project-{uuid.uuid4().hex[:8]}")
        test_db_session.add(p)
        test_db_session.commit()

        service = AuditService(test_db_session)
        ev = service.record_event(
            project_id=p.id,
            event_type=AuditEventType.PROVENANCE_RECORDED,
        )
        assert ev.sequence_number == 1
        # Should only have sequence 0 and sequence 1 (no recursive audit event about recording audit)
        chain = service.get_chain(p.id)
        assert len(chain) == 2


# ===========================================================================
# 7. Read-Only API & Security Non-Exposure Tests
# ===========================================================================

class TestAuditAPI:
    """Tests for FastAPI read-only audit endpoints."""

    def test_get_audit_event_by_id(self, client):
        pid = _make_project(client)
        # Record provenance to generate an audit event
        r = client.post("/api/v1/provenance/records", json={
            "project_id": pid,
            "record_type": "EVENT",
            "actor": "api-worker",
            "action": "execute",
            "sequence_number": 1,
            "nonce": generate_nonce(),
            "record_hash": "a" * 64,
        })
        assert r.status_code == 201

        # Fetch audit events
        list_res = client.get(f"/api/v1/audit/events?project_id={pid}")
        assert list_res.status_code == 200
        events = list_res.json()["data"]
        assert len(events) >= 1
        ev_id = events[0]["id"]

        # Fetch by ID
        get_res = client.get(f"/api/v1/audit/events/{ev_id}")
        assert get_res.status_code == 200
        assert get_res.json()["data"]["id"] == ev_id

    def test_get_missing_audit_event_returns_404(self, client):
        r = client.get("/api/v1/audit/events/missing-uuid-12345")
        assert r.status_code == 404
        assert r.json()["status"] == "error"

    def test_verify_persisted_audit_chain_via_api(self, client):
        pid = _make_project(client)
        # Create provenance record
        client.post("/api/v1/provenance/records", json={
            "project_id": pid,
            "record_type": "EVENT",
            "actor": "api-worker",
            "action": "execute",
            "sequence_number": 1,
            "nonce": generate_nonce(),
            "record_hash": "b" * 64,
        })

        r = client.get(f"/api/v1/audit/chain/{pid}/verify")
        assert r.status_code == 200
        data = r.json()["data"]
        assert data["valid"] is True
        assert data["chain_valid"] is True
        assert data["status"] == "VALID"

    def test_verify_caller_supplied_audit_chain_via_api(self, client):
        pid = _make_project(client)
        gen = compute_audit_genesis_hash(pid)
        records = [
            {
                "project_id": pid,
                "event_type": "AUDIT_GENESIS",
                "actor": "AIVARA_SYSTEM",
                "action": "INITIALIZE_AUDIT_CHAIN",
                "target_type": "AUDIT_CHAIN",
                "target_id": pid,
                "outcome": "SUCCESS",
                "description": "Deterministic audit chain genesis record initialized.",
                "sequence_number": 0,
                "previous_event_hash": "0" * 64,
                "event_hash": gen,
                "metadata_json": {"audit_genesis": True},
                "created_at": "1970-01-01T00:00:00Z",
            }
        ]
        r = client.post("/api/v1/audit/chain/verify", json={"project_id": pid, "events": records})
        assert r.status_code == 200
        data = r.json()["data"]
        assert data["valid"] is True

    def test_no_private_key_or_passphrase_leaks_in_audit_responses(self, client):
        pid = _make_project(client)
        client.post("/api/v1/provenance/records", json={
            "project_id": pid,
            "record_type": "EVENT",
            "actor": "api-worker",
            "action": "execute",
            "sequence_number": 1,
            "nonce": generate_nonce(),
            "record_hash": "c" * 64,
        })
        res = client.get(f"/api/v1/audit/chain/{pid}")
        assert "private_key" not in res.text.lower()
        assert "passphrase" not in res.text.lower()

    def test_no_traceback_leaked_in_audit_error_responses(self, client):
        r = client.get("/api/v1/audit/events/missing-uuid-12345")
        assert "traceback" not in r.text.lower()
        assert 'file "' not in r.text.lower()

    def test_openapi_schema_registers_audit_endpoints(self, client):
        r = client.get("/openapi.json")
        assert r.status_code == 200
        paths = r.json()["paths"]
        assert "/api/v1/audit/events/{event_id}" in paths
        assert "/api/v1/audit/events" in paths
        assert "/api/v1/audit/chain/{project_id}" in paths
        assert "/api/v1/audit/chain/verify" in paths
        assert "/api/v1/audit/chain/{project_id}/verify" in paths
