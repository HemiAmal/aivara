"""Comprehensive Security Tests for Persistent Replay Detection (Phase 4.11).

Validates:
  1. First record accepted.
  2. Duplicate nonce rejected within same project.
  3. Duplicate sequence rejected within same project.
  4. Duplicate record hash rejected within same project.
  5. Same sequence in different projects is allowed (compound uniqueness).
  6. Same nonce in different projects is allowed (project-scoped nonce).
  7. Same record hash in different projects is allowed.
  8. Replay detection survives application/process restart (database authoritative).
  9. Duplicate insertion through a fresh service/repository instance rejected.
  10. Concurrent duplicate insertion attempts safely handled (clean rollback, authoritative DB constraint).
  11. Database IntegrityError is translated into structured replay result (ReplayAssessment).
  12. Unrelated database errors (e.g. foreign key violations) are NOT classified as replay.
  13. Valid old signed record is classified as replay, NOT tampering.
  14. Nonce format validation remains strictly enforced.
  15. Sequence validation remains strictly enforced.
  16. Existing in-memory replay tests continue to work.
  17. Genesis record behavior remains correct and non-replayable.
  18. Legitimate sequential records remain accepted and queryable.
"""

from __future__ import annotations

import concurrent.futures
import uuid
from datetime import datetime, timezone
from pathlib import Path

import pytest
from sqlalchemy import create_engine, event
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import sessionmaker

from aivara.core.exceptions import AivaraException
from aivara.crypto.canonical import CANONICAL_SCHEMA_VERSION, format_canonical_datetime
from aivara.crypto.chain import (
    GENESIS_PREVIOUS_RECORD_HASH,
    ChainRecord,
    DuplicateNonceError,
    DuplicateRecordError,
    DuplicateSequenceError,
    InvalidNonceError,
    InvalidSequenceError,
    ProvenanceChain,
    ReplayDetectedError,
    compute_genesis_nonce,
    generate_nonce,
)
from aivara.crypto.hashing import hash_provenance_payload, sha256_text
from aivara.crypto.keys import KeyManager
from aivara.crypto.replay import (
    ReplayAssessment,
    ReplayType,
    classify_integrity_error,
)
from aivara.crypto.signing import sign_hash
from aivara.crypto.tamper_detection import assess_record_tampering
from aivara.crypto.verification import verify_record
from aivara.database.connection import Base
from aivara.database.models import ProjectModel, ProvenanceRecordModel
from aivara.domain.schemas import ProvenanceRecordCreate
from aivara.services.provenance_service import ProvenanceService


# ---------------------------------------------------------------------------
# Test Helpers
# ---------------------------------------------------------------------------

def _create_project(session, name: str = "Test Project") -> ProjectModel:
    """Helper to create and commit a project."""
    project = ProjectModel(
        name=name,
        description="Test project for replay detection",
        genesis_nonce=generate_nonce(),
    )
    session.add(project)
    session.commit()
    session.refresh(project)
    return project


def _make_record_dict(
    project_id: str,
    sequence_number: int = 1,
    nonce: str | None = None,
    previous_record_hash: str = "0" * 64,
    record_hash: str | None = None,
    signature: str | None = None,
    signer_key_id: str | None = None,
) -> dict:
    """Helper to construct a valid provenance record payload."""
    n = nonce or generate_nonce()
    rh = record_hash or sha256_text(f"{project_id}:{sequence_number}:{n}")
    return {
        "project_id": project_id,
        "record_type": "INFERENCE_EXECUTION",
        "actor": "worker-1",
        "action": "execute",
        "target_type": "model",
        "target_id": str(uuid.uuid4()),
        "input_hash": sha256_text("input_data"),
        "output_hash": sha256_text("output_data"),
        "metadata_json": {"latency_ms": 42},
        "sequence_number": sequence_number,
        "nonce": n,
        "previous_record_hash": previous_record_hash,
        "record_hash": rh,
        "signer_key_id": signer_key_id,
        "signature": signature,
    }


# ===========================================================================
# 1. First Record Acceptance & Sequential Validity
# ===========================================================================

class TestProvenanceRecordAcceptance:
    """Validates baseline acceptance and legitimate sequencing."""

    def test_first_record_accepted(self, test_db_session):
        project = _create_project(test_db_session)
        service = ProvenanceService(test_db_session)

        payload = _make_record_dict(project.id, sequence_number=1)
        record = service.record_provenance_event(payload)

        assert record.id is not None
        assert record.project_id == project.id
        assert record.sequence_number == 1
        assert record.nonce == payload["nonce"]
        assert record.record_hash == payload["record_hash"]

    def test_legitimate_sequential_records_remain_accepted(self, test_db_session):
        project = _create_project(test_db_session)
        service = ProvenanceService(test_db_session)

        r0_payload = _make_record_dict(
            project.id, sequence_number=0, previous_record_hash=GENESIS_PREVIOUS_RECORD_HASH
        )
        r0 = service.record_provenance_event(r0_payload)

        r1_payload = _make_record_dict(
            project.id, sequence_number=1, previous_record_hash=r0.record_hash
        )
        r1 = service.record_provenance_event(r1_payload)

        r2_payload = _make_record_dict(
            project.id, sequence_number=2, previous_record_hash=r1.record_hash
        )
        r2 = service.record_provenance_event(r2_payload)

        records = service.list_records(project.id)
        assert len(records) == 3
        assert [r.sequence_number for r in records] == [0, 1, 2]
        assert service.get_latest_record(project.id).sequence_number == 2


# ===========================================================================
# 2. Duplicate Nonce, Sequence & Record Hash Replay Protection
# ===========================================================================

class TestReplayRejection:
    """Validates that duplicate nonces, sequences, and record hashes are rejected within project."""

    def test_duplicate_nonce_rejected_within_project(self, test_db_session):
        project = _create_project(test_db_session)
        service = ProvenanceService(test_db_session)

        shared_nonce = generate_nonce()
        rec1 = _make_record_dict(project.id, sequence_number=1, nonce=shared_nonce)
        service.record_provenance_event(rec1)

        # Attempt to insert a different record with the SAME nonce
        rec2 = _make_record_dict(project.id, sequence_number=2, nonce=shared_nonce)
        with pytest.raises(DuplicateNonceError) as exc_info:
            service.record_provenance_event(rec2)

        err = exc_info.value
        assert err.code == "DUPLICATE_NONCE"
        assert shared_nonce in str(err)
        assert err.details.get("replay_type") == ReplayType.DUPLICATE_NONCE.value

    def test_duplicate_sequence_rejected_within_project(self, test_db_session):
        project = _create_project(test_db_session)
        service = ProvenanceService(test_db_session)

        rec1 = _make_record_dict(project.id, sequence_number=1)
        service.record_provenance_event(rec1)

        # Attempt to insert another record with sequence 1 (different nonce and hash)
        rec2 = _make_record_dict(project.id, sequence_number=1)
        with pytest.raises(DuplicateSequenceError) as exc_info:
            service.record_provenance_event(rec2)

        err = exc_info.value
        assert err.code == "DUPLICATE_SEQUENCE"
        assert "1" in str(err)
        assert err.details.get("replay_type") == ReplayType.DUPLICATE_SEQUENCE.value

    def test_duplicate_record_hash_rejected_within_project(self, test_db_session):
        project = _create_project(test_db_session)
        service = ProvenanceService(test_db_session)

        shared_hash = sha256_text("unique_shared_event_hash")
        rec1 = _make_record_dict(project.id, sequence_number=1, record_hash=shared_hash)
        service.record_provenance_event(rec1)

        # Attempt to insert different sequence and nonce, but same record_hash
        rec2 = _make_record_dict(project.id, sequence_number=2, record_hash=shared_hash)
        with pytest.raises(DuplicateRecordError) as exc_info:
            service.record_provenance_event(rec2)

        err = exc_info.value
        assert err.code == "DUPLICATE_RECORD"
        assert shared_hash in str(err)
        assert err.details.get("replay_type") == ReplayType.DUPLICATE_RECORD.value


# ===========================================================================
# 3. Cross-Project Scope Independence (Compound Uniqueness)
# ===========================================================================

class TestCrossProjectIndependence:
    """Validates that uniqueness constraints are properly project-scoped, not global."""

    def test_same_sequence_in_different_projects_allowed(self, test_db_session):
        proj_a = _create_project(test_db_session, "Project A")
        proj_b = _create_project(test_db_session, "Project B")
        service = ProvenanceService(test_db_session)

        rec_a = _make_record_dict(proj_a.id, sequence_number=1)
        rec_b = _make_record_dict(proj_b.id, sequence_number=1)

        res_a = service.record_provenance_event(rec_a)
        res_b = service.record_provenance_event(rec_b)

        assert res_a.sequence_number == 1
        assert res_b.sequence_number == 1
        assert res_a.project_id == proj_a.id
        assert res_b.project_id == proj_b.id

    def test_same_nonce_in_different_projects_allowed(self, test_db_session):
        proj_a = _create_project(test_db_session, "Project A")
        proj_b = _create_project(test_db_session, "Project B")
        service = ProvenanceService(test_db_session)

        shared_nonce = generate_nonce()
        rec_a = _make_record_dict(proj_a.id, sequence_number=1, nonce=shared_nonce)
        rec_b = _make_record_dict(proj_b.id, sequence_number=1, nonce=shared_nonce)

        res_a = service.record_provenance_event(rec_a)
        res_b = service.record_provenance_event(rec_b)

        assert res_a.nonce == shared_nonce
        assert res_b.nonce == shared_nonce

    def test_same_record_hash_in_different_projects_allowed(self, test_db_session):
        proj_a = _create_project(test_db_session, "Project A")
        proj_b = _create_project(test_db_session, "Project B")
        service = ProvenanceService(test_db_session)

        shared_hash = sha256_text("identical_output_in_different_projects")
        rec_a = _make_record_dict(proj_a.id, sequence_number=1, record_hash=shared_hash)
        rec_b = _make_record_dict(proj_b.id, sequence_number=1, record_hash=shared_hash)

        res_a = service.record_provenance_event(rec_a)
        res_b = service.record_provenance_event(rec_b)

        assert res_a.record_hash == shared_hash
        assert res_b.record_hash == shared_hash


# ===========================================================================
# 4. Restart Safety & Multi-Instance Replay Protection
# ===========================================================================

class TestRestartSafety:
    """Validates that replay detection survives process restarts and fresh instances."""

    def test_replay_after_application_restart(self, tmp_path):
        """Simulates complete application shutdown, memory discard, and reboot."""
        db_file = tmp_path / "restart_safety.db"
        engine_url = f"sqlite:///{db_file}"

        # 1. First "lifecycle" of the application
        engine1 = create_engine(engine_url)
        Base.metadata.create_all(bind=engine1)
        Session1 = sessionmaker(bind=engine1)
        session1 = Session1()

        proj = ProjectModel(name="Restart Proj", description="Persistence Test")
        session1.add(proj)
        session1.commit()
        project_id = proj.id

        service1 = ProvenanceService(session1)
        payload = _make_record_dict(project_id, sequence_number=1)
        service1.record_provenance_event(payload)

        # 2. Simulate complete application restart: close session, dispose engine, discard memory
        session1.close()
        engine1.dispose()
        del session1
        del engine1
        del service1

        # 3. Second "lifecycle" after restart
        engine2 = create_engine(engine_url)
        Session2 = sessionmaker(bind=engine2)
        session2 = Session2()
        service2 = ProvenanceService(session2)

        # Re-submitting the exact same provenance record must be detected as replay by DB
        with pytest.raises((DuplicateNonceError, DuplicateSequenceError, DuplicateRecordError)) as exc_info:
            service2.record_provenance_event(payload)

        assert exc_info.value.code in ("DUPLICATE_NONCE", "DUPLICATE_SEQUENCE", "DUPLICATE_RECORD")
        session2.close()
        engine2.dispose()

    def test_duplicate_insertion_through_fresh_service_instance(self, test_db_session):
        project = _create_project(test_db_session)
        service_a = ProvenanceService(test_db_session)
        service_b = ProvenanceService(test_db_session)

        payload = _make_record_dict(project.id, sequence_number=1)
        service_a.record_provenance_event(payload)

        # Fresh service instance attempting duplicate
        with pytest.raises(DuplicateNonceError):
            service_b.record_provenance_event(payload)


# ===========================================================================
# 5. Concurrency Safety & Authoritative Constraint Enforcement
# ===========================================================================

class TestConcurrencySafety:
    """Validates behavior under concurrent insertion attempts."""

    def test_concurrent_duplicate_insertion_attempts(self, tmp_path):
        """Dispatches concurrent insertion attempts of identical provenance record across threads.

        Proves that application-level 'check then insert' race is safely prevented
        by the authoritative database uniqueness constraint, with clean rollback.
        """
        db_file = tmp_path / "concurrent_test.db"
        engine = create_engine(
            f"sqlite:///{db_file}",
            connect_args={"check_same_thread": False, "timeout": 30},
        )

        @event.listens_for(engine, "connect")
        def _set_pragmas(dbapi_con, con_record):
            cursor = dbapi_con.cursor()
            cursor.execute("PRAGMA foreign_keys=ON;")
            cursor.execute("PRAGMA journal_mode=WAL;")
            cursor.close()

        Base.metadata.create_all(bind=engine)
        SessionFactory = sessionmaker(bind=engine)

        # Setup project
        setup_session = SessionFactory()
        proj = ProjectModel(name="Concurrent Proj", description="Concurrency Test")
        setup_session.add(proj)
        setup_session.commit()
        project_id = proj.id
        setup_session.close()

        target_payload = _make_record_dict(project_id, sequence_number=1)

        def _attempt_insert(worker_id: int):
            session = SessionFactory()
            service = ProvenanceService(session)
            try:
                rec = service.record_provenance_event(target_payload)
                return "SUCCESS", rec.id
            except (DuplicateNonceError, DuplicateSequenceError, DuplicateRecordError, ReplayDetectedError) as exc:
                return "REPLAY_DETECTED", exc.code
            except Exception as exc:
                return "UNEXPECTED_ERROR", str(exc)
            finally:
                session.close()

        # Run concurrent attempts
        workers_count = 5
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers_count) as executor:
            futures = [executor.submit(_attempt_insert, i) for i in range(workers_count)]
            results = [f.result() for f in futures]

        statuses = [r[0] for r in results]
        # Exactly one must succeed, all others must be REPLAY_DETECTED
        assert statuses.count("SUCCESS") == 1
        assert statuses.count("REPLAY_DETECTED") == workers_count - 1
        assert "UNEXPECTED_ERROR" not in statuses

        # Verify DB integrity: exactly one record exists in DB
        verify_session = SessionFactory()
        records = verify_session.query(ProvenanceRecordModel).filter(ProvenanceRecordModel.project_id == project_id).all()
        assert len(records) == 1
        verify_session.close()
        engine.dispose()


# ===========================================================================
# 6. Database Error Classification & Translation
# ===========================================================================

class TestErrorClassification:
    """Validates accurate classification between replay and unrelated database errors."""

    def test_database_integrity_error_translated_to_structured_replay_result(self, test_db_session):
        project = _create_project(test_db_session)
        service = ProvenanceService(test_db_session)

        shared_nonce = generate_nonce()
        p1 = _make_record_dict(project.id, sequence_number=1, nonce=shared_nonce)
        service.record_provenance_event(p1)

        p2 = _make_record_dict(project.id, sequence_number=2, nonce=shared_nonce)
        with pytest.raises(DuplicateNonceError) as exc_info:
            service.record_provenance_event(p2)

        details = exc_info.value.details
        assert details is not None
        assert details["replay_detected"] is True
        assert details["replay_type"] == ReplayType.DUPLICATE_NONCE.value
        assert details["nonce"] == shared_nonce
        assert details["conflicting_record_id"] is not None

    def test_unrelated_database_errors_not_classified_as_replay(self, test_db_session):
        service = ProvenanceService(test_db_session)

        # Non-existent project ID triggers Foreign Key constraint violation
        bad_payload = _make_record_dict("00000000-0000-0000-0000-000000000000", sequence_number=1)

        with pytest.raises(IntegrityError) as exc_info:
            service.record_provenance_event(bad_payload)

        # Must NOT be wrapped into a ReplayDetectedError
        assert not isinstance(exc_info.value, (DuplicateNonceError, DuplicateSequenceError, DuplicateRecordError, ReplayDetectedError))
        is_replay, r_type, reason, _ = classify_integrity_error(exc_info.value)
        assert is_replay is False
        assert r_type == ReplayType.NONE


# ===========================================================================
# 7. Replay vs Tampering Distinction
# ===========================================================================

class TestReplayVsTampering:
    """Proves that a valid old signed record is recognized as replay, NOT tampering."""

    def test_valid_old_signed_record_is_replay_not_tampering(self, test_db_session, tmp_path):
        key_manager = KeyManager(keys_dir=tmp_path / "keys")
        handle = key_manager.generate_key(passphrase="SecretPassphrase123!")

        project = _create_project(test_db_session)
        service = ProvenanceService(test_db_session)

        nonce = generate_nonce()
        seq = 1
        prev_hash = GENESIS_PREVIOUS_RECORD_HASH
        ts = format_canonical_datetime(datetime.now(timezone.utc))

        # Compute canonical hash
        rec_hash = hash_provenance_payload(
            record_type="INFERENCE_EXECUTION",
            project_id=project.id,
            actor="crypto-service",
            action="evaluate",
            sequence_number=seq,
            nonce=nonce,
            timestamp=ts,
            signer_key_id=handle.key_id,
            previous_record_hash=prev_hash,
            schema_version=CANONICAL_SCHEMA_VERSION,
        )

        sig_res = sign_hash(rec_hash, handle)

        valid_signed_record = {
            "project_id": project.id,
            "record_type": "INFERENCE_EXECUTION",
            "actor": "crypto-service",
            "action": "evaluate",
            "sequence_number": seq,
            "nonce": nonce,
            "timestamp": ts,
            "signer_key_id": handle.key_id,
            "previous_record_hash": prev_hash,
            "record_hash": rec_hash,
            "signature": sig_res.signature,
            "schema_version": CANONICAL_SCHEMA_VERSION,
        }

        # 1. Cryptographic verification passes completely
        v_res = verify_record(valid_signed_record, key_manager=key_manager)
        assert v_res.overall_valid is True
        assert v_res.record_valid is True
        assert v_res.signature_valid is True

        # 2. Tamper assessment reports NO tampering
        tamper_assessment = assess_record_tampering(v_res)
        assert tamper_assessment.tampering_detected is False

        # 3. First acceptance succeeds
        persisted = service.record_provenance_event(valid_signed_record, verify_first=True, key_manager=key_manager)
        assert persisted.id is not None

        # 4. Same valid signed record is submitted again
        # Cryptographic layer still confirms the record itself is valid
        v_res_replay = verify_record(valid_signed_record, key_manager=key_manager)
        assert v_res_replay.overall_valid is True
        assert assess_record_tampering(v_res_replay).tampering_detected is False

        # 5. Persistent replay detection rejects it as duplicate, NOT tampering
        with pytest.raises(DuplicateNonceError) as exc_info:
            service.record_provenance_event(valid_signed_record, verify_first=True, key_manager=key_manager)

        assert exc_info.value.code == "DUPLICATE_NONCE"
        assert exc_info.value.code != "RECORD_PAYLOAD_TAMPERING"
        assert exc_info.value.code != "SIGNATURE_TAMPERING"


# ===========================================================================
# 8. Nonce & Sequence Validation Constraints
# ===========================================================================

class TestValidationConstraints:
    """Validates format and range rules for nonces and sequences."""

    def test_nonce_format_validation_enforced(self, test_db_session):
        project = _create_project(test_db_session)
        service = ProvenanceService(test_db_session)

        # Non-hex characters
        bad_payload = _make_record_dict(project.id, nonce="z" * 64)
        with pytest.raises(InvalidNonceError):
            service.record_provenance_event(bad_payload)

        # Upper case
        bad_upper = _make_record_dict(project.id, nonce=generate_nonce().upper())
        with pytest.raises(InvalidNonceError):
            service.record_provenance_event(bad_upper)

        # Short length
        bad_short = _make_record_dict(project.id, nonce="abcd1234")
        with pytest.raises(InvalidNonceError):
            service.record_provenance_event(bad_short)

    def test_sequence_validation_enforced(self, test_db_session):
        project = _create_project(test_db_session)
        service = ProvenanceService(test_db_session)

        # Negative sequence
        bad_neg = _make_record_dict(project.id, sequence_number=-1)
        with pytest.raises(InvalidSequenceError):
            service.record_provenance_event(bad_neg)


# ===========================================================================
# 9. In-Memory & Genesis Verification Compatibility
# ===========================================================================

class TestChainCompatibility:
    """Validates that existing in-memory replay checks and genesis rules remain intact."""

    def test_existing_in_memory_replay_tests_continue_to_pass(self):
        chain = ProvenanceChain(project_id="test-proj-chain")
        assert chain.genesis_record.sequence_number == 0

        # Append record 1
        r1 = chain.append(record_type="EVENT", action="action_1", actor="system")
        assert r1.sequence_number == 1

        # In-memory chain rejection of duplicate nonce
        with pytest.raises(DuplicateNonceError):
            chain.append(record_type="EVENT", action="action_2", actor="system", nonce=r1.nonce)

        # In-memory chain rejection of duplicate sequence
        with pytest.raises(DuplicateSequenceError):
            chain.append(record_type="EVENT", action="action_3", actor="system", sequence_number=1)

    def test_genesis_behavior_remains_correct(self, test_db_session):
        project = _create_project(test_db_session)
        service = ProvenanceService(test_db_session)

        genesis_nonce = compute_genesis_nonce(project.id)
        genesis_payload = _make_record_dict(
            project_id=project.id,
            sequence_number=0,
            nonce=genesis_nonce,
            previous_record_hash=GENESIS_PREVIOUS_RECORD_HASH,
        )

        # Genesis accepted
        gen_rec = service.record_provenance_event(genesis_payload)
        assert gen_rec.sequence_number == 0

        # Replaying genesis rejected
        with pytest.raises((DuplicateSequenceError, DuplicateNonceError)):
            service.record_provenance_event(genesis_payload)


# ===========================================================================
# 10. Advisory Replay Check & Queries
# ===========================================================================

class TestAdvisoryCheckAndQueries:
    """Validates check_replay advisory inspection and service query methods."""

    def test_advisory_check_replay(self, test_db_session):
        project = _create_project(test_db_session)
        service = ProvenanceService(test_db_session)

        nonce = generate_nonce()
        rh = sha256_text("hash1")

        # Prior to insertion, advisory reports clean
        advisory_before = service.check_replay(
            project_id=project.id,
            sequence_number=1,
            nonce=nonce,
            record_hash=rh,
        )
        assert advisory_before.replay_detected is False
        assert advisory_before.replay_type == ReplayType.NONE

        # Insert record
        service.record_provenance_event(
            _make_record_dict(project.id, sequence_number=1, nonce=nonce, record_hash=rh)
        )

        # After insertion, advisory identifies replay
        adv_seq = service.check_replay(project.id, sequence_number=1)
        assert adv_seq.replay_detected is True
        assert adv_seq.replay_type == ReplayType.DUPLICATE_SEQUENCE

        adv_nonce = service.check_replay(project.id, nonce=nonce)
        assert adv_nonce.replay_detected is True
        assert adv_nonce.replay_type == ReplayType.DUPLICATE_NONCE

        adv_hash = service.check_replay(project.id, record_hash=rh)
        assert adv_hash.replay_detected is True
        assert adv_hash.replay_type == ReplayType.DUPLICATE_RECORD

    def test_service_lookup_queries(self, test_db_session):
        project = _create_project(test_db_session)
        service = ProvenanceService(test_db_session)

        nonce = generate_nonce()
        rh = sha256_text("lookup_test")
        rec = service.record_provenance_event(
            _make_record_dict(project.id, sequence_number=1, nonce=nonce, record_hash=rh)
        )

        assert service.get_record(rec.id) is not None
        assert service.get_record_by_sequence(project.id, 1).id == rec.id
        assert service.get_record_by_nonce(project.id, nonce).id == rec.id
        assert service.get_record_by_hash(project.id, rh).id == rec.id
        assert service.get_record("nonexistent-id") is None


# ===========================================================================
# 11. Existing Database Schema Reconciliation
# ===========================================================================

class TestSchemaCompatibility:
    """Validates that existing Phase 3 SQLite databases are safely reconciled without data loss."""

    def test_reconcile_existing_phase3_database(self, tmp_path):
        from sqlalchemy import inspect, text
        from aivara.database.connection import reconcile_provenance_schema, init_db

        db_file = tmp_path / "legacy_phase3.db"
        engine = create_engine(f"sqlite:///{db_file}")

        # Construct legacy Phase 3 table without nonce or signer_key_id, non-unique index
        with engine.begin() as conn:
            conn.execute(text("""
                CREATE TABLE projects (
                    id VARCHAR(36) PRIMARY KEY,
                    name VARCHAR(255) NOT NULL,
                    description TEXT,
                    status VARCHAR(50) NOT NULL DEFAULT 'active',
                    genesis_nonce VARCHAR(64),
                    config_json JSON NOT NULL DEFAULT '{}',
                    created_at DATETIME NOT NULL,
                    updated_at DATETIME NOT NULL
                );
            """))
            conn.execute(text("""
                CREATE TABLE provenance_records (
                    id VARCHAR(36) PRIMARY KEY,
                    project_id VARCHAR(36) NOT NULL,
                    record_type VARCHAR(100) NOT NULL,
                    actor VARCHAR(255) NOT NULL,
                    action VARCHAR(100) NOT NULL,
                    target_type VARCHAR(50),
                    target_id VARCHAR(36),
                    input_hash VARCHAR(64),
                    output_hash VARCHAR(64),
                    metadata_json JSON NOT NULL,
                    signature TEXT,
                    previous_record_hash VARCHAR(64),
                    record_hash VARCHAR(64),
                    sequence_number INTEGER,
                    blockchain_tx_id VARCHAR(128),
                    created_at DATETIME NOT NULL
                );
            """))
            conn.execute(text("CREATE INDEX ix_provenance_records_project_id ON provenance_records (project_id);"))
            conn.execute(text("CREATE INDEX ix_provenance_records_sequence ON provenance_records (project_id, sequence_number);"))
            # Insert existing legacy row
            conn.execute(text("""
                INSERT INTO projects (id, name, created_at, updated_at)
                VALUES ('proj-legacy', 'Legacy Project', '2026-09-01 00:00:00', '2026-09-01 00:00:00');
            """))
            conn.execute(text("""
                INSERT INTO provenance_records (id, project_id, record_type, actor, action, metadata_json, sequence_number, created_at)
                VALUES ('rec-legacy-1', 'proj-legacy', 'EVENT', 'system', 'test', '{}', 0, '2026-09-01 00:00:00');
            """))

        # 1. Run schema reconciliation via init_db
        init_db(db_engine=engine)

        # 2. Inspect resulting schema
        inspector = inspect(engine)
        columns = {col["name"] for col in inspector.get_columns("provenance_records")}
        assert "nonce" in columns
        assert "signer_key_id" in columns

        indexes = {idx["name"]: idx for idx in inspector.get_indexes("provenance_records")}
        assert indexes["ix_provenance_records_sequence"]["unique"] == 1
        assert indexes["ix_provenance_records_project_nonce"]["unique"] == 1
        assert indexes["ix_provenance_records_project_record_hash"]["unique"] == 1

        # 3. Assert pre-existing data was preserved
        with engine.connect() as conn:
            row = conn.execute(text("SELECT id, project_id, sequence_number, nonce FROM provenance_records WHERE id='rec-legacy-1'")).fetchone()
            assert row[0] == "rec-legacy-1"
            assert row[1] == "proj-legacy"
            assert row[2] == 0
            assert row[3] is None

        # 4. Use ProvenanceService on upgraded database to test replay protection
        SessionCls = sessionmaker(bind=engine)
        session = SessionCls()
        service = ProvenanceService(session)

        # Replay sequence 0 in proj-legacy rejected
        r_dup = _make_record_dict("proj-legacy", sequence_number=0)
        with pytest.raises(DuplicateSequenceError):
            service.record_provenance_event(r_dup)

        # Sequence 1 in proj-legacy accepted
        r_valid = _make_record_dict("proj-legacy", sequence_number=1)
        res = service.record_provenance_event(r_valid)
        assert res.sequence_number == 1

        # Duplicate nonce rejected
        r_dup_nonce = _make_record_dict("proj-legacy", sequence_number=2, nonce=res.nonce)
        with pytest.raises(DuplicateNonceError):
            service.record_provenance_event(r_dup_nonce)

        session.close()

        # 5. Idempotence: running init_db / reconcile a second time does not error
        init_db(db_engine=engine)
        engine.dispose()

