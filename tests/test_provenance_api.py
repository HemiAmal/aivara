"""Comprehensive API integration tests for Phase 4.12.

Validates:
  1. Provenance creation succeeds (POST /records -> 201).
  2. Valid provenance retrieval succeeds (GET /records/{id} -> 200).
  3. Missing provenance returns 404 with standard envelope.
  4. Valid record verification succeeds (POST /records/verify -> 200, overall_valid=True).
  5. Invalid record verification returns structured failure (POST /records/verify -> 200, overall_valid=False).
  6. Invalid signature returns structured verification result (signature_valid=False).
  7. Unknown signer returns authenticity-unavailable result.
  8. Malformed request returns validation error (422).
  9. Tamper assessment detects a modified record (tampering_detected=True, INTEGRITY_VIOLATION).
  10. Clean record tamper assessment returns CLEAN.
  11. Chain verification succeeds for valid chain.
  12. Broken chain returns structured chain failure (BROKEN_CHAIN).
  13. Replay submission returns structured replay/conflict response (409).
  14. Duplicate nonce is correctly surfaced (409, DUPLICATE_NONCE).
  15. Duplicate sequence is correctly surfaced (409, DUPLICATE_SEQUENCE).
  16. Duplicate record hash is correctly surfaced (409, DUPLICATE_RECORD).
  17. Database rollback occurs after replay rejection (no duplicate rows in DB).
  18. No private key / passphrase appears in API response.
  19. No traceback leaks through expected API errors.
  20. Advisory replay check endpoint works (POST /replay-check).
  21. OpenAPI schema registration includes all provenance endpoints.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

import pytest

from aivara.crypto.canonical import CANONICAL_SCHEMA_VERSION, format_canonical_datetime
from aivara.crypto.chain import (
    GENESIS_PREVIOUS_RECORD_HASH,
    ProvenanceChain,
    compute_genesis_nonce,
    generate_nonce,
)
from aivara.crypto.hashing import hash_provenance_payload, sha256_text
from aivara.crypto.keys import KeyManager
from aivara.crypto.signing import sign_hash


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_project(client, name: str = "Provenance Project") -> str:
    """Create a project and return its ID."""
    r = client.post("/api/v1/projects", json={"name": name, "description": "For API tests"})
    assert r.status_code == 201
    return r.json()["data"]["id"]


def _make_record_payload(
    project_id: str,
    sequence_number: int = 1,
    nonce: str | None = None,
    previous_record_hash: str = "0" * 64,
    record_hash: str | None = None,
    signature: str | None = None,
    signer_key_id: str | None = None,
) -> dict:
    """Generate a valid provenance record payload dictionary."""
    n = nonce or generate_nonce()
    rh = record_hash or sha256_text(f"{project_id}:{sequence_number}:{n}")
    return {
        "project_id": project_id,
        "record_type": "INFERENCE_EXECUTION",
        "actor": "worker-api",
        "action": "execute",
        "target_type": "model",
        "target_id": str(uuid.uuid4()),
        "input_hash": sha256_text("input"),
        "output_hash": sha256_text("output"),
        "metadata_json": {"test": True},
        "sequence_number": sequence_number,
        "nonce": n,
        "previous_record_hash": previous_record_hash,
        "record_hash": rh,
        "signer_key_id": signer_key_id,
        "signature": signature,
    }


def _build_signed_record(project_id: str, key_manager: KeyManager, seq: int = 1, prev_hash: str = "0" * 64) -> dict:
    """Build a cryptographically authentic, signed provenance record."""
    handle = key_manager.generate_key(passphrase="ApiTestPassphrase123!")
    nonce = generate_nonce()
    ts = format_canonical_datetime(datetime.now(timezone.utc))

    rec_hash = hash_provenance_payload(
        record_type="INFERENCE_EXECUTION",
        project_id=project_id,
        actor="worker-api",
        action="execute",
        sequence_number=seq,
        nonce=nonce,
        timestamp=ts,
        signer_key_id=handle.key_id,
        previous_record_hash=prev_hash,
        schema_version=CANONICAL_SCHEMA_VERSION,
    )

    sig_res = sign_hash(rec_hash, handle)

    return {
        "project_id": project_id,
        "record_type": "INFERENCE_EXECUTION",
        "actor": "worker-api",
        "action": "execute",
        "sequence_number": seq,
        "nonce": nonce,
        "timestamp": ts,
        "signer_key_id": handle.key_id,
        "previous_record_hash": prev_hash,
        "record_hash": rec_hash,
        "signature": sig_res.signature,
        "schema_version": CANONICAL_SCHEMA_VERSION,
    }


# ===========================================================================
# 1. Provenance Event Recording & Retrieval Tests
# ===========================================================================

class TestProvenanceRecordCRUDAPI:
    """Tests for record creation, retrieval, and chain queries."""

    def test_provenance_creation_succeeds(self, client):
        pid = _make_project(client)
        payload = _make_record_payload(pid, sequence_number=1)

        r = client.post("/api/v1/provenance/records", json=payload)
        assert r.status_code == 201
        data = r.json()
        assert data["status"] == "success"
        rec = data["data"]
        assert rec["id"] is not None
        assert rec["project_id"] == pid
        assert rec["sequence_number"] == 1
        assert rec["nonce"] == payload["nonce"]
        assert rec["record_hash"] == payload["record_hash"]
        assert "meta" in data

    def test_valid_provenance_retrieval_succeeds(self, client):
        pid = _make_project(client)
        payload = _make_record_payload(pid, sequence_number=1)
        create_res = client.post("/api/v1/provenance/records", json=payload)
        assert create_res.status_code == 201
        rec_id = create_res.json()["data"]["id"]

        r = client.get(f"/api/v1/provenance/records/{rec_id}")
        assert r.status_code == 200
        data = r.json()
        assert data["status"] == "success"
        assert data["data"]["id"] == rec_id
        assert data["data"]["sequence_number"] == 1

    def test_missing_provenance_returns_404(self, client):
        r = client.get("/api/v1/provenance/records/non-existent-uuid-99999")
        assert r.status_code == 404
        data = r.json()
        assert data["status"] == "error"
        assert data["error"]["code"] == "NOT_FOUND"
        assert "not found" in data["error"]["message"].lower()

    def test_list_records_and_get_chain(self, client):
        pid = _make_project(client)
        r0 = _make_record_payload(pid, sequence_number=0, previous_record_hash=GENESIS_PREVIOUS_RECORD_HASH)
        client.post("/api/v1/provenance/records", json=r0)

        r1 = _make_record_payload(pid, sequence_number=1, previous_record_hash=r0["record_hash"])
        client.post("/api/v1/provenance/records", json=r1)

        # Query /records?project_id=...
        list_res = client.get(f"/api/v1/provenance/records?project_id={pid}")
        assert list_res.status_code == 200
        records = list_res.json()["data"]
        assert len(records) == 2
        assert [r["sequence_number"] for r in records] == [0, 1]

        # Query /chain/{project_id}
        chain_res = client.get(f"/api/v1/provenance/chain/{pid}")
        assert chain_res.status_code == 200
        chain_records = chain_res.json()["data"]
        assert len(chain_records) == 2


# ===========================================================================
# 2. Advisory Replay Check & Replay Conflict Tests
# ===========================================================================

class TestReplayAPI:
    """Tests for advisory check and database-enforced replay rejections."""

    def test_advisory_replay_check_endpoint(self, client):
        pid = _make_project(client)
        nonce = generate_nonce()
        rh = sha256_text("hash_advisory")

        # Before insert: clean
        chk1 = client.post("/api/v1/provenance/replay-check", json={
            "project_id": pid, "sequence_number": 1, "nonce": nonce, "record_hash": rh
        })
        assert chk1.status_code == 200
        assert chk1.json()["data"]["replay_detected"] is False

        # Insert record
        client.post("/api/v1/provenance/records", json=_make_record_payload(pid, sequence_number=1, nonce=nonce, record_hash=rh))

        # After insert: duplicate detected
        chk2 = client.post("/api/v1/provenance/replay-check", json={
            "project_id": pid, "sequence_number": 1, "nonce": nonce
        })
        assert chk2.status_code == 200
        assert chk2.json()["data"]["replay_detected"] is True

    def test_replay_submission_returns_structured_conflict_409(self, client):
        pid = _make_project(client)
        payload = _make_record_payload(pid, sequence_number=1)

        # 1st insertion succeeds
        r1 = client.post("/api/v1/provenance/records", json=payload)
        assert r1.status_code == 201

        # 2nd insertion is duplicate -> 409 Conflict
        r2 = client.post("/api/v1/provenance/records", json=payload)
        assert r2.status_code == 409
        data = r2.json()
        assert data["status"] == "error"
        assert data["error"]["code"] in ("DUPLICATE_NONCE", "DUPLICATE_SEQUENCE", "DUPLICATE_RECORD", "REPLAY_DETECTED")
        assert "details" in data["error"]
        assert data["error"]["details"]["replay_detected"] is True

    def test_duplicate_nonce_is_correctly_surfaced(self, client):
        pid = _make_project(client)
        shared_nonce = generate_nonce()

        client.post("/api/v1/provenance/records", json=_make_record_payload(pid, sequence_number=1, nonce=shared_nonce))

        r = client.post("/api/v1/provenance/records", json=_make_record_payload(pid, sequence_number=2, nonce=shared_nonce))
        assert r.status_code == 409
        err = r.json()["error"]
        assert err["code"] == "DUPLICATE_NONCE"
        assert err["details"]["replay_type"] == "DUPLICATE_NONCE"
        assert err["details"]["nonce"] == shared_nonce

    def test_duplicate_sequence_is_correctly_surfaced(self, client):
        pid = _make_project(client)

        client.post("/api/v1/provenance/records", json=_make_record_payload(pid, sequence_number=1))

        # Different nonce and hash, but same sequence
        r = client.post("/api/v1/provenance/records", json=_make_record_payload(pid, sequence_number=1))
        assert r.status_code == 409
        err = r.json()["error"]
        assert err["code"] == "DUPLICATE_SEQUENCE"
        assert err["details"]["replay_type"] == "DUPLICATE_SEQUENCE"
        assert err["details"]["sequence_number"] == 1

    def test_duplicate_record_hash_is_correctly_surfaced(self, client):
        pid = _make_project(client)
        shared_hash = sha256_text("shared_hash_test")

        client.post("/api/v1/provenance/records", json=_make_record_payload(pid, sequence_number=1, record_hash=shared_hash))

        r = client.post("/api/v1/provenance/records", json=_make_record_payload(pid, sequence_number=2, record_hash=shared_hash))
        assert r.status_code == 409
        err = r.json()["error"]
        assert err["code"] == "DUPLICATE_RECORD"
        assert err["details"]["replay_type"] == "DUPLICATE_RECORD"
        assert err["details"]["record_hash"] == shared_hash

    def test_database_rollback_occurs_after_replay_rejection(self, client):
        pid = _make_project(client)
        p1 = _make_record_payload(pid, sequence_number=1)
        client.post("/api/v1/provenance/records", json=p1)

        # Attempt duplicate
        p2 = _make_record_payload(pid, sequence_number=1)
        r = client.post("/api/v1/provenance/records", json=p2)
        assert r.status_code == 409

        # Verify DB row count is strictly 1 (no half-inserted rows)
        list_res = client.get(f"/api/v1/provenance/records?project_id={pid}")
        assert len(list_res.json()["data"]) == 1


# ===========================================================================
# 3. Cryptographic Verification API Tests
# ===========================================================================

class TestVerificationAPI:
    """Tests for record and chain cryptographic verification endpoints."""

    def test_valid_record_verification_succeeds(self, client, tmp_path):
        from aivara.api.routers.provenance import get_key_manager
        from aivara.main import app

        km = KeyManager(keys_dir=tmp_path / "keys")
        app.dependency_overrides[get_key_manager] = lambda: km

        pid = _make_project(client)
        record = _build_signed_record(pid, km, seq=1)

        r = client.post("/api/v1/provenance/records/verify", json={"record": record})
        assert r.status_code == 200
        data = r.json()["data"]
        assert data["overall_valid"] is True
        assert data["record_valid"] is True
        assert data["signature_valid"] is True
        assert len(data["failures"]) == 0
        app.dependency_overrides.clear()

    def test_invalid_record_verification_returns_structured_failure(self, client, tmp_path):
        from aivara.api.routers.provenance import get_key_manager
        from aivara.main import app

        km = KeyManager(keys_dir=tmp_path / "keys")
        app.dependency_overrides[get_key_manager] = lambda: km

        pid = _make_project(client)
        record = _build_signed_record(pid, km, seq=1)
        # Corrupt stored hash
        record["record_hash"] = sha256_text("corrupted_hash")

        # Must return 200 OK with structured failure (NOT 500)
        r = client.post("/api/v1/provenance/records/verify", json={"record": record})
        assert r.status_code == 200
        data = r.json()["data"]
        assert data["overall_valid"] is False
        assert data["record_valid"] is False
        failure_codes = [f["code"] for f in data["failures"]]
        assert "RECORD_HASH_MISMATCH" in failure_codes
        app.dependency_overrides.clear()

    def test_invalid_signature_returns_structured_verification_result(self, client, tmp_path):
        from aivara.api.routers.provenance import get_key_manager
        from aivara.main import app

        km = KeyManager(keys_dir=tmp_path / "keys")
        app.dependency_overrides[get_key_manager] = lambda: km

        pid = _make_project(client)
        record = _build_signed_record(pid, km, seq=1)
        # Corrupt signature (valid base64 length 88, wrong bytes)
        record["signature"] = "A" * 86 + "=="

        r = client.post("/api/v1/provenance/records/verify", json={"record": record})
        assert r.status_code == 200
        data = r.json()["data"]
        assert data["overall_valid"] is False
        assert data["signature_valid"] is False
        failure_codes = [f["code"] for f in data["failures"]]
        assert "INVALID_SIGNATURE" in failure_codes
        app.dependency_overrides.clear()

    def test_chain_verification_succeeds_for_valid_chain(self, client):
        pid = _make_project(client)
        chain = ProvenanceChain(pid)
        chain.append(
            record_type="INFERENCE_EXECUTION",
            action="execute",
            actor="worker-api",
        )
        records = [r.model_dump() for r in chain.records]

        r = client.post("/api/v1/provenance/chain/verify", json={"records": records})
        assert r.status_code == 200
        data = r.json()["data"]
        assert data["overall_valid"] is True
        assert data["chain_valid"] is True
        assert data["records_verified_count"] == 2

    def test_broken_chain_returns_structured_chain_failure(self, client):
        pid = _make_project(client)
        r0 = _make_record_payload(pid, sequence_number=0, previous_record_hash=GENESIS_PREVIOUS_RECORD_HASH)
        r1 = _make_record_payload(pid, sequence_number=1, previous_record_hash="f" * 64)  # Broken link

        r = client.post("/api/v1/provenance/chain/verify", json={"records": [r0, r1]})
        assert r.status_code == 200
        data = r.json()["data"]
        assert data["overall_valid"] is False
        assert data["chain_valid"] is False
        failure_codes = [f["code"] for f in data["failures"]]
        assert "BROKEN_CHAIN" in failure_codes


# ===========================================================================
# 4. Tamper Assessment API Tests
# ===========================================================================

class TestTamperAssessmentAPI:
    """Tests for record and chain tamper evaluation endpoints."""

    def test_clean_record_tamper_assessment_returns_clean(self, client, tmp_path):
        from aivara.api.routers.provenance import get_key_manager
        from aivara.main import app

        km = KeyManager(keys_dir=tmp_path / "keys")
        app.dependency_overrides[get_key_manager] = lambda: km

        pid = _make_project(client)
        record = _build_signed_record(pid, km, seq=1)

        r = client.post("/api/v1/provenance/records/tamper-assessment", json={"record": record})
        assert r.status_code == 200
        data = r.json()["data"]
        assert data["tampering_detected"] is False
        assert data["status"].lower() == "clean"
        assert data["severity"].lower() == "none"
        assert len(data["findings"]) == 0
        app.dependency_overrides.clear()

    def test_tamper_assessment_detects_modified_record(self, client, tmp_path):
        from aivara.api.routers.provenance import get_key_manager
        from aivara.main import app

        km = KeyManager(keys_dir=tmp_path / "keys")
        app.dependency_overrides[get_key_manager] = lambda: km

        pid = _make_project(client)
        record = _build_signed_record(pid, km, seq=1)
        # Modify payload without updating signature/hash (classic payload tampering)
        record["actor"] = "malicious-actor"

        r = client.post("/api/v1/provenance/records/tamper-assessment", json={"record": record})
        assert r.status_code == 200
        data = r.json()["data"]
        assert data["tampering_detected"] is True
        assert data["status"].lower() == "integrity_violation"
        assert data["confidence"] == 1.0
        assert data["severity"].upper() in ("HIGH", "CRITICAL")
        assert "RECORD_PAYLOAD_TAMPERING" in data["categories"]
        app.dependency_overrides.clear()

    def test_unknown_signer_returns_authenticity_unavailable(self, client, tmp_path):
        from aivara.api.routers.provenance import get_key_manager
        from aivara.main import app

        km = KeyManager(keys_dir=tmp_path / "keys")
        km_other = KeyManager(keys_dir=tmp_path / "keys_other")
        app.dependency_overrides[get_key_manager] = lambda: km

        pid = _make_project(client)
        # Signed with km_other, whose key is not present in km
        record = _build_signed_record(pid, km_other, seq=1)

        r = client.post("/api/v1/provenance/records/tamper-assessment", json={"record": record})
        assert r.status_code == 200
        data = r.json()["data"]
        assert data["tampering_detected"] is False
        assert data["status"].lower() == "authenticity_unavailable"
        assert len(data["findings"]) == 0
        app.dependency_overrides.clear()


# ===========================================================================
# 5. Schema Validation & Security Invariant Tests
# ===========================================================================

class TestAPISecurityAndValidation:
    """Tests for schema validation, security non-exposure, and OpenAPI."""

    def test_malformed_request_returns_validation_error_422(self, client):
        # Missing required 'action' field
        r = client.post("/api/v1/provenance/records", json={"project_id": "p1", "record_type": "EVENT"})
        assert r.status_code == 422
        data = r.json()
        assert data["status"] == "error"
        assert data["error"]["code"] == "REQUEST_VALIDATION_ERROR"

    def test_no_private_key_or_passphrase_appears_in_api_response(self, client, tmp_path):
        from aivara.api.routers.provenance import get_key_manager
        from aivara.main import app

        km = KeyManager(keys_dir=tmp_path / "keys")
        app.dependency_overrides[get_key_manager] = lambda: km

        pid = _make_project(client)
        record = _build_signed_record(pid, km, seq=1)

        # 1. Create
        res_create = client.post("/api/v1/provenance/records", json=record)
        assert "private_key" not in res_create.text.lower()
        assert "passphrase" not in res_create.text.lower()

        # 2. Verify
        res_ver = client.post("/api/v1/provenance/records/verify", json={"record": record})
        assert "private_key" not in res_ver.text.lower()
        assert "passphrase" not in res_ver.text.lower()

        # 3. Tamper
        res_tamp = client.post("/api/v1/provenance/records/tamper-assessment", json={"record": record})
        assert "private_key" not in res_tamp.text.lower()
        assert "passphrase" not in res_tamp.text.lower()

        app.dependency_overrides.clear()

    def test_no_traceback_leaks_through_expected_api_errors(self, client):
        # Trigger 404
        r404 = client.get("/api/v1/provenance/records/missing-id")
        assert "traceback" not in r404.text.lower()
        assert 'file "' not in r404.text.lower()

        # Trigger 422
        r422 = client.post("/api/v1/provenance/records", json={})
        assert "traceback" not in r422.text.lower()
        assert 'file "' not in r422.text.lower()

    def test_openapi_registration(self, client):
        """Verify all Phase 4.12 provenance endpoints are registered in OpenAPI schema."""
        r = client.get("/openapi.json")
        assert r.status_code == 200
        paths = r.json()["paths"]

        expected_endpoints = [
            "/api/v1/provenance/records",
            "/api/v1/provenance/records/{record_id}",
            "/api/v1/provenance/chain/{project_id}",
            "/api/v1/provenance/replay-check",
            "/api/v1/provenance/records/verify",
            "/api/v1/provenance/chain/verify",
            "/api/v1/provenance/records/tamper-assessment",
            "/api/v1/provenance/chain/tamper-assessment",
        ]

        for ep in expected_endpoints:
            assert ep in paths, f"Endpoint '{ep}' missing from OpenAPI documentation."
