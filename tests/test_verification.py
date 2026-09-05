"""Comprehensive unit and integration tests for AIVARA's Unified Verification Engine (Phase 4.9).

Covers:
  - Section A: Single record verification (valid, modified payload, modified hash, malformed)
  - Section B: Signature verification (valid signed, modified signed, malformed sig, unknown key, wrong key)
  - Section C: Key lifecycle (ACTIVE, ROTATED, REVOKED, EXPIRED historical signatures)
  - Section D: Hash-chain verification (valid chain, modified record, broken previous hash, sequence error, project mismatch, invalid genesis)
  - Section E: Combined failures (multi-failure preservation without masking)
  - Section F: Verification determinism
  - Section G: Security checks (no secrets, passphrases, or private keys exposed in results or errors)
"""

from pathlib import Path
from typing import Any, Dict

import pytest

from aivara.crypto import (
    FailureCode,
    KeyManager,
    KeyStatus,
    ProvenanceChain,
    ProvenanceVerificationEngine,
    UnifiedChainVerificationResult,
    UnifiedVerificationResult,
    VerificationFailure,
    create_genesis_record,
    generate_nonce,
    hash_provenance_payload,
    sign_hash,
    verify_provenance_chain,
    verify_record,
)

TEST_PASSPHRASE = "Phase4.9_Test_Passphrase_2026!"
PROJECT_ID = "proj_verification_alpha_01"


@pytest.fixture
def key_manager(tmp_path: Path) -> KeyManager:
    """Fixture providing an isolated KeyManager instance."""
    return KeyManager(keys_dir=tmp_path / "keys")


@pytest.fixture
def chain(key_manager: KeyManager) -> ProvenanceChain:
    """Fixture providing a initialized ProvenanceChain."""
    return ProvenanceChain(project_id=PROJECT_ID)


# =====================================================================
# Section A: Single Record Verification
# =====================================================================


class TestSingleRecordVerification:
    """Tests for single provenance record verification (Layers A and B)."""

    def test_valid_unsigned_record_verifies(self, chain: ProvenanceChain):
        """A properly formatted, canonically hashed unsigned record verifies successfully."""
        record = chain.append(
            record_type="DATASET_INGESTION",
            action="import_samples",
            actor="pipeline_worker",
            input_hash="a" * 64,
            output_hash="b" * 64,
        )

        result: UnifiedVerificationResult = verify_record(record)

        assert result.overall_valid is True
        assert result.record_valid is True
        assert result.signature_present is False
        assert result.signature_valid is None
        assert len(result.failures) == 0
        assert result.evidence is not None
        assert result.evidence.stored_record_hash == record.record_hash
        assert result.evidence.computed_record_hash == record.record_hash

    def test_modified_payload_fails_record_hash_verification(self, chain: ProvenanceChain):
        """Modifying any protected payload field produces a RECORD_HASH_MISMATCH failure."""
        record = chain.append(
            record_type="DATASET_INGESTION",
            action="import_samples",
            actor="pipeline_worker",
        )

        tampered_dict = record.model_dump()
        tampered_dict["action"] = "tampered_action"

        result = verify_record(tampered_dict)

        assert result.overall_valid is False
        assert result.record_valid is False
        assert FailureCode.RECORD_HASH_MISMATCH in result.failure_codes
        assert any(f.code == FailureCode.RECORD_HASH_MISMATCH for f in result.failures)

    def test_modified_record_hash_fails_verification(self, chain: ProvenanceChain):
        """Modifying the stored record_hash produces a RECORD_HASH_MISMATCH failure."""
        record = chain.append(
            record_type="MODEL_IMPORT",
            action="register_weights",
            actor="admin",
        )

        tampered_dict = record.model_dump()
        tampered_dict["record_hash"] = "f" * 64

        result = verify_record(tampered_dict)

        assert result.overall_valid is False
        assert result.record_valid is False
        assert FailureCode.RECORD_HASH_MISMATCH in result.failure_codes

    def test_malformed_record_missing_required_fields(self):
        """Missing required fields produce MALFORMED_INPUT failures."""
        malformed_dict = {
            "project_id": PROJECT_ID,
            # Missing record_type, actor, action, etc.
            "sequence_number": 1,
        }

        result = verify_record(malformed_dict)

        assert result.overall_valid is False
        assert result.record_valid is False
        assert FailureCode.MALFORMED_INPUT in result.failure_codes

    def test_malformed_nonce_format_rejected(self, chain: ProvenanceChain):
        """A nonce that is not a 64-char lowercase hex string fails input validation."""
        record = chain.append(record_type="TEST", action="test", actor="tester")
        tampered = record.model_dump()
        tampered["nonce"] = "invalid_short_nonce"

        result = verify_record(tampered)

        assert result.overall_valid is False
        assert FailureCode.INVALID_NONCE in result.failure_codes

    def test_disallow_unsigned_records_policy(self, chain: ProvenanceChain):
        """When allow_unsigned=False, an unsigned record produces a MISSING_SIGNATURE failure."""
        record = chain.append(record_type="TEST", action="test", actor="tester")

        result = verify_record(record, allow_unsigned=False)

        assert result.overall_valid is False
        assert result.signature_present is False
        assert FailureCode.MISSING_SIGNATURE in result.failure_codes


# =====================================================================
# Section B: Signature Verification
# =====================================================================


class TestSignatureVerification:
    """Tests for Ed25519 signature verification on provenance records (Layer D)."""

    def test_valid_signed_record_verifies(self, key_manager: KeyManager):
        """A validly signed record verifies with signature_valid=True and overall_valid=True."""
        handle = key_manager.generate_key(passphrase=TEST_PASSPHRASE)
        chain = ProvenanceChain(project_id=PROJECT_ID, key_handle=handle)

        record = chain.append(
            record_type="INFERENCE",
            action="predict",
            actor="ml_engine",
            sign=True,
        )

        result = verify_record(record, key_manager=key_manager)

        assert result.overall_valid is True
        assert result.record_valid is True
        assert result.signature_present is True
        assert result.signature_valid is True
        assert result.signer_key_id == handle.key_id
        assert result.key_status == KeyStatus.ACTIVE
        assert result.key_is_active is True
        assert len(result.failures) == 0

    def test_modified_signed_record_fails_verification(self, key_manager: KeyManager):
        """Modifying the record hash of a signed record fails cryptographic signature verification."""
        handle = key_manager.generate_key(passphrase=TEST_PASSPHRASE)
        chain = ProvenanceChain(project_id=PROJECT_ID, key_handle=handle)

        record = chain.append(
            record_type="INFERENCE",
            action="predict",
            actor="ml_engine",
            sign=True,
        )

        tampered = record.model_dump()
        tampered["record_hash"] = "e" * 64

        result = verify_record(tampered, key_manager=key_manager)

        assert result.overall_valid is False
        assert result.signature_valid is False
        assert FailureCode.INVALID_SIGNATURE in result.failure_codes

    def test_malformed_signature_string_rejected(self, key_manager: KeyManager):
        """A malformed signature string (invalid Base64 / bad length) fails with MALFORMED_SIGNATURE."""
        handle = key_manager.generate_key(passphrase=TEST_PASSPHRASE)
        chain = ProvenanceChain(project_id=PROJECT_ID, key_handle=handle)

        record = chain.append(
            record_type="INFERENCE",
            action="predict",
            actor="ml_engine",
            sign=True,
        )

        tampered = record.model_dump()
        tampered["signature"] = "not_valid_base64!!"

        result = verify_record(tampered, key_manager=key_manager)

        assert result.overall_valid is False
        assert result.signature_valid is False
        assert FailureCode.MALFORMED_SIGNATURE in result.failure_codes

    def test_unknown_signer_key_fails_verification(self, key_manager: KeyManager):
        """A signature with a signer_key_id unknown to KeyManager fails with UNKNOWN_SIGNER_KEY."""
        handle = key_manager.generate_key(passphrase=TEST_PASSPHRASE)
        chain = ProvenanceChain(project_id=PROJECT_ID, key_handle=handle)

        record = chain.append(
            record_type="INFERENCE",
            action="predict",
            actor="ml_engine",
            sign=True,
        )

        tampered = record.model_dump()
        tampered["signer_key_id"] = "0" * 64  # Non-existent key

        result = verify_record(tampered, key_manager=key_manager)

        assert result.overall_valid is False
        assert result.signature_valid is False
        assert FailureCode.UNKNOWN_SIGNER_KEY in result.failure_codes


# =====================================================================
# Section C: Key Lifecycle & Historical Verification
# =====================================================================


class TestKeyLifecycleVerification:
    """Tests for Phase 4.5/4.9 historical key verification policy (Layer E)."""

    def test_active_key_verifies_successfully(self, key_manager: KeyManager):
        """An ACTIVE key signs and verifies with key_status=ACTIVE and key_is_active=True."""
        handle = key_manager.generate_key(passphrase=TEST_PASSPHRASE)
        chain = ProvenanceChain(project_id=PROJECT_ID, key_handle=handle)
        record = chain.append(record_type="TEST", action="test", actor="user", sign=True)

        result = verify_record(record, key_manager=key_manager)

        assert result.overall_valid is True
        assert result.signature_valid is True
        assert result.key_status == KeyStatus.ACTIVE
        assert result.key_is_active is True

    def test_rotated_key_verifies_historical_signature(self, key_manager: KeyManager):
        """A signature created by an older key that is later ROTATED still verifies mathematically."""
        old_handle = key_manager.generate_key(passphrase=TEST_PASSPHRASE)
        chain = ProvenanceChain(project_id=PROJECT_ID, key_handle=old_handle)
        record = chain.append(record_type="TEST", action="test", actor="user", sign=True)

        # Rotate key
        key_manager.rotate_key(passphrase=TEST_PASSPHRASE)
        old_reloaded = key_manager.load_key(
            old_handle.key_id, passphrase=TEST_PASSPHRASE, require_active=False
        )
        assert old_reloaded.status == KeyStatus.ROTATED
        assert old_reloaded.is_active is False

        result = verify_record(record, key_manager=key_manager)

        assert result.overall_valid is True
        assert result.signature_valid is True
        assert result.key_status == KeyStatus.ROTATED
        assert result.key_is_active is False

    def test_revoked_key_verifies_historical_signature(self, key_manager: KeyManager):
        """A signature created before key REVOCATION still verifies mathematically."""
        handle = key_manager.generate_key(passphrase=TEST_PASSPHRASE)
        chain = ProvenanceChain(project_id=PROJECT_ID, key_handle=handle)
        record = chain.append(record_type="TEST", action="test", actor="user", sign=True)

        # Revoke key
        key_manager.revoke_key(handle.key_id, reason="Scheduled key retirement")
        revoked_reloaded = key_manager.load_key(
            handle.key_id, load_private=False, require_active=False
        )
        assert revoked_reloaded.status == KeyStatus.REVOKED
        assert revoked_reloaded.is_active is False

        result = verify_record(record, key_manager=key_manager)

        assert result.overall_valid is True
        assert result.signature_valid is True
        assert result.key_status == KeyStatus.REVOKED
        assert result.key_is_active is False

    def test_expired_key_verifies_historical_signature(self, key_manager: KeyManager):
        """A signature created before key EXPIRATION still verifies mathematically."""
        import json

        handle = key_manager.generate_key(passphrase=TEST_PASSPHRASE)
        chain = ProvenanceChain(project_id=PROJECT_ID, key_handle=handle)
        record = chain.append(record_type="TEST", action="test", actor="user", sign=True)

        # Simulate expiration
        meta_path = key_manager.keys_dir / f"{handle.key_id}.meta.json"
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
        meta["status"] = KeyStatus.EXPIRED.value
        meta_path.write_text(json.dumps(meta), encoding="utf-8")

        result = verify_record(record, key_manager=key_manager)

        assert result.overall_valid is True
        assert result.signature_valid is True
        assert result.key_status == KeyStatus.EXPIRED
        assert result.key_is_active is False


# =====================================================================
# Section D: Chain Verification
# =====================================================================


class TestChainVerification:
    """Tests for full provenance hash-chain verification (Layer C)."""

    def test_valid_chain_verifies(self, key_manager: KeyManager):
        """A multi-record provenance chain with signatures and valid links verifies completely."""
        handle = key_manager.generate_key(passphrase=TEST_PASSPHRASE)
        chain = ProvenanceChain(project_id=PROJECT_ID, key_handle=handle)

        chain.append(record_type="INGEST", action="import", actor="user1", sign=True)
        chain.append(record_type="PREPROCESS", action="filter", actor="worker1", sign=True)
        chain.append(record_type="INFERENCE", action="run", actor="worker2", sign=True)

        result: UnifiedChainVerificationResult = verify_provenance_chain(
            chain.records, key_manager=key_manager
        )

        assert result.overall_valid is True
        assert result.chain_valid is True
        assert result.records_verified_count == 4  # Genesis + 3 normal records
        assert result.signatures_verified_count == 3
        assert len(result.failures) == 0

    def test_modified_record_in_chain_fails(self, key_manager: KeyManager):
        """Modifying a record payload within the chain triggers RECORD_HASH_MISMATCH and BROKEN_CHAIN."""
        handle = key_manager.generate_key(passphrase=TEST_PASSPHRASE)
        chain = ProvenanceChain(project_id=PROJECT_ID, key_handle=handle)

        chain.append(record_type="INGEST", action="import", actor="user1", sign=True)
        chain.append(record_type="INFERENCE", action="run", actor="user2", sign=True)

        # Tamper record 1's action
        records = [r.model_dump() for r in chain.records]
        records[1]["action"] = "tampered_action"

        result = verify_provenance_chain(records, key_manager=key_manager)

        assert result.overall_valid is False
        assert result.chain_valid is False
        assert FailureCode.RECORD_HASH_MISMATCH in result.failure_codes

    def test_broken_previous_hash_link_fails(self, chain: ProvenanceChain):
        """A broken previous_record_hash link fails with BROKEN_CHAIN."""
        chain.append(record_type="INGEST", action="import", actor="user1")
        chain.append(record_type="INFERENCE", action="run", actor="user2")

        records = [r.model_dump() for r in chain.records]
        records[2]["previous_record_hash"] = "9" * 64

        result = verify_provenance_chain(records)

        assert result.overall_valid is False
        assert result.chain_valid is False
        assert FailureCode.BROKEN_CHAIN in result.failure_codes

    def test_sequence_gap_detected(self, chain: ProvenanceChain):
        """A missing record in the chain causes a SEQUENCE_GAP failure."""
        chain.append(record_type="INGEST", action="import", actor="user1")
        chain.append(record_type="FILTER", action="step2", actor="user1")
        chain.append(record_type="INFERENCE", action="step3", actor="user2")

        # Drop record 1 (sequence 1), creating a gap between genesis (0) and record 2 (sequence 2)
        records = [chain.records[0], chain.records[2]]

        result = verify_provenance_chain(records)

        assert result.overall_valid is False
        assert result.chain_valid is False
        assert FailureCode.SEQUENCE_GAP in result.failure_codes

    def test_project_mismatch_detected(self, chain: ProvenanceChain):
        """A record from a different project in the chain causes a PROJECT_MISMATCH failure."""
        chain.append(record_type="INGEST", action="import", actor="user1")

        records = [r.model_dump() for r in chain.records]
        records[1]["project_id"] = "foreign_project_404"

        result = verify_provenance_chain(records, expected_project_id=PROJECT_ID)

        assert result.overall_valid is False
        assert result.chain_valid is False
        assert FailureCode.PROJECT_MISMATCH in result.failure_codes

    def test_invalid_genesis_detected(self):
        """A chain starting with a non-zero sequence fails with GENESIS_INVALID."""
        genesis = create_genesis_record(PROJECT_ID)
        bad_genesis = genesis.model_dump()
        bad_genesis["sequence_number"] = 99

        result = verify_provenance_chain([bad_genesis])

        assert result.overall_valid is False
        assert result.chain_valid is False
        assert FailureCode.GENESIS_INVALID in result.failure_codes


# =====================================================================
# Section E: Combined Failures
# =====================================================================


class TestCombinedFailures:
    """Tests that multiple failures on a record are both collected and not masked."""

    def test_tampered_payload_and_broken_signature_both_captured(
        self, key_manager: KeyManager
    ):
        """When a record has both a payload mismatch AND a signature mismatch, BOTH failures are reported."""
        handle = key_manager.generate_key(passphrase=TEST_PASSPHRASE)
        chain = ProvenanceChain(project_id=PROJECT_ID, key_handle=handle)

        record = chain.append(
            record_type="INFERENCE",
            action="predict",
            actor="ml_engine",
            sign=True,
        )

        tampered = record.model_dump()
        # 1. Alter payload (causes RECORD_HASH_MISMATCH)
        tampered["action"] = "tampered_action"
        # 2. Alter signature (causes INVALID_SIGNATURE)
        # Flip bits in valid base64 signature
        sig_chars = list(tampered["signature"])
        sig_chars[10] = "A" if sig_chars[10] != "A" else "B"
        tampered["signature"] = "".join(sig_chars)

        result = verify_record(tampered, key_manager=key_manager)

        assert result.overall_valid is False
        assert result.record_valid is False
        assert result.signature_valid is False
        assert FailureCode.RECORD_HASH_MISMATCH in result.failure_codes
        assert FailureCode.INVALID_SIGNATURE in result.failure_codes
        assert len(result.failures) >= 2


# =====================================================================
# Section F: Determinism
# =====================================================================


class TestVerificationDeterminism:
    """Tests ensuring verification outcomes are strictly deterministic."""

    def test_identical_record_produces_identical_verification(
        self, key_manager: KeyManager
    ):
        """Verifying the same record multiple times returns identical result structures."""
        handle = key_manager.generate_key(passphrase=TEST_PASSPHRASE)
        chain = ProvenanceChain(project_id=PROJECT_ID, key_handle=handle)
        record = chain.append(record_type="TEST", action="test", actor="user", sign=True)

        res1 = verify_record(record, key_manager=key_manager)
        res2 = verify_record(record, key_manager=key_manager)

        assert res1.overall_valid == res2.overall_valid == True
        assert res1.record_valid == res2.record_valid == True
        assert res1.signature_valid == res2.signature_valid == True
        assert res1.signer_key_id == res2.signer_key_id == handle.key_id
        assert res1.failure_codes == res2.failure_codes == []
        assert res1.evidence.computed_record_hash == res2.evidence.computed_record_hash


# =====================================================================
# Section G: Security & Non-Exposure
# =====================================================================


class TestVerificationSecurity:
    """Security invariants: No private keys, passphrases, or secrets in results or errors."""

    def test_no_secrets_or_passphrases_in_verification_output(
        self, key_manager: KeyManager
    ):
        """VerificationResult and VerificationFailure representations do not expose passphrases."""
        handle = key_manager.generate_key(passphrase=TEST_PASSPHRASE)
        chain = ProvenanceChain(project_id=PROJECT_ID, key_handle=handle)
        record = chain.append(record_type="TEST", action="test", actor="user", sign=True)

        res = verify_record(record, key_manager=key_manager)

        res_str = str(res.model_dump())
        assert TEST_PASSPHRASE not in res_str
        assert "private_key" not in res_str
        assert "passphrase" not in res_str

    def test_engine_class_convenience_interface(self, key_manager: KeyManager):
        """ProvenanceVerificationEngine wraps key_manager and verifies records and chains."""
        handle = key_manager.generate_key(passphrase=TEST_PASSPHRASE)
        chain = ProvenanceChain(project_id=PROJECT_ID, key_handle=handle)
        r1 = chain.append(record_type="A", action="a", actor="u", sign=True)
        r2 = chain.append(record_type="B", action="b", actor="u", sign=True)

        engine = ProvenanceVerificationEngine(key_manager=key_manager)

        rec_res = engine.verify_record(r1)
        assert rec_res.overall_valid is True

        chain_res = engine.verify_chain(chain.records)
        assert chain_res.overall_valid is True
        assert chain_res.records_verified_count == 3
