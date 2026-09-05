"""Comprehensive unit and integration tests for AIVARA's Tamper Detection Engine (Phase 4.10).

Covers:
  - Clean record evaluation (no tampering)
  - Clean chain evaluation (no tampering)
  - Payload modification (RECORD_PAYLOAD_TAMPERING)
  - Record hash modification (RECORD_PAYLOAD_TAMPERING / RECORD_HASH_TAMPERING)
  - Signature modification (SIGNATURE_TAMPERING)
  - Previous-record hash link break (CHAIN_TAMPERING)
  - Sequence modification (SEQUENCE_TAMPERING)
  - Genesis modification (GENESIS_TAMPERING)
  - Project context mismatch (PROJECT_CONTEXT_TAMPERING)
  - Multi-failure preservation
  - False-positive protections (malformed input, invalid schema, unknown key, permissive unsigned, rotated/revoked/expired keys)
  - Deterministic confidence semantics (1.0 for tampering, 0.0 otherwise)
  - Deterministic objective human-readable summaries
  - Evidence preservation
  - Non-recalculation assertion (detector consumes verification result directly)
  - TamperDetector orchestrator interface
"""

import json
from pathlib import Path
from typing import Any, Dict
from unittest.mock import patch

import pytest

from aivara.crypto import (
    ChainRecord,
    ChainTamperAssessment,
    FailureCode,
    KeyManager,
    KeyStatus,
    ProvenanceChain,
    TamperAssessment,
    TamperAssessmentStatus,
    TamperCategory,
    TamperDetector,
    TamperSeverity,
    UnifiedChainVerificationResult,
    UnifiedVerificationResult,
    VerificationEvidence,
    VerificationFailure,
    assess_chain_tampering,
    assess_record_tampering,
    create_genesis_record,
    verify_provenance_chain,
    verify_record,
)

TEST_PASSPHRASE = "Phase4.10_Test_Passphrase_2026!"
PROJECT_ID = "proj_tamper_detect_01"


@pytest.fixture
def key_manager(tmp_path: Path) -> KeyManager:
    """Fixture providing an isolated KeyManager instance."""
    return KeyManager(keys_dir=tmp_path / "keys")


@pytest.fixture
def chain(key_manager: KeyManager) -> ProvenanceChain:
    """Fixture providing a initialized ProvenanceChain."""
    return ProvenanceChain(project_id=PROJECT_ID)


# =====================================================================
# Tests: Clean Evaluation (No Tampering)
# =====================================================================


class TestCleanAssessments:
    """Tests verifying clean records and chains produce no tampering findings."""

    def test_clean_record_produces_no_tampering(self, chain: ProvenanceChain):
        """A valid record yields tampering_detected=False, status=CLEAN, confidence=0.0."""
        record = chain.append(record_type="INGEST", action="import", actor="user")
        ver_res = verify_record(record)

        assessment: TamperAssessment = assess_record_tampering(ver_res, record=record)

        assert assessment.tampering_detected is False
        assert assessment.status == TamperAssessmentStatus.CLEAN
        assert assessment.confidence == 0.0
        assert assessment.severity == TamperSeverity.NONE
        assert assessment.categories == []
        assert len(assessment.findings) == 0
        assert "No cryptographic integrity violations detected" in assessment.summary

    def test_clean_chain_produces_no_tampering(self, key_manager: KeyManager):
        """A valid chain yields tampering_detected=False, status=CLEAN, confidence=0.0."""
        handle = key_manager.generate_key(passphrase=TEST_PASSPHRASE)
        chain = ProvenanceChain(project_id=PROJECT_ID, key_handle=handle)
        chain.append(record_type="INGEST", action="import", actor="u1", sign=True)
        chain.append(record_type="FILTER", action="step2", actor="u2", sign=True)

        chain_ver = verify_provenance_chain(chain.records, key_manager=key_manager)
        assessment: ChainTamperAssessment = assess_chain_tampering(chain_ver, records=chain.records)

        assert assessment.tampering_detected is False
        assert assessment.status == TamperAssessmentStatus.CLEAN
        assert assessment.confidence == 0.0
        assert assessment.severity == TamperSeverity.NONE
        assert assessment.affected_sequences == []
        assert assessment.categories == []
        assert len(assessment.findings) == 0
        assert "No cryptographic integrity violations detected" in assessment.summary


# =====================================================================
# Tests: Cryptographic Tampering Categories
# =====================================================================


class TestTamperCategories:
    """Tests confirming precise mapping of verification discrepancies to tamper categories."""

    def test_payload_modification_produces_record_payload_tampering(self, chain: ProvenanceChain):
        """Altering a protected payload field produces RECORD_PAYLOAD_TAMPERING."""
        record = chain.append(record_type="INGEST", action="import", actor="user")
        tampered = record.model_dump()
        tampered["action"] = "tampered_action"

        ver_res = verify_record(tampered)
        assessment = assess_record_tampering(ver_res, record=tampered)

        assert assessment.tampering_detected is True
        assert assessment.status == TamperAssessmentStatus.INTEGRITY_VIOLATION
        assert assessment.confidence == 1.0
        assert assessment.severity == TamperSeverity.HIGH
        assert TamperCategory.RECORD_PAYLOAD_TAMPERING in assessment.categories
        assert len(assessment.findings) >= 1
        assert assessment.findings[0].failure_code == FailureCode.RECORD_HASH_MISMATCH
        assert "Cryptographic integrity violation detected" in assessment.summary

    def test_record_hash_modification_detected(self, chain: ProvenanceChain):
        """Modifying stored record_hash produces tampering assessment with preserved evidence."""
        record = chain.append(record_type="INGEST", action="import", actor="user")
        tampered = record.model_dump()
        tampered["record_hash"] = "d" * 64

        ver_res = verify_record(tampered)
        assessment = assess_record_tampering(ver_res, record=tampered)

        assert assessment.tampering_detected is True
        assert assessment.status == TamperAssessmentStatus.INTEGRITY_VIOLATION
        assert assessment.confidence == 1.0
        assert assessment.evidence is not None
        assert assessment.evidence.stored_record_hash == "d" * 64
        assert assessment.evidence.computed_record_hash == record.record_hash

    def test_signature_modification_produces_signature_tampering(self, key_manager: KeyManager):
        """Corrupting a signature produces SIGNATURE_TAMPERING."""
        handle = key_manager.generate_key(passphrase=TEST_PASSPHRASE)
        chain = ProvenanceChain(project_id=PROJECT_ID, key_handle=handle)
        record = chain.append(record_type="INFERENCE", action="predict", actor="ml", sign=True)

        tampered = record.model_dump()
        sig_list = list(tampered["signature"])
        sig_list[10] = "B" if sig_list[10] != "B" else "C"
        tampered["signature"] = "".join(sig_list)

        ver_res = verify_record(tampered, key_manager=key_manager)
        assessment = assess_record_tampering(ver_res, record=tampered)

        assert assessment.tampering_detected is True
        assert assessment.status == TamperAssessmentStatus.INTEGRITY_VIOLATION
        assert TamperCategory.SIGNATURE_TAMPERING in assessment.categories
        assert assessment.severity == TamperSeverity.HIGH

    def test_broken_previous_hash_produces_chain_tampering(self, chain: ProvenanceChain):
        """Altering previous_record_hash produces CHAIN_TAMPERING."""
        chain.append(record_type="INGEST", action="import", actor="user1")
        chain.append(record_type="INFERENCE", action="run", actor="user2")

        records = [r.model_dump() for r in chain.records]
        records[2]["previous_record_hash"] = "e" * 64

        chain_ver = verify_provenance_chain(records)
        assessment = assess_chain_tampering(chain_ver, records=records)

        assert assessment.tampering_detected is True
        assert assessment.status == TamperAssessmentStatus.INTEGRITY_VIOLATION
        assert TamperCategory.CHAIN_TAMPERING in assessment.categories
        assert 2 in assessment.affected_sequences

    def test_sequence_modification_produces_sequence_tampering(self, chain: ProvenanceChain):
        """A sequence gap or non-monotonic transition produces SEQUENCE_TAMPERING."""
        record = chain.append(record_type="INGEST", action="import", actor="user1")
        ver_res = verify_record(record, expected_sequence=99)
        assessment = assess_record_tampering(ver_res, record=record)

        assert assessment.tampering_detected is True
        assert TamperCategory.SEQUENCE_TAMPERING in assessment.categories
        assert assessment.severity == TamperSeverity.MEDIUM

    def test_genesis_modification_produces_genesis_tampering(self):
        """An invalid genesis record produces GENESIS_TAMPERING with CRITICAL severity."""
        genesis = create_genesis_record(PROJECT_ID)
        bad_genesis = genesis.model_dump()
        bad_genesis["previous_record_hash"] = "1" * 64  # Violates genesis anchor ("0"*64)

        chain_ver = verify_provenance_chain([bad_genesis])
        assessment = assess_chain_tampering(chain_ver, records=[bad_genesis])

        assert assessment.tampering_detected is True
        assert TamperCategory.GENESIS_TAMPERING in assessment.categories
        assert assessment.severity == TamperSeverity.CRITICAL

    def test_project_mismatch_produces_project_context_tampering(self, chain: ProvenanceChain):
        """Inserting a record from another project produces PROJECT_CONTEXT_TAMPERING."""
        chain.append(record_type="INGEST", action="import", actor="user1")
        records = [r.model_dump() for r in chain.records]
        records[1]["project_id"] = "foreign_project_999"

        chain_ver = verify_provenance_chain(records, expected_project_id=PROJECT_ID)
        assessment = assess_chain_tampering(chain_ver, records=records)

        assert assessment.tampering_detected is True
        assert TamperCategory.PROJECT_CONTEXT_TAMPERING in assessment.categories


# =====================================================================
# Tests: Multi-Failure Preservation
# =====================================================================


class TestMultiFailurePreservation:
    """Tests confirming multiple simultaneous failures are preserved and categorized."""

    def test_multiple_simultaneous_tamperings_preserved(self, key_manager: KeyManager):
        """A record with both altered payload and corrupted signature preserves both categories."""
        handle = key_manager.generate_key(passphrase=TEST_PASSPHRASE)
        chain = ProvenanceChain(project_id=PROJECT_ID, key_handle=handle)
        record = chain.append(record_type="INFERENCE", action="predict", actor="ml", sign=True)

        tampered = record.model_dump()
        tampered["action"] = "tampered_action"
        sig_list = list(tampered["signature"])
        sig_list[12] = "Z" if sig_list[12] != "Z" else "Y"
        tampered["signature"] = "".join(sig_list)

        ver_res = verify_record(tampered, key_manager=key_manager)
        assessment = assess_record_tampering(ver_res, record=tampered)

        assert assessment.tampering_detected is True
        assert TamperCategory.RECORD_PAYLOAD_TAMPERING in assessment.categories
        assert TamperCategory.SIGNATURE_TAMPERING in assessment.categories
        assert len(assessment.findings) >= 2


# =====================================================================
# Tests: False-Positive Protection (Mandatory Separation)
# =====================================================================


class TestFalsePositiveProtection:
    """Tests verifying that non-integrity issues are NOT classified as tampering."""

    def test_malformed_input_is_not_tampering(self):
        """Structurally malformed input yields UNVERIFIABLE_INPUT, tampering_detected=False."""
        malformed = {"project_id": PROJECT_ID}  # Missing required fields
        ver_res = verify_record(malformed)

        assessment = assess_record_tampering(ver_res, record=malformed)

        assert assessment.tampering_detected is False
        assert assessment.status == TamperAssessmentStatus.UNVERIFIABLE_INPUT
        assert assessment.confidence == 0.0
        assert assessment.severity == TamperSeverity.NONE
        assert len(assessment.categories) == 0

    def test_invalid_nonce_format_is_not_tampering(self, chain: ProvenanceChain):
        """An unparseable nonce format yields UNVERIFIABLE_INPUT, not tampering."""
        record = chain.append(record_type="TEST", action="run", actor="user")
        bad = record.model_dump()
        bad["nonce"] = "too_short"
        ver_res = verify_record(bad)

        assessment = assess_record_tampering(ver_res, record=bad)

        assert assessment.tampering_detected is False
        assert assessment.status == TamperAssessmentStatus.UNVERIFIABLE_INPUT
        assert assessment.confidence == 0.0

    def test_unknown_signer_key_is_not_tampering(self, key_manager: KeyManager, tmp_path: Path):
        """An unresolvable key yields AUTHENTICITY_UNAVAILABLE, tampering_detected=False."""
        handle = key_manager.generate_key(passphrase=TEST_PASSPHRASE)
        chain = ProvenanceChain(project_id=PROJECT_ID, key_handle=handle)
        record = chain.append(record_type="TEST", action="run", actor="user", sign=True)

        # Verify against an empty auditor KeyManager where handle.key_id is not stored
        auditor_km = KeyManager(keys_dir=tmp_path / "auditor_keys")
        ver_res = verify_record(record, key_manager=auditor_km)

        assessment = assess_record_tampering(ver_res, record=record)

        assert assessment.tampering_detected is False
        assert assessment.status == TamperAssessmentStatus.AUTHENTICITY_UNAVAILABLE
        assert assessment.confidence == 0.0
        assert assessment.severity == TamperSeverity.NONE

    def test_missing_signature_under_permissive_policy_is_not_tampering(self, chain: ProvenanceChain):
        """An unsigned record under default permissive policy is clean, not tampering."""
        record = chain.append(record_type="TEST", action="run", actor="user")
        ver_res = verify_record(record, allow_unsigned=True)

        assessment = assess_record_tampering(ver_res, record=record)

        assert assessment.tampering_detected is False
        assert assessment.status == TamperAssessmentStatus.CLEAN
        assert assessment.confidence == 0.0

    def test_rotated_key_valid_signature_is_not_tampering(self, key_manager: KeyManager):
        """A valid signature from a ROTATED key is NOT classified as tampering."""
        old_handle = key_manager.generate_key(passphrase=TEST_PASSPHRASE)
        chain = ProvenanceChain(project_id=PROJECT_ID, key_handle=old_handle)
        record = chain.append(record_type="TEST", action="run", actor="user", sign=True)

        # Rotate key
        key_manager.rotate_key(passphrase=TEST_PASSPHRASE)

        ver_res = verify_record(record, key_manager=key_manager)
        assessment = assess_record_tampering(ver_res, record=record)

        assert assessment.tampering_detected is False
        assert assessment.status == TamperAssessmentStatus.CLEAN
        assert assessment.confidence == 0.0

    def test_revoked_key_valid_signature_is_not_tampering(self, key_manager: KeyManager):
        """A valid signature from a REVOKED historical key is NOT classified as tampering."""
        handle = key_manager.generate_key(passphrase=TEST_PASSPHRASE)
        chain = ProvenanceChain(project_id=PROJECT_ID, key_handle=handle)
        record = chain.append(record_type="TEST", action="run", actor="user", sign=True)

        # Revoke key
        key_manager.revoke_key(handle.key_id, reason="Scheduled key retirement")

        ver_res = verify_record(record, key_manager=key_manager)
        assessment = assess_record_tampering(ver_res, record=record)

        assert assessment.tampering_detected is False
        assert assessment.status == TamperAssessmentStatus.CLEAN
        assert assessment.confidence == 0.0

    def test_expired_key_valid_signature_is_not_tampering(self, key_manager: KeyManager):
        """A valid signature from an EXPIRED historical key is NOT classified as tampering."""
        handle = key_manager.generate_key(passphrase=TEST_PASSPHRASE)
        chain = ProvenanceChain(project_id=PROJECT_ID, key_handle=handle)
        record = chain.append(record_type="TEST", action="run", actor="user", sign=True)

        # Simulate expiration
        meta_path = key_manager.keys_dir / f"{handle.key_id}.meta.json"
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
        meta["status"] = KeyStatus.EXPIRED.value
        meta_path.write_text(json.dumps(meta), encoding="utf-8")

        ver_res = verify_record(record, key_manager=key_manager)
        assessment = assess_record_tampering(ver_res, record=record)

        assert assessment.tampering_detected is False
        assert assessment.status == TamperAssessmentStatus.CLEAN
        assert assessment.confidence == 0.0


# =====================================================================
# Tests: Non-Recalculation Assertion & Security Semantics
# =====================================================================


class TestTamperDetectionArchitecture:
    """Tests proving the tamper detector consumes results without repeating crypto operations."""

    def test_detector_does_not_recalculate_hashes_or_signatures(self):
        """assess_record_tampering purely consumes UnifiedVerificationResult without hashing/signing."""
        # Create a synthetic UnifiedVerificationResult directly
        synthetic_evidence = VerificationEvidence(
            project_id=PROJECT_ID,
            sequence_number=1,
            stored_record_hash="a" * 64,
            computed_record_hash="b" * 64,
        )
        synthetic_result = UnifiedVerificationResult(
            overall_valid=False,
            record_valid=False,
            chain_valid=None,
            signature_valid=None,
            signature_present=False,
            failures=[
                VerificationFailure(
                    code=FailureCode.RECORD_HASH_MISMATCH,
                    layer="RECORD",
                    message="Simulated mismatch",
                    sequence_number=1,
                )
            ],
            warnings=[],
            evidence=synthetic_evidence,
        )

        with patch("aivara.crypto.hashing.hash_provenance_payload") as mock_hash, \
             patch("aivara.crypto.canonical.canonicalize_provenance_payload") as mock_canon:

            assessment = assess_record_tampering(synthetic_result)

            # Neither canonicalization nor hashing should be called during assessment
            mock_hash.assert_not_called()
            mock_canon.assert_not_called()

        assert assessment.tampering_detected is True
        assert TamperCategory.RECORD_PAYLOAD_TAMPERING in assessment.categories
        assert assessment.confidence == 1.0

    def test_tamper_detector_orchestrator_class(self, chain: ProvenanceChain):
        """TamperDetector wrapper provides convenient record and chain assessment methods."""
        record = chain.append(record_type="TEST", action="run", actor="user")
        ver_res = verify_record(record)
        chain_ver = verify_provenance_chain(chain.records)

        detector = TamperDetector()

        rec_assessment = detector.assess_record(ver_res, record=record)
        assert rec_assessment.tampering_detected is False

        chain_assessment = detector.assess_chain(chain_ver, records=chain.records)
        assert chain_assessment.tampering_detected is False

    def test_objective_phrasing_never_claims_malicious_attacker(self, chain: ProvenanceChain):
        """Assessments state 'Cryptographic integrity violation detected', never 'Malicious attacker'."""
        record = chain.append(record_type="TEST", action="run", actor="user")
        tampered = record.model_dump()
        tampered["action"] = "tampered"
        ver_res = verify_record(tampered)

        assessment = assess_record_tampering(ver_res, record=tampered)

        summary_lower = assessment.summary.lower()
        assert "cryptographic integrity violation detected" in summary_lower
        assert "malicious attacker" not in summary_lower
        assert "attacker" not in summary_lower
