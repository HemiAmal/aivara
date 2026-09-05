"""Unit and integration tests for AIVARA's Nonce, Sequence & Provenance Chain Engine (Phase 4.6).

Covers:
- Section A: Nonce generation (32 bytes, 64-char lowercase hex, CSPRNG, validation)
- Section B: Sequence numbering (genesis=0, normal=1, 2, 3..., gap & duplicate rejection)
- Section C: Genesis state (deterministic, correct previous hash anchor, validation)
- Section D: Hash linking (linear previous_record_hash continuity, broken links)
- Section E: Protected record hashing (sensitivity to sequence, nonce, project, signer, payload)
- Section F: Replay detection (duplicate nonce, duplicate sequence, duplicate record hash)
- Section G: Chain verification (valid chains, removed records, reordered records, tampered fields)
- Section H: Signature integration (Phase 4.5 signature verification, tampering detection, historical keys)
"""

from pathlib import Path
from typing import Any, Dict

import pytest

from aivara.crypto import (
    FIRST_NORMAL_SEQUENCE_NUMBER,
    GENESIS_PREVIOUS_RECORD_HASH,
    GENESIS_RECORD_TYPE,
    GENESIS_SEQUENCE_NUMBER,
    NONCE_BYTES_LEN,
    NONCE_HEX_LEN,
    BrokenChainError,
    ChainError,
    ChainRecord,
    ChainVerificationResult,
    ChainVerificationStatus,
    DuplicateNonceError,
    DuplicateRecordError,
    DuplicateSequenceError,
    InvalidNonceError,
    InvalidPreviousHashError,
    InvalidProjectError,
    InvalidSequenceError,
    KeyManager,
    ProvenanceChain,
    RecordHashMismatchError,
    ReplayDetectedError,
    SequenceGapError,
    compute_genesis_nonce,
    create_genesis_record,
    generate_nonce,
    validate_nonce,
    verify_chain,
)

TEST_PASSPHRASE = "Phase4.6_Test_Passphrase_2026!"
PROJECT_ID = "proj_assurance_alpha_01"


@pytest.fixture
def key_manager(tmp_path: Path) -> KeyManager:
    """Fixture providing a KeyManager in temporary storage."""
    return KeyManager(keys_dir=tmp_path / "keys")


@pytest.fixture
def chain() -> ProvenanceChain:
    """Fixture providing a fresh ProvenanceChain anchored with genesis."""
    return ProvenanceChain(project_id=PROJECT_ID)


class TestProvenanceChainEngine:
    """Test suite covering Phase 4.6 Nonce, Sequence, and Hash-Linked Chains."""

    # =================================================================
    # Section A: Nonce Generation
    # =================================================================

    def test_nonce_generation_length_and_format(self):
        """Nonce must be 32 bytes represented as 64 lowercase hexadecimal characters."""
        nonce = generate_nonce()

        assert isinstance(nonce, str)
        assert len(nonce) == NONCE_HEX_LEN
        assert bytes.fromhex(nonce)  # Valid hex
        assert nonce == nonce.lower()  # Lowercase enforcement
        assert len(bytes.fromhex(nonce)) == NONCE_BYTES_LEN

    def test_nonce_validation_accepts_valid(self):
        """validate_nonce accepts valid 64-char lowercase hex strings."""
        valid_nonce = "0123456789abcdef" * 4
        validate_nonce(valid_nonce)  # Must not raise

    def test_nonce_validation_rejects_malformed(self):
        """validate_nonce strictly rejects invalid length, uppercase, non-hex, or non-string."""
        malformed_nonces = [
            "A" * 64,  # Uppercase
            "a" * 63,  # Short
            "a" * 65,  # Long
            "g" * 64,  # Non-hex character
            "",  # Empty
            123456,  # Integer
            None,  # None
            " " * 64,  # Whitespace
        ]
        for bad in malformed_nonces:
            with pytest.raises(InvalidNonceError):
                validate_nonce(bad)  # type: ignore[arg-type]

    def test_nonce_randomness_and_uniqueness(self):
        """1000 generated nonces must all be completely unique (no counter or timestamp bias)."""
        nonces = {generate_nonce() for _ in range(1000)}
        assert len(nonces) == 1000

    # =================================================================
    # Section B: Sequence Numbers
    # =================================================================

    def test_sequence_numbering_starts_at_genesis_zero(self, chain: ProvenanceChain):
        """Genesis record must have sequence_number == 0."""
        assert chain.genesis_record.sequence_number == GENESIS_SEQUENCE_NUMBER
        assert chain.latest_sequence_number == 0
        assert len(chain) == 1

    def test_normal_records_start_at_one_and_increase_monotonically(
        self, chain: ProvenanceChain
    ):
        """Normal records strictly increment sequence: 1, 2, 3..."""
        r1 = chain.append(record_type="INFERENCE", action="run", actor="user1")
        assert r1.sequence_number == FIRST_NORMAL_SEQUENCE_NUMBER
        assert chain.latest_sequence_number == 1

        r2 = chain.append(record_type="INFERENCE", action="run", actor="user2")
        assert r2.sequence_number == 2
        assert chain.latest_sequence_number == 2

        r3 = chain.append(record_type="INFERENCE", action="run", actor="user3")
        assert r3.sequence_number == 3
        assert chain.latest_sequence_number == 3

    def test_negative_sequence_number_rejected(self, chain: ProvenanceChain):
        """Negative sequence numbers are rejected."""
        with pytest.raises(InvalidSequenceError):
            chain.append(
                record_type="INFERENCE",
                action="run",
                actor="user1",
                sequence_number=-1,
            )

    def test_sequence_gap_rejected(self, chain: ProvenanceChain):
        """Skipping sequence numbers (e.g. 0 -> 2) raises SequenceGapError."""
        with pytest.raises(SequenceGapError) as exc:
            chain.append(
                record_type="INFERENCE",
                action="run",
                actor="user1",
                sequence_number=2,  # Expected 1
            )
        assert exc.value.code == "SEQUENCE_GAP"

    def test_duplicate_sequence_number_rejected(self, chain: ProvenanceChain):
        """Reusing an already issued sequence number raises DuplicateSequenceError."""
        chain.append(record_type="INFERENCE", action="run", actor="user1")

        with pytest.raises(DuplicateSequenceError) as exc:
            chain.append(
                record_type="INFERENCE",
                action="run",
                actor="user2",
                sequence_number=1,  # Reusing sequence 1
            )
        assert exc.value.code == "DUPLICATE_SEQUENCE"

    # =================================================================
    # Section C: Genesis State
    # =================================================================

    def test_genesis_state_is_deterministic(self):
        """Two independently created genesis records for the same project must be identical."""
        g1 = create_genesis_record(PROJECT_ID)
        g2 = create_genesis_record(PROJECT_ID)

        assert g1.sequence_number == 0
        assert g2.sequence_number == 0
        assert g1.previous_record_hash == GENESIS_PREVIOUS_RECORD_HASH
        assert g2.previous_record_hash == GENESIS_PREVIOUS_RECORD_HASH
        assert g1.nonce == g2.nonce
        assert g1.record_hash == g2.record_hash
        assert g1.record_type == GENESIS_RECORD_TYPE

    def test_genesis_state_differs_across_projects(self):
        """Different project IDs produce distinct genesis records and distinct nonces."""
        g1 = create_genesis_record("project_one")
        g2 = create_genesis_record("project_two")

        assert g1.nonce != g2.nonce
        assert g1.record_hash != g2.record_hash

    def test_first_record_links_to_genesis_hash(self, chain: ProvenanceChain):
        """The first normal record (seq 1) must have previous_record_hash == genesis.record_hash."""
        r1 = chain.append(record_type="INFERENCE", action="run", actor="user1")

        assert r1.previous_record_hash == chain.genesis_record.record_hash
        assert r1.previous_record_hash != GENESIS_PREVIOUS_RECORD_HASH

    # =================================================================
    # Section D: Hash Linking
    # =================================================================

    def test_hash_linking_continuity(self, chain: ProvenanceChain):
        """Each subsequent record links to the exact hash of the preceding record."""
        r1 = chain.append(record_type="INFERENCE", action="run_1", actor="user1")
        r2 = chain.append(record_type="INFERENCE", action="run_2", actor="user2")
        r3 = chain.append(record_type="INFERENCE", action="run_3", actor="user3")

        assert r2.previous_record_hash == r1.record_hash
        assert r3.previous_record_hash == r2.record_hash

    def test_invalid_previous_record_hash_rejected_on_append(self, chain: ProvenanceChain):
        """Supplying an incorrect previous_record_hash on append raises InvalidPreviousHashError."""
        chain.append(record_type="INFERENCE", action="run_1", actor="user1")

        with pytest.raises(InvalidPreviousHashError) as exc:
            chain.append(
                record_type="INFERENCE",
                action="run_2",
                actor="user2",
                previous_record_hash="f" * 64,  # Incorrect previous hash
            )
        assert exc.value.code == "INVALID_PREVIOUS_HASH"

    # =================================================================
    # Section E: Protected Record Hashing
    # =================================================================

    def test_record_hash_consistency_and_verification(self, chain: ProvenanceChain):
        """Record's verify_record_hash confirms its stored hash matches canonical recomputed hash."""
        r1 = chain.append(record_type="INFERENCE", action="run_1", actor="user1")
        assert r1.verify_record_hash()
        assert r1.compute_record_hash() == r1.record_hash

    def test_modifying_any_field_changes_record_hash(self, chain: ProvenanceChain):
        """Modifying sequence, nonce, previous_record_hash, project, or signer changes the hash."""
        r = chain.append(
            record_type="INFERENCE",
            action="run_1",
            actor="user1",
            nonce="1" * 64,
            signer_key_id="2" * 64,
        )
        base_dict = r.model_dump()
        base_hash = r.record_hash

        # 1. Modify sequence_number
        d_seq = dict(base_dict, sequence_number=99)
        assert ChainRecord(**d_seq).compute_record_hash() != base_hash

        # 2. Modify nonce
        d_nonce = dict(base_dict, nonce="3" * 64)
        assert ChainRecord(**d_nonce).compute_record_hash() != base_hash

        # 3. Modify previous_record_hash
        d_prev = dict(base_dict, previous_record_hash="4" * 64)
        assert ChainRecord(**d_prev).compute_record_hash() != base_hash

        # 4. Modify project_id
        d_proj = dict(base_dict, project_id="other_project")
        assert ChainRecord(**d_proj).compute_record_hash() != base_hash

        # 5. Modify signer_key_id
        d_signer = dict(base_dict, signer_key_id="5" * 64)
        assert ChainRecord(**d_signer).compute_record_hash() != base_hash

    # =================================================================
    # Section F: Replay Detection
    # =================================================================

    def test_duplicate_nonce_rejected(self, chain: ProvenanceChain):
        """Reusing a nonce in the same chain raises DuplicateNonceError."""
        fixed_nonce = "a" * 64
        chain.append(record_type="INFERENCE", action="run_1", actor="user1", nonce=fixed_nonce)

        with pytest.raises(DuplicateNonceError) as exc:
            chain.append(record_type="INFERENCE", action="run_2", actor="user2", nonce=fixed_nonce)
        assert exc.value.code == "DUPLICATE_NONCE"

    def test_duplicate_record_hash_rejected(self, chain: ProvenanceChain):
        """Attempting to append a record with an identical record hash raises DuplicateRecordError."""
        r1 = chain.append(record_type="INFERENCE", action="run_1", actor="user1")

        # Attempt to append pre-constructed record identical to r1
        with pytest.raises(DuplicateSequenceError):
            chain.append_record(r1)

    # =================================================================
    # Section G: Chain Verification
    # =================================================================

    def test_valid_chain_verifies_successfully(self, chain: ProvenanceChain):
        """A properly linked, unmodified chain verifies cleanly."""
        chain.append(record_type="INFERENCE", action="run_1", actor="user1")
        chain.append(record_type="INFERENCE", action="run_2", actor="user2")
        chain.append(record_type="INFERENCE", action="run_3", actor="user3")

        result = chain.verify()
        assert result.is_valid
        assert result.status == ChainVerificationStatus.VALID
        assert result.verified_records_count == 4  # genesis + 3 records
        assert result.error_message is None

    def test_tampered_record_hash_detected(self, chain: ProvenanceChain):
        """If a record's content is tampered with, verification fails with HASH_MISMATCH."""
        chain.append(record_type="INFERENCE", action="run_1", actor="user1")
        chain.append(record_type="INFERENCE", action="run_2", actor="user2")

        records = chain.records
        # Tamper actor in record 1 without updating its hash
        tampered_dict = records[1].model_dump()
        tampered_dict["actor"] = "malicious_attacker"
        tampered_record = ChainRecord(**tampered_dict)

        tampered_records = [records[0], tampered_record, records[2]]
        result = verify_chain(tampered_records, project_id=chain.project_id)

        assert not result.is_valid
        assert result.status == ChainVerificationStatus.HASH_MISMATCH
        assert result.failed_sequence_number == 1

    def test_broken_hash_link_detected(self, chain: ProvenanceChain):
        """If a record's previous_record_hash does not match preceding record, BROKEN_CHAIN is reported."""
        chain.append(record_type="INFERENCE", action="run_1", actor="user1")
        chain.append(record_type="INFERENCE", action="run_2", actor="user2")

        records = chain.records
        # Break previous_record_hash of record 2
        d2 = records[2].model_dump()
        d2["previous_record_hash"] = "9" * 64
        # Also recompute record_hash so internal hash matches, but chain link is broken!
        tampered_r2 = ChainRecord(**d2)
        d2["record_hash"] = tampered_r2.compute_record_hash()
        rehashed_r2 = ChainRecord(**d2)

        broken_records = [records[0], records[1], rehashed_r2]
        result = verify_chain(broken_records, project_id=chain.project_id)

        assert not result.is_valid
        assert result.status == ChainVerificationStatus.BROKEN_CHAIN
        assert result.failed_sequence_number == 2

    def test_removed_record_detected(self, chain: ProvenanceChain):
        """Deleting/omitting a record from the chain creates a gap and breaks linkage."""
        chain.append(record_type="INFERENCE", action="run_1", actor="user1")
        chain.append(record_type="INFERENCE", action="run_2", actor="user2")
        chain.append(record_type="INFERENCE", action="run_3", actor="user3")

        records = chain.records
        # Remove record 2 (seq 2): list becomes [genesis, r1(seq 1), r3(seq 3)]
        omitted_records = [records[0], records[1], records[3]]

        result = verify_chain(omitted_records, project_id=chain.project_id)
        assert not result.is_valid
        assert result.status == ChainVerificationStatus.SEQUENCE_VIOLATION
        assert result.failed_sequence_number == 3

    def test_reordered_records_detected(self, chain: ProvenanceChain):
        """Swapping record positions violates sequence ordering and breaks hash linkage."""
        chain.append(record_type="INFERENCE", action="run_1", actor="user1")
        chain.append(record_type="INFERENCE", action="run_2", actor="user2")

        records = chain.records
        # Swap record 1 and record 2
        swapped_records = [records[0], records[2], records[1]]

        result = verify_chain(swapped_records, project_id=chain.project_id)
        assert not result.is_valid
        assert result.status == ChainVerificationStatus.SEQUENCE_VIOLATION

    def test_project_mismatch_detected(self, chain: ProvenanceChain):
        """A record with a foreign project_id fails chain verification."""
        chain.append(record_type="INFERENCE", action="run_1", actor="user1")

        records = chain.records
        foreign_dict = records[1].model_dump()
        foreign_dict["project_id"] = "foreign_project_999"
        foreign_record = ChainRecord(**foreign_dict)

        invalid_records = [records[0], foreign_record]
        result = verify_chain(invalid_records, project_id=chain.project_id)

        assert not result.is_valid
        assert result.status == ChainVerificationStatus.INVALID_STRUCTURE
        assert "Project mismatch" in result.error_message

    def test_duplicate_nonce_detected_in_chain_verification(self, chain: ProvenanceChain):
        """If two records in the chain reuse the same nonce, REPLAY_DETECTED is reported."""
        chain.append(record_type="INFERENCE", action="run_1", actor="user1")
        chain.append(record_type="INFERENCE", action="run_2", actor="user2")

        records = chain.records
        # Force record 2 to have record 1's nonce
        d2 = records[2].model_dump()
        d2["nonce"] = records[1].nonce
        d2_rec = ChainRecord(**d2)
        d2["record_hash"] = d2_rec.compute_record_hash()
        d2_final = ChainRecord(**d2)

        dup_records = [records[0], records[1], d2_final]
        result = verify_chain(dup_records, project_id=chain.project_id)

        assert not result.is_valid
        assert result.status == ChainVerificationStatus.REPLAY_DETECTED

    # =================================================================
    # Section H: Digital Signature Integration (Phase 4.5)
    # =================================================================

    def test_signed_records_verify_with_key_manager(
        self, key_manager: KeyManager
    ):
        """Records signed with active keys verify cryptographically during chain verification."""
        handle = key_manager.generate_key(passphrase=TEST_PASSPHRASE)
        chain = ProvenanceChain(project_id=PROJECT_ID, key_handle=handle)

        r1 = chain.append(
            record_type="INFERENCE",
            action="run_1",
            actor="user1",
            sign=True,
        )
        r2 = chain.append(
            record_type="INFERENCE",
            action="run_2",
            actor="user2",
            sign=True,
        )

        assert r1.signature is not None
        assert r2.signature is not None

        # Verify chain with key_manager
        result = chain.verify(key_manager=key_manager)
        assert result.is_valid
        assert result.status == ChainVerificationStatus.VALID
        assert result.signatures_verified_count == 2

    def test_tampered_signed_record_fails_signature_verification(
        self, key_manager: KeyManager
    ):
        """Tampering with a signed record causes signature verification to fail."""
        handle = key_manager.generate_key(passphrase=TEST_PASSPHRASE)
        chain = ProvenanceChain(project_id=PROJECT_ID, key_handle=handle)

        chain.append(
            record_type="INFERENCE",
            action="run_1",
            actor="user1",
            sign=True,
        )
        records = chain.records

        # Tamper payload and rehash record so hash check passes, but signature check fails!
        d1 = records[1].model_dump()
        d1["action"] = "tampered_action"
        d1_rec = ChainRecord(**d1)
        d1["record_hash"] = d1_rec.compute_record_hash()
        # Keep original signature over the old hash!
        rehashed_tampered = ChainRecord(**d1)

        tampered_chain = [records[0], rehashed_tampered]
        result = verify_chain(tampered_chain, project_id=chain.project_id, key_manager=key_manager)

        assert not result.is_valid
        assert result.status == ChainVerificationStatus.SIGNATURE_INVALID
        assert "Digital signature verification failed" in result.error_message

    def test_historical_key_verifies_historical_chain(
        self, key_manager: KeyManager
    ):
        """Chain signed by a key that was subsequently ROTATED verifies cleanly."""
        key1 = key_manager.generate_key(passphrase=TEST_PASSPHRASE)
        chain = ProvenanceChain(project_id=PROJECT_ID, key_handle=key1)

        chain.append(
            record_type="INFERENCE",
            action="run_1",
            actor="user1",
            sign=True,
        )

        # Rotate key1 to ROTATED
        key_manager.rotate_key(passphrase="NewPassphrase_2026!")

        # Key1 is now ROTATED
        old_handle = key_manager.load_key(key1.key_id, load_private=False, require_active=False)
        assert old_handle.is_rotated

        # Chain verification must succeed because historical keys can verify signatures
        result = chain.verify(key_manager=key_manager)
        assert result.is_valid
        assert result.status == ChainVerificationStatus.VALID
        assert result.signatures_verified_count == 1
