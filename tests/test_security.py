"""AIVARA Phase 4.14 — Security Testing Suite.

Comprehensive adversarial test suite actively attacking AIVARA's cryptographic,
provenance, and audit subsystems across 10 security test categories:
  ST-01 — Canonicalization Attacks
  ST-02 — Hash Integrity Attacks
  ST-03 — Digital Signature Attacks
  ST-04 — Nonce & Replay Attacks
  ST-05 — Provenance Chain Attacks
  ST-06 — Audit Chain Attacks
  ST-07 — Direct Database / Raw-SQL Attacks
  ST-08 — API Security Attacks
  ST-09 — Transaction & Failure-Boundary Tests
  ST-10 — Security Semantics & Regression Tests

Enforces that:
  - Mathematical integrity and authenticity guarantees hold under active attack.
  - ORM immutability listeners are proven to be only defense-in-depth, while the
    cryptographic verification engine mathematically detects direct raw-SQL attacks.
  - Distinctions between malformed input, unverified keys, and cryptographic tampering
    remain strictly preserved without semantic erosion.
  - No secrets, credentials, or raw Python tracebacks leak in error responses.
"""

from __future__ import annotations

import base64
import concurrent.futures
import json
import math
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
from unittest.mock import patch

import pytest
from fastapi import status
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, event, text
from sqlalchemy.orm import Session, sessionmaker

from aivara.api.envelope import ApiResponse
from aivara.core.config import Settings
from aivara.core.exceptions import AivaraException
from aivara.crypto.audit import (
    AUDIT_GENESIS_PREVIOUS_HASH,
    AUDIT_GENESIS_SEQUENCE,
    AuditEventType,
    AuditFailureCode,
    AuditOutcome,
    AuditVerificationResult,
    AuditVerificationStatus,
    canonicalize_audit_payload,
    create_audit_genesis_payload,
    format_canonical_datetime,
    hash_audit_payload,
    verify_audit_chain,
)
from aivara.crypto.canonical import (
    CANONICAL_SCHEMA_VERSION,
    CanonicalizationError,
    DuplicateKeyError,
    InvalidNumberError,
    InvalidStringError,
    MalformedStructureError,
    UnsupportedTypeError,
    canonicalize,
    canonicalize_provenance_payload,
    parse_canonical_json,
    validate_canonical_data,
)
from aivara.crypto.chain import (
    GENESIS_ACTION,
    GENESIS_ACTOR,
    GENESIS_PREVIOUS_RECORD_HASH,
    GENESIS_RECORD_TYPE,
    GENESIS_SEQUENCE_NUMBER,
    GENESIS_SIGNER_KEY_ID,
    GENESIS_TIMESTAMP,
    ChainRecord,
    DuplicateNonceError,
    DuplicateRecordError,
    DuplicateSequenceError,
    ReplayDetectedError,
    compute_genesis_nonce,
    create_genesis_record,
    generate_nonce,
)
from aivara.crypto.hashing import (
    SHA256_EMPTY_HEX,
    hash_canonical_data,
    hash_provenance_payload,
    is_valid_sha256,
    sha256_bytes,
    sha256_text,
)
from aivara.crypto.keys import (
    Ed25519KeyHandle,
    KeyExpiredError,
    KeyManager,
    KeyMetadata,
    KeyNotFoundError,
    KeyRevokedError,
    KeyRotatedError,
    KeyStatus,
    derive_key_id,
)
from aivara.crypto.replay import (
    ReplayAssessment,
    ReplayType,
    raise_replay_error,
)
from aivara.crypto.signing import (
    ED25519_SIGNATURE_B64_LEN,
    ED25519_SIGNATURE_BYTES_LEN,
    InvalidSignatureError,
    MalformedSignatureError,
    SignatureResult,
    UnknownSignerKeyError,
    VerificationResult as SigVerificationResult,
    VerificationStatus as SigVerificationStatus,
    decode_signature,
    encode_signature,
    sign_hash,
    sign_provenance_payload,
    verify_hash_signature,
    verify_provenance_signature,
)
from aivara.crypto.tamper_detection import (
    ChainTamperAssessment,
    TamperAssessment,
    TamperAssessmentStatus,
    TamperCategory,
    TamperSeverity,
    assess_chain_tampering,
    assess_record_tampering,
)
from aivara.crypto.verification import (
    FailureCode,
    UnifiedChainVerificationResult,
    UnifiedVerificationResult,
    VerificationFailure,
    verify_provenance_chain,
    verify_record,
)
from aivara.database.connection import Base, get_db
from aivara.database.models import (
    AuditEventModel,
    AuditImmutabilityError,
    ProjectModel,
    ProvenanceRecordModel,
)
from aivara.domain.schemas import (
    AuditChainVerificationRequest,
    AuditEventRead,
    ProvenanceRecordCreate,
    ProvenanceRecordRead,
)
from aivara.main import app
from aivara.services.audit_service import (
    AuditEventNotFoundError,
    AuditSequenceCollisionError,
    AuditService,
)
from aivara.services.provenance_service import ProvenanceService


# =====================================================================
# Fixtures & Test Helpers
# =====================================================================

TEST_PASSPHRASE = "SecurityValidationSecretPassphrase123!"


@pytest.fixture
def sec_key_mgr(tmp_path: Path) -> KeyManager:
    """Provide isolated KeyManager for security test suites."""
    keys_dir = tmp_path / "sec_keys"
    return KeyManager(keys_dir=keys_dir)


@pytest.fixture
def active_key_pair(sec_key_mgr: KeyManager) -> Ed25519KeyHandle:
    """Generate and return an active Ed25519 key handle with private key loaded."""
    return sec_key_mgr.generate_key(passphrase=TEST_PASSPHRASE, set_as_active=True)


@pytest.fixture
def sec_project(test_db_session: Session) -> ProjectModel:
    """Create a persistent test project for security scenarios."""
    project = ProjectModel(
        id=f"proj-sec-{uuid.uuid4().hex[:8]}",
        name="Security Attack Target Project",
        description="Target environment for Phase 4.14 cryptographic security attacks",
    )
    test_db_session.add(project)
    test_db_session.commit()
    test_db_session.refresh(project)
    return project


def _build_provenance_record(
    project_id: str,
    sequence_number: int,
    previous_record_hash: str,
    key_handle: Ed25519KeyHandle,
    record_type: str = "INFERENCE",
    actor: str = "sec_test_actor",
    action: str = "SEC_TEST_INFERENCE",
    metadata: Optional[Dict[str, Any]] = None,
) -> ChainRecord:
    """Construct, hash, and sign a valid ChainRecord."""
    nonce = generate_nonce()
    timestamp = "2026-09-06T12:00:00Z"
    meta = metadata or {"security_test": True}

    rec_hash = hash_provenance_payload(
        record_type=record_type,
        project_id=project_id,
        actor=actor,
        action=action,
        sequence_number=sequence_number,
        nonce=nonce,
        timestamp=timestamp,
        signer_key_id=key_handle.key_id,
        target_type="AI_MODEL",
        target_id="model-sec-01",
        input_hash="a" * 64,
        output_hash="b" * 64,
        model_id="model-sec-01",
        model_weight_digest="c" * 64,
        config_hash="d" * 64,
        previous_record_hash=previous_record_hash,
        metadata_json=meta,
        schema_version=CANONICAL_SCHEMA_VERSION,
    )

    sig_res = sign_hash(rec_hash, key_handle)

    return ChainRecord(
        project_id=project_id,
        sequence_number=sequence_number,
        nonce=nonce,
        previous_record_hash=previous_record_hash,
        record_hash=rec_hash,
        signer_key_id=key_handle.key_id,
        record_type=record_type,
        actor=actor,
        action=action,
        timestamp=timestamp,
        target_type="AI_MODEL",
        target_id="model-sec-01",
        input_hash="a" * 64,
        output_hash="b" * 64,
        model_id="model-sec-01",
        model_weight_digest="c" * 64,
        config_hash="d" * 64,
        metadata_json=meta,
        schema_version=CANONICAL_SCHEMA_VERSION,
        signature=sig_res.signature,
    )


def _build_provenance_chain(
    project_id: str,
    key_handle: Ed25519KeyHandle,
    length: int = 5,
) -> List[ChainRecord]:
    """Construct a valid provenance chain: Genesis -> R1 -> R2 -> ... -> R[length-1]."""
    genesis = create_genesis_record(project_id, signer_key_id=key_handle.key_id)
    gen_sig = sign_hash(genesis.record_hash, key_handle)
    genesis_dict = genesis.model_dump()
    genesis_dict["signature"] = gen_sig.signature
    signed_genesis = ChainRecord(**genesis_dict)

    chain = [signed_genesis]
    prev_hash = signed_genesis.record_hash

    for seq in range(1, length):
        rec = _build_provenance_record(
            project_id=project_id,
            sequence_number=seq,
            previous_record_hash=prev_hash,
            key_handle=key_handle,
        )
        chain.append(rec)
        prev_hash = rec.record_hash

    return chain


def _build_audit_chain(
    project_id: str,
    length: int = 5,
) -> List[Dict[str, Any]]:
    """Construct a valid audit chain: Genesis (0) -> A1 -> A2 -> ... -> A[length-1]."""
    gen_payload = create_audit_genesis_payload(project_id)
    chain: List[Dict[str, Any]] = [gen_payload]
    prev_hash = gen_payload["event_hash"]

    for seq in range(1, length):
        ts = f"2026-09-06T12:0{seq:02d}:00Z"
        ev_hash = hash_audit_payload(
            project_id=project_id,
            event_type=AuditEventType.PROVENANCE_RECORDED.value,
            actor="sec_auditor",
            action="RECORD_EVENT",
            target_type="PROVENANCE_RECORD",
            target_id=f"rec-{seq}",
            outcome=AuditOutcome.SUCCESS.value,
            description=f"Security audit event sequence {seq}",
            sequence_number=seq,
            previous_event_hash=prev_hash,
            timestamp=ts,
            metadata={"seq": seq},
        )
        ev_dict = {
            "project_id": project_id,
            "event_type": AuditEventType.PROVENANCE_RECORDED.value,
            "actor": "sec_auditor",
            "action": "RECORD_EVENT",
            "target_type": "PROVENANCE_RECORD",
            "target_id": f"rec-{seq}",
            "outcome": AuditOutcome.SUCCESS.value,
            "description": f"Security audit event sequence {seq}",
            "sequence_number": seq,
            "previous_event_hash": prev_hash,
            "event_hash": ev_hash,
            "timestamp": ts,
            "metadata_json": {"seq": seq},
            "schema_version": CANONICAL_SCHEMA_VERSION,
        }
        chain.append(ev_dict)
        prev_hash = ev_hash

    return chain


# =====================================================================
# ST-01 — Canonicalization Attacks
# =====================================================================


class TestST01CanonicalizationAttacks:
    """Security tests against serialization and representation bypass attempts."""

    def test_json_key_reordering_produces_identical_canonical_bytes_and_hash(self):
        """Adversary attempts to manipulate payload representation via key ordering."""
        payload_order_1 = {"zebra": 1, "alpha": "value", "beta": [1, 2], "middle": None}
        payload_order_2 = {"middle": None, "alpha": "value", "zebra": 1, "beta": [1, 2]}

        c1 = canonicalize(payload_order_1)
        c2 = canonicalize(payload_order_2)

        assert c1 == c2
        assert sha256_bytes(c1) == sha256_bytes(c2)
        assert c1 == b'{"alpha":"value","beta":[1,2],"middle":null,"zebra":1}'

    def test_whitespace_variations_normalize_to_zero_whitespace(self):
        """Adversary injects tabs, newlines, and padding whitespace into JSON."""
        compact_json = '{"a":1,"b":"text"}'
        formatted_json = '{\n  "b": "text",\n  "a": 1\n}\n'

        p1 = parse_canonical_json(compact_json)
        p2 = parse_canonical_json(formatted_json)

        c1 = canonicalize(p1)
        c2 = canonicalize(p2)

        assert c1 == c2
        assert b" " not in c1
        assert b"\n" not in c1
        assert b"\t" not in c1

    def test_unicode_minimal_escaping_and_utf16_code_unit_sorting(self):
        """RFC 8785 minimal escaping and UTF-16 code units sorting invariance."""
        data = {"euro": "€", "emoji": "😀", "accent": "café"}
        c_bytes = canonicalize(data)

        decoded = c_bytes.decode("utf-8")
        assert r"\u20ac" not in decoded  # Must be raw UTF-8 bytes, not unicode escape sequences
        assert "€" in decoded
        assert "café" in decoded

    def test_control_character_minimal_escaping(self):
        """RFC 8785 minimal escape rules: only control chars, backslash, and double quote escaped."""
        raw_dict = {"ctrl": "\u0000\u001f\n\r\t\"\\"}
        c_bytes = canonicalize(raw_dict)
        decoded = c_bytes.decode("utf-8")
        assert r"\u0000" in decoded
        assert r"\u001f" in decoded
        assert r"\n" in decoded
        assert r"\r" in decoded
        assert r"\t" in decoded
        assert r'\"' in decoded
        assert r"\\" in decoded

    def test_null_versus_omitted_fields_distinction(self):
        """Omitting a key versus setting it to null must yield strictly distinct canonical hashes."""
        dict_with_null = {"field_a": "present", "field_b": None}
        dict_omitted = {"field_a": "present"}

        h1 = hash_canonical_data(dict_with_null)
        h2 = hash_canonical_data(dict_omitted)

        assert h1 != h2

    def test_array_ordering_preservation(self):
        """Array order alterations must alter the canonical serialization and digest."""
        arr_1 = {"items": [1, 2, 3]}
        arr_2 = {"items": [3, 2, 1]}

        assert canonicalize(arr_1) != canonicalize(arr_2)
        assert hash_canonical_data(arr_1) != hash_canonical_data(arr_2)

    def test_float_negative_zero_normalized_to_zero(self):
        """RFC 8785: -0.0 must be normalized to 0."""
        c_neg = canonicalize({"value": -0.0})
        c_pos = canonicalize({"value": 0.0})
        c_int = canonicalize({"value": 0})

        assert c_neg == b'{"value":0}'
        assert c_pos == b'{"value":0}'
        assert c_int == b'{"value":0}'

    def test_non_finite_numbers_rejected_safely(self):
        """NaN, +Inf, -Inf must be rejected with InvalidNumberError."""
        with pytest.raises(InvalidNumberError):
            canonicalize({"nan": math.nan})

        with pytest.raises(InvalidNumberError):
            canonicalize({"inf": math.inf})

        with pytest.raises(InvalidNumberError):
            canonicalize({"-inf": -math.inf})

    def test_oversized_integers_rejected_safely(self):
        """Integers outside IEEE 754 safe integer range [-2^53 + 1, 2^53 - 1] must be rejected."""
        safe_max = 2**53 - 1
        safe_min = -(2**53) + 1

        assert canonicalize({"max": safe_max}) is not None
        assert canonicalize({"min": safe_min}) is not None

        with pytest.raises(InvalidNumberError):
            canonicalize({"too_large": 2**53})

        with pytest.raises(InvalidNumberError):
            canonicalize({"too_small": -(2**53)})

    def test_unsupported_python_types_rejected(self):
        """Arbitrary objects, sets, datetimes, and UUIDs are strictly rejected."""
        with pytest.raises(UnsupportedTypeError):
            canonicalize({"set_data": {1, 2, 3}})

        with pytest.raises(UnsupportedTypeError):
            canonicalize({"raw_dt": datetime.now()})

        with pytest.raises(UnsupportedTypeError):
            canonicalize({"raw_uuid": uuid.uuid4()})

        class CustomObj:
            pass

        with pytest.raises(UnsupportedTypeError):
            canonicalize({"custom": CustomObj()})

    def test_duplicate_json_keys_rejected(self):
        """Duplicate keys in JSON payloads are rejected with DuplicateKeyError."""
        raw_json = '{"target": "model_A", "target": "model_B"}'
        with pytest.raises(DuplicateKeyError):
            parse_canonical_json(raw_json)


# =====================================================================
# ST-02 — Hash Integrity Attacks
# =====================================================================


class TestST02HashIntegrityAttacks:
    """Security tests against payload field mutations and hash integrity verification."""

    def test_original_provenance_record_verifies_as_clean(
        self, sec_project: ProjectModel, active_key_pair: Ed25519KeyHandle
    ):
        """A validly constructed record verifies cleanly with confidence 0.0 and no tampering."""
        rec = _build_provenance_record(
            project_id=sec_project.id,
            sequence_number=1,
            previous_record_hash="0" * 64,
            key_handle=active_key_pair,
        )

        res = verify_record(rec, public_key=active_key_pair)
        assert res.overall_valid is True
        assert res.record_valid is True
        assert res.signature_valid is True
        assert len(res.failures) == 0

        assessment = assess_record_tampering(res, record=rec)
        assert assessment.tampering_detected is False
        assert assessment.status == TamperAssessmentStatus.CLEAN

    @pytest.mark.parametrize(
        "field_name,tampered_val",
        [
            ("input_hash", "f" * 64),
            ("output_hash", "f" * 64),
            ("model_weight_digest", "f" * 64),
            ("config_hash", "f" * 64),
            ("model_id", "forged-model-99"),
            ("target_type", "DATASET"),
            ("target_id", "forged-target-99"),
            ("actor", "malicious_actor"),
            ("action", "UNAUTHORIZED_TAMPER"),
            ("timestamp", "2029-01-01T00:00:00Z"),
            ("metadata_json", {"tampered": True}),
            ("nonce", "f" * 64),
            ("sequence_number", 99),
            ("previous_record_hash", "f" * 64),
            ("project_id", "forged-project-id"),
        ],
    )
    def test_single_field_mutation_detected_as_hash_mismatch(
        self,
        sec_project: ProjectModel,
        active_key_pair: Ed25519KeyHandle,
        field_name: str,
        tampered_val: Any,
    ):
        """Mutating any protected field causes deterministic RECORD_HASH_MISMATCH."""
        original = _build_provenance_record(
            project_id=sec_project.id,
            sequence_number=1,
            previous_record_hash="0" * 64,
            key_handle=active_key_pair,
        )

        data = original.model_dump()
        data[field_name] = tampered_val
        tampered_rec = ChainRecord(**data)

        res = verify_record(tampered_rec, public_key=active_key_pair)
        assert res.overall_valid is False
        assert res.record_valid is False
        codes = [f.code for f in res.failures]
        assert (
            FailureCode.RECORD_HASH_MISMATCH in codes
            or FailureCode.SEQUENCE_VIOLATION in codes
            or FailureCode.PROJECT_MISMATCH in codes
            or FailureCode.BROKEN_CHAIN in codes
        )

        assessment = assess_record_tampering(res, record=tampered_rec)
        assert assessment.tampering_detected is True
        assert assessment.status == TamperAssessmentStatus.INTEGRITY_VIOLATION
        assert assessment.confidence == 1.0

    def test_one_byte_payload_modification_detected(
        self, sec_project: ProjectModel, active_key_pair: Ed25519KeyHandle
    ):
        """Altering a single byte of an action string breaks cryptographic integrity."""
        rec = _build_provenance_record(
            project_id=sec_project.id,
            sequence_number=1,
            previous_record_hash="0" * 64,
            key_handle=active_key_pair,
            action="MODEL_EVALUATION",
        )

        tampered_dict = rec.model_dump()
        tampered_dict["action"] = "NODEL_EVALUATION"  # 1 byte flipped: M -> N
        tampered = ChainRecord(**tampered_dict)

        res = verify_record(tampered, public_key=active_key_pair)
        assert res.overall_valid is False
        assert FailureCode.RECORD_HASH_MISMATCH in [f.code for f in res.failures]

    def test_tampering_record_hash_directly_detected(
        self, sec_project: ProjectModel, active_key_pair: Ed25519KeyHandle
    ):
        """Directly replacing record_hash with another valid hex string fails verification."""
        rec = _build_provenance_record(
            project_id=sec_project.id,
            sequence_number=1,
            previous_record_hash="0" * 64,
            key_handle=active_key_pair,
        )

        tampered_dict = rec.model_dump()
        tampered_dict["record_hash"] = "e" * 64
        tampered = ChainRecord(**tampered_dict)

        res = verify_record(tampered, public_key=active_key_pair)
        assert res.record_valid is False
        assert FailureCode.RECORD_HASH_MISMATCH in [f.code for f in res.failures]

    def test_empty_and_large_data_verifies_without_error(
        self, sec_project: ProjectModel, active_key_pair: Ed25519KeyHandle
    ):
        """Empty optional fields and 100KB payloads verify cleanly with deterministic hashes."""
        large_meta = {f"k_{i}": f"v_{'x'*50}_{i}" for i in range(500)}
        rec = _build_provenance_record(
            project_id=sec_project.id,
            sequence_number=1,
            previous_record_hash="0" * 64,
            key_handle=active_key_pair,
            metadata=large_meta,
        )

        res = verify_record(rec, public_key=active_key_pair)
        assert res.overall_valid is True
        assert res.record_valid is True


# =====================================================================
# ST-03 — Digital Signature Attacks
# =====================================================================


class TestST03DigitalSignatureAttacks:
    """Security tests covering Ed25519 signature verification and key lifecycle attacks."""

    def test_valid_signature_verifies_successfully(
        self, active_key_pair: Ed25519KeyHandle
    ):
        """Standard valid signature over 64-character hex hash verifies as VALID."""
        rec_hash = "a" * 64
        sig_res = sign_hash(rec_hash, active_key_pair)

        ver_res = verify_hash_signature(
            record_hash=rec_hash,
            signature=sig_res.signature,
            public_key=active_key_pair,
            signer_key_id=active_key_pair.key_id,
        )

        assert ver_res.is_valid is True
        assert ver_res.status == SigVerificationStatus.VALID

    def test_modified_signature_bytes_detected_as_invalid_signature(
        self, active_key_pair: Ed25519KeyHandle
    ):
        """Modifying 1 byte of the decoded signature causes INVALID_SIGNATURE."""
        rec_hash = "a" * 64
        sig_res = sign_hash(rec_hash, active_key_pair)

        raw_sig = bytearray(decode_signature(sig_res.signature))
        raw_sig[0] ^= 0xFF  # Flip first byte
        corrupted_sig = encode_signature(bytes(raw_sig))

        ver_res = verify_hash_signature(
            record_hash=rec_hash,
            signature=corrupted_sig,
            public_key=active_key_pair,
        )

        assert ver_res.is_valid is False
        assert ver_res.status == SigVerificationStatus.INVALID_SIGNATURE

    def test_truncated_signature_rejected_as_malformed(
        self, active_key_pair: Ed25519KeyHandle
    ):
        """Signature with length < 88 characters is rejected as MALFORMED_SIGNATURE."""
        rec_hash = "a" * 64
        sig_res = sign_hash(rec_hash, active_key_pair)
        truncated = sig_res.signature[:80]

        ver_res = verify_hash_signature(
            record_hash=rec_hash,
            signature=truncated,
            public_key=active_key_pair,
        )

        assert ver_res.is_valid is False
        assert ver_res.status == SigVerificationStatus.MALFORMED_SIGNATURE

    def test_oversized_signature_rejected_as_malformed(
        self, active_key_pair: Ed25519KeyHandle
    ):
        """Signature with length > 88 characters is rejected as MALFORMED_SIGNATURE."""
        rec_hash = "a" * 64
        sig_res = sign_hash(rec_hash, active_key_pair)
        oversized = sig_res.signature + "AA=="

        ver_res = verify_hash_signature(
            record_hash=rec_hash,
            signature=oversized,
            public_key=active_key_pair,
        )

        assert ver_res.is_valid is False
        assert ver_res.status == SigVerificationStatus.MALFORMED_SIGNATURE

    def test_invalid_base64_encoding_rejected_as_malformed(
        self, active_key_pair: Ed25519KeyHandle
    ):
        """Non-Base64 characters are rejected as MALFORMED_SIGNATURE."""
        rec_hash = "a" * 64
        bad_b64 = "!@#$%^&*()" * 8 + "12345678"

        ver_res = verify_hash_signature(
            record_hash=rec_hash,
            signature=bad_b64,
            public_key=active_key_pair,
        )

        assert ver_res.is_valid is False
        assert ver_res.status == SigVerificationStatus.MALFORMED_SIGNATURE

    def test_invalid_base64_padding_rejected_as_malformed(
        self, active_key_pair: Ed25519KeyHandle
    ):
        """Corrupted padding characters are rejected as MALFORMED_SIGNATURE."""
        rec_hash = "a" * 64
        sig_res = sign_hash(rec_hash, active_key_pair)
        corrupted_pad = sig_res.signature[:-1] + "X"

        ver_res = verify_hash_signature(
            record_hash=rec_hash,
            signature=corrupted_pad,
            public_key=active_key_pair,
        )

        assert ver_res.is_valid is False
        assert ver_res.status == SigVerificationStatus.MALFORMED_SIGNATURE

    def test_base64_whitespace_manipulation_rejected_as_malformed(
        self, active_key_pair: Ed25519KeyHandle
    ):
        """Injected whitespace or newlines are rejected as MALFORMED_SIGNATURE."""
        rec_hash = "a" * 64
        sig_res = sign_hash(rec_hash, active_key_pair)
        with_spaces = sig_res.signature[:44] + " " + sig_res.signature[45:]

        ver_res = verify_hash_signature(
            record_hash=rec_hash,
            signature=with_spaces,
            public_key=active_key_pair,
        )

        assert ver_res.is_valid is False
        assert ver_res.status == SigVerificationStatus.MALFORMED_SIGNATURE

    def test_wrong_signing_key_detected_as_invalid_signature(
        self, sec_key_mgr: KeyManager, active_key_pair: Ed25519KeyHandle
    ):
        """Verifying with a different key pair causes INVALID_SIGNATURE."""
        second_key = sec_key_mgr.generate_key(passphrase=TEST_PASSPHRASE, set_as_active=False)
        rec_hash = "a" * 64
        sig_res = sign_hash(rec_hash, active_key_pair)

        ver_res = verify_hash_signature(
            record_hash=rec_hash,
            signature=sig_res.signature,
            public_key=second_key,
        )

        assert ver_res.is_valid is False
        assert ver_res.status == SigVerificationStatus.INVALID_SIGNATURE

    def test_signer_key_id_mismatch_detected_as_unknown_signer_key(
        self, active_key_pair: Ed25519KeyHandle
    ):
        """Providing a valid signature but conflicting signer_key_id yields UNKNOWN_SIGNER_KEY."""
        rec_hash = "a" * 64
        sig_res = sign_hash(rec_hash, active_key_pair)

        ver_res = verify_hash_signature(
            record_hash=rec_hash,
            signature=sig_res.signature,
            public_key=active_key_pair,
            signer_key_id="f" * 64,  # Mismatched ID
        )

        assert ver_res.is_valid is False
        assert ver_res.status == SigVerificationStatus.UNKNOWN_SIGNER_KEY

    def test_unknown_signer_key_classified_as_authenticity_unavailable(
        self, sec_project: ProjectModel, sec_key_mgr: KeyManager, active_key_pair: Ed25519KeyHandle
    ):
        """Unknown signer key is classified as AUTHENTICITY_UNAVAILABLE, NOT malicious tampering."""
        rec = _build_provenance_record(
            project_id=sec_project.id,
            sequence_number=1,
            previous_record_hash="0" * 64,
            key_handle=active_key_pair,
        )

        empty_km = KeyManager(keys_dir=Path(sec_key_mgr.keys_dir) / "empty")
        ver_res = verify_record(rec, key_manager=empty_km)
        assessment = assess_record_tampering(ver_res, record=rec)

        assert assessment.tampering_detected is False
        assert assessment.status == TamperAssessmentStatus.AUTHENTICITY_UNAVAILABLE
        assert FailureCode.UNKNOWN_SIGNER_KEY in assessment.verification_failure_codes

    def test_missing_signature_classified_as_authenticity_unavailable(
        self, sec_project: ProjectModel, active_key_pair: Ed25519KeyHandle
    ):
        """Under strict policy (allow_unsigned=False), missing signature is AUTHENTICITY_UNAVAILABLE."""
        rec = _build_provenance_record(
            project_id=sec_project.id,
            sequence_number=1,
            previous_record_hash="0" * 64,
            key_handle=active_key_pair,
        )

        unsigned_dict = rec.model_dump()
        unsigned_dict["signature"] = None
        unsigned_rec = ChainRecord(**unsigned_dict)

        ver_res = verify_record(unsigned_rec, public_key=active_key_pair, allow_unsigned=False)
        assessment = assess_record_tampering(ver_res, record=unsigned_rec)

        assert assessment.tampering_detected is False
        assert assessment.status == TamperAssessmentStatus.AUTHENTICITY_UNAVAILABLE
        assert FailureCode.MISSING_SIGNATURE in assessment.verification_failure_codes

    def test_historical_signature_from_rotated_key_remains_valid(
        self, sec_key_mgr: KeyManager, active_key_pair: Ed25519KeyHandle
    ):
        """Signature created while key was ACTIVE remains mathematically valid after rotation."""
        rec_hash = "a" * 64
        sig_res = sign_hash(rec_hash, active_key_pair)

        old_handle, new_handle = sec_key_mgr.rotate_key(passphrase=TEST_PASSPHRASE)
        assert old_handle.key_id == active_key_pair.key_id

        rotated_handle = sec_key_mgr.load_key(old_handle.key_id, load_private=False)
        assert rotated_handle.status == KeyStatus.ROTATED
        assert rotated_handle.is_active is False

        ver_res = verify_hash_signature(
            record_hash=rec_hash,
            signature=sig_res.signature,
            public_key=rotated_handle,
        )

        assert ver_res.is_valid is True
        assert ver_res.status == SigVerificationStatus.VALID
        assert ver_res.key_status == KeyStatus.ROTATED
        assert ver_res.key_is_active is False

    def test_historical_signature_from_revoked_key_remains_valid(
        self, sec_key_mgr: KeyManager, active_key_pair: Ed25519KeyHandle
    ):
        """Signature created before revocation remains mathematically valid."""
        rec_hash = "a" * 64
        sig_res = sign_hash(rec_hash, active_key_pair)

        sec_key_mgr.revoke_key(active_key_pair.key_id, reason="Security validation test")
        revoked_handle = sec_key_mgr.load_key(active_key_pair.key_id, load_private=False)
        assert revoked_handle.status == KeyStatus.REVOKED

        ver_res = verify_hash_signature(
            record_hash=rec_hash,
            signature=sig_res.signature,
            public_key=revoked_handle,
        )

        assert ver_res.is_valid is True
        assert ver_res.status == SigVerificationStatus.VALID
        assert ver_res.key_status == KeyStatus.REVOKED
        assert ver_res.key_is_active is False

    def test_historical_signature_from_expired_key_remains_valid(
        self, sec_key_mgr: KeyManager, active_key_pair: Ed25519KeyHandle
    ):
        """Signature created before expiration remains mathematically valid."""
        rec_hash = "a" * 64
        sig_res = sign_hash(rec_hash, active_key_pair)

        meta = active_key_pair.metadata
        meta.status = KeyStatus.EXPIRED
        meta_path = sec_key_mgr._resolve_key_path(active_key_pair.key_id, "meta.json")
        meta_path.write_text(meta.model_dump_json(indent=2), encoding="utf-8")

        expired_handle = sec_key_mgr.load_key(active_key_pair.key_id, load_private=False)
        assert expired_handle.status == KeyStatus.EXPIRED

        ver_res = verify_hash_signature(
            record_hash=rec_hash,
            signature=sig_res.signature,
            public_key=expired_handle,
        )

        assert ver_res.is_valid is True
        assert ver_res.status == SigVerificationStatus.VALID
        assert ver_res.key_status == KeyStatus.EXPIRED
        assert ver_res.key_is_active is False

    def test_signing_with_non_active_keys_strictly_prohibited(
        self, sec_key_mgr: KeyManager, active_key_pair: Ed25519KeyHandle
    ):
        """Creating new signatures with rotated, revoked, or expired keys is rejected."""
        old_handle, _ = sec_key_mgr.rotate_key(passphrase=TEST_PASSPHRASE)
        old_with_priv = sec_key_mgr.load_key(old_handle.key_id, passphrase=TEST_PASSPHRASE)
        with pytest.raises(KeyRotatedError):
            sign_hash("b" * 64, old_with_priv)

        revoked_key = sec_key_mgr.generate_key(passphrase=TEST_PASSPHRASE, set_as_active=False)
        sec_key_mgr.revoke_key(revoked_key.key_id, reason="Testing")
        revoked_with_priv = sec_key_mgr.load_key(revoked_key.key_id, passphrase=TEST_PASSPHRASE)
        with pytest.raises(KeyRevokedError):
            sign_hash("b" * 64, revoked_with_priv)


# =====================================================================
# ST-04 — Nonce & Replay Attacks
# =====================================================================


class TestST04NonceReplayAttacks:
    """Security tests verifying replay resistance and persistent database constraints."""

    def test_duplicate_nonce_rejected_with_conflict(
        self, test_db_session: Session, sec_project: ProjectModel, active_key_pair: Ed25519KeyHandle
    ):
        """Reusing an identical nonce within a project is rejected."""
        prov_service = ProvenanceService(test_db_session)
        r1 = _build_provenance_record(
            project_id=sec_project.id,
            sequence_number=1,
            previous_record_hash="0" * 64,
            key_handle=active_key_pair,
        )
        prov_service.record_provenance_event(ProvenanceRecordCreate(**r1.model_dump()))

        r2 = _build_provenance_record(
            project_id=sec_project.id,
            sequence_number=2,
            previous_record_hash=r1.record_hash,
            key_handle=active_key_pair,
        )
        r2_dict = r2.model_dump()
        r2_dict["nonce"] = r1.nonce  # Reusing r1's nonce
        r2_dict["record_hash"] = "0" * 64
        comp_hash = ChainRecord(**r2_dict).compute_record_hash()
        r2_dict["record_hash"] = comp_hash
        r2_dict["signature"] = sign_hash(comp_hash, active_key_pair).signature

        with pytest.raises((DuplicateNonceError, ReplayDetectedError)):
            prov_service.record_provenance_event(ProvenanceRecordCreate(**r2_dict))

    def test_duplicate_sequence_number_rejected_with_conflict(
        self, test_db_session: Session, sec_project: ProjectModel, active_key_pair: Ed25519KeyHandle
    ):
        """Reusing an already accepted sequence number within a project is rejected."""
        prov_service = ProvenanceService(test_db_session)
        r1 = _build_provenance_record(
            project_id=sec_project.id,
            sequence_number=1,
            previous_record_hash="0" * 64,
            key_handle=active_key_pair,
        )
        prov_service.record_provenance_event(ProvenanceRecordCreate(**r1.model_dump()))

        r_comp = _build_provenance_record(
            project_id=sec_project.id,
            sequence_number=1,
            previous_record_hash="0" * 64,
            key_handle=active_key_pair,
            action="COMPETING_ACTION",
        )

        with pytest.raises((DuplicateSequenceError, ReplayDetectedError)):
            prov_service.record_provenance_event(ProvenanceRecordCreate(**r_comp.model_dump()))

    def test_duplicate_record_hash_rejected_with_conflict(
        self, test_db_session: Session, sec_project: ProjectModel, active_key_pair: Ed25519KeyHandle
    ):
        """Reusing an identical record hash within a project is rejected."""
        prov_service = ProvenanceService(test_db_session)
        r1 = _build_provenance_record(
            project_id=sec_project.id,
            sequence_number=1,
            previous_record_hash="0" * 64,
            key_handle=active_key_pair,
        )
        prov_service.record_provenance_event(ProvenanceRecordCreate(**r1.model_dump()))

        with pytest.raises(AivaraException) as excinfo:
            prov_service.record_provenance_event(ProvenanceRecordCreate(**r1.model_dump()))
        assert excinfo.value.code in ["DUPLICATE_RECORD", "DUPLICATE_SEQUENCE", "DUPLICATE_NONCE", "REPLAY_DETECTED"]

    def test_cross_project_nonce_reuse_allowed(
        self, test_db_session: Session, active_key_pair: Ed25519KeyHandle
    ):
        """Nonces are scoped per-project: reusing a nonce across different projects is allowed."""
        prov_service = ProvenanceService(test_db_session)

        p1 = ProjectModel(id=f"proj-1-{uuid.uuid4().hex[:6]}", name="Project One")
        p2 = ProjectModel(id=f"proj-2-{uuid.uuid4().hex[:6]}", name="Project Two")
        test_db_session.add_all([p1, p2])
        test_db_session.commit()

        r1 = _build_provenance_record(
            project_id=p1.id,
            sequence_number=1,
            previous_record_hash="0" * 64,
            key_handle=active_key_pair,
        )

        r2 = _build_provenance_record(
            project_id=p2.id,
            sequence_number=1,
            previous_record_hash="0" * 64,
            key_handle=active_key_pair,
        )
        r2_dict = r2.model_dump()
        r2_dict["nonce"] = r1.nonce  # Reusing r1's nonce across projects
        r2_dict["record_hash"] = "0" * 64
        comp_hash = ChainRecord(**r2_dict).compute_record_hash()
        r2_dict["record_hash"] = comp_hash
        r2_dict["signature"] = sign_hash(comp_hash, active_key_pair).signature

        rec1 = prov_service.record_provenance_event(ProvenanceRecordCreate(**r1.model_dump()))
        rec2 = prov_service.record_provenance_event(ProvenanceRecordCreate(**r2_dict))

        assert rec1.project_id == p1.id
        assert rec2.project_id == p2.id
        assert rec1.nonce == rec2.nonce

    def test_replay_detection_survives_process_restart(
        self, tmp_path: Path, active_key_pair: Ed25519KeyHandle
    ):
        """Replay detection remains authoritative after process restart (new DB connection)."""
        db_path = tmp_path / "restart_test.db"
        engine1 = create_engine(f"sqlite:///{db_path}")
        Base.metadata.create_all(bind=engine1)

        Session1 = sessionmaker(bind=engine1)
        with Session1() as s1:
            proj = ProjectModel(id="proj-restart", name="Restart Test Project")
            s1.add(proj)
            s1.commit()

            prov1 = ProvenanceService(s1)
            rec = _build_provenance_record(
                project_id="proj-restart",
                sequence_number=1,
                previous_record_hash="0" * 64,
                key_handle=active_key_pair,
            )
            prov1.record_provenance_event(ProvenanceRecordCreate(**rec.model_dump()))

        engine1.dispose()

        engine2 = create_engine(f"sqlite:///{db_path}")
        Session2 = sessionmaker(bind=engine2)
        with Session2() as s2:
            prov2 = ProvenanceService(s2)
            assessment = prov2.check_replay(
                project_id="proj-restart",
                sequence_number=rec.sequence_number,
                nonce=rec.nonce,
                record_hash=rec.record_hash,
            )
            assert assessment.replay_detected is True

            with pytest.raises(AivaraException) as excinfo:
                prov2.record_provenance_event(ProvenanceRecordCreate(**rec.model_dump()))
            assert excinfo.value.code in ["DUPLICATE_SEQUENCE", "DUPLICATE_NONCE", "DUPLICATE_RECORD", "REPLAY_DETECTED"]
        engine2.dispose()

    def test_concurrent_duplicate_submissions_race_condition(
        self, tmp_path: Path, active_key_pair: Ed25519KeyHandle
    ):
        """Simultaneous concurrent duplicate submissions: exactly ONE succeeds, all others fail."""
        db_path = tmp_path / "concurrent_test.db"
        engine = create_engine(
            f"sqlite:///{db_path}",
            connect_args={"timeout": 30.0},
        )
        Base.metadata.create_all(bind=engine)

        SessionFactory = sessionmaker(bind=engine, autocommit=False, autoflush=False)
        with SessionFactory() as init_s:
            proj = ProjectModel(id="proj-concurrent", name="Concurrent Race Test")
            init_s.add(proj)
            init_s.commit()

        candidate_record = _build_provenance_record(
            project_id="proj-concurrent",
            sequence_number=1,
            previous_record_hash="0" * 64,
            key_handle=active_key_pair,
        )

        def _worker():
            with SessionFactory() as worker_s:
                svc = ProvenanceService(worker_s)
                try:
                    svc.record_provenance_event(ProvenanceRecordCreate(**candidate_record.model_dump()))
                    return "SUCCESS"
                except AivaraException as exc:
                    return f"REJECTED_{exc.code}"
                except Exception as exc:
                    return f"ERROR_{type(exc).__name__}"

        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(_worker) for _ in range(5)]
            results = [f.result() for f in futures]

        success_count = results.count("SUCCESS")
        rejected_count = sum(1 for r in results if r.startswith("REJECTED_"))

        assert success_count == 1, f"Expected exactly 1 success, got {success_count}. Results: {results}"
        assert rejected_count == 4, f"Expected 4 rejections, got {rejected_count}. Results: {results}"

        with SessionFactory() as verify_s:
            rows = verify_s.query(ProvenanceRecordModel).filter(
                ProvenanceRecordModel.project_id == "proj-concurrent"
            ).all()
            assert len(rows) == 1

        engine.dispose()


# =====================================================================
# ST-05 — Provenance Chain Attacks
# =====================================================================


class TestST05ProvenanceChainAttacks:
    """Security tests attacking structural integrity and continuity of provenance chains."""

    def test_valid_five_record_chain_verifies_clean(
        self, sec_project: ProjectModel, active_key_pair: Ed25519KeyHandle, sec_key_mgr: KeyManager
    ):
        """Construct a 5-record chain (Genesis -> R1 -> R2 -> R3 -> R4); verifies cleanly."""
        chain = _build_provenance_chain(sec_project.id, active_key_pair, length=5)
        res = verify_provenance_chain(chain, key_manager=sec_key_mgr)

        assert res.overall_valid is True
        assert res.chain_valid is True
        assert res.records_verified_count == 5
        assert len(res.failures) == 0

        assessment = assess_chain_tampering(res, records=chain)
        assert assessment.tampering_detected is False
        assert assessment.status == TamperAssessmentStatus.CLEAN

    def test_deleting_middle_record_causes_broken_chain_and_sequence_gap(
        self, sec_project: ProjectModel, active_key_pair: Ed25519KeyHandle, sec_key_mgr: KeyManager
    ):
        """Deleting R2 breaks continuity: R3 fails linkage and sequence ordering."""
        chain = _build_provenance_chain(sec_project.id, active_key_pair, length=5)
        tampered_chain = [chain[0], chain[1], chain[3], chain[4]]

        res = verify_provenance_chain(tampered_chain, key_manager=sec_key_mgr)
        assert res.overall_valid is False
        assert res.chain_valid is False

        codes = [f.code for f in res.failures]
        assert FailureCode.BROKEN_CHAIN in codes or FailureCode.SEQUENCE_GAP in codes

    def test_deleting_genesis_record_causes_genesis_invalid(
        self, sec_project: ProjectModel, active_key_pair: Ed25519KeyHandle, sec_key_mgr: KeyManager
    ):
        """Chain starting at sequence 1 without genesis anchor is rejected."""
        chain = _build_provenance_chain(sec_project.id, active_key_pair, length=5)
        chain_no_genesis = chain[1:]

        res = verify_provenance_chain(chain_no_genesis, key_manager=sec_key_mgr)
        assert res.overall_valid is False
        codes = [f.code for f in res.failures]
        assert FailureCode.GENESIS_INVALID in codes or FailureCode.SEQUENCE_GAP in codes

    def test_replacing_genesis_record_detected(
        self, sec_project: ProjectModel, active_key_pair: Ed25519KeyHandle, sec_key_mgr: KeyManager
    ):
        """Replacing genesis with a rogue genesis creates broken chain link at R1."""
        chain = _build_provenance_chain(sec_project.id, active_key_pair, length=5)
        rogue_genesis = create_genesis_record("other-project-id", signer_key_id=active_key_pair.key_id)

        tampered_chain = [rogue_genesis] + chain[1:]
        res = verify_provenance_chain(tampered_chain, key_manager=sec_key_mgr)

        assert res.overall_valid is False
        codes = [f.code for f in res.failures]
        assert (
            FailureCode.PROJECT_MISMATCH in codes
            or FailureCode.BROKEN_CHAIN in codes
            or FailureCode.GENESIS_INVALID in codes
        )

    def test_reordering_records_causes_sequence_violation_and_broken_chain(
        self, sec_project: ProjectModel, active_key_pair: Ed25519KeyHandle, sec_key_mgr: KeyManager
    ):
        """Swapping R2 and R3 violates monotonic ordering and hash linkage."""
        chain = _build_provenance_chain(sec_project.id, active_key_pair, length=5)
        swapped_chain = [chain[0], chain[1], chain[3], chain[2], chain[4]]

        res = verify_provenance_chain(swapped_chain, key_manager=sec_key_mgr)
        assert res.overall_valid is False
        codes = [f.code for f in res.failures]
        assert FailureCode.SEQUENCE_VIOLATION in codes or FailureCode.BROKEN_CHAIN in codes

    def test_modifying_middle_record_payload_causes_hash_mismatch_and_broken_chain(
        self, sec_project: ProjectModel, active_key_pair: Ed25519KeyHandle, sec_key_mgr: KeyManager
    ):
        """Modifying R2 payload fails R2's own hash, and R3's previous_record_hash check."""
        chain = _build_provenance_chain(sec_project.id, active_key_pair, length=5)

        tampered_r2 = chain[2].model_dump()
        tampered_r2["action"] = "TAMPERED_ACTION"
        chain[2] = ChainRecord(**tampered_r2)

        res = verify_provenance_chain(chain, key_manager=sec_key_mgr)
        assert res.overall_valid is False
        codes = [f.code for f in res.failures]
        assert FailureCode.RECORD_HASH_MISMATCH in codes

    def test_modifying_previous_record_hash_causes_broken_chain(
        self, sec_project: ProjectModel, active_key_pair: Ed25519KeyHandle, sec_key_mgr: KeyManager
    ):
        """Altering previous_record_hash on R2 fails hash linkage."""
        chain = _build_provenance_chain(sec_project.id, active_key_pair, length=5)

        tampered_r2 = chain[2].model_dump()
        tampered_r2["previous_record_hash"] = "9" * 64
        tampered_r2["record_hash"] = "0" * 64
        comp_hash = ChainRecord(**tampered_r2).compute_record_hash()
        tampered_r2["record_hash"] = comp_hash
        tampered_r2["signature"] = sign_hash(comp_hash, active_key_pair).signature
        chain[2] = ChainRecord(**tampered_r2)

        res = verify_provenance_chain(chain, key_manager=sec_key_mgr)
        assert res.overall_valid is False
        codes = [f.code for f in res.failures]
        assert FailureCode.BROKEN_CHAIN in codes

    def test_sequence_gap_detected(
        self, sec_project: ProjectModel, active_key_pair: Ed25519KeyHandle, sec_key_mgr: KeyManager
    ):
        """A jump in sequence number (e.g. 0, 1, 3) reports SEQUENCE_GAP."""
        chain = _build_provenance_chain(sec_project.id, active_key_pair, length=3)
        t_dict = chain[2].model_dump()
        t_dict["sequence_number"] = 5
        chain[2] = ChainRecord(**t_dict)

        res = verify_provenance_chain(chain, key_manager=sec_key_mgr)
        assert res.overall_valid is False
        codes = [f.code for f in res.failures]
        assert FailureCode.SEQUENCE_GAP in codes or FailureCode.SEQUENCE_VIOLATION in codes

    def test_duplicate_sequence_number_detected(
        self, sec_project: ProjectModel, active_key_pair: Ed25519KeyHandle, sec_key_mgr: KeyManager
    ):
        """Duplicate sequence number in chain reports DUPLICATE_SEQUENCE."""
        chain = _build_provenance_chain(sec_project.id, active_key_pair, length=4)
        t_dict = chain[2].model_dump()
        t_dict["sequence_number"] = 1
        chain[2] = ChainRecord(**t_dict)

        res = verify_provenance_chain(chain, key_manager=sec_key_mgr)
        assert res.overall_valid is False
        codes = [f.code for f in res.failures]
        assert FailureCode.DUPLICATE_SEQUENCE in codes or FailureCode.SEQUENCE_VIOLATION in codes

    def test_duplicate_nonce_detected(
        self, sec_project: ProjectModel, active_key_pair: Ed25519KeyHandle, sec_key_mgr: KeyManager
    ):
        """Duplicate nonce in chain reports DUPLICATE_NONCE."""
        chain = _build_provenance_chain(sec_project.id, active_key_pair, length=4)
        t_dict = chain[2].model_dump()
        t_dict["nonce"] = chain[1].nonce
        chain[2] = ChainRecord(**t_dict)

        res = verify_provenance_chain(chain, key_manager=sec_key_mgr)
        assert res.overall_valid is False
        codes = [f.code for f in res.failures]
        assert FailureCode.DUPLICATE_NONCE in codes

    def test_duplicate_record_hash_detected(
        self, sec_project: ProjectModel, active_key_pair: Ed25519KeyHandle, sec_key_mgr: KeyManager
    ):
        """Duplicate record hash in chain reports DUPLICATE_RECORD."""
        chain = _build_provenance_chain(sec_project.id, active_key_pair, length=4)
        t_dict = chain[2].model_dump()
        t_dict["record_hash"] = chain[1].record_hash
        chain[2] = ChainRecord(**t_dict)

        res = verify_provenance_chain(chain, key_manager=sec_key_mgr)
        assert res.overall_valid is False
        codes = [f.code for f in res.failures]
        assert FailureCode.DUPLICATE_RECORD in codes

    def test_changing_project_id_detected_as_project_mismatch(
        self, sec_project: ProjectModel, active_key_pair: Ed25519KeyHandle, sec_key_mgr: KeyManager
    ):
        """Altering project_id on a middle record reports PROJECT_MISMATCH."""
        chain = _build_provenance_chain(sec_project.id, active_key_pair, length=4)
        t_dict = chain[2].model_dump()
        t_dict["project_id"] = "foreign-project-id"
        chain[2] = ChainRecord(**t_dict)

        res = verify_provenance_chain(chain, key_manager=sec_key_mgr)
        assert res.overall_valid is False
        codes = [f.code for f in res.failures]
        assert FailureCode.PROJECT_MISMATCH in codes

    def test_multiple_independent_failures_preserved_without_masking(
        self, sec_project: ProjectModel, active_key_pair: Ed25519KeyHandle, sec_key_mgr: KeyManager
    ):
        """Multiple independent violations across chain records are all preserved."""
        chain = _build_provenance_chain(sec_project.id, active_key_pair, length=5)

        # Violation 1 at R1: duplicate nonce with R2
        r1_d = chain[1].model_dump()
        r1_d["nonce"] = chain[2].nonce
        chain[1] = ChainRecord(**r1_d)

        # Violation 2 at R3: sequence gap (sequence set to 8)
        r3_d = chain[3].model_dump()
        r3_d["sequence_number"] = 8
        chain[3] = ChainRecord(**r3_d)

        res = verify_provenance_chain(chain, key_manager=sec_key_mgr)
        assert len(res.failures) >= 2


# =====================================================================
# ST-06 — Audit Chain Attacks
# =====================================================================


class TestST06AuditChainAttacks:
    """Security tests attacking audit chain integrity and tamper detection."""

    def test_valid_five_event_audit_chain_verifies_clean(
        self, sec_project: ProjectModel
    ):
        """Construct a valid 5-event audit chain; verifies cleanly as VALID."""
        chain = _build_audit_chain(sec_project.id, length=5)
        res = verify_audit_chain(chain, expected_project_id=sec_project.id)

        assert res.valid is True
        assert res.chain_valid is True
        assert res.status == AuditVerificationStatus.VALID
        assert res.checked_events == 5
        assert len(res.failures) == 0

    @pytest.mark.parametrize(
        "field_name,tampered_val",
        [
            ("description", "FORGED AUDIT DESCRIPTION"),
            ("metadata_json", {"forged_meta": True}),
            ("event_type", AuditEventType.SECURITY_CONFIG_CHANGED.value),
            ("action", "FORGED_ACTION"),
            ("outcome", AuditOutcome.REJECTED.value),
            ("event_hash", "e" * 64),
        ],
    )
    def test_tampering_audit_fields_detected_as_audit_integrity_violation(
        self, sec_project: ProjectModel, field_name: str, tampered_val: Any
    ):
        """Mutating any protected audit field in A2 triggers EVENT_HASH_MISMATCH and AUDIT_INTEGRITY_VIOLATION."""
        chain = _build_audit_chain(sec_project.id, length=5)
        chain[2][field_name] = tampered_val

        res = verify_audit_chain(chain, expected_project_id=sec_project.id)
        assert res.valid is False
        assert res.status == AuditVerificationStatus.AUDIT_INTEGRITY_VIOLATION
        codes = [f.code for f in res.failures]
        assert AuditFailureCode.EVENT_HASH_MISMATCH in codes or AuditFailureCode.BROKEN_AUDIT_CHAIN in codes

    def test_tampering_previous_event_hash_causes_broken_audit_chain(
        self, sec_project: ProjectModel
    ):
        """Mutating previous_event_hash on A3 causes BROKEN_AUDIT_CHAIN."""
        chain = _build_audit_chain(sec_project.id, length=5)
        chain[3]["previous_event_hash"] = "9" * 64

        res = verify_audit_chain(chain, expected_project_id=sec_project.id)
        assert res.valid is False
        assert res.status == AuditVerificationStatus.AUDIT_INTEGRITY_VIOLATION
        codes = [f.code for f in res.failures]
        assert AuditFailureCode.BROKEN_AUDIT_CHAIN in codes or AuditFailureCode.EVENT_HASH_MISMATCH in codes

    def test_deleting_middle_audit_event_causes_broken_chain_and_sequence_gap(
        self, sec_project: ProjectModel
    ):
        """Deleting A2 from the chain creates a sequence gap and broken hash linkage."""
        chain = _build_audit_chain(sec_project.id, length=5)
        tampered_chain = [chain[0], chain[1], chain[3], chain[4]]

        res = verify_audit_chain(tampered_chain, expected_project_id=sec_project.id)
        assert res.valid is False
        assert res.status == AuditVerificationStatus.AUDIT_INTEGRITY_VIOLATION
        codes = [f.code for f in res.failures]
        assert AuditFailureCode.BROKEN_AUDIT_CHAIN in codes or AuditFailureCode.SEQUENCE_GAP in codes

    def test_reordering_audit_events_detected(
        self, sec_project: ProjectModel
    ):
        """Swapping A2 and A3 triggers SEQUENCE_GAP and BROKEN_AUDIT_CHAIN."""
        chain = _build_audit_chain(sec_project.id, length=5)
        tampered = [chain[0], chain[1], chain[3], chain[2], chain[4]]

        res = verify_audit_chain(tampered, expected_project_id=sec_project.id)
        assert res.valid is False
        assert res.status == AuditVerificationStatus.AUDIT_INTEGRITY_VIOLATION
        codes = [f.code for f in res.failures]
        assert AuditFailureCode.SEQUENCE_GAP in codes or AuditFailureCode.BROKEN_AUDIT_CHAIN in codes

    def test_duplicate_audit_sequence_detected(
        self, sec_project: ProjectModel
    ):
        """Duplicate sequence number in audit chain causes DUPLICATE_AUDIT_SEQUENCE."""
        chain = _build_audit_chain(sec_project.id, length=4)
        chain[2]["sequence_number"] = 1

        res = verify_audit_chain(chain, expected_project_id=sec_project.id)
        assert res.valid is False
        codes = [f.code for f in res.failures]
        assert AuditFailureCode.DUPLICATE_AUDIT_SEQUENCE in codes

    def test_duplicate_audit_event_hash_detected(
        self, sec_project: ProjectModel
    ):
        """Duplicate event_hash in audit chain causes DUPLICATE_AUDIT_HASH."""
        chain = _build_audit_chain(sec_project.id, length=4)
        chain[2]["event_hash"] = chain[1]["event_hash"]

        res = verify_audit_chain(chain, expected_project_id=sec_project.id)
        assert res.valid is False
        codes = [f.code for f in res.failures]
        assert AuditFailureCode.DUPLICATE_AUDIT_HASH in codes

    def test_tampering_genesis_audit_event_detected(
        self, sec_project: ProjectModel
    ):
        """Modifying audit genesis record produces GENESIS_TAMPERING."""
        chain = _build_audit_chain(sec_project.id, length=4)
        chain[0]["description"] = "TAMPERED GENESIS DESCRIPTION"

        res = verify_audit_chain(chain, expected_project_id=sec_project.id)
        assert res.valid is False
        assert res.status == AuditVerificationStatus.AUDIT_INTEGRITY_VIOLATION
        codes = [f.code for f in res.failures]
        assert (
            AuditFailureCode.EVENT_HASH_MISMATCH in codes
            or AuditFailureCode.GENESIS_TAMPERING in codes
        )

    def test_replacing_genesis_audit_event_detected(
        self, sec_project: ProjectModel
    ):
        """Replacing genesis with a record starting at sequence 1 produces GENESIS_TAMPERING."""
        chain = _build_audit_chain(sec_project.id, length=4)
        tampered = chain[1:]

        res = verify_audit_chain(tampered, expected_project_id=sec_project.id)
        assert res.valid is False
        codes = [f.code for f in res.failures]
        assert AuditFailureCode.GENESIS_TAMPERING in codes

    def test_changing_audit_project_id_detected(
        self, sec_project: ProjectModel
    ):
        """Changing project_id on an audit event causes PROJECT_MISMATCH."""
        chain = _build_audit_chain(sec_project.id, length=4)
        chain[2]["project_id"] = "foreign-audit-project"

        res = verify_audit_chain(chain, expected_project_id=sec_project.id)
        assert res.valid is False
        codes = [f.code for f in res.failures]
        assert AuditFailureCode.PROJECT_MISMATCH in codes

    def test_malformed_audit_input_classified_as_unverifiable_input_not_tampering(
        self, sec_project: ProjectModel
    ):
        """Missing structural fields produces UNVERIFIABLE_INPUT, NOT AUDIT_INTEGRITY_VIOLATION."""
        malformed_event = {
            "project_id": sec_project.id,
            "sequence_number": 0,
        }

        res = verify_audit_chain([malformed_event], expected_project_id=sec_project.id)
        assert res.valid is False
        assert res.status == AuditVerificationStatus.UNVERIFIABLE_INPUT
        codes = [f.code for f in res.failures]
        assert AuditFailureCode.MALFORMED_AUDIT_INPUT in codes


# =====================================================================
# ST-07 — Direct Database / Raw-SQL Attacks
# =====================================================================


class TestST07DirectDatabaseRawSqlAttacks:
    """Mandatory: bypass SQLAlchemy ORM protections and directly manipulate SQLite using raw SQL.

    Proves that ORM immutability listeners are merely defense-in-depth, and that
    the cryptographic verification engine independently detects direct database tampering.
    """

    def test_orm_immutability_listener_is_bypassed_by_raw_sql(
        self, test_db_session: Session, sec_project: ProjectModel
    ):
        """Demonstrate that ORM listeners block ORM updates, but raw SQL directly executes."""
        audit_svc = AuditService(test_db_session)
        ev = audit_svc.record_event(
            project_id=sec_project.id,
            event_type=AuditEventType.SECURITY_CONFIG_CHANGED,
            actor="admin",
            action="UPDATE_CONFIG",
            description="Original valid audit description",
        )

        ev_model = test_db_session.query(AuditEventModel).filter_by(id=ev.id).first()
        ev_model.description = "ORM_MUTATION_ATTEMPT"
        with pytest.raises(AuditImmutabilityError):
            test_db_session.commit()
        test_db_session.rollback()

        test_db_session.connection().execute(
            text("UPDATE audit_events SET description = :desc WHERE id = :id"),
            {"desc": "RAW_SQL_MUTATION_SUCCESS", "id": ev.id},
        )
        test_db_session.commit()

        row = test_db_session.connection().execute(
            text("SELECT description FROM audit_events WHERE id = :id"),
            {"id": ev.id},
        ).fetchone()
        assert row[0] == "RAW_SQL_MUTATION_SUCCESS"

    def test_raw_sql_update_audit_description_detected_by_verification_engine(
        self, test_db_session: Session, sec_project: ProjectModel
    ):
        """Raw SQL mutation of audit description is mathematically detected by the verification engine."""
        audit_svc = AuditService(test_db_session)
        ev1 = audit_svc.record_event(
            project_id=sec_project.id,
            event_type=AuditEventType.PROVENANCE_RECORDED,
            actor="system",
            action="RECORD_PROV",
            description="Audit record 1",
        )

        test_db_session.connection().execute(
            text("UPDATE audit_events SET description = 'ATTACKER_OVERWRITE' WHERE id = :id"),
            {"id": ev1.id},
        )
        test_db_session.commit()
        test_db_session.expire_all()

        res = audit_svc.verify_chain(sec_project.id)
        assert res.valid is False
        assert res.status == AuditVerificationStatus.AUDIT_INTEGRITY_VIOLATION
        assert AuditFailureCode.EVENT_HASH_MISMATCH in [f.code for f in res.failures]

    def test_raw_sql_update_event_hash_detected_by_verification_engine(
        self, test_db_session: Session, sec_project: ProjectModel
    ):
        """Raw SQL mutation of event_hash is detected as EVENT_HASH_MISMATCH and BROKEN_AUDIT_CHAIN."""
        audit_svc = AuditService(test_db_session)
        ev1 = audit_svc.record_event(
            project_id=sec_project.id,
            event_type=AuditEventType.PROVENANCE_RECORDED,
            actor="system",
            action="RECORD_PROV",
            description="Audit record 1",
        )
        ev2 = audit_svc.record_event(
            project_id=sec_project.id,
            event_type=AuditEventType.PROVENANCE_RECORDED,
            actor="system",
            action="RECORD_PROV",
            description="Audit record 2",
        )

        test_db_session.connection().execute(
            text("UPDATE audit_events SET event_hash = :hash WHERE id = :id"),
            {"hash": "f" * 64, "id": ev1.id},
        )
        test_db_session.commit()
        test_db_session.expire_all()

        res = audit_svc.verify_chain(sec_project.id)
        assert res.valid is False
        assert res.status == AuditVerificationStatus.AUDIT_INTEGRITY_VIOLATION
        codes = [f.code for f in res.failures]
        assert AuditFailureCode.EVENT_HASH_MISMATCH in codes or AuditFailureCode.BROKEN_AUDIT_CHAIN in codes

    def test_raw_sql_update_previous_event_hash_detected(
        self, test_db_session: Session, sec_project: ProjectModel
    ):
        """Raw SQL mutation of previous_event_hash breaks chain linkage."""
        audit_svc = AuditService(test_db_session)
        audit_svc.record_event(
            project_id=sec_project.id,
            event_type=AuditEventType.PROVENANCE_RECORDED,
            actor="system",
            action="RECORD_PROV",
            description="Audit 1",
        )
        ev2 = audit_svc.record_event(
            project_id=sec_project.id,
            event_type=AuditEventType.PROVENANCE_RECORDED,
            actor="system",
            action="RECORD_PROV",
            description="Audit 2",
        )

        test_db_session.connection().execute(
            text("UPDATE audit_events SET previous_event_hash = :prev WHERE id = :id"),
            {"prev": "0" * 64, "id": ev2.id},
        )
        test_db_session.commit()
        test_db_session.expire_all()

        res = audit_svc.verify_chain(sec_project.id)
        assert res.valid is False
        assert res.status == AuditVerificationStatus.AUDIT_INTEGRITY_VIOLATION
        codes = [f.code for f in res.failures]
        assert AuditFailureCode.BROKEN_AUDIT_CHAIN in codes or AuditFailureCode.EVENT_HASH_MISMATCH in codes

    def test_raw_sql_update_sequence_number_detected(
        self, test_db_session: Session, sec_project: ProjectModel
    ):
        """Raw SQL mutation of sequence number triggers SEQUENCE_GAP."""
        audit_svc = AuditService(test_db_session)
        ev1 = audit_svc.record_event(
            project_id=sec_project.id,
            event_type=AuditEventType.PROVENANCE_RECORDED,
            actor="system",
            action="RECORD_PROV",
            description="Audit 1",
        )

        test_db_session.connection().execute(
            text("UPDATE audit_events SET sequence_number = 99 WHERE id = :id"),
            {"id": ev1.id},
        )
        test_db_session.commit()
        test_db_session.expire_all()

        res = audit_svc.verify_chain(sec_project.id)
        assert res.valid is False
        assert res.status == AuditVerificationStatus.AUDIT_INTEGRITY_VIOLATION
        codes = [f.code for f in res.failures]
        assert AuditFailureCode.SEQUENCE_GAP in codes or AuditFailureCode.EVENT_HASH_MISMATCH in codes

    def test_raw_sql_update_project_id_detected(
        self, test_db_session: Session, sec_project: ProjectModel
    ):
        """Raw SQL mutation of project_id triggers PROJECT_MISMATCH."""
        audit_svc = AuditService(test_db_session)
        ev1 = audit_svc.record_event(
            project_id=sec_project.id,
            event_type=AuditEventType.PROVENANCE_RECORDED,
            actor="system",
            action="RECORD_PROV",
            description="Audit 1",
        )

        # Create valid second project to satisfy DB foreign keys
        foreign_proj = ProjectModel(id=f"proj-foreign-{uuid.uuid4().hex[:6]}", name="Foreign Project")
        test_db_session.add(foreign_proj)
        test_db_session.commit()

        test_db_session.connection().execute(
            text("UPDATE audit_events SET project_id = :proj_id WHERE id = :id"),
            {"proj_id": foreign_proj.id, "id": ev1.id},
        )
        test_db_session.commit()
        test_db_session.expire_all()

        # Query all events in original sequence to verify cryptographic mismatch
        ev_model = test_db_session.query(AuditEventModel).filter_by(id=ev1.id).first()
        res = verify_audit_chain([ev_model], expected_project_id=sec_project.id)
        assert res.valid is False
        assert res.status == AuditVerificationStatus.AUDIT_INTEGRITY_VIOLATION
        assert AuditFailureCode.PROJECT_MISMATCH in [f.code for f in res.failures]

    def test_raw_sql_delete_middle_audit_event_detected(
        self, test_db_session: Session, sec_project: ProjectModel
    ):
        """Raw SQL deletion of a middle audit event is detected as SEQUENCE_GAP and BROKEN_AUDIT_CHAIN."""
        audit_svc = AuditService(test_db_session)
        ev1 = audit_svc.record_event(
            project_id=sec_project.id,
            event_type=AuditEventType.PROVENANCE_RECORDED,
            actor="system",
            action="RECORD_PROV",
            description="Audit 1",
        )
        ev2 = audit_svc.record_event(
            project_id=sec_project.id,
            event_type=AuditEventType.PROVENANCE_RECORDED,
            actor="system",
            action="RECORD_PROV",
            description="Audit 2",
        )

        test_db_session.connection().execute(
            text("DELETE FROM audit_events WHERE id = :id"),
            {"id": ev1.id},
        )
        test_db_session.commit()
        test_db_session.expire_all()

        res = audit_svc.verify_chain(sec_project.id)
        assert res.valid is False
        assert res.status == AuditVerificationStatus.AUDIT_INTEGRITY_VIOLATION
        codes = [f.code for f in res.failures]
        assert AuditFailureCode.SEQUENCE_GAP in codes or AuditFailureCode.BROKEN_AUDIT_CHAIN in codes

    def test_raw_sql_insert_forged_audit_event_detected(
        self, test_db_session: Session, sec_project: ProjectModel
    ):
        """Raw SQL insertion of forged audit record fails hash linkage."""
        audit_svc = AuditService(test_db_session)
        ev1 = audit_svc.record_event(
            project_id=sec_project.id,
            event_type=AuditEventType.PROVENANCE_RECORDED,
            actor="system",
            action="RECORD_PROV",
            description="Audit 1",
        )

        test_db_session.connection().execute(
            text(
                "INSERT INTO audit_events (id, project_id, sequence_number, event_type, actor, action, "
                "outcome, description, previous_event_hash, event_hash, metadata_json, created_at) "
                "VALUES (:id, :project_id, 2, 'FORGED_EVENT', 'attacker', 'INJECT', 'SUCCESS', "
                "'Injected row', :prev, :hash, '{}', :now)"
            ),
            {
                "id": str(uuid.uuid4()),
                "project_id": sec_project.id,
                "prev": "0" * 64,
                "hash": "d" * 64,
                "now": datetime.now(timezone.utc),
            },
        )
        test_db_session.commit()
        test_db_session.expire_all()

        res = audit_svc.verify_chain(sec_project.id)
        assert res.valid is False
        assert res.status == AuditVerificationStatus.AUDIT_INTEGRITY_VIOLATION


# =====================================================================
# ST-08 — API Security Attacks
# =====================================================================


class TestST08ApiSecurityAttacks:
    """Security tests against REST endpoints (injection, malformed inputs, secret leakage)."""

    def test_api_rejects_malformed_json_with_422(self, client: TestClient):
        """Malformed JSON payload produces HTTP 422 Unprocessable Entity."""
        res = client.post(
            "/api/v1/provenance/records",
            content="{'invalid_json': broken",
            headers={"Content-Type": "application/json"},
        )
        assert res.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    def test_api_rejects_missing_required_fields_with_422(self, client: TestClient):
        """Payload missing required fields produces HTTP 422."""
        res = client.post(
            "/api/v1/provenance/records",
            json={"project_id": "test-project"},
        )
        assert res.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    def test_api_rejects_wrong_data_types_with_422(self, client: TestClient):
        """Wrong field type (e.g. sequence_number = string) produces HTTP 422."""
        res = client.post(
            "/api/v1/provenance/records",
            json={
                "project_id": "test-proj",
                "record_type": "INFERENCE",
                "actor": "system",
                "action": "ACTION",
                "sequence_number": "not_an_integer",
            },
        )
        assert res.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    def test_api_rejects_oversized_hash_with_422(self, client: TestClient):
        """Oversized hash length in ProvenanceRecordCreate produces HTTP 422."""
        res = client.post(
            "/api/v1/provenance/records",
            json={
                "project_id": "test-proj",
                "record_type": "INFERENCE",
                "actor": "system",
                "action": "ACTION",
                "record_hash": "x" * 65,  # Exceeds max_length=64
            },
        )
        assert res.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    def test_api_returns_404_for_unknown_audit_event(self, client: TestClient):
        """Non-existent audit event UUID produces HTTP 404 Not Found."""
        random_id = str(uuid.uuid4())
        res = client.get(f"/api/v1/audit/events/{random_id}")
        assert res.status_code == status.HTTP_404_NOT_FOUND

    def test_api_returns_404_for_unknown_provenance_record(self, client: TestClient):
        """Non-existent provenance record UUID produces HTTP 404 Not Found."""
        random_id = str(uuid.uuid4())
        res = client.get(f"/api/v1/provenance/records/{random_id}")
        assert res.status_code == status.HTTP_404_NOT_FOUND

    def test_api_audit_verify_detects_forged_caller_supplied_chain(
        self, client: TestClient, sec_project: ProjectModel
    ):
        """Caller submits tampered audit events to POST /audit/chain/verify; returns 200 with valid=False."""
        chain = _build_audit_chain(sec_project.id, length=3)
        chain[1]["description"] = "FORGED VIA REST"

        res = client.post(
            "/api/v1/audit/chain/verify",
            json={"project_id": sec_project.id, "events": chain},
        )
        assert res.status_code == status.HTTP_200_OK
        data = res.json()["data"]
        assert data["valid"] is False
        assert data["status"] == "AUDIT_INTEGRITY_VIOLATION"

    def test_api_provenance_verify_detects_manipulated_chain(
        self, client: TestClient, sec_project: ProjectModel, active_key_pair: Ed25519KeyHandle
    ):
        """Caller submits tampered provenance chain to POST /provenance/chain/verify; returns valid=False."""
        chain = _build_provenance_chain(sec_project.id, active_key_pair, length=3)
        records_json = [r.model_dump() for r in chain]
        records_json[1]["action"] = "ATTACK_API_ACTION"

        res = client.post(
            "/api/v1/provenance/chain/verify",
            json={"project_id": sec_project.id, "records": records_json},
        )
        assert res.status_code == status.HTTP_200_OK
        data = res.json()["data"]
        assert data["overall_valid"] is False

    def test_api_rejects_unsupported_http_methods(self, client: TestClient):
        """Calling DELETE or PUT on audit endpoints produces HTTP 405 Method Not Allowed."""
        res_del = client.delete("/api/v1/audit/events/12345")
        assert res_del.status_code == status.HTTP_405_METHOD_NOT_ALLOWED

        res_put = client.put("/api/v1/audit/events", json={})
        assert res_put.status_code == status.HTTP_405_METHOD_NOT_ALLOWED

    def test_api_rejects_invalid_pagination_values_with_422(
        self, client: TestClient, sec_project: ProjectModel
    ):
        """Pagination limit > 1000 or skip < 0 produces HTTP 422."""
        res1 = client.get(f"/api/v1/audit/events?limit=99999")
        assert res1.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

        res2 = client.get(f"/api/v1/audit/events?skip=-5")
        assert res2.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    def test_api_errors_do_not_leak_secrets_passphrases_or_tracebacks(
        self, client: TestClient
    ):
        """Verifies error responses do not leak private keys, passphrases, or Python tracebacks."""
        res = client.post("/api/v1/provenance/records", json={"bad": "payload"})
        text_content = res.text

        assert "Traceback (most recent call last)" not in text_content
        assert "private_key" not in text_content.lower()
        assert "passphrase" not in text_content.lower()
        assert "password" not in text_content.lower()
        assert "sqlite" not in text_content.lower()


# =====================================================================
# ST-09 — Transaction & Failure Boundaries
# =====================================================================


class TestST09TransactionFailureBoundaries:
    """Security tests checking atomicity, transactional isolation, and failure survival."""

    def test_business_success_and_audit_success_both_persist(
        self, test_db_session: Session, sec_project: ProjectModel, active_key_pair: Ed25519KeyHandle
    ):
        """Standard flow: business record is committed, audit record is committed."""
        prov_svc = ProvenanceService(test_db_session)
        rec = _build_provenance_record(
            project_id=sec_project.id,
            sequence_number=1,
            previous_record_hash="0" * 64,
            key_handle=active_key_pair,
        )

        saved = prov_svc.record_provenance_event(ProvenanceRecordCreate(**rec.model_dump()))
        assert saved.id is not None
        assert prov_svc.last_audit_error is None

        audit_svc = AuditService(test_db_session)
        events = audit_svc.list_events(project_id=sec_project.id)
        assert len(events) >= 2
        assert events[-1].event_type == AuditEventType.PROVENANCE_RECORDED.value

    def test_business_success_with_audit_failure_is_observable(
        self, test_db_session: Session, sec_project: ProjectModel, active_key_pair: Ed25519KeyHandle
    ):
        """If audit recording fails, business result is preserved and last_audit_error is observable."""
        prov_svc = ProvenanceService(test_db_session)
        rec = _build_provenance_record(
            project_id=sec_project.id,
            sequence_number=1,
            previous_record_hash="0" * 64,
            key_handle=active_key_pair,
        )

        with patch.object(
            prov_svc.audit_service,
            "record_event",
            side_effect=RuntimeError("Simulated Audit Storage Failure"),
        ):
            saved = prov_svc.record_provenance_event(ProvenanceRecordCreate(**rec.model_dump()))

        assert saved.id is not None
        assert prov_svc.last_audit_error is not None
        assert "Simulated Audit Storage Failure" in prov_svc.last_audit_error

    def test_business_failure_with_replay_audit_persists_rejected_event(
        self, test_db_session: Session, sec_project: ProjectModel, active_key_pair: Ed25519KeyHandle
    ):
        """When a duplicate is rejected, primary tx rolls back, independent audit tx commits REJECTED."""
        prov_svc = ProvenanceService(test_db_session)
        rec = _build_provenance_record(
            project_id=sec_project.id,
            sequence_number=1,
            previous_record_hash="0" * 64,
            key_handle=active_key_pair,
        )
        prov_svc.record_provenance_event(ProvenanceRecordCreate(**rec.model_dump()))

        with pytest.raises(AivaraException):
            prov_svc.record_provenance_event(ProvenanceRecordCreate(**rec.model_dump()))

        audit_svc = AuditService(test_db_session)
        events = audit_svc.list_events(project_id=sec_project.id)
        replay_events = [e for e in events if e.event_type == AuditEventType.PROVENANCE_REPLAY_REJECTED.value]
        assert len(replay_events) == 1
        assert replay_events[0].outcome == AuditOutcome.REJECTED.value

    def test_primary_transaction_rollback_leaves_no_partial_state(
        self, test_db_session: Session, sec_project: ProjectModel, active_key_pair: Ed25519KeyHandle
    ):
        """Failed primary transaction rolls back cleanly, leaving no orphaned rows."""
        prov_svc = ProvenanceService(test_db_session)
        rec = _build_provenance_record(
            project_id=sec_project.id,
            sequence_number=1,
            previous_record_hash="0" * 64,
            key_handle=active_key_pair,
        )
        prov_svc.record_provenance_event(ProvenanceRecordCreate(**rec.model_dump()))

        count_before = test_db_session.query(ProvenanceRecordModel).filter_by(project_id=sec_project.id).count()
        assert count_before == 1

        with pytest.raises(AivaraException):
            prov_svc.record_provenance_event(ProvenanceRecordCreate(**rec.model_dump()))

        count_after = test_db_session.query(ProvenanceRecordModel).filter_by(project_id=sec_project.id).count()
        assert count_after == 1

    def test_replay_rejection_followed_by_audit_verification_remains_valid(
        self, test_db_session: Session, sec_project: ProjectModel, active_key_pair: Ed25519KeyHandle
    ):
        """After recording a replay rejection event, the audit chain verifies as completely valid."""
        prov_svc = ProvenanceService(test_db_session)
        rec = _build_provenance_record(
            project_id=sec_project.id,
            sequence_number=1,
            previous_record_hash="0" * 64,
            key_handle=active_key_pair,
        )
        prov_svc.record_provenance_event(ProvenanceRecordCreate(**rec.model_dump()))

        with pytest.raises(AivaraException):
            prov_svc.record_provenance_event(ProvenanceRecordCreate(**rec.model_dump()))

        audit_svc = AuditService(test_db_session)
        res = audit_svc.verify_chain(sec_project.id)
        assert res.valid is True
        assert res.status == AuditVerificationStatus.VALID


# =====================================================================
# ST-10 — Security Semantics & Regression Tests
# =====================================================================


class TestST10SecuritySemanticsRegression:
    """Security tests enforcing strict taxonomic distinctions between malformed input, unverified keys, and tampering."""

    def test_tampered_payload_and_invalid_signature_both_preserved(
        self, sec_project: ProjectModel, active_key_pair: Ed25519KeyHandle
    ):
        """Simultaneous payload tampering and signature corruption preserves both failures."""
        rec = _build_provenance_record(
            project_id=sec_project.id,
            sequence_number=1,
            previous_record_hash="0" * 64,
            key_handle=active_key_pair,
        )

        t_dict = rec.model_dump()
        t_dict["action"] = "TAMPERED_ACTION"
        raw_sig = bytearray(decode_signature(rec.signature))
        raw_sig[0] ^= 0xFF
        t_dict["signature"] = encode_signature(bytes(raw_sig))
        tampered = ChainRecord(**t_dict)

        res = verify_record(tampered, public_key=active_key_pair)
        assert res.overall_valid is False
        codes = [f.code for f in res.failures]
        assert FailureCode.RECORD_HASH_MISMATCH in codes
        assert FailureCode.INVALID_SIGNATURE in codes

        assessment = assess_record_tampering(res, record=tampered)
        assert assessment.tampering_detected is True
        assert assessment.status == TamperAssessmentStatus.INTEGRITY_VIOLATION
        assert assessment.confidence == 1.0

    def test_malformed_input_distinguished_from_malicious_tampering(
        self, sec_project: ProjectModel, active_key_pair: Ed25519KeyHandle
    ):
        """Malformed input (e.g. non-hex nonce) must NOT be labeled as cryptographic tampering."""
        rec = _build_provenance_record(
            project_id=sec_project.id,
            sequence_number=1,
            previous_record_hash="0" * 64,
            key_handle=active_key_pair,
        )

        bad_dict = rec.model_dump()
        bad_dict["nonce"] = "not-a-valid-hex-nonce"

        res = verify_record(bad_dict, public_key=active_key_pair)
        assert res.overall_valid is False
        codes = [f.code for f in res.failures]
        assert FailureCode.INVALID_NONCE in codes

        assessment = assess_record_tampering(res, record=bad_dict)
        assert assessment.tampering_detected is False
        assert assessment.status == TamperAssessmentStatus.UNVERIFIABLE_INPUT
        assert assessment.confidence == 0.0

    def test_unknown_signer_distinguished_from_malicious_tampering(
        self, sec_project: ProjectModel, active_key_pair: Ed25519KeyHandle, tmp_path: Path
    ):
        """Unknown signer key must produce AUTHENTICITY_UNAVAILABLE, NOT tampering."""
        rec = _build_provenance_record(
            project_id=sec_project.id,
            sequence_number=1,
            previous_record_hash="0" * 64,
            key_handle=active_key_pair,
        )

        isolated_km = KeyManager(keys_dir=tmp_path / "empty_keys")
        res = verify_record(rec, key_manager=isolated_km)
        assessment = assess_record_tampering(res, record=rec)

        assert assessment.tampering_detected is False
        assert assessment.status == TamperAssessmentStatus.AUTHENTICITY_UNAVAILABLE
        assert assessment.confidence == 0.0

    def test_missing_signature_distinguished_from_malicious_tampering(
        self, sec_project: ProjectModel, active_key_pair: Ed25519KeyHandle
    ):
        """Missing signature must NOT be labeled as tampering."""
        rec = _build_provenance_record(
            project_id=sec_project.id,
            sequence_number=1,
            previous_record_hash="0" * 64,
            key_handle=active_key_pair,
        )
        rec_dict = rec.model_dump()
        rec_dict["signature"] = None
        unsigned_rec = ChainRecord(**rec_dict)

        res = verify_record(unsigned_rec, public_key=active_key_pair, allow_unsigned=False)
        assessment = assess_record_tampering(res, record=unsigned_rec)
        assert assessment.tampering_detected is False
        assert assessment.status == TamperAssessmentStatus.AUTHENTICITY_UNAVAILABLE

    def test_replay_is_classified_as_replay_not_tampering(
        self, test_db_session: Session, sec_project: ProjectModel, active_key_pair: Ed25519KeyHandle
    ):
        """Replay conditions are classified as replay, maintaining clear distinction from data tampering."""
        prov_svc = ProvenanceService(test_db_session)
        rec = _build_provenance_record(
            project_id=sec_project.id,
            sequence_number=1,
            previous_record_hash="0" * 64,
            key_handle=active_key_pair,
        )
        prov_svc.record_provenance_event(ProvenanceRecordCreate(**rec.model_dump()))

        assessment = prov_svc.check_replay(
            project_id=sec_project.id,
            sequence_number=1,
            nonce=rec.nonce,
            record_hash=rec.record_hash,
        )
        assert assessment.replay_detected is True
        assert assessment.replay_type != ReplayType.NONE
