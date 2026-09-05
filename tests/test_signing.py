"""Unit and integration tests for AIVARA's Ed25519 Digital Signing and Verification Engine (Phase 4.5).

Covers:
- Section A: Basic signing (active key, valid signature, 64-byte raw decoding)
- Section B: Determinism of signing input and signatures
- Section C: Verification (valid signature, tampered input, tampered signature, wrong public key)
- Section D: Signature encoding (Base64 round trip, malformed Base64, invalid decoded lengths)
- Section E: Key lifecycle enforcement (ACTIVE can sign; ROTATED, REVOKED, EXPIRED cannot sign)
- Section F: Historical verification (ROTATED, REVOKED, and EXPIRED keys can verify existing signatures)
- Section G: Key ID binding and validation
- Section H: Security (no private key exposure, no secret logging, no plaintext key creation)
- End-to-end pipeline: sign_provenance_payload and verify_provenance_signature
"""

import base64
import json
from pathlib import Path
from typing import Any, Dict

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from aivara.crypto import (
    ED25519_SIGNATURE_B64_LEN,
    ED25519_SIGNATURE_BYTES_LEN,
    InvalidKeyIdError,
    InvalidSignatureError,
    InvalidSigningInputError,
    KeyExpiredError,
    KeyManagementError,
    KeyManager,
    KeyNotFoundError,
    KeyRevokedError,
    KeyRotatedError,
    KeyStatus,
    KeyStatusError,
    MalformedSignatureError,
    SignatureResult,
    SignatureVerificationError,
    SigningError,
    UnknownSignerKeyError,
    VerificationResult,
    VerificationStatus,
    assert_signature_valid,
    canonicalize_provenance_payload,
    decode_signature,
    derive_key_id,
    encode_signature,
    hash_provenance_payload,
    is_valid_sha256,
    record_hash_to_signing_bytes,
    sha256_bytes,
    sha256_text,
    sign_hash,
    sign_provenance_payload,
    sign_raw_bytes,
    verify_hash_signature,
    verify_provenance_signature,
)

TEST_PASSPHRASE = "Passphrase_Phase4.5_Test_2026!"
SAMPLE_HASH = "a" * 64
SAMPLE_HASH_2 = "b" * 64


@pytest.fixture
def key_manager(tmp_path: Path) -> KeyManager:
    """Fixture providing a fresh KeyManager initialized in temporary storage."""
    return KeyManager(keys_dir=tmp_path / "keys")


@pytest.fixture
def sample_payload() -> Dict[str, Any]:
    """Sample protected provenance payload dictionary."""
    return {
        "record_type": "inference_record",
        "project_id": "proj_assurance_01",
        "actor": "system",
        "action": "model_inference",
        "sequence_number": 1,
        "nonce": "3" * 64,
        "timestamp": "2026-09-05T12:00:00Z",
        "config_hash": "c" * 64,
        "input_hash": "1" * 64,
        "model_id": "resnet50_v1",
        "model_weight_digest": "2" * 64,
        "output_hash": "4" * 64,
        "previous_record_hash": "0" * 64,
    }


class TestDigitalSignaturesEngine:
    """Comprehensive test suite for Phase 4.5 Digital Signatures and Verification."""

    # =================================================================
    # Section A: Basic Signing
    # =================================================================

    def test_basic_signing_with_active_key(self, key_manager: KeyManager):
        """Active key signs deterministic record hash and produces valid 64-byte signature."""
        handle = key_manager.generate_key(passphrase=TEST_PASSPHRASE)
        result = sign_hash(SAMPLE_HASH, handle)

        assert isinstance(result, SignatureResult)
        assert result.algorithm == "Ed25519"
        assert result.signer_key_id == handle.key_id
        assert len(result.signature) == ED25519_SIGNATURE_B64_LEN

        # Raw signature decodes to exactly 64 bytes
        raw_sig = decode_signature(result.signature)
        assert len(raw_sig) == ED25519_SIGNATURE_BYTES_LEN
        assert result.signed_bytes_count == 64

    def test_sign_provenance_payload_pipeline(
        self, key_manager: KeyManager, sample_payload: Dict[str, Any]
    ):
        """End-to-end provenance payload signing produces expected signature and signer binding."""
        handle = key_manager.generate_key(passphrase=TEST_PASSPHRASE)
        result = sign_provenance_payload(sample_payload, handle)

        assert isinstance(result, SignatureResult)
        assert result.signer_key_id == handle.key_id
        assert len(result.signature) == ED25519_SIGNATURE_B64_LEN

        # Verify signature against the payload's hash
        record_hash = hash_provenance_payload(
            **sample_payload,
            signer_key_id=handle.key_id,
        )
        verification = verify_hash_signature(record_hash, result.signature, handle)
        assert verification.is_valid
        assert verification.status == VerificationStatus.VALID

    def test_sign_raw_bytes(self, key_manager: KeyManager):
        """Active key can sign arbitrary non-empty raw bytes."""
        handle = key_manager.generate_key(passphrase=TEST_PASSPHRASE)
        data = b"Air-gapped verification payload bytes 2026"
        result = sign_raw_bytes(data, handle)

        assert isinstance(result, SignatureResult)
        assert result.signer_key_id == handle.key_id
        assert result.signed_bytes_count == len(data)

        # Cryptographically verify using raw public key
        raw_sig = decode_signature(result.signature)
        handle.public_key.verify(raw_sig, data)

    # =================================================================
    # Section B: Determinism of Signing Input & Ed25519
    # =================================================================

    def test_signing_input_determinism(self, key_manager: KeyManager):
        """Ed25519 is deterministic (RFC 8032): same key + same hash = exact same signature."""
        handle = key_manager.generate_key(passphrase=TEST_PASSPHRASE)

        res1 = sign_hash(SAMPLE_HASH, handle)
        res2 = sign_hash(SAMPLE_HASH, handle)

        assert res1.signature == res2.signature
        assert res1.signer_key_id == res2.signer_key_id

    def test_distinct_hashes_produce_distinct_signatures(self, key_manager: KeyManager):
        """Different hashes produce completely different signatures under the same key."""
        handle = key_manager.generate_key(passphrase=TEST_PASSPHRASE)

        res1 = sign_hash(SAMPLE_HASH, handle)
        res2 = sign_hash(SAMPLE_HASH_2, handle)

        assert res1.signature != res2.signature

    def test_signing_bytes_format_definition(self):
        """Verify record_hash_to_signing_bytes exactly produces 64 UTF-8 bytes."""
        valid_hash = "0123456789abcdef" * 4
        signing_bytes = record_hash_to_signing_bytes(valid_hash)

        assert isinstance(signing_bytes, bytes)
        assert len(signing_bytes) == 64
        assert signing_bytes == valid_hash.encode("utf-8")

    def test_invalid_hash_signing_input_rejected(self, key_manager: KeyManager):
        """Invalid hash strings are rejected before any signing occurs."""
        handle = key_manager.generate_key(passphrase=TEST_PASSPHRASE)

        invalid_hashes = [
            "A" * 64,  # Uppercase not allowed
            "a" * 63,  # Too short
            "a" * 65,  # Too long
            "g" * 64,  # Non-hex characters
            "",  # Empty
            12345,  # Non-string
            "sha256:" + "a" * 64,  # Prefix not allowed
        ]

        for bad_hash in invalid_hashes:
            with pytest.raises(InvalidSigningInputError):
                record_hash_to_signing_bytes(bad_hash)  # type: ignore[arg-type]

            with pytest.raises(InvalidSigningInputError):
                sign_hash(bad_hash, handle)  # type: ignore[arg-type]

    # =================================================================
    # Section C: Verification
    # =================================================================

    def test_valid_signature_verifies_successfully(self, key_manager: KeyManager):
        """Valid signature successfully verifies and reports VALID status."""
        handle = key_manager.generate_key(passphrase=TEST_PASSPHRASE)
        sig_result = sign_hash(SAMPLE_HASH, handle)

        # Verification with Ed25519KeyHandle
        res1 = verify_hash_signature(SAMPLE_HASH, sig_result.signature, handle)
        assert res1.is_valid
        assert res1.status == VerificationStatus.VALID
        assert res1.signer_key_id == handle.key_id
        assert res1.key_is_active
        assert res1.key_status == KeyStatus.ACTIVE
        assert res1.error_message is None

        # Verification with raw Ed25519PublicKey
        res2 = verify_hash_signature(SAMPLE_HASH, sig_result.signature, handle.public_key)
        assert res2.is_valid
        assert res2.status == VerificationStatus.VALID
        assert res2.signer_key_id == handle.key_id

    def test_modified_signing_input_fails_verification(self, key_manager: KeyManager):
        """Modifying the record hash causes verification to fail with INVALID_SIGNATURE."""
        handle = key_manager.generate_key(passphrase=TEST_PASSPHRASE)
        sig_result = sign_hash(SAMPLE_HASH, handle)

        tampered_hash = "b" * 64
        res = verify_hash_signature(tampered_hash, sig_result.signature, handle)

        assert not res.is_valid
        assert res.status == VerificationStatus.INVALID_SIGNATURE
        assert "verification failed" in res.error_message.lower()

    def test_modified_signature_fails_verification(self, key_manager: KeyManager):
        """Flipping a byte in the signature causes cryptographic verification to fail."""
        handle = key_manager.generate_key(passphrase=TEST_PASSPHRASE)
        sig_result = sign_hash(SAMPLE_HASH, handle)

        raw_sig = bytearray(decode_signature(sig_result.signature))
        raw_sig[10] ^= 0xFF  # Corrupt a byte
        corrupted_b64 = encode_signature(bytes(raw_sig))

        res = verify_hash_signature(SAMPLE_HASH, corrupted_b64, handle)
        assert not res.is_valid
        assert res.status == VerificationStatus.INVALID_SIGNATURE

    def test_wrong_public_key_fails_verification(self, key_manager: KeyManager):
        """Verifying with a public key that did not create the signature fails."""
        key1 = key_manager.generate_key(passphrase=TEST_PASSPHRASE, set_as_active=True)
        key2 = key_manager.generate_key(passphrase=TEST_PASSPHRASE, set_as_active=False)

        sig_result = sign_hash(SAMPLE_HASH, key1)

        # Attempt verification using key2
        res = verify_hash_signature(SAMPLE_HASH, sig_result.signature, key2)
        assert not res.is_valid
        assert res.status == VerificationStatus.INVALID_SIGNATURE

    def test_assert_signature_valid_raises_appropriate_exceptions(
        self, key_manager: KeyManager
    ):
        """assert_signature_valid raises typed exceptions upon failure."""
        handle = key_manager.generate_key(passphrase=TEST_PASSPHRASE)
        sig_result = sign_hash(SAMPLE_HASH, handle)

        # 1. Valid signature passes without exception
        assert_signature_valid(SAMPLE_HASH, sig_result.signature, handle)

        # 2. Tampered signature raises InvalidSignatureError
        raw_sig = bytearray(decode_signature(sig_result.signature))
        raw_sig[0] ^= 0xFF
        with pytest.raises(InvalidSignatureError):
            assert_signature_valid(SAMPLE_HASH, encode_signature(bytes(raw_sig)), handle)

        # 3. Malformed signature raises MalformedSignatureError
        with pytest.raises(MalformedSignatureError):
            assert_signature_valid(SAMPLE_HASH, "not_a_valid_b64!!!", handle)

        # 4. Invalid hash raises InvalidSigningInputError
        with pytest.raises(InvalidSigningInputError):
            assert_signature_valid("bad_hash", sig_result.signature, handle)

        # 5. Mismatched signer key ID raises UnknownSignerKeyError
        with pytest.raises(UnknownSignerKeyError):
            assert_signature_valid(
                SAMPLE_HASH,
                sig_result.signature,
                handle,
                signer_key_id="0" * 64,
            )

    # =================================================================
    # Section D: Signature Encoding / Decoding
    # =================================================================

    def test_signature_encoding_roundtrip(self):
        """Raw 64 bytes round-trip cleanly through Base64 encode/decode."""
        raw_sig = b"\x01\x02\x03\x04" * 16
        assert len(raw_sig) == 64

        b64_sig = encode_signature(raw_sig)
        assert len(b64_sig) == 88
        assert b64_sig.endswith("==")

        decoded = decode_signature(b64_sig)
        assert decoded == raw_sig

    def test_malformed_base64_rejected(self):
        """Malformed Base64 strings are strictly rejected."""
        invalid_signatures = [
            "invalid_base64_chars!@#$",
            "a" * 87,  # Length 87
            "a" * 89,  # Length 89
            " " + "a" * 87,  # Whitespace padding
            b"bytes_not_string",  # Wrong type
            12345,  # Wrong type
            None,  # None
        ]

        for bad in invalid_signatures:
            with pytest.raises(MalformedSignatureError):
                decode_signature(bad)  # type: ignore[arg-type]

    def test_wrong_decoded_length_rejected(self):
        """Base64 strings decoding to anything other than 64 bytes are rejected."""
        # 32-byte payload base64 encoded (44 chars)
        short_b64 = base64.b64encode(b"A" * 32).decode("ascii")
        with pytest.raises(MalformedSignatureError):
            decode_signature(short_b64)

        # 68-byte payload base64 encoded
        long_b64 = base64.b64encode(b"A" * 68).decode("ascii")
        with pytest.raises(MalformedSignatureError):
            decode_signature(long_b64)

    # =================================================================
    # Section E: Key Lifecycle Enforcement for Signing
    # =================================================================

    def test_active_key_can_sign(self, key_manager: KeyManager):
        """Active key is authorized to sign."""
        handle = key_manager.generate_key(passphrase=TEST_PASSPHRASE)
        assert handle.is_active
        assert handle.can_sign

        result = sign_hash(SAMPLE_HASH, handle)
        assert result.signature is not None

    def test_rotated_key_cannot_sign(self, key_manager: KeyManager):
        """Rotated key cannot create new signatures and raises KeyRotatedError."""
        old_handle = key_manager.generate_key(passphrase=TEST_PASSPHRASE)
        key_manager.rotate_key(passphrase="NewPassphrase_2026!")

        # Reload old handle
        old_reloaded = key_manager.load_key(
            old_handle.key_id, passphrase=TEST_PASSPHRASE, require_active=False
        )
        assert old_reloaded.is_rotated
        assert not old_reloaded.can_sign

        with pytest.raises(KeyRotatedError) as exc:
            sign_hash(SAMPLE_HASH, old_reloaded)
        assert exc.value.code == "KEY_ROTATED"
        assert isinstance(exc.value, KeyStatusError)

    def test_revoked_key_cannot_sign(self, key_manager: KeyManager):
        """Revoked key cannot create new signatures and raises KeyRevokedError."""
        handle = key_manager.generate_key(passphrase=TEST_PASSPHRASE)
        key_manager.revoke_key(handle.key_id, reason="Emergency audit")

        # Reload revoked handle with private key
        revoked_handle = key_manager.load_key(
            handle.key_id, passphrase=TEST_PASSPHRASE, require_active=False
        )
        assert revoked_handle.is_revoked
        assert not revoked_handle.can_sign

        with pytest.raises(KeyRevokedError) as exc:
            sign_hash(SAMPLE_HASH, revoked_handle)
        assert exc.value.code == "KEY_REVOKED"
        assert isinstance(exc.value, KeyStatusError)

    def test_expired_key_cannot_sign(self, key_manager: KeyManager):
        """Expired key cannot create new signatures and raises KeyExpiredError."""
        handle = key_manager.generate_key(passphrase=TEST_PASSPHRASE)

        # Simulate expiration in metadata
        meta_path = key_manager.keys_dir / f"{handle.key_id}.meta.json"
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
        meta["status"] = KeyStatus.EXPIRED.value
        meta_path.write_text(json.dumps(meta), encoding="utf-8")

        expired_handle = key_manager.load_key(
            handle.key_id, passphrase=TEST_PASSPHRASE, require_active=False
        )
        assert expired_handle.is_expired
        assert not expired_handle.can_sign

        with pytest.raises(KeyExpiredError) as exc:
            sign_hash(SAMPLE_HASH, expired_handle)
        assert exc.value.code == "KEY_EXPIRED"
        assert isinstance(exc.value, KeyStatusError)

    def test_unloaded_private_key_cannot_sign(self, key_manager: KeyManager):
        """Key handle without loaded private key raises KeyManagementError."""
        handle = key_manager.generate_key(passphrase=TEST_PASSPHRASE)
        public_only_handle = key_manager.load_key(
            handle.key_id, load_private=False, require_active=False
        )
        assert not public_only_handle.has_private_key

        with pytest.raises(KeyManagementError) as exc:
            sign_hash(SAMPLE_HASH, public_only_handle)
        assert "not loaded" in str(exc.value).lower()

    # =================================================================
    # Section F: Historical Signature Verification
    # =================================================================

    def test_rotated_key_can_verify_historical_signature(
        self, key_manager: KeyManager
    ):
        """Signatures made before rotation remain mathematically valid and verifiable."""
        old_handle = key_manager.generate_key(passphrase=TEST_PASSPHRASE)
        sig_result = sign_hash(SAMPLE_HASH, old_handle)

        # Now rotate key
        key_manager.rotate_key(passphrase="NewPassphrase_2026!")

        # Load old key for verification (public only)
        old_pub = key_manager.load_key(
            old_handle.key_id, load_private=False, require_active=False
        )
        assert old_pub.is_rotated

        # Verify historical signature
        ver_res = verify_hash_signature(SAMPLE_HASH, sig_result.signature, old_pub)
        assert ver_res.is_valid
        assert ver_res.status == VerificationStatus.VALID
        assert ver_res.key_status == KeyStatus.ROTATED
        assert not ver_res.key_is_active  # Clearly reports key is no longer active

    def test_revoked_key_can_verify_historical_signature(
        self, key_manager: KeyManager
    ):
        """Signatures made before revocation remain cryptographically verifiable."""
        handle = key_manager.generate_key(passphrase=TEST_PASSPHRASE)
        sig_result = sign_hash(SAMPLE_HASH, handle)

        # Now revoke key
        key_manager.revoke_key(handle.key_id, reason="Retired")

        # Load revoked key for historical audit
        revoked_pub = key_manager.load_key(
            handle.key_id, load_private=False, require_active=False
        )
        assert revoked_pub.is_revoked

        ver_res = verify_hash_signature(SAMPLE_HASH, sig_result.signature, revoked_pub)
        assert ver_res.is_valid
        assert ver_res.status == VerificationStatus.VALID
        assert ver_res.key_status == KeyStatus.REVOKED
        assert not ver_res.key_is_active

    def test_expired_key_can_verify_historical_signature(
        self, key_manager: KeyManager
    ):
        """Signatures made before expiration remain cryptographically verifiable."""
        handle = key_manager.generate_key(passphrase=TEST_PASSPHRASE)
        sig_result = sign_hash(SAMPLE_HASH, handle)

        # Simulate expiration
        meta_path = key_manager.keys_dir / f"{handle.key_id}.meta.json"
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
        meta["status"] = KeyStatus.EXPIRED.value
        meta_path.write_text(json.dumps(meta), encoding="utf-8")

        expired_pub = key_manager.load_key(
            handle.key_id, load_private=False, require_active=False
        )
        assert expired_pub.is_expired

        ver_res = verify_hash_signature(SAMPLE_HASH, sig_result.signature, expired_pub)
        assert ver_res.is_valid
        assert ver_res.status == VerificationStatus.VALID
        assert ver_res.key_status == KeyStatus.EXPIRED
        assert not ver_res.key_is_active

    # =================================================================
    # Section G: Key ID Association & KeyManager Integration
    # =================================================================

    def test_verify_provenance_signature_with_key_manager(
        self, key_manager: KeyManager
    ):
        """verify_provenance_signature automatically resolves public key by signer_key_id."""
        handle = key_manager.generate_key(passphrase=TEST_PASSPHRASE)
        sig_result = sign_hash(SAMPLE_HASH, handle)

        # Verification through KeyManager
        ver_res = verify_provenance_signature(
            record_hash=SAMPLE_HASH,
            signature=sig_result.signature,
            signer_key_id=handle.key_id,
            key_manager=key_manager,
        )
        assert ver_res.is_valid
        assert ver_res.status == VerificationStatus.VALID
        assert ver_res.signer_key_id == handle.key_id
        assert ver_res.key_is_active

    def test_verify_with_unknown_signer_key_id(self, key_manager: KeyManager):
        """Verification fails gracefully when signer_key_id is not in KeyManager."""
        handle = key_manager.generate_key(passphrase=TEST_PASSPHRASE)
        sig_result = sign_hash(SAMPLE_HASH, handle)

        unknown_id = "0" * 64
        ver_res = verify_provenance_signature(
            record_hash=SAMPLE_HASH,
            signature=sig_result.signature,
            signer_key_id=unknown_id,
            key_manager=key_manager,
        )
        assert not ver_res.is_valid
        assert ver_res.status == VerificationStatus.UNKNOWN_SIGNER_KEY
        assert "not found in key storage" in ver_res.error_message.lower()

    def test_verify_with_mismatched_key_id(self, key_manager: KeyManager):
        """Specifying an explicit signer_key_id that does not match public key fails."""
        handle1 = key_manager.generate_key(passphrase=TEST_PASSPHRASE)
        sig_result = sign_hash(SAMPLE_HASH, handle1)

        mismatched_id = "e" * 64
        ver_res = verify_hash_signature(
            record_hash=SAMPLE_HASH,
            signature=sig_result.signature,
            public_key=handle1,
            signer_key_id=mismatched_id,
        )
        assert not ver_res.is_valid
        assert ver_res.status == VerificationStatus.UNKNOWN_SIGNER_KEY
        assert "does not match" in ver_res.error_message

    # =================================================================
    # Section H: Security Properties
    # =================================================================

    def test_private_key_not_exposed_in_signature_result(
        self, key_manager: KeyManager
    ):
        """SignatureResult must never expose private key bytes or seed."""
        handle = key_manager.generate_key(passphrase=TEST_PASSPHRASE)
        sig_result = sign_hash(SAMPLE_HASH, handle)

        result_dict = sig_result.model_dump()
        result_repr = repr(sig_result)
        result_str = str(sig_result)

        assert "private_key" not in result_dict
        assert "passphrase" not in result_dict
        assert "PRIVATE KEY" not in result_repr
        assert "PRIVATE KEY" not in result_str
        assert TEST_PASSPHRASE not in result_repr

    def test_verification_result_does_not_expose_secrets(
        self, key_manager: KeyManager
    ):
        """VerificationResult must never expose secret material."""
        handle = key_manager.generate_key(passphrase=TEST_PASSPHRASE)
        sig_result = sign_hash(SAMPLE_HASH, handle)

        ver_res = verify_hash_signature(SAMPLE_HASH, sig_result.signature, handle)
        res_dict = ver_res.model_dump()

        assert "private_key" not in res_dict
        assert "passphrase" not in res_dict
        assert TEST_PASSPHRASE not in repr(ver_res)
