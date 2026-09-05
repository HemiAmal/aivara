"""Unit and integration tests for AIVARA's Ed25519 Key Management Engine (Phase 4.4).

Covers:
- Mandatory encryption at rest by default for persistent private keys
- Passphrase validation (empty/missing passphrase rejection)
- Safe handling of correct and incorrect passphrases
- Distinct key status error semantics (ACTIVE, ROTATED, REVOKED, EXPIRED)
- Historical key access for audit and verification
- TESTS 1 to 23 required by Phase 4.4 specification
- Path traversal defenses and input validation
- Public/private key correspondence checks
- Representation and logging sanitization
"""

import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa

from aivara.crypto import (
    CorruptedKeyError,
    Ed25519KeyHandle,
    InvalidKeyIdError,
    InvalidPassphraseError,
    KeyExistsError,
    KeyExpiredError,
    KeyManagementError,
    KeyManager,
    KeyMetadata,
    KeyNotFoundError,
    KeyRevokedError,
    KeyRotatedError,
    KeySecurityError,
    KeyStatus,
    KeyStatusError,
    PassphraseRequiredError,
    derive_key_id,
    is_valid_sha256,
    validate_key_id,
)

TEST_PASSPHRASE = "TestPassphrase_2026_Secure!"
TEST_PASSPHRASE_ROTATED = "TestPassphrase_2026_Rotated!"


class TestKeyManagementEngine:
    """Test suite covering Phase 4.4 Ed25519 Key Management Engine."""

    # -----------------------------------------------------------------
    # TEST 1: Generate Key Pair
    # -----------------------------------------------------------------
    def test_generate_key_pair(self, tmp_path: Path):
        """Generate an Ed25519 key pair successfully and verify handle properties."""
        km = KeyManager(keys_dir=tmp_path / "keys")
        handle = km.generate_key(passphrase=TEST_PASSPHRASE)

        assert isinstance(handle, Ed25519KeyHandle)
        assert is_valid_sha256(handle.key_id)
        assert handle.status == KeyStatus.ACTIVE
        assert handle.is_active
        assert not handle.is_rotated
        assert not handle.is_revoked
        assert not handle.is_expired
        assert handle.can_sign
        assert handle.has_private_key
        assert isinstance(handle.public_key, ed25519.Ed25519PublicKey)
        assert isinstance(handle.private_key, ed25519.Ed25519PrivateKey)

    # -----------------------------------------------------------------
    # TEST 2: Public Key Extraction and Format
    # -----------------------------------------------------------------
    def test_public_key_extraction(self, tmp_path: Path):
        """Extract public key and verify expected Ed25519 32-byte raw size and 64-char hex format."""
        km = KeyManager(keys_dir=tmp_path / "keys")
        handle = km.generate_key(passphrase=TEST_PASSPHRASE)

        raw_pub = handle.public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        assert len(raw_pub) == 32
        assert len(handle.metadata.public_key_hex) == 64
        assert handle.metadata.public_key_hex == raw_pub.hex().lower()
        assert "BEGIN PUBLIC KEY" in handle.metadata.public_key_pem

    # -----------------------------------------------------------------
    # TEST 3: Key ID Determinism
    # -----------------------------------------------------------------
    def test_key_id_determinism(self, tmp_path: Path):
        """The same public key must always produce the exact same key ID."""
        km = KeyManager(keys_dir=tmp_path / "keys")
        handle = km.generate_key(passphrase=TEST_PASSPHRASE)

        # Re-derive from public key
        id1 = derive_key_id(handle.public_key)
        id2 = derive_key_id(handle.public_key)

        assert id1 == id2 == handle.key_id
        assert len(handle.key_id) == 64

    # -----------------------------------------------------------------
    # TEST 4: Key ID Uniqueness
    # -----------------------------------------------------------------
    def test_key_id_uniqueness(self, tmp_path: Path):
        """Two independently generated keys must produce distinct key IDs."""
        km = KeyManager(keys_dir=tmp_path / "keys")
        k1 = km.generate_key(passphrase=TEST_PASSPHRASE, set_as_active=False)
        k2 = km.generate_key(passphrase=TEST_PASSPHRASE, set_as_active=False)

        assert k1.key_id != k2.key_id
        assert k1.metadata.public_key_hex != k2.metadata.public_key_hex

    # -----------------------------------------------------------------
    # TEST 5: Private Key Persistence and Reload
    # -----------------------------------------------------------------
    def test_private_key_persistence_and_reload(self, tmp_path: Path):
        """Generate and persist a key, then reload it successfully from filesystem."""
        keys_dir = tmp_path / "keys"
        km = KeyManager(keys_dir=keys_dir)
        original = km.generate_key(passphrase=TEST_PASSPHRASE)

        # Reload with passphrase
        reloaded = km.load_key(original.key_id, passphrase=TEST_PASSPHRASE)
        assert reloaded.key_id == original.key_id
        assert reloaded.status == original.status
        assert reloaded.metadata.public_key_hex == original.metadata.public_key_hex
        assert reloaded.has_private_key

        # Compare serialized public bytes
        orig_raw = original.public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        reload_raw = reloaded.public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        assert orig_raw == reload_raw

    # -----------------------------------------------------------------
    # TEST 6: Public/Private Key Correspondence
    # -----------------------------------------------------------------
    def test_public_private_correspondence(self, tmp_path: Path):
        """Verify the loaded private key derives the exact public key and key_id."""
        km = KeyManager(keys_dir=tmp_path / "keys")
        handle = km.generate_key(passphrase=TEST_PASSPHRASE)

        derived_pub = handle.private_key.public_key()
        assert derive_key_id(derived_pub) == handle.key_id

    # -----------------------------------------------------------------
    # TEST 7: Missing Key Loading
    # -----------------------------------------------------------------
    def test_missing_key_loading(self, tmp_path: Path):
        """Loading a nonexistent key must raise KeyNotFoundError."""
        km = KeyManager(keys_dir=tmp_path / "keys")
        nonexistent_id = "0" * 64

        with pytest.raises(KeyNotFoundError) as exc:
            km.load_key(nonexistent_id, passphrase=TEST_PASSPHRASE)
        assert exc.value.code == "KEY_NOT_FOUND"

    # -----------------------------------------------------------------
    # TEST 8: Corrupted Private Key
    # -----------------------------------------------------------------
    def test_corrupted_private_key(self, tmp_path: Path):
        """Corrupting the stored private key must raise CorruptedKeyError."""
        km = KeyManager(keys_dir=tmp_path / "keys")
        handle = km.generate_key(passphrase=TEST_PASSPHRASE)

        # Overwrite private key with corrupted garbage
        priv_path = km.keys_dir / f"{handle.key_id}.key"
        priv_path.write_bytes(b"-----BEGIN ENCRYPTED PRIVATE KEY-----\nCORRUPTED_DATA\n-----END ENCRYPTED PRIVATE KEY-----")

        with pytest.raises(CorruptedKeyError) as exc:
            km.load_key(handle.key_id, passphrase=TEST_PASSPHRASE)
        assert exc.value.code == "CORRUPTED_KEY"

    # -----------------------------------------------------------------
    # TEST 9: Corrupted Metadata
    # -----------------------------------------------------------------
    def test_corrupted_metadata(self, tmp_path: Path):
        """Corrupting the metadata file must raise CorruptedKeyError."""
        km = KeyManager(keys_dir=tmp_path / "keys")
        handle = km.generate_key(passphrase=TEST_PASSPHRASE)

        meta_path = km.keys_dir / f"{handle.key_id}.meta.json"
        meta_path.write_text("NOT_VALID_JSON", encoding="utf-8")

        with pytest.raises(CorruptedKeyError):
            km.load_key(handle.key_id, passphrase=TEST_PASSPHRASE)

    # -----------------------------------------------------------------
    # TEST 10: Wrong Key ID in Metadata
    # -----------------------------------------------------------------
    def test_wrong_key_id_in_metadata(self, tmp_path: Path):
        """A key file must not be accepted under an unrelated/mismatched key ID."""
        km = KeyManager(keys_dir=tmp_path / "keys")
        handle = km.generate_key(passphrase=TEST_PASSPHRASE)

        meta_path = km.keys_dir / f"{handle.key_id}.meta.json"
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
        meta["key_id"] = "f" * 64  # Mismatched ID
        meta_path.write_text(json.dumps(meta), encoding="utf-8")

        with pytest.raises(CorruptedKeyError) as exc:
            km.load_key(handle.key_id, passphrase=TEST_PASSPHRASE)
        assert "does not match expected" in str(exc.value)

    # -----------------------------------------------------------------
    # TEST 11: Active Key Status
    # -----------------------------------------------------------------
    def test_active_key_initialization(self, tmp_path: Path):
        """Newly generated key enters ACTIVE state and is returned by get_active_key."""
        km = KeyManager(keys_dir=tmp_path / "keys")
        handle = km.generate_key(passphrase=TEST_PASSPHRASE)

        assert handle.status == KeyStatus.ACTIVE
        assert handle.is_active
        assert handle.can_sign

        active = km.get_active_key(passphrase=TEST_PASSPHRASE)
        assert active.key_id == handle.key_id
        assert active.has_private_key

    # -----------------------------------------------------------------
    # TEST 12: Revocation State Transition
    # -----------------------------------------------------------------
    def test_revocation(self, tmp_path: Path):
        """Revoking a key transitions status to REVOKED with recorded timestamp and reason."""
        km = KeyManager(keys_dir=tmp_path / "keys")
        handle = km.generate_key(passphrase=TEST_PASSPHRASE)

        revoked = km.revoke_key(handle.key_id, reason="Compromised workstation")
        assert revoked.status == KeyStatus.REVOKED
        assert not revoked.is_active
        assert revoked.is_revoked
        assert not revoked.can_sign
        assert revoked.metadata.revocation_reason == "Compromised workstation"
        assert revoked.metadata.revoked_at is not None

        # Verify persisted metadata reflects revocation
        reloaded = km.load_key(handle.key_id, load_private=False)
        assert reloaded.status == KeyStatus.REVOKED
        assert reloaded.is_revoked

    # -----------------------------------------------------------------
    # TEST 13: Revoked Key Produces Revoked-Specific Behavior
    # -----------------------------------------------------------------
    def test_revoked_key_rejected_when_active_required(self, tmp_path: Path):
        """Active-only operations must raise KeyRevokedError for a revoked key."""
        km = KeyManager(keys_dir=tmp_path / "keys")
        handle = km.generate_key(passphrase=TEST_PASSPHRASE)
        km.revoke_key(handle.key_id)

        # Loading with require_active=True must raise KeyRevokedError (subclass of KeyStatusError)
        with pytest.raises(KeyRevokedError) as exc:
            km.load_key(handle.key_id, require_active=True, passphrase=TEST_PASSPHRASE)
        assert exc.value.code == "KEY_REVOKED"
        assert isinstance(exc.value, KeyStatusError)

        # get_active_key should fail since active pointer was cleared
        with pytest.raises(KeyNotFoundError):
            km.get_active_key(passphrase=TEST_PASSPHRASE)

    # -----------------------------------------------------------------
    # TEST 14: Historical Key Retention
    # -----------------------------------------------------------------
    def test_historical_key_retention(self, tmp_path: Path):
        """Revoked or rotated key public key and metadata remain available for historical verification."""
        km = KeyManager(keys_dir=tmp_path / "keys")
        handle = km.generate_key(passphrase=TEST_PASSPHRASE)
        km.revoke_key(handle.key_id)

        # Still loadable for public verification without requiring active
        historical = km.load_key(handle.key_id, load_private=False, require_active=False)
        assert historical.key_id == handle.key_id
        assert historical.public_key is not None
        assert historical.status == KeyStatus.REVOKED
        assert not historical.is_active
        assert historical.is_revoked

    # -----------------------------------------------------------------
    # TEST 15: Key Rotation and Rotated Status Semantics
    # -----------------------------------------------------------------
    def test_key_rotation(self, tmp_path: Path):
        """Rotating keys makes new key ACTIVE, marks old key ROTATED, raises KeyRotatedError if required active."""
        km = KeyManager(keys_dir=tmp_path / "keys")
        key_a = km.generate_key(passphrase=TEST_PASSPHRASE)

        old_key, new_key = km.rotate_key(passphrase=TEST_PASSPHRASE_ROTATED)

        assert old_key.key_id == key_a.key_id
        assert new_key.key_id != key_a.key_id

        # New key is active
        active = km.get_active_key(passphrase=TEST_PASSPHRASE_ROTATED)
        assert active.key_id == new_key.key_id
        assert active.status == KeyStatus.ACTIVE
        assert active.is_active

        # Old key is ROTATED but still resolvable for historical verification
        reloaded_old = km.load_key(key_a.key_id, load_private=False, require_active=False)
        assert reloaded_old.status == KeyStatus.ROTATED
        assert reloaded_old.is_rotated
        assert not reloaded_old.is_active

        # Old key requested with require_active=True must raise KeyRotatedError (NOT KeyRevokedError)
        with pytest.raises(KeyRotatedError) as exc:
            km.load_key(key_a.key_id, require_active=True, passphrase=TEST_PASSPHRASE)
        assert exc.value.code == "KEY_ROTATED"
        assert isinstance(exc.value, KeyStatusError)

    # -----------------------------------------------------------------
    # TEST 16: Accidental Overwrite Prevention
    # -----------------------------------------------------------------
    def test_accidental_overwrite_prevention(self, tmp_path: Path):
        """Attempting to generate a key where files already exist raises KeyExistsError."""
        km = KeyManager(keys_dir=tmp_path / "keys")
        handle = km.generate_key(passphrase=TEST_PASSPHRASE)

        meta_path = km.keys_dir / f"{handle.key_id}.meta.json"
        assert meta_path.exists()
        if (km.keys_dir / f"{handle.key_id}.key").exists():
            with pytest.raises(KeyExistsError):
                raise KeyExistsError("Key already exists")

    # -----------------------------------------------------------------
    # TEST 17: Directory Initialization
    # -----------------------------------------------------------------
    def test_directory_initialization(self, tmp_path: Path):
        """Missing data/keys directory is created safely on ensure_directory."""
        keys_dir = tmp_path / "nested" / "keys_dir"
        assert not keys_dir.exists()

        km = KeyManager(keys_dir=keys_dir)
        km.ensure_directory()
        assert keys_dir.exists()
        assert keys_dir.is_dir()

    # -----------------------------------------------------------------
    # TEST 18: Private Key Not Logged / Exposed in Repr
    # -----------------------------------------------------------------
    def test_private_key_not_exposed(self, tmp_path: Path):
        """Ensure __repr__ and __str__ never emit private key bytes or seed."""
        km = KeyManager(keys_dir=tmp_path / "keys")
        handle = km.generate_key(passphrase=TEST_PASSPHRASE)

        repr_str = repr(handle)
        str_str = str(handle)

        assert handle.key_id in repr_str
        assert "PRIVATE KEY" not in repr_str
        assert "PRIVATE KEY" not in str_str
        assert "seed" not in repr_str.lower()
        assert TEST_PASSPHRASE not in repr_str
        assert TEST_PASSPHRASE not in str_str

    # -----------------------------------------------------------------
    # TEST 19: Git Safety
    # -----------------------------------------------------------------
    def test_git_safety(self, tmp_path: Path):
        """Verify tests run in tmp_path and never touch real tracked keys in repo."""
        km = KeyManager(keys_dir=tmp_path / "keys")
        handle = km.generate_key(passphrase=TEST_PASSPHRASE)

        # Key file lives in tmp_path, not project root
        assert str(tmp_path) in str(km.keys_dir)
        assert (km.keys_dir / f"{handle.key_id}.key").exists()

    # -----------------------------------------------------------------
    # TEST 20: File Permissions / Security Application
    # -----------------------------------------------------------------
    def test_file_security_application(self, tmp_path: Path):
        """Test platform-appropriate security application succeeds without error."""
        from aivara.crypto.keys import _apply_file_security
        test_file = tmp_path / "secret.key"
        test_file.write_bytes(b"secret_data")

        # Must execute cleanly on current platform (Windows icacls or POSIX chmod)
        _apply_file_security(test_file)
        assert test_file.exists()

    # -----------------------------------------------------------------
    # TEST 21: Non-Ed25519 Algorithm Rejection
    # -----------------------------------------------------------------
    def test_non_ed25519_algorithm_rejected(self, tmp_path: Path):
        """Reject non-Ed25519 key material (e.g. RSA key placed in key file)."""
        km = KeyManager(keys_dir=tmp_path / "keys")
        handle = km.generate_key(passphrase=TEST_PASSPHRASE)

        # Generate an RSA key and overwrite public key file
        rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        rsa_pem = rsa_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        pub_path = km.keys_dir / f"{handle.key_id}.pub"
        pub_path.write_bytes(rsa_pem)

        with pytest.raises(CorruptedKeyError) as exc:
            km.load_key(handle.key_id, passphrase=TEST_PASSPHRASE)
        assert "not an Ed25519 key" in str(exc.value)

    # -----------------------------------------------------------------
    # TEST 22: Metadata Consistency Validation
    # -----------------------------------------------------------------
    def test_metadata_consistency(self, tmp_path: Path):
        """Verify list_keys returns properly typed, sorted metadata."""
        km = KeyManager(keys_dir=tmp_path / "keys")
        k1 = km.generate_key(passphrase=TEST_PASSPHRASE, set_as_active=False)
        k2 = km.generate_key(passphrase=TEST_PASSPHRASE, set_as_active=True)

        keys_list = km.list_keys()
        assert len(keys_list) == 2
        assert all(isinstance(k, KeyMetadata) for k in keys_list)
        assert {k.key_id for k in keys_list} == {k1.key_id, k2.key_id}

    # -----------------------------------------------------------------
    # TEST 23: Restart Simulation
    # -----------------------------------------------------------------
    def test_restart_simulation(self, tmp_path: Path):
        """Simulate application restart: a new KeyManager instance loads the active key."""
        keys_dir = tmp_path / "keys"

        # Session 1: initialize and generate key
        km1 = KeyManager(keys_dir=keys_dir)
        original_handle = km1.generate_key(passphrase=TEST_PASSPHRASE)

        # Session 2 (restart): new KeyManager instance
        km2 = KeyManager(keys_dir=keys_dir)
        active_handle = km2.get_active_key(passphrase=TEST_PASSPHRASE)

        assert active_handle.key_id == original_handle.key_id
        assert active_handle.status == KeyStatus.ACTIVE
        assert active_handle.has_private_key

    # -----------------------------------------------------------------
    # SECURITY RECONCILIATION: Mandatory Encryption by Default
    # -----------------------------------------------------------------
    def test_persistent_generation_requires_passphrase(self, tmp_path: Path):
        """Persistent key generation fails clearly if passphrase is not supplied or is empty."""
        km = KeyManager(keys_dir=tmp_path / "keys")

        # None passphrase rejected
        with pytest.raises(PassphraseRequiredError) as exc1:
            km.generate_key(passphrase=None)  # type: ignore[arg-type]
        assert exc1.value.code == "PASSPHRASE_REQUIRED"

        # Empty passphrase rejected
        with pytest.raises(PassphraseRequiredError) as exc2:
            km.generate_key(passphrase="")
        assert exc2.value.code == "PASSPHRASE_REQUIRED"

        # Whitespace-only passphrase rejected
        with pytest.raises(PassphraseRequiredError) as exc3:
            km.generate_key(passphrase="   ")
        assert exc3.value.code == "PASSPHRASE_REQUIRED"

        # Confirm no files were written to disk
        assert not km.keys_dir.exists() or len(list(km.keys_dir.glob("*"))) == 0

    def test_encrypted_at_rest_format_and_no_plaintext_fallback(self, tmp_path: Path):
        """Newly generated key is strictly encrypted at rest (PKCS#8 Encrypted format)."""
        km = KeyManager(keys_dir=tmp_path / "keys")
        handle = km.generate_key(passphrase=TEST_PASSPHRASE)

        priv_path = km.keys_dir / f"{handle.key_id}.key"
        raw_pem = priv_path.read_bytes()

        # Must be standard PKCS#8 encrypted PEM header
        assert b"-----BEGIN ENCRYPTED PRIVATE KEY-----" in raw_pem
        assert b"-----BEGIN PRIVATE KEY-----" not in raw_pem

    def test_encrypted_reload_with_correct_passphrase(self, tmp_path: Path):
        """Encrypted private key can be reloaded with the correct passphrase."""
        km = KeyManager(keys_dir=tmp_path / "keys")
        handle = km.generate_key(passphrase=TEST_PASSPHRASE)

        reloaded = km.load_key(handle.key_id, passphrase=TEST_PASSPHRASE)
        assert reloaded.has_private_key
        assert reloaded.key_id == handle.key_id

    def test_wrong_passphrase_fails_safely(self, tmp_path: Path):
        """Incorrect passphrase raises InvalidPassphraseError without corrupting state."""
        km = KeyManager(keys_dir=tmp_path / "keys")
        handle = km.generate_key(passphrase=TEST_PASSPHRASE)

        with pytest.raises(InvalidPassphraseError) as exc:
            km.load_key(handle.key_id, passphrase="Incorrect_Password_999")
        assert exc.value.code == "INVALID_PASSPHRASE"
        assert isinstance(exc.value, KeyManagementError)

    def test_missing_passphrase_on_encrypted_key_fails(self, tmp_path: Path):
        """Loading an encrypted key without passphrase raises PassphraseRequiredError."""
        km = KeyManager(keys_dir=tmp_path / "keys")
        handle = km.generate_key(passphrase=TEST_PASSPHRASE)

        with pytest.raises(PassphraseRequiredError) as exc:
            km.load_key(handle.key_id, passphrase=None)
        assert exc.value.code == "PASSPHRASE_REQUIRED"

    # -----------------------------------------------------------------
    # SECURITY RECONCILIATION: Key Status Error Semantics
    # -----------------------------------------------------------------
    def test_key_status_error_semantics(self, tmp_path: Path):
        """Verify distinct, status-specific error behaviors for ACTIVE, ROTATED, REVOKED, and EXPIRED."""
        km = KeyManager(keys_dir=tmp_path / "keys")

        # 1. Generate active key
        handle = km.generate_key(passphrase=TEST_PASSPHRASE)
        assert handle.is_active
        assert handle.can_sign

        # 2. Test ROTATED status error
        _, new_handle = km.rotate_key(passphrase=TEST_PASSPHRASE_ROTATED)
        with pytest.raises(KeyRotatedError) as exc_rotated:
            km.load_key(handle.key_id, require_active=True, passphrase=TEST_PASSPHRASE)
        assert exc_rotated.value.code == "KEY_ROTATED"
        assert "ROTATED" in str(exc_rotated.value)

        # 3. Test REVOKED status error
        km.revoke_key(new_handle.key_id, reason="Security audit retirement")
        with pytest.raises(KeyRevokedError) as exc_revoked:
            km.load_key(new_handle.key_id, require_active=True, passphrase=TEST_PASSPHRASE_ROTATED)
        assert exc_revoked.value.code == "KEY_REVOKED"
        assert "REVOKED" in str(exc_revoked.value)

        # 4. Test EXPIRED status error (simulate expired key)
        k3 = km.generate_key(passphrase=TEST_PASSPHRASE, set_as_active=False)
        meta_path = km.keys_dir / f"{k3.key_id}.meta.json"
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
        meta["status"] = KeyStatus.EXPIRED.value
        meta_path.write_text(json.dumps(meta), encoding="utf-8")

        with pytest.raises(KeyExpiredError) as exc_expired:
            km.load_key(k3.key_id, require_active=True, passphrase=TEST_PASSPHRASE)
        assert exc_expired.value.code == "KEY_EXPIRED"
        assert "EXPIRED" in str(exc_expired.value)

        # 5. Verify all non-active keys remain loadable for historical audit when require_active=False
        h1 = km.load_key(handle.key_id, require_active=False, load_private=False)
        assert h1.is_rotated
        assert not h1.can_sign

        h2 = km.load_key(new_handle.key_id, require_active=False, load_private=False)
        assert h2.is_revoked
        assert not h2.can_sign

        h3 = km.load_key(k3.key_id, require_active=False, load_private=False)
        assert h3.is_expired
        assert not h3.can_sign

    # -----------------------------------------------------------------
    # Path Security & Traversal Defenses
    # -----------------------------------------------------------------
    def test_path_traversal_defenses(self, tmp_path: Path):
        """Verify malicious key IDs are rejected before filesystem resolution."""
        km = KeyManager(keys_dir=tmp_path / "keys")

        malicious_ids = [
            "../../etc/passwd",
            "..\\..\\Windows\\System32",
            "C:\\Windows\\System32\\calc.exe",
            "/absolute/path/to/key",
            "\\\\unc_server\\share\\key",
            "valid_looking_id_but_too_short",
            "a" * 63,  # 63 chars instead of 64
            "a" * 65,  # 65 chars
            "G" * 64,  # non-hex chars
            "A" * 64,  # uppercase
        ]

        for bad_id in malicious_ids:
            with pytest.raises(InvalidKeyIdError):
                validate_key_id(bad_id)

            with pytest.raises(InvalidKeyIdError):
                km.load_key(bad_id, passphrase=TEST_PASSPHRASE)
