"""Ed25519 Key Lifecycle Management Engine for AIVARA (Phase 4.4).

Provides secure local filesystem-backed key generation, storage, loading,
metadata tracking, rotation, and revocation for offline workstations.
"""

from __future__ import annotations

import getpass
import json
import os
import subprocess
import tempfile
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from pydantic import BaseModel, ConfigDict, Field

from aivara.core.config import settings
from aivara.core.exceptions import AivaraException
from aivara.crypto.canonical import format_canonical_datetime
from aivara.crypto.hashing import is_valid_sha256, sha256_bytes

# =====================================================================
# Exceptions
# =====================================================================


class KeyManagementError(AivaraException, ValueError):
    """Base exception for all key management operations."""

    def __init__(
        self,
        message: str,
        code: str = "KEY_MANAGEMENT_ERROR",
        details: Optional[Any] = None,
    ) -> None:
        super().__init__(message, code=code, details=details)


class KeyStatusError(KeyManagementError):
    """Base exception for operations rejected due to incompatible key lifecycle status."""

    def __init__(
        self,
        message: str,
        code: str = "KEY_STATUS_ERROR",
        details: Optional[Any] = None,
    ) -> None:
        super().__init__(message, code=code, details=details)


class KeyRevokedError(KeyStatusError):
    """Raised when attempting an operation requiring an active key on a revoked key."""

    def __init__(self, message: str, details: Optional[Any] = None) -> None:
        super().__init__(message, code="KEY_REVOKED", details=details)


class KeyRotatedError(KeyStatusError):
    """Raised when attempting an operation requiring an active key on a rotated key."""

    def __init__(self, message: str, details: Optional[Any] = None) -> None:
        super().__init__(message, code="KEY_ROTATED", details=details)


class KeyExpiredError(KeyStatusError):
    """Raised when attempting an operation requiring an active key on an expired key."""

    def __init__(self, message: str, details: Optional[Any] = None) -> None:
        super().__init__(message, code="KEY_EXPIRED", details=details)


class PassphraseRequiredError(KeyManagementError):
    """Raised when a passphrase is required for private key encryption or decryption but not provided."""

    def __init__(self, message: str, details: Optional[Any] = None) -> None:
        super().__init__(message, code="PASSPHRASE_REQUIRED", details=details)


class InvalidPassphraseError(KeyManagementError):
    """Raised when an incorrect passphrase is provided to decrypt a private key."""

    def __init__(self, message: str, details: Optional[Any] = None) -> None:
        super().__init__(message, code="INVALID_PASSPHRASE", details=details)


class KeyNotFoundError(KeyManagementError):
    """Raised when an identified key does not exist."""

    def __init__(self, message: str, details: Optional[Any] = None) -> None:
        super().__init__(message, code="KEY_NOT_FOUND", details=details)


class KeyExistsError(KeyManagementError):
    """Raised when an attempt is made to overwrite an existing key."""

    def __init__(self, message: str, details: Optional[Any] = None) -> None:
        super().__init__(message, code="KEY_ALREADY_EXISTS", details=details)


class InvalidKeyIdError(KeyManagementError):
    """Raised when a key_id fails format or path security validation."""

    def __init__(self, message: str, details: Optional[Any] = None) -> None:
        super().__init__(message, code="INVALID_KEY_ID", details=details)


class CorruptedKeyError(KeyManagementError):
    """Raised when key material or metadata is malformed or tampered with."""

    def __init__(self, message: str, details: Optional[Any] = None) -> None:
        super().__init__(message, code="CORRUPTED_KEY", details=details)


class KeySecurityError(KeyManagementError):
    """Raised on security violations such as path traversal or permission failures."""

    def __init__(self, message: str, details: Optional[Any] = None) -> None:
        super().__init__(message, code="KEY_SECURITY_ERROR", details=details)


# =====================================================================
# Key Status & Metadata Models
# =====================================================================


class KeyStatus(str, Enum):
    """Lifecycle states for an Ed25519 signing key."""

    ACTIVE = "ACTIVE"
    ROTATED = "ROTATED"
    REVOKED = "REVOKED"
    EXPIRED = "EXPIRED"


class KeyMetadata(BaseModel):
    """Public metadata associated with an Ed25519 key."""

    model_config = ConfigDict(use_enum_values=True)

    key_id: str = Field(..., description="Deterministic SHA-256 digest of public key bytes")
    algorithm: str = Field(default="Ed25519", description="Cryptographic algorithm")
    created_at: str = Field(..., description="UTC ISO 8601 creation timestamp")
    status: KeyStatus = Field(default=KeyStatus.ACTIVE, description="Current lifecycle state")
    public_key_hex: str = Field(..., description="64-character lowercase hex representation of raw public key")
    public_key_pem: str = Field(..., description="PEM format SubjectPublicKeyInfo string")
    revoked_at: Optional[str] = Field(None, description="UTC ISO 8601 revocation timestamp if revoked")
    revocation_reason: Optional[str] = Field(None, description="Documented reason for revocation")


# =====================================================================
# Controlled Key Handle
# =====================================================================


class Ed25519KeyHandle:
    """Safe abstraction wrapping an Ed25519 key pair and its metadata.

    Guarantees:
      - Never exposes private key bytes in __repr__ or __str__.
      - Restricts access to private key material.
      - Provides access to public key and verified metadata.
    """

    def __init__(
        self,
        metadata: KeyMetadata,
        public_key: ed25519.Ed25519PublicKey,
        private_key: Optional[ed25519.Ed25519PrivateKey] = None,
    ) -> None:
        self._metadata = metadata
        self._public_key = public_key
        self._private_key = private_key

    @property
    def key_id(self) -> str:
        return self._metadata.key_id

    @property
    def status(self) -> KeyStatus:
        return KeyStatus(self._metadata.status)

    @property
    def is_active(self) -> bool:
        return self.status == KeyStatus.ACTIVE

    @property
    def is_rotated(self) -> bool:
        return self.status == KeyStatus.ROTATED

    @property
    def is_revoked(self) -> bool:
        return self.status == KeyStatus.REVOKED

    @property
    def is_expired(self) -> bool:
        return self.status == KeyStatus.EXPIRED

    @property
    def can_sign(self) -> bool:
        """Whether this key is eligible for signing new records in Phase 4.5."""
        return self.is_active and self.has_private_key

    @property
    def metadata(self) -> KeyMetadata:
        return self._metadata

    @property
    def public_key(self) -> ed25519.Ed25519PublicKey:
        return self._public_key

    @property
    def has_private_key(self) -> bool:
        return self._private_key is not None

    @property
    def private_key(self) -> ed25519.Ed25519PrivateKey:
        if self._private_key is None:
            raise KeyManagementError(
                f"Private key material is not loaded for key '{self.key_id}'."
            )
        return self._private_key

    def __repr__(self) -> str:
        return (
            f"<Ed25519KeyHandle key_id='{self.key_id}' status='{self.status.value}' "
            f"has_private_key={self.has_private_key}>"
        )

    def __str__(self) -> str:
        return self.__repr__()


# =====================================================================
# Key ID & Filesystem Security Helpers
# =====================================================================


def derive_key_id(public_key: ed25519.Ed25519PublicKey) -> str:
    """Derive deterministic, collision-resistant key_id: SHA-256 of raw 32-byte public key."""
    raw_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return sha256_bytes(raw_bytes)


def validate_key_id(key_id: str) -> None:
    """Enforce that key_id is strictly a 64-character lowercase hexadecimal string.

    This prevents directory traversal (e.g. '../', drive paths, UNC paths)
    by strictly disallowing non-hex characters.
    """
    if not isinstance(key_id, str) or not is_valid_sha256(key_id):
        raise InvalidKeyIdError(
            f"Invalid key_id: '{key_id}'. Must be a 64-character lowercase hex string."
        )


def _apply_file_security(path: Path) -> None:
    """Apply restrictive permissions to a file (0600 on POSIX, ACL on Windows)."""
    if os.name == "nt":
        try:
            user = os.environ.get("USERNAME", getpass.getuser())
            subprocess.run(
                ["icacls", str(path.resolve()), "/inheritance:r", "/grant:r", f"{user}:(R,W)"],
                capture_output=True,
                check=False,
            )
        except Exception:
            pass
    else:
        try:
            os.chmod(path, 0o600)
        except Exception:
            pass


def _apply_dir_security(path: Path) -> None:
    """Apply restrictive permissions to a directory (0700 on POSIX, ACL on Windows)."""
    if os.name == "nt":
        try:
            user = os.environ.get("USERNAME", getpass.getuser())
            subprocess.run(
                ["icacls", str(path.resolve()), "/inheritance:r", "/grant:r", f"{user}:(OI)(CI)F"],
                capture_output=True,
                check=False,
            )
        except Exception:
            pass
    else:
        try:
            os.chmod(path, 0o700)
        except Exception:
            pass


def _atomic_write_file(target_path: Path, data: bytes, is_secret: bool = False) -> None:
    """Write file atomically using temporary file, fsync, and atomic rename."""
    target_path.parent.mkdir(parents=True, exist_ok=True)
    temp_file = tempfile.NamedTemporaryFile(
        dir=target_path.parent,
        delete=False,
        prefix=".tmp_key_",
    )
    temp_path = Path(temp_file.name)
    try:
        temp_file.write(data)
        temp_file.flush()
        os.fsync(temp_file.fileno())
        temp_file.close()

        if is_secret:
            _apply_file_security(temp_path)

        os.replace(temp_path, target_path)

        if is_secret:
            _apply_file_security(target_path)
    except Exception:
        if temp_path.exists():
            try:
                os.unlink(temp_path)
            except Exception:
                pass
        raise


# =====================================================================
# Key Manager Implementation
# =====================================================================


class KeyManager:
    """Filesystem-backed Ed25519 Key Management Engine."""

    def __init__(self, keys_dir: Optional[Path] = None) -> None:
        """Initialize KeyManager with target keys directory.

        Args:
            keys_dir: Optional override for keys storage directory.
                      Defaults to settings.keys_dir (data/keys).
        """
        self._keys_dir = Path(keys_dir) if keys_dir is not None else settings.keys_dir
        self._active_file = self._keys_dir / "active_key_id.txt"

    @property
    def keys_dir(self) -> Path:
        return self._keys_dir

    def ensure_directory(self) -> Path:
        """Ensure the keys directory exists with restrictive permissions."""
        self._keys_dir.mkdir(parents=True, exist_ok=True)
        _apply_dir_security(self._keys_dir)
        return self._keys_dir

    def _resolve_key_path(self, key_id: str, extension: str) -> Path:
        """Safely resolve a key file path with strict traversal checking."""
        validate_key_id(key_id)
        path = (self._keys_dir / f"{key_id}.{extension}").resolve()
        # Verify resolved path is strictly within keys_dir
        keys_dir_resolved = self._keys_dir.resolve()
        try:
            path.relative_to(keys_dir_resolved)
        except ValueError as err:
            raise KeySecurityError(
                f"Path traversal detected for key_id '{key_id}'."
            ) from err
        return path

    def generate_key(
        self,
        passphrase: str,
        set_as_active: bool = True,
        description: Optional[str] = None,
    ) -> Ed25519KeyHandle:
        """Generate a fresh Ed25519 key pair and persist it encrypted at rest.

        Note:
            Private keys are strictly encrypted with AES-256-CBC via BestAvailableEncryption
            using the provided passphrase. The passphrase is the user's responsibility and
            cannot be recovered by AIVARA. If a passphrase is not supplied or is empty,
            key generation fails immediately and no plaintext key is ever stored.

        Args:
            passphrase: Required non-empty passphrase to encrypt the private key at rest.
            set_as_active: Whether to set this key as the current active key.
            description: Optional human-readable description for key metadata.

        Returns:
            Ed25519KeyHandle with loaded private and public key.

        Raises:
            PassphraseRequiredError: If passphrase is missing, empty, or whitespace-only.
            KeyExistsError: If a key with the derived key_id already exists.
        """
        if not passphrase or not isinstance(passphrase, str) or len(passphrase.strip()) == 0:
            raise PassphraseRequiredError(
                "A non-empty passphrase is required to encrypt the private key at rest. "
                "AIVARA does not store plaintext private keys."
            )

        self.ensure_directory()

        # 1. Generate Ed25519 key pair
        private_key = ed25519.Ed25519PrivateKey.generate()
        public_key = private_key.public_key()

        # 2. Derive deterministic key_id
        key_id = derive_key_id(public_key)

        # 3. Check for collision / existing key
        private_path = self._resolve_key_path(key_id, "key")
        public_path = self._resolve_key_path(key_id, "pub")
        meta_path = self._resolve_key_path(key_id, "meta.json")

        if private_path.exists() or meta_path.exists():
            raise KeyExistsError(f"Key '{key_id}' already exists in key storage.")

        # 4. Serialize private key with standard PKCS#8 encrypted format (BestAvailableEncryption)
        encryption = serialization.BestAvailableEncryption(passphrase.encode("utf-8"))
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption,
        )

        # 5. Serialize public key (SubjectPublicKeyInfo PEM & raw hex)
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        raw_public_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        public_hex = raw_public_bytes.hex().lower()

        # 6. Create metadata
        now_str = format_canonical_datetime(datetime.now(timezone.utc))
        metadata = KeyMetadata(
            key_id=key_id,
            algorithm="Ed25519",
            created_at=now_str,
            status=KeyStatus.ACTIVE,
            public_key_hex=public_hex,
            public_key_pem=public_pem.decode("utf-8"),
        )

        # 7. Atomically write files (private key is marked is_secret=True for ACL / 0600)
        _atomic_write_file(private_path, private_pem, is_secret=True)
        _atomic_write_file(public_path, public_pem, is_secret=False)
        _atomic_write_file(meta_path, metadata.model_dump_json(indent=2).encode("utf-8"), is_secret=False)

        # 8. Update active key pointer if requested
        if set_as_active or not self._active_file.exists():
            self._set_active_key_id(key_id)

        return Ed25519KeyHandle(
            metadata=metadata,
            public_key=public_key,
            private_key=private_key,
        )

    def _set_active_key_id(self, key_id: str) -> None:
        """Atomically set the current active key ID pointer."""
        validate_key_id(key_id)
        _atomic_write_file(self._active_file, key_id.encode("utf-8"), is_secret=False)

    def get_active_key_id(self) -> Optional[str]:
        """Return the current active key ID if configured, else None."""
        if not self._active_file.exists():
            return None
        try:
            content = self._active_file.read_text(encoding="utf-8").strip()
            validate_key_id(content)
            return content
        except Exception:
            return None

    def load_key(
        self,
        key_id: str,
        passphrase: Optional[str] = None,
        require_active: bool = False,
        load_private: bool = True,
    ) -> Ed25519KeyHandle:
        """Load an existing key by key_id and verify integrity.

        Args:
            key_id: 64-character lowercase hex key identifier.
            passphrase: Passphrase if private key is encrypted.
            require_active: If True, enforces status == ACTIVE. Raises KeyRevokedError,
                            KeyRotatedError, or KeyExpiredError if non-active.
            load_private: If True, loads private key; if False, loads public key and metadata only.

        Returns:
            Ed25519KeyHandle.

        Raises:
            KeyNotFoundError: If key does not exist.
            CorruptedKeyError: If metadata or key files are corrupted.
            KeyRevokedError: If require_active=True and key status is REVOKED.
            KeyRotatedError: If require_active=True and key status is ROTATED.
            KeyExpiredError: If require_active=True and key status is EXPIRED.
            KeyStatusError: If require_active=True and key status is otherwise non-active.
            PassphraseRequiredError: If private key is encrypted but no passphrase is provided.
            InvalidPassphraseError: If an incorrect passphrase is provided.
        """
        validate_key_id(key_id)

        meta_path = self._resolve_key_path(key_id, "meta.json")
        public_path = self._resolve_key_path(key_id, "pub")
        private_path = self._resolve_key_path(key_id, "key")

        if not meta_path.exists():
            raise KeyNotFoundError(f"Key metadata for '{key_id}' not found.")

        # 1. Load and validate metadata
        try:
            meta_data = json.loads(meta_path.read_text(encoding="utf-8"))
            metadata = KeyMetadata(**meta_data)
        except Exception as err:
            raise CorruptedKeyError(f"Corrupted metadata for key '{key_id}': {err}") from err

        if metadata.key_id != key_id:
            raise CorruptedKeyError(
                f"Metadata key_id '{metadata.key_id}' does not match expected '{key_id}'."
            )

        if metadata.algorithm != "Ed25519":
            raise CorruptedKeyError(
                f"Unsupported algorithm '{metadata.algorithm}' in key '{key_id}'."
            )

        # 2. Check active status constraint with precise status-specific semantics
        if require_active and metadata.status != KeyStatus.ACTIVE.value:
            if metadata.status == KeyStatus.REVOKED.value:
                raise KeyRevokedError(
                    f"Key '{key_id}' is REVOKED and cannot be used as an active key.",
                    details={
                        "key_id": key_id,
                        "status": metadata.status,
                        "revoked_at": metadata.revoked_at,
                        "reason": metadata.revocation_reason,
                    },
                )
            elif metadata.status == KeyStatus.ROTATED.value:
                raise KeyRotatedError(
                    f"Key '{key_id}' is ROTATED and cannot be used as an active key.",
                    details={"key_id": key_id, "status": metadata.status},
                )
            elif metadata.status == KeyStatus.EXPIRED.value:
                raise KeyExpiredError(
                    f"Key '{key_id}' is EXPIRED and cannot be used as an active key.",
                    details={"key_id": key_id, "status": metadata.status},
                )
            else:
                raise KeyStatusError(
                    f"Key '{key_id}' has non-active status '{metadata.status}'.",
                    details={"key_id": key_id, "status": metadata.status},
                )

        # 3. Load public key and verify correspondence
        if not public_path.exists():
            raise CorruptedKeyError(f"Public key file for '{key_id}' missing.")

        try:
            pub_pem = public_path.read_bytes()
            loaded_public = serialization.load_pem_public_key(pub_pem)
            if not isinstance(loaded_public, ed25519.Ed25519PublicKey):
                raise CorruptedKeyError("Loaded public key is not an Ed25519 key.")
        except Exception as err:
            raise CorruptedKeyError(f"Failed to load public key for '{key_id}': {err}") from err

        # Verify public key hash matches key_id
        derived_id = derive_key_id(loaded_public)
        if derived_id != key_id:
            raise CorruptedKeyError(
                f"Public key for '{key_id}' derives unexpected key_id '{derived_id}'."
            )

        # 4. Optionally load private key
        loaded_private: Optional[ed25519.Ed25519PrivateKey] = None
        if load_private:
            if not private_path.exists():
                raise KeyNotFoundError(f"Private key file for '{key_id}' missing.")
            try:
                priv_pem = private_path.read_bytes()
                pass_bytes = passphrase.encode("utf-8") if passphrase is not None else None
                loaded_priv = serialization.load_pem_private_key(priv_pem, password=pass_bytes)
                if not isinstance(loaded_priv, ed25519.Ed25519PrivateKey):
                    raise CorruptedKeyError("Loaded private key is not an Ed25519 key.")
                loaded_private = loaded_priv
            except TypeError as err:
                # "Password was not given but private key is encrypted"
                raise PassphraseRequiredError(
                    f"Passphrase is required to decrypt private key '{key_id}'."
                ) from err
            except ValueError as err:
                err_str = str(err).lower()
                if "password" in err_str or "bad decrypt" in err_str or "could not decrypt" in err_str:
                    raise InvalidPassphraseError(
                        f"Incorrect passphrase provided for private key '{key_id}'."
                    ) from err
                raise CorruptedKeyError(f"Failed to parse private key for '{key_id}': {err}") from err
            except Exception as err:
                raise CorruptedKeyError(f"Failed to load private key for '{key_id}': {err}") from err

            # Verify private key derives the exact same public key
            if derive_key_id(loaded_private.public_key()) != key_id:
                raise CorruptedKeyError(
                    f"Private key does not correspond to public key for '{key_id}'."
                )

        return Ed25519KeyHandle(
            metadata=metadata,
            public_key=loaded_public,
            private_key=loaded_private,
        )

    def get_active_key(
        self,
        passphrase: Optional[str] = None,
        load_private: bool = True,
    ) -> Ed25519KeyHandle:
        """Load the currently active signing key.

        Args:
            passphrase: Required if load_private=True to decrypt the active private key.
            load_private: If True, loads and decrypts private key. If False, loads public key only.

        Raises:
            KeyNotFoundError: If no active key is configured.
            KeyRevokedError: If the active key has been revoked.
            KeyRotatedError: If the active key has been rotated.
            KeyExpiredError: If the active key has expired.
            PassphraseRequiredError: If load_private=True and key is encrypted but no passphrase is provided.
            InvalidPassphraseError: If load_private=True and incorrect passphrase is provided.
        """
        active_id = self.get_active_key_id()
        if active_id is None:
            raise KeyNotFoundError("No active signing key is currently configured.")
        return self.load_key(
            active_id,
            passphrase=passphrase,
            require_active=True,
            load_private=load_private,
        )

    def rotate_key(
        self,
        passphrase: str,
    ) -> Tuple[Ed25519KeyHandle, Ed25519KeyHandle]:
        """Rotate the signing key by generating a new encrypted key and retiring the old one.

        The old key's status is transitioned to ROTATED and remains available
        for historical signature verification.

        Args:
            passphrase: Required passphrase to encrypt the new private key at rest.

        Returns:
            Tuple of (old_key_handle, new_active_key_handle).

        Raises:
            PassphraseRequiredError: If passphrase is missing or empty.
            KeyNotFoundError: If no active key exists to rotate from.
        """
        if not passphrase or not isinstance(passphrase, str) or len(passphrase.strip()) == 0:
            raise PassphraseRequiredError(
                "A non-empty passphrase is required to encrypt the rotated private key at rest."
            )

        old_key = self.get_active_key(load_private=False)

        # 1. Generate new active key
        new_key = self.generate_key(passphrase=passphrase, set_as_active=True)

        # 2. Update old key status to ROTATED
        old_meta_path = self._resolve_key_path(old_key.key_id, "meta.json")
        old_metadata = old_key.metadata
        old_metadata.status = KeyStatus.ROTATED
        _atomic_write_file(
            old_meta_path,
            old_metadata.model_dump_json(indent=2).encode("utf-8"),
            is_secret=False,
        )

        return old_key, new_key

    def revoke_key(
        self,
        key_id: str,
        reason: str = "Unspecified",
    ) -> Ed25519KeyHandle:
        """Revoke a key, marking its status as REVOKED.

        Preserves public key and metadata for historical audit and verification.
        If the revoked key is the active key, clears the active key pointer.

        Args:
            key_id: Key ID to revoke.
            reason: Documented revocation reason.

        Returns:
            Updated Ed25519KeyHandle with REVOKED status.

        Raises:
            KeyNotFoundError: If key does not exist.
        """
        handle = self.load_key(key_id, load_private=False)
        metadata = handle.metadata

        # Update metadata state
        now_str = format_canonical_datetime(datetime.now(timezone.utc))
        metadata.status = KeyStatus.REVOKED
        metadata.revoked_at = now_str
        metadata.revocation_reason = reason

        meta_path = self._resolve_key_path(key_id, "meta.json")
        _atomic_write_file(
            meta_path,
            metadata.model_dump_json(indent=2).encode("utf-8"),
            is_secret=False,
        )

        # If this key was active, clear active pointer
        if self.get_active_key_id() == key_id:
            if self._active_file.exists():
                try:
                    os.unlink(self._active_file)
                except Exception:
                    pass

        return Ed25519KeyHandle(
            metadata=metadata,
            public_key=handle.public_key,
            private_key=None,
        )

    def list_keys(self) -> List[KeyMetadata]:
        """List metadata for all known keys sorted by creation timestamp."""
        if not self._keys_dir.exists():
            return []

        keys: List[KeyMetadata] = []
        for meta_path in self._keys_dir.glob("*.meta.json"):
            try:
                data = json.loads(meta_path.read_text(encoding="utf-8"))
                keys.append(KeyMetadata(**data))
            except Exception:
                continue

        keys.sort(key=lambda k: k.created_at)
        return keys
