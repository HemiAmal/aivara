"""Ed25519 Digital Signing and Verification Engine for AIVARA (Phase 4.5).

Provides deterministic Ed25519 digital signature generation and verification
over canonicalized and SHA-256 hashed provenance payloads.

Enforces:
  - Exact 64-byte raw Ed25519 signatures formatted as 88-character Base64 strings.
  - Signing input bound strictly to SHA-256 record hashes encoded as UTF-8 bytes.
  - Active key lifecycle validation for new signatures (rejects ROTATED, REVOKED, EXPIRED).
  - Historical signature verification using archived/historical public keys.
  - Clear, structured verification results distinguishing cryptographic validity
    from key authorization.
"""

from __future__ import annotations

import base64
from enum import Enum
from typing import Any, Dict, Optional, Union

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ed25519
from pydantic import BaseModel, ConfigDict, Field

from aivara.core.exceptions import AivaraException
from aivara.crypto.hashing import hash_provenance_payload, is_valid_sha256
from aivara.crypto.keys import (
    Ed25519KeyHandle,
    KeyExpiredError,
    KeyManagementError,
    KeyNotFoundError,
    KeyRevokedError,
    KeyRotatedError,
    KeyStatus,
    KeyStatusError,
    derive_key_id,
    validate_key_id,
)

# =====================================================================
# Constants
# =====================================================================

ED25519_SIGNATURE_BYTES_LEN: int = 64
ED25519_SIGNATURE_B64_LEN: int = 88
SIGNING_ALGORITHM_NAME: str = "Ed25519"


# =====================================================================
# Exceptions
# =====================================================================


class SigningError(AivaraException, ValueError):
    """Base exception for all cryptographic signing operations."""

    def __init__(
        self,
        message: str,
        code: str = "SIGNING_ERROR",
        details: Optional[Any] = None,
    ) -> None:
        super().__init__(message, code=code, details=details)


class InvalidSigningInputError(SigningError):
    """Raised when the input provided for signing or verification is malformed."""

    def __init__(self, message: str, details: Optional[Any] = None) -> None:
        super().__init__(message, code="INVALID_SIGNING_INPUT", details=details)


class SignatureVerificationError(SigningError):
    """Base exception for signature verification failures."""

    def __init__(
        self,
        message: str,
        code: str = "SIGNATURE_VERIFICATION_ERROR",
        details: Optional[Any] = None,
    ) -> None:
        super().__init__(message, code=code, details=details)


class MalformedSignatureError(SignatureVerificationError):
    """Raised when a signature is not valid Base64 or has an invalid decoded byte length."""

    def __init__(self, message: str, details: Optional[Any] = None) -> None:
        super().__init__(message, code="MALFORMED_SIGNATURE", details=details)


class InvalidSignatureError(SignatureVerificationError):
    """Raised when a signature is cryptographically invalid (mathematical verification failure)."""

    def __init__(self, message: str, details: Optional[Any] = None) -> None:
        super().__init__(message, code="INVALID_SIGNATURE", details=details)


class UnknownSignerKeyError(SignatureVerificationError):
    """Raised when the signer key ID cannot be resolved or does not match the public key."""

    def __init__(self, message: str, details: Optional[Any] = None) -> None:
        super().__init__(message, code="UNKNOWN_SIGNER_KEY", details=details)


# =====================================================================
# Result Models & Enums
# =====================================================================


class VerificationStatus(str, Enum):
    """Detailed categorization of signature verification results."""

    VALID = "VALID"
    INVALID_SIGNATURE = "INVALID_SIGNATURE"
    MALFORMED_SIGNATURE = "MALFORMED_SIGNATURE"
    UNKNOWN_SIGNER_KEY = "UNKNOWN_SIGNER_KEY"
    INVALID_SIGNING_INPUT = "INVALID_SIGNING_INPUT"


class SignatureResult(BaseModel):
    """Encapsulates the output of an Ed25519 signing operation."""

    model_config = ConfigDict(frozen=True)

    signature: str = Field(..., description="Standard Base64-encoded Ed25519 signature (88 chars)")
    signer_key_id: str = Field(..., description="64-character lowercase hex identifier of the signer key")
    algorithm: str = Field(default=SIGNING_ALGORITHM_NAME, description="Digital signature algorithm")
    signed_bytes_count: int = Field(default=64, description="Exact number of raw bytes signed")


class VerificationResult(BaseModel):
    """Encapsulates the complete result of an Ed25519 signature verification operation.

    Distinguishes mathematical cryptographic validity from current key authorization status:
      - is_valid: Answers 'Was this signature mathematically valid for this public key?'
      - key_status: Lifecycle status of the key (ACTIVE, ROTATED, REVOKED, EXPIRED).
      - key_is_active: Answers 'Is this key currently authorized to sign new records?'
    """

    model_config = ConfigDict(frozen=True)

    is_valid: bool = Field(..., description="True if mathematically valid, False otherwise")
    status: VerificationStatus = Field(..., description="Verification status category")
    signer_key_id: Optional[str] = Field(None, description="Resolved signer key ID")
    key_status: Optional[KeyStatus] = Field(None, description="Lifecycle status of verification key if known")
    key_is_active: bool = Field(default=False, description="Whether the verification key is currently ACTIVE")
    error_message: Optional[str] = Field(None, description="Diagnostic error description if verification failed")


# =====================================================================
# Signature Encoding & Decoding
# =====================================================================


def encode_signature(raw_signature: bytes) -> str:
    """Encode a 64-byte raw Ed25519 signature into an 88-character Base64 string.

    Args:
        raw_signature: Raw bytes of the Ed25519 signature.

    Returns:
        Standard Base64 string representation with standard '=' padding.

    Raises:
        MalformedSignatureError: If input is not bytes or length is not 64 bytes.
    """
    if not isinstance(raw_signature, (bytes, bytearray, memoryview)):
        raise MalformedSignatureError("Raw signature must be bytes, bytearray, or memoryview.")
    raw_bytes = bytes(raw_signature)
    if len(raw_bytes) != ED25519_SIGNATURE_BYTES_LEN:
        raise MalformedSignatureError(
            f"Ed25519 signature must be exactly {ED25519_SIGNATURE_BYTES_LEN} bytes, got {len(raw_bytes)}."
        )
    return base64.b64encode(raw_bytes).decode("ascii")


def decode_signature(signature_b64: str) -> bytes:
    """Strictly decode an 88-character Base64 signature into 64 raw bytes.

    Args:
        signature_b64: Standard Base64 string representation.

    Returns:
        64 raw signature bytes.

    Raises:
        MalformedSignatureError: If string is malformed, has invalid length, or invalid padding.
    """
    if not isinstance(signature_b64, str):
        raise MalformedSignatureError("Signature must be a string.")

    if len(signature_b64) != ED25519_SIGNATURE_B64_LEN or signature_b64.strip() != signature_b64:
        raise MalformedSignatureError(
            f"Base64 signature must be exactly {ED25519_SIGNATURE_B64_LEN} characters without whitespace."
        )

    try:
        raw_bytes = base64.b64decode(signature_b64, validate=True)
    except Exception as err:
        raise MalformedSignatureError(f"Malformed Base64 signature encoding: {err}") from err

    if len(raw_bytes) != ED25519_SIGNATURE_BYTES_LEN:
        raise MalformedSignatureError(
            f"Decoded signature must be exactly {ED25519_SIGNATURE_BYTES_LEN} bytes, got {len(raw_bytes)}."
        )

    return raw_bytes


# =====================================================================
# Signing Input Preparation
# =====================================================================


def record_hash_to_signing_bytes(record_hash: str) -> bytes:
    """Convert a 64-character lowercase hexadecimal record hash into exact signing bytes.

    Flow:
        record_hash (64 hex characters)
              ↓
        UTF-8 encode
              ↓
        signing bytes (64 UTF-8 / ASCII bytes)

    Args:
        record_hash: Lowercase 64-character hexadecimal SHA-256 digest.

    Returns:
        64 bytes representing the UTF-8 encoded hash string.

    Raises:
        InvalidSigningInputError: If record_hash is not a valid 64-char lowercase hex string.
    """
    if not isinstance(record_hash, str) or not is_valid_sha256(record_hash):
        raise InvalidSigningInputError(
            f"Invalid record_hash: '{record_hash}'. Must be a 64-character lowercase hex string."
        )
    return record_hash.encode("utf-8")


# =====================================================================
# Signing Operations
# =====================================================================


def _validate_key_for_signing(key_handle: Ed25519KeyHandle) -> None:
    """Enforce that only ACTIVE keys with loaded private key material may create new signatures.

    Raises:
        KeyRevokedError: If key is REVOKED.
        KeyRotatedError: If key is ROTATED.
        KeyExpiredError: If key is EXPIRED.
        KeyStatusError: If key is otherwise non-active.
        KeyManagementError: If private key material is not loaded.
    """
    if not isinstance(key_handle, Ed25519KeyHandle):
        raise KeyManagementError(f"Expected Ed25519KeyHandle, got {type(key_handle).__name__}.")

    if key_handle.status == KeyStatus.REVOKED:
        raise KeyRevokedError(
            f"Key '{key_handle.key_id}' is REVOKED and cannot create new signatures."
        )
    elif key_handle.status == KeyStatus.ROTATED:
        raise KeyRotatedError(
            f"Key '{key_handle.key_id}' is ROTATED and cannot create new signatures."
        )
    elif key_handle.status == KeyStatus.EXPIRED:
        raise KeyExpiredError(
            f"Key '{key_handle.key_id}' is EXPIRED and cannot create new signatures."
        )
    elif not key_handle.is_active:
        raise KeyStatusError(
            f"Key '{key_handle.key_id}' is in non-active status '{key_handle.status.value}'."
        )

    if not key_handle.has_private_key:
        raise KeyManagementError(
            f"Private key material is not loaded for key '{key_handle.key_id}'."
        )


def sign_hash(record_hash: str, key_handle: Ed25519KeyHandle) -> SignatureResult:
    """Sign a 64-character lowercase hexadecimal record hash using an active Ed25519 key.

    Args:
        record_hash: Valid 64-char lowercase hex digest string.
        key_handle: Ed25519KeyHandle in ACTIVE status with private key loaded.

    Returns:
        SignatureResult containing the Base64 signature and signer_key_id.

    Raises:
        InvalidSigningInputError: If record_hash format is invalid.
        KeyRevokedError / KeyRotatedError / KeyExpiredError / KeyStatusError: If key is not ACTIVE.
        KeyManagementError: If private key is missing.
    """
    _validate_key_for_signing(key_handle)
    signing_bytes = record_hash_to_signing_bytes(record_hash)

    # Deterministic Ed25519 signing (RFC 8032)
    raw_signature = key_handle.private_key.sign(signing_bytes)
    b64_signature = encode_signature(raw_signature)

    return SignatureResult(
        signature=b64_signature,
        signer_key_id=key_handle.key_id,
        algorithm=SIGNING_ALGORITHM_NAME,
        signed_bytes_count=len(signing_bytes),
    )


def sign_provenance_payload(
    payload: Dict[str, Any],
    key_handle: Ed25519KeyHandle,
) -> SignatureResult:
    """Canonicalize, hash, and sign a provenance payload in one deterministic pipeline.

    Flow:
        payload (dict)
              ↓
        canonicalize_provenance_payload() or canonicalize() (RFC 8785 JCS)
              ↓
        sha256_bytes() (FIPS 180-4)
              ↓
        record_hash (64 hex characters)
              ↓
        record_hash.encode('utf-8') (64 bytes)
              ↓
        Ed25519PrivateKey.sign() (RFC 8032)
              ↓
        encode_signature() (Base64 88 chars)

    Args:
        payload: Protected provenance payload dictionary.
        key_handle: Ed25519KeyHandle in ACTIVE status with private key loaded.

    Returns:
        SignatureResult containing the Base64 signature and signer_key_id.
    """
    _validate_key_for_signing(key_handle)
    if not isinstance(payload, dict):
        raise InvalidSigningInputError(f"Payload must be a dictionary, got {type(payload).__name__}.")

    # If payload matches provenance schema, hash with hash_provenance_payload
    payload_copy = dict(payload)
    if "signer_key_id" not in payload_copy:
        payload_copy["signer_key_id"] = key_handle.key_id

    try:
        record_hash = hash_provenance_payload(**payload_copy)
    except (TypeError, KeyError):
        from aivara.crypto.hashing import hash_canonical_data
        record_hash = hash_canonical_data(payload)

    return sign_hash(record_hash, key_handle)


def sign_raw_bytes(data: bytes, key_handle: Ed25519KeyHandle) -> SignatureResult:
    """Sign arbitrary non-empty raw bytes directly using an active Ed25519 key.

    Args:
        data: Non-empty byte sequence to sign.
        key_handle: Ed25519KeyHandle in ACTIVE status with private key loaded.

    Returns:
        SignatureResult containing the Base64 signature and signer_key_id.

    Raises:
        InvalidSigningInputError: If data is empty or not bytes.
        KeyStatusError: If key is not ACTIVE.
    """
    _validate_key_for_signing(key_handle)
    if not isinstance(data, (bytes, bytearray, memoryview)) or len(data) == 0:
        raise InvalidSigningInputError("Data to sign must be non-empty bytes.")
    raw_data = bytes(data)

    raw_signature = key_handle.private_key.sign(raw_data)
    b64_signature = encode_signature(raw_signature)

    return SignatureResult(
        signature=b64_signature,
        signer_key_id=key_handle.key_id,
        algorithm=SIGNING_ALGORITHM_NAME,
        signed_bytes_count=len(raw_data),
    )


# =====================================================================
# Verification Operations
# =====================================================================


def verify_hash_signature(
    record_hash: str,
    signature: str,
    public_key: Union[ed25519.Ed25519PublicKey, Ed25519KeyHandle],
    signer_key_id: Optional[str] = None,
) -> VerificationResult:
    """Verify an Ed25519 signature over a 64-character lowercase hex record hash.

    Important:
        Supports historical verification. If an Ed25519KeyHandle is supplied that is
        ROTATED, REVOKED, or EXPIRED, cryptographic verification still evaluates
        the mathematical validity of the signature, returning is_valid=True with
        the key's status accurately reflected.

    Args:
        record_hash: 64-character lowercase hexadecimal hash.
        signature: 88-character Base64 encoded Ed25519 signature.
        public_key: Either Ed25519PublicKey or Ed25519KeyHandle.
        signer_key_id: Optional key_id to verify correspondence with the public key.

    Returns:
        VerificationResult with detailed diagnostic information.
    """
    # 1. Validate signing input
    try:
        signing_bytes = record_hash_to_signing_bytes(record_hash)
    except InvalidSigningInputError as err:
        return VerificationResult(
            is_valid=False,
            status=VerificationStatus.INVALID_SIGNING_INPUT,
            signer_key_id=signer_key_id,
            error_message=str(err),
        )

    # 2. Decode signature
    try:
        raw_signature = decode_signature(signature)
    except MalformedSignatureError as err:
        return VerificationResult(
            is_valid=False,
            status=VerificationStatus.MALFORMED_SIGNATURE,
            signer_key_id=signer_key_id,
            error_message=str(err),
        )

    # 3. Extract public key and key status
    key_status: Optional[KeyStatus] = None
    key_is_active: bool = False

    if isinstance(public_key, Ed25519KeyHandle):
        pub = public_key.public_key
        derived_key_id = public_key.key_id
        key_status = public_key.status
        key_is_active = public_key.is_active
    elif isinstance(public_key, ed25519.Ed25519PublicKey):
        pub = public_key
        derived_key_id = derive_key_id(pub)
    else:
        return VerificationResult(
            is_valid=False,
            status=VerificationStatus.UNKNOWN_SIGNER_KEY,
            signer_key_id=signer_key_id,
            error_message=f"Unsupported public_key type: {type(public_key).__name__}.",
        )

    # 4. Check signer_key_id binding if provided
    if signer_key_id is not None:
        if signer_key_id != derived_key_id:
            return VerificationResult(
                is_valid=False,
                status=VerificationStatus.UNKNOWN_SIGNER_KEY,
                signer_key_id=signer_key_id,
                key_status=key_status,
                key_is_active=key_is_active,
                error_message=(
                    f"Supplied signer_key_id '{signer_key_id}' does not match "
                    f"public key derived ID '{derived_key_id}'."
                ),
            )

    # 5. Perform cryptographic verification
    try:
        pub.verify(raw_signature, signing_bytes)
        return VerificationResult(
            is_valid=True,
            status=VerificationStatus.VALID,
            signer_key_id=derived_key_id,
            key_status=key_status,
            key_is_active=key_is_active,
            error_message=None,
        )
    except InvalidSignature:
        return VerificationResult(
            is_valid=False,
            status=VerificationStatus.INVALID_SIGNATURE,
            signer_key_id=derived_key_id,
            key_status=key_status,
            key_is_active=key_is_active,
            error_message="Cryptographic verification failed: signature does not match payload and public key.",
        )


def verify_provenance_signature(
    record_hash: str,
    signature: str,
    signer_key_id: str,
    key_manager: KeyManager,
) -> VerificationResult:
    """Verify an Ed25519 signature by resolving the public key from a KeyManager.

    Supports historical keys: Loads the public key and metadata for signer_key_id
    without requiring the key to be ACTIVE, allowing verification of historical records.

    Args:
        record_hash: 64-character lowercase hex digest string.
        signature: 88-character Base64 Ed25519 signature.
        signer_key_id: 64-character lowercase hex signer key identifier.
        key_manager: KeyManager instance storing the key material.

    Returns:
        VerificationResult.
    """
    # 1. Validate key_id format early
    try:
        validate_key_id(signer_key_id)
    except Exception as err:
        return VerificationResult(
            is_valid=False,
            status=VerificationStatus.UNKNOWN_SIGNER_KEY,
            signer_key_id=signer_key_id,
            error_message=f"Invalid signer_key_id format: {err}",
        )

    # 2. Resolve key handle from KeyManager (historical verification: require_active=False)
    try:
        key_handle = key_manager.load_key(
            key_id=signer_key_id,
            load_private=False,
            require_active=False,
        )
    except KeyNotFoundError:
        return VerificationResult(
            is_valid=False,
            status=VerificationStatus.UNKNOWN_SIGNER_KEY,
            signer_key_id=signer_key_id,
            error_message=f"Signer key '{signer_key_id}' not found in key storage.",
        )
    except Exception as err:
        return VerificationResult(
            is_valid=False,
            status=VerificationStatus.UNKNOWN_SIGNER_KEY,
            signer_key_id=signer_key_id,
            error_message=f"Failed to load key '{signer_key_id}': {err}",
        )

    # 3. Verify signature using the loaded key handle
    return verify_hash_signature(
        record_hash=record_hash,
        signature=signature,
        public_key=key_handle,
        signer_key_id=signer_key_id,
    )


def assert_signature_valid(
    record_hash: str,
    signature: str,
    public_key: Union[ed25519.Ed25519PublicKey, Ed25519KeyHandle],
    signer_key_id: Optional[str] = None,
) -> None:
    """Verify an Ed25519 signature and raise a specific exception if verification fails.

    Args:
        record_hash: 64-character lowercase hex record hash.
        signature: 88-character Base64 encoded signature.
        public_key: Ed25519PublicKey or Ed25519KeyHandle.
        signer_key_id: Optional expected signer key ID.

    Raises:
        InvalidSigningInputError: If record_hash format is invalid.
        MalformedSignatureError: If signature encoding or length is invalid.
        UnknownSignerKeyError: If signer_key_id does not match public key.
        InvalidSignatureError: If signature is mathematically invalid.
    """
    result = verify_hash_signature(
        record_hash=record_hash,
        signature=signature,
        public_key=public_key,
        signer_key_id=signer_key_id,
    )
    if result.is_valid:
        return

    if result.status == VerificationStatus.INVALID_SIGNING_INPUT:
        raise InvalidSigningInputError(result.error_message or "Invalid signing input.")
    elif result.status == VerificationStatus.MALFORMED_SIGNATURE:
        raise MalformedSignatureError(result.error_message or "Malformed signature.")
    elif result.status == VerificationStatus.UNKNOWN_SIGNER_KEY:
        raise UnknownSignerKeyError(result.error_message or "Unknown signer key.")
    else:
        raise InvalidSignatureError(result.error_message or "Invalid cryptographic signature.")
