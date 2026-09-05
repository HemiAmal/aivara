"""SHA-256 Hashing Engine for AIVARA.

Provides deterministic SHA-256 content hashing, verification utilities,
constant-time comparison, and canonical provenance payload hashing bridges.
"""

from __future__ import annotations

import hashlib
import hmac
from datetime import datetime
from typing import Any, Dict, Optional, Union

from aivara.core.exceptions import AivaraException
from aivara.crypto.canonical import (
    CANONICAL_SCHEMA_VERSION,
    canonicalize,
    canonicalize_provenance_payload,
)

# Canonical digest length (256 bits = 32 bytes = 64 hexadecimal characters)
SHA256_HEX_LENGTH: int = 64

# Standard NIST / RFC 4634 empty input vector
SHA256_EMPTY_HEX: str = (
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
)

_VALID_HEX_CHARS = frozenset("0123456789abcdef")


# =====================================================================
# Exceptions
# =====================================================================


class HashingError(AivaraException, ValueError):
    """Base exception for all cryptographic hashing failures."""

    def __init__(
        self,
        message: str,
        code: str = "HASHING_ERROR",
        details: Optional[Any] = None,
    ) -> None:
        super().__init__(message, code=code, details=details)


class UnsupportedHashInputError(HashingError):
    """Raised when unsupported input is passed to a hashing function."""

    def __init__(self, message: str, details: Optional[Any] = None) -> None:
        super().__init__(message, code="UNSUPPORTED_HASH_INPUT", details=details)


class InvalidHashFormatError(HashingError):
    """Raised when a hash digest does not conform to the 64-character lowercase hex format."""

    def __init__(self, message: str, details: Optional[Any] = None) -> None:
        super().__init__(message, code="INVALID_HASH_FORMAT", details=details)


# =====================================================================
# Core Hashing Functions
# =====================================================================


def sha256_bytes(data: Union[bytes, bytearray, memoryview]) -> str:
    """Compute deterministic SHA-256 digest of exact bytes.

    Specification:
      - Algorithm: SHA-256 (FIPS 180-4)
      - Digest size: 32 bytes (256 bits)
      - Textual representation: 64-character lowercase hexadecimal
      - Empty input: b"" is valid and returns standard empty digest
      - Immutability: Input buffer is never mutated

    Args:
        data: Exact bytes-like input (bytes, bytearray, or memoryview).

    Returns:
        64-character lowercase hexadecimal digest string.

    Raises:
        UnsupportedHashInputError: If data is not a bytes-like object.
    """
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise UnsupportedHashInputError(
            f"Expected bytes-like input (bytes, bytearray, memoryview), got '{type(data).__name__}'. "
            f"Use sha256_text() for strings or hash_canonical_data() for structured objects."
        )

    return hashlib.sha256(data).hexdigest().lower()


def sha256_text(text: str) -> str:
    """Compute SHA-256 digest of a text string with explicit UTF-8 encoding.

    Convenience helper for hashing text strings. Implicit multi-encoding
    is strictly prohibited; text is always encoded as UTF-8.

    Args:
        text: Text string to hash.

    Returns:
        64-character lowercase hexadecimal digest string.

    Raises:
        UnsupportedHashInputError: If text is not a string.
    """
    if not isinstance(text, str):
        raise UnsupportedHashInputError(
            f"Expected string input, got '{type(text).__name__}'."
        )

    return sha256_bytes(text.encode("utf-8"))


# =====================================================================
# Validation & Comparison Utilities
# =====================================================================


def is_valid_sha256(digest: str) -> bool:
    """Validate that a string conforms to AIVARA's canonical SHA-256 representation.

    Rules:
      - Must be a string
      - Exactly 64 characters
      - Lowercase hexadecimal characters ('0'-'9', 'a'-'f') only
      - No uppercase characters or prefixes (e.g. 'sha256:')

    Args:
        digest: String to validate.

    Returns:
        True if valid canonical SHA-256 digest, False otherwise.
    """
    if not isinstance(digest, str):
        return False
    if len(digest) != SHA256_HEX_LENGTH:
        return False
    return all(c in _VALID_HEX_CHARS for c in digest)


def secure_compare_hashes(a: str, b: str) -> bool:
    """Compare two hash digests in constant time to prevent timing side-channel attacks.

    Args:
        a: First hexadecimal digest.
        b: Second hexadecimal digest.

    Returns:
        True if digests are character-for-character identical, False otherwise.
    """
    if not isinstance(a, str) or not isinstance(b, str):
        return False

    # Enforce lowercase comparison
    return hmac.compare_digest(a.lower(), b.lower())


# =====================================================================
# Canonicalization Bridges
# =====================================================================


def hash_canonical_data(data: Any) -> str:
    """Canonicalize structured JSON data via RFC 8785 and compute its SHA-256 digest.

    Bridge between Phase 4.2 (canonical serialization) and Phase 4.3 (hashing).

    Flow:
        structured data ──► canonicalize() ──► canonical UTF-8 bytes ──► sha256_bytes() ──► digest

    Args:
        data: Safe JSON data structure.

    Returns:
        64-character lowercase hexadecimal digest.

    Raises:
        CanonicalizationError: If data fails canonicalization.
    """
    canonical_bytes = canonicalize(data)
    return sha256_bytes(canonical_bytes)


def hash_provenance_payload(
    *,
    record_type: str,
    project_id: str,
    actor: str,
    action: str,
    sequence_number: int,
    nonce: str,
    timestamp: Union[str, datetime],
    signer_key_id: str,
    target_type: Optional[str] = None,
    target_id: Optional[str] = None,
    input_hash: Optional[str] = None,
    output_hash: Optional[str] = None,
    model_id: Optional[str] = None,
    model_weight_digest: Optional[str] = None,
    config_hash: Optional[str] = None,
    previous_record_hash: Optional[str] = None,
    metadata_json: Optional[Dict[str, Any]] = None,
    schema_version: str = CANONICAL_SCHEMA_VERSION,
) -> str:
    """Compute the deterministic SHA-256 record hash of a protected provenance payload.

    Flow:
        protected fields ──► canonicalize_provenance_payload() ──► canonical bytes ──► sha256_bytes() ──► record_hash

    This computes the content identity over all protected provenance fields.
    It does NOT include digital signatures, database row identifiers, or mutable state.

    Returns:
        64-character lowercase hexadecimal record hash.
    """
    canonical_bytes = canonicalize_provenance_payload(
        record_type=record_type,
        project_id=project_id,
        actor=actor,
        action=action,
        sequence_number=sequence_number,
        nonce=nonce,
        timestamp=timestamp,
        signer_key_id=signer_key_id,
        target_type=target_type,
        target_id=target_id,
        input_hash=input_hash,
        output_hash=output_hash,
        model_id=model_id,
        model_weight_digest=model_weight_digest,
        config_hash=config_hash,
        previous_record_hash=previous_record_hash,
        metadata_json=metadata_json,
        schema_version=schema_version,
    )
    return sha256_bytes(canonical_bytes)
