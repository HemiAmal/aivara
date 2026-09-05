"""AIVARA Cryptographic Engines Package."""

from aivara.crypto.canonical import (
    CANONICAL_SCHEMA_VERSION,
    CanonicalizationError,
    DuplicateKeyError,
    InvalidNumberError,
    InvalidSchemaVersionError,
    InvalidStringError,
    MalformedStructureError,
    UnsupportedTypeError,
    canonicalize,
    canonicalize_provenance_payload,
    format_canonical_datetime,
    parse_canonical_json,
    validate_canonical_data,
)
from aivara.crypto.hashing import (
    SHA256_EMPTY_HEX,
    SHA256_HEX_LENGTH,
    HashingError,
    InvalidHashFormatError,
    UnsupportedHashInputError,
    hash_canonical_data,
    hash_provenance_payload,
    is_valid_sha256,
    secure_compare_hashes,
    sha256_bytes,
    sha256_text,
)

__all__ = [
    # Canonicalization (Phase 4.2)
    "CANONICAL_SCHEMA_VERSION",
    "CanonicalizationError",
    "UnsupportedTypeError",
    "InvalidNumberError",
    "InvalidStringError",
    "MalformedStructureError",
    "InvalidSchemaVersionError",
    "DuplicateKeyError",
    "validate_canonical_data",
    "parse_canonical_json",
    "format_canonical_datetime",
    "canonicalize",
    "canonicalize_provenance_payload",
    # Hashing (Phase 4.3)
    "SHA256_HEX_LENGTH",
    "SHA256_EMPTY_HEX",
    "HashingError",
    "UnsupportedHashInputError",
    "InvalidHashFormatError",
    "sha256_bytes",
    "sha256_text",
    "is_valid_sha256",
    "secure_compare_hashes",
    "hash_canonical_data",
    "hash_provenance_payload",
]
