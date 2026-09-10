"""Level 3: Canonical Sample Fingerprinting Engine (Phase 5.3).

Binds image file identity, decoded pixel buffer identity, annotation set identity,
sample dimensions, paths, and contributor provenance into an immutable, versioned
cryptographic sample fingerprint.
"""

from __future__ import annotations

import re
from typing import Any, Dict, Optional, Sequence

from aivara.crypto.canonical import canonicalize
from aivara.crypto.hashing import sha256_bytes
from aivara.dataset.fingerprinting.exceptions import (
    FingerprintVersionMismatchError,
    InvalidCanonicalInputError,
    InvalidHashFormatError,
)
from aivara.dataset.schemas import CanonicalSample

SAMPLE_DOMAIN_PREFIX: str = "aivara-sample-v1:"
SAMPLE_FINGERPRINT_VERSION: str = "1.0"

_HEX_64_REGEX = re.compile(r"^[0-9a-f]{64}$")


def _validate_hex_64(val: str, field_name: str) -> str:
    """Validate that a string is a 64-character lowercase hexadecimal hash."""
    if not isinstance(val, str) or not _HEX_64_REGEX.match(val):
        raise InvalidHashFormatError(
            f"Invalid hash format for '{field_name}': expected 64 lowercase hex characters, got '{val}'."
        )
    return val


def compute_sample_fingerprint(
    sample: CanonicalSample,
    raw_image_sha256: str,
    decoded_rgb_sha256: str,
    annotation_set_hash: str,
    version: str = SAMPLE_FINGERPRINT_VERSION,
) -> str:
    """Compute deterministic SHA-256 fingerprint for a CanonicalSample.

    Composition:
      - schema_version: Version identifier of the fingerprint scheme.
      - sample_id: Canonical sample identifier.
      - relative_path: POSIX normalized path.
      - file_size_bytes: Size on disk.
      - width, height, channels, color_space: Structural image parameters.
      - raw_image_sha256: Level 0 raw file hash.
      - decoded_rgb_sha256: Level 1 uncompressed pixel buffer hash.
      - annotation_set_hash: Level 2 composite annotation hash.
      - annotation_count: Total annotations associated with sample.
      - contributors: Lexicographically sorted contributor IDs.
      - metadata: Additional source metadata.

    Args:
        sample: CanonicalSample domain object.
        raw_image_sha256: Level 0 SHA-256 digest of raw file on disk.
        decoded_rgb_sha256: Level 1 SHA-256 digest of decoded RGB pixel grid.
        annotation_set_hash: Level 2 SHA-256 digest of annotation set.
        version: Expected fingerprint schema version (default "1.0").

    Returns:
        64-character lowercase hexadecimal SHA-256 digest.

    Raises:
        InvalidCanonicalInputError: If sample is not a CanonicalSample.
        InvalidHashFormatError: If any sub-hash is malformed.
        FingerprintVersionMismatchError: If version is unsupported.
    """
    if not isinstance(sample, CanonicalSample):
        raise InvalidCanonicalInputError(
            f"Expected CanonicalSample instance, got '{type(sample).__name__}'."
        )

    if version != SAMPLE_FINGERPRINT_VERSION:
        raise FingerprintVersionMismatchError(
            f"Unsupported fingerprint schema version '{version}'. Expected '{SAMPLE_FINGERPRINT_VERSION}'."
        )

    raw_hash_valid = _validate_hex_64(raw_image_sha256, "raw_image_sha256")
    pixel_hash_valid = _validate_hex_64(decoded_rgb_sha256, "decoded_rgb_sha256")
    annot_hash_valid = _validate_hex_64(annotation_set_hash, "annotation_set_hash")

    # Deterministically sort contributors
    sorted_contributors = sorted(str(c) for c in (sample.contributors or ()))

    payload: Dict[str, Any] = {
        "schema_version": version,
        "sample_id": str(sample.sample_id),
        "relative_path": str(sample.relative_path),
        "file_size_bytes": int(sample.file_size_bytes),
        "width": int(sample.width),
        "height": int(sample.height),
        "channels": int(sample.channels),
        "color_space": str(sample.color_space),
        "raw_image_sha256": raw_hash_valid,
        "decoded_rgb_sha256": pixel_hash_valid,
        "annotation_set_hash": annot_hash_valid,
        "annotation_count": len(sample.annotations),
        "contributors": sorted_contributors,
        "metadata": dict(sample.metadata or {}),
    }

    try:
        jcs_bytes = canonicalize(payload)
    except Exception as exc:
        raise InvalidCanonicalInputError(
            f"Failed to canonicalize sample payload: {exc}",
            details={"sample_id": sample.sample_id, "error": str(exc)},
        ) from exc

    prefixed_bytes = SAMPLE_DOMAIN_PREFIX.encode("utf-8") + jcs_bytes
    return sha256_bytes(prefixed_bytes)
