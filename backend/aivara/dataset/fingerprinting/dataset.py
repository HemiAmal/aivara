"""Dataset Manifest Digest Engine (Phase 5.3).

Computes deterministic dataset_hash binding dataset metadata, category hierarchy,
sample counts, format, and the sample Merkle tree root into an immutable RFC 8785
manifest digest.
"""

from __future__ import annotations

import re
from typing import Any, Dict

from aivara.crypto.canonical import canonicalize
from aivara.crypto.hashing import sha256_bytes
from aivara.dataset.fingerprinting.exceptions import (
    FingerprintVersionMismatchError,
    InvalidCanonicalInputError,
    InvalidHashFormatError,
)
from aivara.dataset.schemas import CanonicalDatasetManifest

DATASET_DOMAIN_PREFIX: str = "aivara-dataset-v1:"
DATASET_FINGERPRINT_VERSION: str = "1.0"

_HEX_64_REGEX = re.compile(r"^[0-9a-f]{64}$")


def compute_dataset_hash(
    manifest: CanonicalDatasetManifest,
    dataset_merkle_root: str,
    fingerprint_version: str = DATASET_FINGERPRINT_VERSION,
) -> str:
    """Compute deterministic SHA-256 digest over the canonical dataset manifest.

    Binds:
      - schema_version: Manifest schema version.
      - fingerprint_version: Fingerprint algorithm version.
      - format: Dataset format (COCO, YOLO, ImageFolder, etc.).
      - dataset_name: Logical dataset name.
      - dataset_merkle_root: RFC 6962 binary Merkle root over sample fingerprints.
      - sample_count: Total valid samples in manifest.
      - annotation_count: Total annotations in manifest.
      - categories: Deterministically sorted list of categories.
      - metadata: Global dataset metadata.

    Args:
        manifest: CanonicalDatasetManifest object.
        dataset_merkle_root: 64-character lowercase hex Merkle root.
        fingerprint_version: Version identifier of fingerprint engine.

    Returns:
        64-character lowercase hexadecimal SHA-256 digest.

    Raises:
        InvalidCanonicalInputError: If manifest is not a CanonicalDatasetManifest.
        InvalidHashFormatError: If dataset_merkle_root is not a 64-character hex string.
        FingerprintVersionMismatchError: If fingerprint_version is unsupported.
    """
    if not isinstance(manifest, CanonicalDatasetManifest):
        raise InvalidCanonicalInputError(
            f"Expected CanonicalDatasetManifest, got '{type(manifest).__name__}'."
        )

    if fingerprint_version != DATASET_FINGERPRINT_VERSION:
        raise FingerprintVersionMismatchError(
            f"Unsupported dataset fingerprint version '{fingerprint_version}'. Expected '{DATASET_FINGERPRINT_VERSION}'."
        )

    if not isinstance(dataset_merkle_root, str) or not _HEX_64_REGEX.match(dataset_merkle_root):
        raise InvalidHashFormatError(
            f"Invalid dataset_merkle_root format: expected 64 lowercase hex characters, got '{dataset_merkle_root}'."
        )

    # Categories sorted by category_id
    sorted_categories = sorted(manifest.categories, key=lambda c: c.category_id)
    category_list = [
        {
            "category_id": int(c.category_id),
            "category_name": str(c.category_name),
            "supercategory": str(c.supercategory) if c.supercategory is not None else None,
        }
        for c in sorted_categories
    ]

    format_str = manifest.format.value if hasattr(manifest.format, "value") else str(manifest.format)

    payload: Dict[str, Any] = {
        "schema_version": str(manifest.schema_version),
        "fingerprint_version": str(fingerprint_version),
        "format": format_str,
        "dataset_name": str(manifest.dataset_name),
        "dataset_merkle_root": dataset_merkle_root.lower(),
        "sample_count": int(manifest.sample_count),
        "annotation_count": int(manifest.annotation_count),
        "categories": category_list,
        "metadata": dict(manifest.metadata or {}),
    }

    try:
        jcs_bytes = canonicalize(payload)
    except Exception as exc:
        raise InvalidCanonicalInputError(
            f"Failed to canonicalize dataset manifest payload: {exc}",
            details={"dataset_name": manifest.dataset_name, "error": str(exc)},
        ) from exc

    prefixed_bytes = DATASET_DOMAIN_PREFIX.encode("utf-8") + jcs_bytes
    return sha256_bytes(prefixed_bytes)
