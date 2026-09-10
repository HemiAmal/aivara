"""Level 2: Canonical Annotation & Annotation-Set Fingerprinting Engine (Phase 5.3).

Provides deterministic RFC 8785 JCS-canonicalized digests for individual bounding
boxes/polygons and composite sample annotation sets with fixed 4-decimal place
coordinate quantization.
"""

from __future__ import annotations

import hashlib
from typing import Any, Dict, List, Sequence, Tuple

from aivara.crypto.canonical import canonicalize
from aivara.crypto.hashing import sha256_bytes, sha256_text
from aivara.dataset.fingerprinting.exceptions import (
    MalformedAnnotationFingerprintError,
)
from aivara.dataset.schemas import CanonicalAnnotation, CanonicalBBox

ANNOTATION_DOMAIN_PREFIX: str = "aivara-annot-v1:"
ANNOTSET_DOMAIN_PREFIX: str = "aivara-annotset-v1:"

# Deterministic constant for negative/empty annotation sets
EMPTY_ANNOTSET_DIGEST: str = sha256_text("aivara-annotset-v1:empty")


def _quantize_float(val: float) -> float:
    """Quantize floating-point coordinate to exactly 4 decimal places."""
    return round(float(val), 4)


def compute_single_annotation_digest(annotation: CanonicalAnnotation) -> str:
    """Compute deterministic SHA-256 digest for a single CanonicalAnnotation.

    Applies:
      1. Fixed 4-decimal place float quantization on bbox & polygon coordinates.
      2. Deterministic dictionary construction.
      3. RFC 8785 JCS canonical JSON encoding.
      4. Domain separation prefix "aivara-annot-v1:".

    Args:
        annotation: CanonicalAnnotation instance to hash.

    Returns:
        64-character lowercase hexadecimal digest string.

    Raises:
        MalformedAnnotationFingerprintError: If the annotation structure is invalid.
    """
    if not isinstance(annotation, CanonicalAnnotation):
        raise MalformedAnnotationFingerprintError(
            f"Expected CanonicalAnnotation instance, got '{type(annotation).__name__}'."
        )

    # Bounding box quantization
    bbox_payload: Any = None
    if annotation.bbox is not None:
        if not isinstance(annotation.bbox, CanonicalBBox):
            raise MalformedAnnotationFingerprintError(
                f"Invalid bbox type '{type(annotation.bbox).__name__}' in annotation."
            )
        bbox_payload = [
            _quantize_float(annotation.bbox.x_min),
            _quantize_float(annotation.bbox.y_min),
            _quantize_float(annotation.bbox.width),
            _quantize_float(annotation.bbox.height),
        ]

    # Segmentation polygon quantization
    seg_payload: Any = None
    if annotation.segmentation is not None:
        seg_list: List[List[float]] = []
        for poly in annotation.segmentation:
            seg_list.append([_quantize_float(pt) for pt in poly])
        seg_payload = seg_list

    # Area quantization
    area_payload: Any = None
    if annotation.area is not None:
        area_payload = _quantize_float(annotation.area)

    payload: Dict[str, Any] = {
        "annotation_id": str(annotation.annotation_id),
        "category_id": int(annotation.category_id),
        "category_name": str(annotation.category_name),
        "bbox": bbox_payload,
        "segmentation": seg_payload,
        "area": area_payload,
        "is_crowd": bool(annotation.is_crowd),
        "attributes": dict(annotation.attributes or {}),
    }

    try:
        jcs_bytes = canonicalize(payload)
    except Exception as exc:
        raise MalformedAnnotationFingerprintError(
            f"Failed to canonicalize annotation: {exc}",
            details={"annotation_id": annotation.annotation_id, "error": str(exc)},
        ) from exc

    prefixed_bytes = ANNOTATION_DOMAIN_PREFIX.encode("utf-8") + jcs_bytes
    return sha256_bytes(prefixed_bytes)


def compute_annotation_set_hash(annotations: Sequence[CanonicalAnnotation]) -> str:
    """Compute deterministic composite SHA-256 digest for an entire set of sample annotations.

    Invariants:
      - Independent of input sequence order (sorted by raw 32-byte binary digest).
      - Empty annotation set evaluates to deterministic constant EMPTY_ANNOTSET_DIGEST.
      - Domain separation prefix "aivara-annotset-v1:".

    Args:
        annotations: Sequence of CanonicalAnnotation objects associated with a sample.

    Returns:
        64-character lowercase hexadecimal digest string.
    """
    if not annotations:
        return EMPTY_ANNOTSET_DIGEST

    raw_digests: List[bytes] = []
    for ann in annotations:
        hex_digest = compute_single_annotation_digest(ann)
        raw_digests.append(bytes.fromhex(hex_digest))

    # Deterministic binary collation sort
    sorted_raw_digests = sorted(raw_digests)

    # Form composite buffer: Domain prefix + concatenated 32-byte binary digests
    composite_buffer = ANNOTSET_DOMAIN_PREFIX.encode("utf-8") + b"".join(sorted_raw_digests)
    return sha256_bytes(composite_buffer)
