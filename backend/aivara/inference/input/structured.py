"""Structured JSON-compatible input validation and canonical JCS hashing."""

from __future__ import annotations

import hashlib
from typing import Any, Dict, List, Optional, Tuple, Union

from aivara.crypto.canonical import canonicalize, validate_canonical_data
from aivara.inference.config import DEFAULT_INFERENCE_LIMITS, InferenceInputLimits
from aivara.inference.exceptions import (
    MalformedInputError,
    ResourceLimitExceededError,
    UnsupportedInputTypeError,
)
from aivara.inference.input.models import StructuredInputMetadata


def _calculate_structured_element_count(data: Any) -> int:
    """Recursively calculate total keys and elements in structured data."""
    if isinstance(data, dict):
        total = len(data)
        for v in data.values():
            total += _calculate_structured_element_count(v)
        return total
    elif isinstance(data, (list, tuple)):
        total = len(data)
        for item in data:
            total += _calculate_structured_element_count(item)
        return total
    return 1


def validate_structured_input(
    data: Any,
    limits: Optional[InferenceInputLimits] = None,
) -> Tuple[StructuredInputMetadata, str]:
    """Validate JSON-compatible structured input data via RFC 8785 JCS.

    Args:
        data: Dict or List representing structured model inputs.
        limits: Configured resource limits.

    Returns:
        Tuple of (StructuredInputMetadata, input_id).

    Raises:
        MalformedInputError: If data is None or malformed.
        UnsupportedInputTypeError: If data is not a dict or list.
        ResourceLimitExceededError: If byte size or key count exceeds limits.
    """
    active_limits = limits or DEFAULT_INFERENCE_LIMITS

    if data is None:
        raise MalformedInputError("Structured input cannot be None.")

    if not isinstance(data, (dict, list)):
        raise UnsupportedInputTypeError(
            f"Expected dict or list for structured input, got '{type(data).__name__}'.",
            details={"type": type(data).__name__},
        )

    # 1. Validate canonical compliance (finite, UTF-8, safe JSON types)
    try:
        validate_canonical_data(data)
    except Exception as err:
        raise MalformedInputError(
            f"Structured input fails canonical JSON validation: {err}",
            details={"error": str(err)},
        ) from err

    # 2. Check Element Count
    element_count = _calculate_structured_element_count(data)
    if element_count > active_limits.max_structured_keys:
        raise ResourceLimitExceededError(
            f"Structured element count {element_count} exceeds limit {active_limits.max_structured_keys}.",
            details={"element_count": element_count, "limit": active_limits.max_structured_keys},
        )

    # 3. Canonicalize via RFC 8785 JCS
    try:
        canonical_bytes = canonicalize(data)
    except Exception as err:
        raise MalformedInputError(
            f"Failed to canonically serialize structured input: {err}",
            details={"error": str(err)},
        ) from err

    canonical_byte_size = len(canonical_bytes)
    if canonical_byte_size > active_limits.max_structured_byte_size:
        raise ResourceLimitExceededError(
            f"Structured canonical payload size {canonical_byte_size} bytes exceeds limit {active_limits.max_structured_byte_size} bytes.",
            details={"byte_size": canonical_byte_size, "limit": active_limits.max_structured_byte_size},
        )

    canonical_hash = hashlib.sha256(canonical_bytes).hexdigest()

    # 4. Form Descriptor & Input ID
    top_level_type = "dict" if isinstance(data, dict) else "list"
    canonical_descriptor = {
        "canonical_hash": canonical_hash,
        "canonical_byte_size": canonical_byte_size,
        "element_count": element_count,
        "schema_version": "1.0",
        "top_level_type": top_level_type,
    }

    input_id = hashlib.sha256(canonicalize(canonical_descriptor)).hexdigest()

    metadata = StructuredInputMetadata(
        top_level_type=top_level_type,
        element_count=element_count,
        canonical_byte_size=canonical_byte_size,
        canonical_hash=canonical_hash,
    )

    return metadata, input_id
