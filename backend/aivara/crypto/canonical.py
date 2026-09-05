"""Deterministic Canonical Serialization Engine for AIVARA.

Implements RFC 8785 (JSON Canonicalization Scheme - JCS) canonical serialization
for cryptographic provenance records, inference records, and assurance payloads.
"""

from __future__ import annotations

import json
import math
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple, Union

import rfc8785
from rfc8785 import FloatDomainError, IntegerDomainError

from aivara.core.exceptions import AivaraException

CANONICAL_SCHEMA_VERSION: str = "1.0"

_SAFE_INT_MIN: int = -(2**53) + 1
_SAFE_INT_MAX: int = 2**53 - 1


# =====================================================================
# Exceptions
# =====================================================================


class CanonicalizationError(AivaraException, ValueError):
    """Base exception for all canonicalization failures."""

    def __init__(
        self,
        message: str,
        code: str = "CANONICALIZATION_ERROR",
        details: Optional[Any] = None,
    ) -> None:
        super().__init__(message, code=code, details=details)


class UnsupportedTypeError(CanonicalizationError):
    """Raised when an unsupported Python type is passed to the canonicalizer."""

    def __init__(self, message: str, details: Optional[Any] = None) -> None:
        super().__init__(message, code="UNSUPPORTED_TYPE", details=details)


class InvalidNumberError(CanonicalizationError):
    """Raised when a number cannot be canonically serialized (e.g., NaN, Inf, out of bounds)."""

    def __init__(self, message: str, details: Optional[Any] = None) -> None:
        super().__init__(message, code="INVALID_NUMBER", details=details)


class InvalidStringError(CanonicalizationError):
    """Raised when a string contains invalid Unicode or lone surrogates."""

    def __init__(self, message: str, details: Optional[Any] = None) -> None:
        super().__init__(message, code="INVALID_STRING", details=details)


class MalformedStructureError(CanonicalizationError):
    """Raised when the data structure is malformed or circular."""

    def __init__(self, message: str, details: Optional[Any] = None) -> None:
        super().__init__(message, code="MALFORMED_STRUCTURE", details=details)


class InvalidSchemaVersionError(CanonicalizationError):
    """Raised when an unknown or unsupported canonical schema version is encountered."""

    def __init__(self, message: str, details: Optional[Any] = None) -> None:
        super().__init__(message, code="INVALID_SCHEMA_VERSION", details=details)


class DuplicateKeyError(CanonicalizationError):
    """Raised when duplicate object keys are detected during JSON parsing."""

    def __init__(self, message: str, details: Optional[Any] = None) -> None:
        super().__init__(message, code="DUPLICATE_KEY", details=details)


# =====================================================================
# Input Validation Boundary
# =====================================================================


def validate_canonical_data(data: Any, path: str = "$") -> None:
    """Validate that input data conforms strictly to safe JSON-compatible types.

    Permitted types:
      - None (null)
      - bool
      - int (within safe IEEE 754 integer range [-2^53 + 1, 2^53 - 1])
      - float (finite numbers only; NaN and Infinity are prohibited)
      - str (valid UTF-8 without unpaired surrogates)
      - list, tuple (all elements recursively validated)
      - dict (all keys must be str, all values recursively validated)

    Prohibited types:
      - datetime / date
      - UUID
      - bytes / bytearray
      - pathlib.Path
      - decimal.Decimal
      - custom classes / ORM models / arbitrary objects

    Raises:
        UnsupportedTypeError: If an unsupported Python object is detected.
        InvalidNumberError: If a float is NaN/Inf or an integer exceeds the safe domain.
        InvalidStringError: If a string cannot be encoded to UTF-8.
    """
    if data is None:
        return

    # Check bool before int, since bool is a subclass of int in Python
    if isinstance(data, bool):
        return

    if isinstance(data, int):
        if data < _SAFE_INT_MIN or data > _SAFE_INT_MAX:
            raise InvalidNumberError(
                f"Integer {data} at {path} exceeds safe JSON integer domain "
                f"[{_SAFE_INT_MIN}, {_SAFE_INT_MAX}]."
            )
        return

    if isinstance(data, float):
        if math.isnan(data) or math.isinf(data):
            raise InvalidNumberError(
                f"Non-finite float value '{data}' at {path} is prohibited in canonical JSON."
            )
        return

    if isinstance(data, str):
        try:
            data.encode("utf-8")
        except UnicodeEncodeError as err:
            raise InvalidStringError(
                f"String at {path} contains invalid Unicode codepoints: {err}"
            ) from err
        return

    if isinstance(data, (list, tuple)):
        for idx, item in enumerate(data):
            validate_canonical_data(item, path=f"{path}[{idx}]")
        return

    if isinstance(data, dict):
        for key, value in data.items():
            if not isinstance(key, str):
                raise UnsupportedTypeError(
                    f"Object key at {path} must be a string, got '{type(key).__name__}'."
                )
            try:
                key.encode("utf-8")
            except UnicodeEncodeError as err:
                raise InvalidStringError(
                    f"Object key '{key}' at {path} contains invalid Unicode codepoints."
                ) from err
            validate_canonical_data(value, path=f"{path}.{key}")
        return

    # Any other type is strictly prohibited at the canonical boundary
    raise UnsupportedTypeError(
        f"Unsupported type '{type(data).__name__}' at {path}. "
        f"Only safe JSON types (dict, list, str, int, float, bool, None) are permitted."
    )


# =====================================================================
# Parsing with Duplicate Key Detection
# =====================================================================


def _detect_duplicate_pairs(pairs: List[Tuple[str, Any]]) -> Dict[str, Any]:
    """Object pairs hook for json.loads that rejects duplicate keys."""
    res: Dict[str, Any] = {}
    for key, value in pairs:
        if key in res:
            raise DuplicateKeyError(
                f"Duplicate key detected in JSON object: {key!r}"
            )
        res[key] = value
    return res


def parse_canonical_json(json_text: Union[str, bytes]) -> Any:
    """Parse JSON text into Python data while strictly rejecting duplicate keys.

    Args:
        json_text: JSON text as str or UTF-8 bytes.

    Returns:
        Parsed Python object.

    Raises:
        DuplicateKeyError: If duplicate keys exist in any JSON object.
        MalformedStructureError: If JSON syntax is invalid.
    """
    try:
        return json.loads(json_text, object_pairs_hook=_detect_duplicate_pairs)
    except DuplicateKeyError:
        raise
    except json.JSONDecodeError as err:
        raise MalformedStructureError(f"Invalid JSON syntax: {err}") from err


# =====================================================================
# Canonical Datetime Helper
# =====================================================================


def format_canonical_datetime(dt: datetime) -> str:
    """Format a datetime into the AIVARA canonical timestamp format.

    Specification:
      - Timezone: UTC only
      - Format: ISO 8601 YYYY-MM-DDTHH:MM:SSZ
      - Fractional seconds: None (truncated to whole seconds)
      - Suffix: 'Z'

    Args:
        dt: datetime object (timezone-aware or naive; naive is assumed UTC).

    Returns:
        Canonical ISO 8601 string ending in 'Z'.

    Raises:
        UnsupportedTypeError: If dt is not a datetime.datetime instance.
    """
    if not isinstance(dt, datetime):
        raise UnsupportedTypeError(
            f"Expected datetime.datetime instance, got '{type(dt).__name__}'."
        )

    # Convert naive to UTC, or convert timezone-aware to UTC
    if dt.tzinfo is None:
        utc_dt = dt.replace(tzinfo=timezone.utc)
    else:
        utc_dt = dt.astimezone(timezone.utc)

    # Format without fractional seconds with explicit Z suffix
    return utc_dt.strftime("%Y-%m-%dT%H:%M:%SZ")


# =====================================================================
# Core Canonicalization Engine
# =====================================================================


def canonicalize(data: Any) -> bytes:
    """Deterministically serialize structured data to RFC 8785 canonical UTF-8 bytes.

    Invariant:
        For any two logically equivalent JSON-compatible data structures A and B:
        canonicalize(A) == canonicalize(B)

    Rules:
        - Key ordering: Sorted lexicographically by UTF-16 code units (RFC 8785 §3.2.3).
        - Whitespace: Zero whitespace between tokens.
        - Strings: UTF-8 with RFC 8785 minimal escape rules.
        - Floats: ECMA 262 shortest representation, -0.0 normalized to 0.
        - Integers: Standard decimal representation within safe domain.
        - Immutability: The caller's input object is never mutated.

    Args:
        data: Safe JSON data structure (dict, list, str, int, float, bool, None).

    Returns:
        Deterministic UTF-8 encoded canonical bytes.

    Raises:
        UnsupportedTypeError: If input contains unsupported Python types.
        InvalidNumberError: If input contains NaN, Infinity, or out-of-bounds integers.
        InvalidStringError: If input contains invalid Unicode.
        CanonicalizationError: If canonicalization fails for any other reason.
    """
    # 1. Validate data against safe JSON types (does not mutate data)
    validate_canonical_data(data)

    # 2. Perform RFC 8785 JCS canonical serialization
    try:
        canonical_bytes = rfc8785.dumps(data)
    except FloatDomainError as err:
        raise InvalidNumberError(f"Floating-point domain error: {err}") from err
    except IntegerDomainError as err:
        raise InvalidNumberError(f"Integer domain error: {err}") from err
    except rfc8785.CanonicalizationError as err:
        msg = str(err)
        if "unsupported type" in msg.lower():
            raise UnsupportedTypeError(msg) from err
        raise CanonicalizationError(f"JCS serialization error: {msg}") from err
    except Exception as err:
        raise CanonicalizationError(f"Unexpected canonicalization error: {err}") from err

    return canonical_bytes


# =====================================================================
# Provenance Payload Canonicalization
# =====================================================================


def canonicalize_provenance_payload(
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
) -> bytes:
    """Construct and canonically serialize a protected provenance record payload.

    All protected fields defined in Phase 4.1 are bound deterministically.
    Null fields are explicitly retained as null per Phase 4.1 Section 5.3
    to avoid omission ambiguities.

    Args:
        record_type: Category of provenance event (e.g. 'INFERENCE', 'MODEL_REGISTRATION').
        project_id: Project identifier string.
        actor: Identity of actor performing the action.
        action: Specific action performed.
        sequence_number: Monotonic sequence number.
        nonce: Cryptographic nonce hex string.
        timestamp: ISO 8601 string or datetime object.
        signer_key_id: Key identifier used for digital signature.
        target_type: Target asset type or None.
        target_id: Target asset identifier or None.
        input_hash: SHA-256 hex digest of inputs or None.
        output_hash: SHA-256 hex digest of outputs or None.
        model_id: Model identifier or None.
        model_weight_digest: Model weight SHA-256 digest or None.
        config_hash: Hash of inference/preprocessing configuration or None.
        previous_record_hash: SHA-256 of preceding provenance record or None (genesis).
        metadata_json: Optional supplementary metadata dict.
        schema_version: Canonical schema version (defaults to CANONICAL_SCHEMA_VERSION).

    Returns:
        Deterministic UTF-8 canonical bytes.

    Raises:
        InvalidSchemaVersionError: If schema_version is unsupported.
        CanonicalizationError: If payload fails validation or serialization.
    """
    if schema_version != CANONICAL_SCHEMA_VERSION:
        raise InvalidSchemaVersionError(
            f"Unsupported canonical schema version '{schema_version}'. "
            f"Expected '{CANONICAL_SCHEMA_VERSION}'."
        )

    # Format timestamp if datetime is provided
    if isinstance(timestamp, datetime):
        ts_str = format_canonical_datetime(timestamp)
    elif isinstance(timestamp, str):
        ts_str = timestamp
    else:
        raise UnsupportedTypeError(
            f"Timestamp must be str or datetime, got '{type(timestamp).__name__}'."
        )

    # Construct complete protected dictionary
    payload: Dict[str, Any] = {
        "_schema_version": schema_version,
        "action": action,
        "actor": actor,
        "config_hash": config_hash,
        "input_hash": input_hash,
        "metadata_json": metadata_json if metadata_json is not None else {},
        "model_id": model_id,
        "model_weight_digest": model_weight_digest,
        "nonce": nonce,
        "output_hash": output_hash,
        "previous_record_hash": previous_record_hash,
        "project_id": str(project_id),
        "record_type": record_type,
        "sequence_number": int(sequence_number),
        "signer_key_id": signer_key_id,
        "target_id": str(target_id) if target_id is not None else None,
        "target_type": target_type,
        "timestamp": ts_str,
    }

    return canonicalize(payload)
