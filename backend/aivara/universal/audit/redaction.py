"""Security, Privacy, and Sensitive Data Redaction (Phase 12.11)."""

from __future__ import annotations

import re
from typing import Any, Dict, List, Union
from aivara.universal.audit.enums import RedactionLevel
from aivara.universal.hashing import compute_sha256_digest


# Sensitive keyword patterns
SENSITIVE_KEY_PATTERNS = [
    re.compile(r"pass(word)?", re.IGNORECASE),
    re.compile(r"secret", re.IGNORECASE),
    re.compile(r"token", re.IGNORECASE),
    re.compile(r"api[_-]?key", re.IGNORECASE),
    re.compile(r"private[_-]?key", re.IGNORECASE),
    re.compile(r"auth(orization)?", re.IGNORECASE),
    re.compile(r"bearer", re.IGNORECASE),
    re.compile(r"cookie", re.IGNORECASE),
    re.compile(r"credential", re.IGNORECASE),
]

# Sensitive value patterns (e.g. JWT tokens, private key headers)
SENSITIVE_VAL_PATTERNS = [
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+"),  # JWT
]


def redact_sensitive_value(val: str) -> str:
    """Deterministically redact a sensitive string."""
    h = compute_sha256_digest(val.encode("utf-8"))[:12]
    return f"[REDACTED_SECRET:sha256_{h}]"


def is_sensitive_key(key: str) -> bool:
    """Check if a dictionary key represents sensitive confidential data."""
    return any(p.search(key) for p in SENSITIVE_KEY_PATTERNS)


def sanitize_data_structure(
    data: Any,
    level: RedactionLevel = RedactionLevel.STANDARD,
) -> Any:
    """Recursively sanitize a nested data structure based on the redaction level."""
    if level == RedactionLevel.NONE:
        return data

    if isinstance(data, dict):
        sanitized: Dict[str, Any] = {}
        for k, v in sorted(data.items(), key=lambda x: str(x[0])):
            str_k = str(k)
            if is_sensitive_key(str_k):
                sanitized[str_k] = redact_sensitive_value(str(v))
            else:
                sanitized[str_k] = sanitize_data_structure(v, level=level)
        return sanitized

    elif isinstance(data, (list, tuple, set)):
        return [sanitize_data_structure(item, level=level) for item in data]

    elif isinstance(data, str):
        for pat in SENSITIVE_VAL_PATTERNS:
            if pat.search(data):
                return redact_sensitive_value(data)
        return data

    return data
