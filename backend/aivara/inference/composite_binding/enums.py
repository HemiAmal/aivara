"""Enums for Phase 10.7 Cryptographic Input-to-Output Binding."""

from __future__ import annotations

from enum import Enum


class InferenceBindingStatus(str, Enum):
    """Integrity verification status taxonomy for end-to-end inference binding."""

    VERIFIED = "VERIFIED"
    INVALID = "INVALID"
    MISSING = "MISSING"
    UNAVAILABLE = "UNAVAILABLE"
    MISMATCHED = "MISMATCHED"
    UNVERIFIABLE = "UNVERIFIABLE"
