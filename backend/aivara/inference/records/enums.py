"""Enums for Phase 10.8 Inference Record Integrity subsystem."""

from enum import Enum


class InferenceRecordStatus(str, Enum):
    """Integrity and persistence status of an inference record."""

    VERIFIED = "VERIFIED"
    INVALID = "INVALID"
    TAMPERED = "TAMPERED"


class InferenceRecordType(str, Enum):
    """Categorical classification of inference records."""

    STANDARD = "STANDARD"
    BATCH = "BATCH"
    AUDIT = "AUDIT"
