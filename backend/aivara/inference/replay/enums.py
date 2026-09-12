"""Enums for Phase 10.9 Replay & Consistency Verification subsystem."""

from enum import Enum


class ReplayEligibilityStatus(str, Enum):
    """Eligibility classification of an inference record for replay."""

    ELIGIBLE = "ELIGIBLE"
    INELIGIBLE = "INELIGIBLE"
    INVALID_RECORD = "INVALID_RECORD"
    INVALID_BINDING = "INVALID_BINDING"
    PROJECT_MISMATCH = "PROJECT_MISMATCH"
    UNSUPPORTED_VERSION = "UNSUPPORTED_VERSION"


class ReplayMode(str, Enum):
    """Operational mode and expectations for replay execution."""

    DETERMINISTIC = "DETERMINISTIC"
    NUMERICALLY_TOLERANT = "NUMERICALLY_TOLERANT"
    NON_REPRODUCIBLE = "NON_REPRODUCIBLE"
    DIVERGENT = "DIVERGENT"


class ReplayConsistencyStatus(str, Enum):
    """Consistency outcome of comparing replayed execution output with recorded baseline."""

    CONSISTENT_EXACT = "CONSISTENT_EXACT"
    CONSISTENT_TOLERANT = "CONSISTENT_TOLERANT"
    STRUCTURAL_DIVERGENCE = "STRUCTURAL_DIVERGENCE"
    NUMERICAL_DIVERGENCE = "NUMERICAL_DIVERGENCE"
    EXECUTION_DIVERGENCE = "EXECUTION_DIVERGENCE"
    NON_REPRODUCIBLE = "NON_REPRODUCIBLE"
    INELIGIBLE = "INELIGIBLE"
    INVALID_RECORD = "INVALID_RECORD"
    INVALID_BINDING = "INVALID_BINDING"


class ComparisonStatus(str, Enum):
    """Detailed structural and numerical comparison status."""

    EXACT_MATCH = "EXACT_MATCH"
    TOLERANT_MATCH = "TOLERANT_MATCH"
    STRUCTURAL_MISMATCH = "STRUCTURAL_MISMATCH"
    NUMERICAL_MISMATCH = "NUMERICAL_MISMATCH"
    SHAPE_MISMATCH = "SHAPE_MISMATCH"
    RANK_MISMATCH = "RANK_MISMATCH"
    COUNT_MISMATCH = "COUNT_MISMATCH"
    DTYPE_MISMATCH = "DTYPE_MISMATCH"
    NAME_MISMATCH = "NAME_MISMATCH"
