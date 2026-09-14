"""Enumerations for Cross-Subsystem Correlation & Dependency Damping Engine (Phase 12.5)."""

from enum import Enum


class CorrelationSchemaVersion(str, Enum):
    """SemVer for Universal Risk Correlation contracts."""
    V1_0 = "1.0.0"


class CorrelationStatus(str, Enum):
    """Analytical status of domain correlation assessment."""
    UNATTENUATED = "UNATTENUATED"
    ATTENUATED = "ATTENUATED"
    INSUFFICIENT_DATA = "INSUFFICIENT_DATA"
    VALID = "VALID"
