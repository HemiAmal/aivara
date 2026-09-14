"""Enumerations for Hierarchical Multi-Asset Risk Aggregation Engine (Phase 12.4)."""

from enum import Enum


class RiskLevel(str, Enum):
    """Categorical classification of calculated operational risk scalars."""
    CRITICAL = "CRITICAL"  # R >= 0.85
    HIGH = "HIGH"          # 0.65 <= R < 0.85
    MEDIUM = "MEDIUM"      # 0.30 <= R < 0.65
    LOW = "LOW"            # 0.0 < R < 0.30
    NONE = "NONE"          # R == 0.0


class AggregationStage(str, Enum):
    """Hierarchical level of risk contribution and aggregation."""
    EVIDENCE_CLUSTER = "EVIDENCE_CLUSTER"
    FINDING = "FINDING"
    ASSET = "ASSET"
    CHAIN = "CHAIN"
    PROJECT = "PROJECT"


class EvidenceSufficiencyStatus(str, Enum):
    """Analytical data-quality and ancestry completeness status (non-decision state)."""
    SUFFICIENT = "SUFFICIENT"
    INSUFFICIENT_ANCESTRY = "INSUFFICIENT_ANCESTRY"
    UNVERIFIED = "UNVERIFIED"


class AggregationSchemaVersion(str, Enum):
    """SemVer for Universal Risk Aggregation contracts."""
    V1_0 = "1.0.0"
