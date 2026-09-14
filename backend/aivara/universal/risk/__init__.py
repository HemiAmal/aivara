"""Hierarchical Multi-Asset Risk Aggregation Engine (Phase 12.4)."""

from aivara.universal.risk.aggregator import HierarchicalRiskAggregator
from aivara.universal.risk.config import ImmutableAggregationConfig
from aivara.universal.risk.enums import (
    AggregationSchemaVersion,
    AggregationStage,
    EvidenceSufficiencyStatus,
    RiskLevel,
)
from aivara.universal.risk.exceptions import (
    InvalidPolicyConfigurationError,
    NonFiniteRiskError,
    RiskOutOfRangeError,
    UniversalRiskError,
)
from aivara.universal.risk.schemas import (
    AssetRiskAssessment,
    ChainRiskAssessment,
    HierarchicalRiskAssessment,
    ProjectRiskAssessment,
    RiskContribution,
    compute_risk_level,
)

__all__ = [
    "AggregationSchemaVersion",
    "AggregationStage",
    "AssetRiskAssessment",
    "ChainRiskAssessment",
    "EvidenceSufficiencyStatus",
    "HierarchicalRiskAggregator",
    "HierarchicalRiskAssessment",
    "ImmutableAggregationConfig",
    "InvalidPolicyConfigurationError",
    "NonFiniteRiskError",
    "ProjectRiskAssessment",
    "RiskContribution",
    "RiskLevel",
    "RiskOutOfRangeError",
    "UniversalRiskError",
    "compute_risk_level",
]
