"""Universal Risk Computation (Phase 12.6) and Hierarchical Risk Aggregation (Phase 12.9) Module."""

from aivara.universal.risk.config import ImmutableAggregationConfig
from aivara.universal.risk.engine import UniversalRiskComputationEngine
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
    UniversalRiskAssessment,
    compute_risk_level,
)
from aivara.universal.risk.aggregator import HierarchicalRiskAggregator

__all__ = [
    # Enums
    "RiskLevel",
    "AggregationStage",
    "EvidenceSufficiencyStatus",
    "AggregationSchemaVersion",
    # Exceptions
    "UniversalRiskError",
    "NonFiniteRiskError",
    "RiskOutOfRangeError",
    "InvalidPolicyConfigurationError",
    # Config
    "ImmutableAggregationConfig",
    # Schemas
    "RiskContribution",
    "UniversalRiskAssessment",
    "AssetRiskAssessment",
    "ChainRiskAssessment",
    "ProjectRiskAssessment",
    "HierarchicalRiskAssessment",
    "compute_risk_level",
    # Engines
    "UniversalRiskComputationEngine",
    "HierarchicalRiskAggregator",
]
