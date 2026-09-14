"""Universal Project & Multi-Asset Risk Aggregation Package (Phase 12.9)."""

from __future__ import annotations

from aivara.universal.aggregation.config import (
    MAX_CHAIN_DEPTH,
    MAX_DEPENDENCY_EDGES,
    MAX_LINEAGE_CHAINS,
    MAX_PROJECT_ASSETS,
    ImmutableAggregationPolicyConfig,
)
from aivara.universal.aggregation.engine import UniversalProjectAggregator
from aivara.universal.aggregation.enums import (
    AggregationSchemaVersion,
    AssetRole,
    DependencyEdgeType,
)
from aivara.universal.aggregation.exceptions import (
    AggregationError,
    AggregationResourceLimitExceededError,
    DependencyCycleError,
    DoubleCountingError,
    InvalidAssetRiskError,
    ScopeMismatchError,
)
from aivara.universal.aggregation.hashing import compute_aggregation_hash
from aivara.universal.aggregation.schemas import (
    AssetDependencyEdge,
    AssetDependencyGraph,
    ChainPath,
    ProjectAggregationDisposition,
)

__all__ = [
    "MAX_CHAIN_DEPTH",
    "MAX_DEPENDENCY_EDGES",
    "MAX_LINEAGE_CHAINS",
    "MAX_PROJECT_ASSETS",
    "ImmutableAggregationPolicyConfig",
    "UniversalProjectAggregator",
    "AggregationSchemaVersion",
    "AssetRole",
    "DependencyEdgeType",
    "AggregationError",
    "AggregationResourceLimitExceededError",
    "DependencyCycleError",
    "DoubleCountingError",
    "InvalidAssetRiskError",
    "ScopeMismatchError",
    "compute_aggregation_hash",
    "AssetDependencyEdge",
    "AssetDependencyGraph",
    "ChainPath",
    "ProjectAggregationDisposition",
]
