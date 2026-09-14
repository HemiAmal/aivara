"""Enums for Universal Project & Multi-Asset Risk Aggregation (Phase 12.9)."""

from __future__ import annotations

from enum import Enum


class AggregationSchemaVersion(str, Enum):
    """Supported schema versions for hierarchical multi-asset risk aggregation."""
    V1_0 = "1.0.0"


class AssetRole(str, Enum):
    """Structural role of an asset within the project architecture."""
    CORE_DEPLOYED = "CORE_DEPLOYED"          # Critical production models, primary inference services, root training sets
    PERIPHERAL_SAMPLE = "PERIPHERAL_SAMPLE"  # Test batches, isolated sample artifacts, monitoring telemetry
    SUPPORTING_INPUT = "SUPPORTING_INPUT"    # Feature definitions, reference baselines, configuration assets


class DependencyEdgeType(str, Enum):
    """Taxonomy of explicit inter-asset dependency relationships in the DAG."""
    DEPENDS_ON = "DEPENDS_ON"      # General structural dependency
    DERIVED_FROM = "DERIVED_FROM"  # Model derived from dataset, or dataset derived from source
    FEEDS = "FEEDS"                # Dataset feeds training, or model feeds inference
    DEPLOYED_AS = "DEPLOYED_AS"    # Model deployed as active inference service
    EVALUATED_BY = "EVALUATED_BY"  # Model evaluated by benchmark dataset
    LINEAGE = "LINEAGE"            # Provenance/lineage evolution chain
