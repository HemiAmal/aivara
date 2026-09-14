"""Tests for Resource Governance & Bounded Ceilings (REQ-12-AGG-018)."""

import pytest

from aivara.universal.aggregation.config import (
    MAX_DEPENDENCY_EDGES,
    MAX_PROJECT_ASSETS,
)
from aivara.universal.aggregation.engine import UniversalProjectAggregator
from aivara.universal.aggregation.exceptions import AggregationResourceLimitExceededError
from aivara.universal.aggregation.schemas import (
    AssetDependencyEdge,
    AssetDependencyGraph,
)


def test_asset_count_over_limit_fails_closed():
    """Graph with more than MAX_PROJECT_ASSETS fails closed with AggregationResourceLimitExceededError."""
    aggregator = UniversalProjectAggregator()

    excess_assets = [f"asset_{i}" for i in range(MAX_PROJECT_ASSETS + 5)]
    graph = AssetDependencyGraph(
        project_id="proj_over_limit",
        asset_ids=excess_assets,
        edges=[],
    )

    base_risks = {a: 0.10 for a in excess_assets}

    with pytest.raises(AggregationResourceLimitExceededError) as exc_info:
        aggregator.propagate_lineage_risks(graph, base_risks)
    assert "exceeds maximum limit" in str(exc_info.value)
