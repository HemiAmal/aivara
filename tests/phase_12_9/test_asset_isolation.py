"""Tests for Asset Isolation (REQ-12-AGG-002)."""

import pytest

from aivara.universal.aggregation.engine import UniversalProjectAggregator
from aivara.universal.aggregation.schemas import AssetDependencyGraph
from aivara.universal.risk.enums import EvidenceSufficiencyStatus, RiskLevel
from aivara.universal.risk.schemas import AssetRiskAssessment


def test_independent_assets_maintain_isolation():
    """Unrelated Asset B's risk remains completely independent of changes in Asset A."""
    aggregator = UniversalProjectAggregator()

    # Project with two isolated assets: Asset A and Asset B (no edges)
    graph = AssetDependencyGraph(
        project_id="proj_iso_01",
        asset_ids=["asset_A", "asset_B"],
        edges=[],
    )

    # Scenario 1: Asset A has risk 0.10, Asset B has risk 0.20
    base_risks_1 = {"asset_A": 0.10, "asset_B": 0.20}
    eff_risks_1 = aggregator.propagate_lineage_risks(graph, base_risks_1)

    assert eff_risks_1["asset_A"] == 0.10
    assert eff_risks_1["asset_B"] == 0.20

    # Scenario 2: Asset A surges to maximum risk 1.00, Asset B remains 0.20
    base_risks_2 = {"asset_A": 1.00, "asset_B": 0.20}
    eff_risks_2 = aggregator.propagate_lineage_risks(graph, base_risks_2)

    assert eff_risks_2["asset_A"] == 1.00
    assert eff_risks_2["asset_B"] == 0.20  # Completely untouched!


def test_isolation_in_three_asset_disconnected_graph():
    """In a graph with A->B and isolated C, changes in A/B never alter C."""
    aggregator = UniversalProjectAggregator()

    from aivara.universal.aggregation.schemas import AssetDependencyEdge

    graph = AssetDependencyGraph(
        project_id="proj_iso_02",
        asset_ids=["asset_A", "asset_B", "asset_C"],
        edges=[
            AssetDependencyEdge(
                project_id="proj_iso_02",
                source_asset_id="asset_A",
                target_asset_id="asset_B",
            )
        ],
    )

    base_risks = {"asset_A": 0.90, "asset_B": 0.10, "asset_C": 0.05}
    eff_risks = aggregator.propagate_lineage_risks(graph, base_risks)

    # B received propagation from A
    assert eff_risks["asset_B"] > 0.10
    # C remained strictly at 0.05
    assert eff_risks["asset_C"] == 0.05
