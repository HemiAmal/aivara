"""Tests for Lineage Propagation along Explicit DAG Edges (REQ-12-AGG-003)."""

from aivara.universal.aggregation.config import ImmutableAggregationPolicyConfig
from aivara.universal.aggregation.engine import UniversalProjectAggregator
from aivara.universal.aggregation.schemas import (
    AssetDependencyEdge,
    AssetDependencyGraph,
)


def test_upstream_risk_propagates_downstream():
    """Contaminated upstream dataset increases effective risk of downstream model."""
    cfg = ImmutableAggregationPolicyConfig(lineage_propagation_factor=0.25)
    aggregator = UniversalProjectAggregator(config=cfg)

    graph = AssetDependencyGraph(
        project_id="proj_prop_01",
        asset_ids=["ds_mnist", "model_cnn"],
        edges=[
            AssetDependencyEdge(
                project_id="proj_prop_01",
                source_asset_id="ds_mnist",
                target_asset_id="model_cnn",
                propagation_weight=1.0,
            )
        ],
    )

    base_risks = {"ds_mnist": 0.80, "model_cnn": 0.20}
    eff_risks = aggregator.propagate_lineage_risks(graph, base_risks)

    # R_eff(ds) = 0.80
    assert eff_risks["ds_mnist"] == 0.80
    # R_eff(model) = 1 - (1 - 0.20) * (1 - 0.25 * 1.0 * 0.80) = 1 - 0.80 * 0.80 = 0.36
    assert eff_risks["model_cnn"] == 0.36


def test_multi_hop_propagation_damped():
    """Three-hop lineage (A -> B -> C) compounds monotonically across layers."""
    cfg = ImmutableAggregationPolicyConfig(lineage_propagation_factor=0.20)
    aggregator = UniversalProjectAggregator(config=cfg)

    graph = AssetDependencyGraph(
        project_id="proj_prop_02",
        asset_ids=["asset_A", "asset_B", "asset_C"],
        edges=[
            AssetDependencyEdge(project_id="proj_prop_02", source_asset_id="asset_A", target_asset_id="asset_B"),
            AssetDependencyEdge(project_id="proj_prop_02", source_asset_id="asset_B", target_asset_id="asset_C"),
        ],
    )

    base_risks = {"asset_A": 0.90, "asset_B": 0.10, "asset_C": 0.05}
    eff_risks = aggregator.propagate_lineage_risks(graph, base_risks)

    assert eff_risks["asset_A"] == 0.90
    assert eff_risks["asset_B"] > base_risks["asset_B"]
    assert eff_risks["asset_C"] > base_risks["asset_C"]
