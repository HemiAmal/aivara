"""Tests for Lineage Chain Identification (REQ-12-AGG-005)."""

from aivara.universal.aggregation.engine import UniversalProjectAggregator
from aivara.universal.aggregation.schemas import (
    AssetDependencyEdge,
    AssetDependencyGraph,
)


def test_linear_chain_identification():
    """A linear 3-hop chain (Dataset -> Model -> Inference) is identified with accurate hop count."""
    aggregator = UniversalProjectAggregator()

    graph = AssetDependencyGraph(
        project_id="proj_chain_01",
        asset_ids=["ds_v1", "model_v1", "inf_pipeline"],
        edges=[
            AssetDependencyEdge(project_id="proj_chain_01", source_asset_id="ds_v1", target_asset_id="model_v1"),
            AssetDependencyEdge(project_id="proj_chain_01", source_asset_id="model_v1", target_asset_id="inf_pipeline"),
        ],
    )

    risks = {"ds_v1": 0.40, "model_v1": 0.50, "inf_pipeline": 0.30}
    chains, pairwise = aggregator.extract_and_evaluate_chains(graph, risks)

    # Discovered pairwise: (ds_v1, model_v1), (model_v1, inf_pipeline)
    assert len(pairwise) == 2
    # Discovered paths: [ds_v1, model_v1], [model_v1, inf_pipeline], [ds_v1, model_v1, inf_pipeline]
    assert len(chains) == 3

    longest = [c for c in chains if c.hop_count == 2][0]
    assert longest.asset_ids == ["ds_v1", "model_v1", "inf_pipeline"]
    assert longest.chain_risk_score > 0.0


def test_branching_and_merging_chains():
    """Branching (A->B, A->C) and merging (B->D, C->D) extract distinct deterministic paths."""
    aggregator = UniversalProjectAggregator()

    graph = AssetDependencyGraph(
        project_id="proj_branch",
        asset_ids=["asset_A", "asset_B", "asset_C", "asset_D"],
        edges=[
            AssetDependencyEdge(project_id="proj_branch", source_asset_id="asset_A", target_asset_id="asset_B"),
            AssetDependencyEdge(project_id="proj_branch", source_asset_id="asset_A", target_asset_id="asset_C"),
            AssetDependencyEdge(project_id="proj_branch", source_asset_id="asset_B", target_asset_id="asset_D"),
            AssetDependencyEdge(project_id="proj_branch", source_asset_id="asset_C", target_asset_id="asset_D"),
        ],
    )

    risks = {"asset_A": 0.60, "asset_B": 0.20, "asset_C": 0.30, "asset_D": 0.10}
    chains, pairwise = aggregator.extract_and_evaluate_chains(graph, risks)

    # 4 two-hop pairwise edges
    assert len(pairwise) == 4
    # All paths: [A, B], [A, C], [B, D], [C, D], [A, B, D], [A, C, D]
    path_ids = [c.asset_ids for c in chains]
    assert ["asset_A", "asset_B", "asset_D"] in path_ids
    assert ["asset_A", "asset_C", "asset_D"] in path_ids
