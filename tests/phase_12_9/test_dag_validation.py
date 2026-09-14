"""Tests for DAG Validation & Cycle Rejection (REQ-12-AGG-004)."""

import pytest
from pydantic import ValidationError

from aivara.universal.aggregation.exceptions import DependencyCycleError
from aivara.universal.aggregation.schemas import (
    AssetDependencyEdge,
    AssetDependencyGraph,
)


def test_self_cycle_fails_closed():
    """Self-referencing dependency (A -> A) triggers DependencyCycleError."""
    with pytest.raises((DependencyCycleError, ValidationError)) as exc_info:
        AssetDependencyGraph(
            project_id="proj_cycle_01",
            asset_ids=["asset_A"],
            edges=[
                AssetDependencyEdge(
                    project_id="proj_cycle_01",
                    source_asset_id="asset_A",
                    target_asset_id="asset_A",
                )
            ],
        )
    assert "Self-dependency cycle" in str(exc_info.value)


def test_two_node_direct_cycle_fails_closed():
    """Direct cycle (A -> B -> A) triggers DependencyCycleError."""
    with pytest.raises((DependencyCycleError, ValidationError)) as exc_info:
        AssetDependencyGraph(
            project_id="proj_cycle_02",
            asset_ids=["asset_A", "asset_B"],
            edges=[
                AssetDependencyEdge(
                    project_id="proj_cycle_02",
                    source_asset_id="asset_A",
                    target_asset_id="asset_B",
                ),
                AssetDependencyEdge(
                    project_id="proj_cycle_02",
                    source_asset_id="asset_B",
                    target_asset_id="asset_A",
                ),
            ],
        )
    assert "Dependency cycle detected" in str(exc_info.value)


def test_three_node_indirect_cycle_fails_closed():
    """Indirect cycle (A -> B -> C -> A) triggers DependencyCycleError."""
    with pytest.raises((DependencyCycleError, ValidationError)) as exc_info:
        AssetDependencyGraph(
            project_id="proj_cycle_03",
            asset_ids=["asset_A", "asset_B", "asset_C"],
            edges=[
                AssetDependencyEdge(
                    project_id="proj_cycle_03",
                    source_asset_id="asset_A",
                    target_asset_id="asset_B",
                ),
                AssetDependencyEdge(
                    project_id="proj_cycle_03",
                    source_asset_id="asset_B",
                    target_asset_id="asset_C",
                ),
                AssetDependencyEdge(
                    project_id="proj_cycle_03",
                    source_asset_id="asset_C",
                    target_asset_id="asset_A",
                ),
            ],
        )
    assert "Dependency cycle detected" in str(exc_info.value)


def test_valid_dag_topological_sort():
    """Valid diamond DAG (A->B, A->C, B->D, C->D) validates and sorts deterministically."""
    graph = AssetDependencyGraph(
        project_id="proj_valid_dag",
        asset_ids=["asset_A", "asset_B", "asset_C", "asset_D"],
        edges=[
            AssetDependencyEdge(project_id="proj_valid_dag", source_asset_id="asset_A", target_asset_id="asset_B"),
            AssetDependencyEdge(project_id="proj_valid_dag", source_asset_id="asset_A", target_asset_id="asset_C"),
            AssetDependencyEdge(project_id="proj_valid_dag", source_asset_id="asset_B", target_asset_id="asset_D"),
            AssetDependencyEdge(project_id="proj_valid_dag", source_asset_id="asset_C", target_asset_id="asset_D"),
        ],
    )
    order = graph.get_topological_order()
    assert order == ["asset_A", "asset_B", "asset_C", "asset_D"]
