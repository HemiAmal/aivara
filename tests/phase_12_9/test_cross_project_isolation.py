"""Tests for Cross-Project Isolation (REQ-12-AGG-013)."""

import pytest

from aivara.universal.aggregation.engine import UniversalProjectAggregator
from aivara.universal.aggregation.exceptions import ScopeMismatchError
from aivara.universal.aggregation.schemas import (
    AssetDependencyEdge,
    AssetDependencyGraph,
)
from aivara.universal.risk.enums import EvidenceSufficiencyStatus, RiskLevel
from aivara.universal.risk.schemas import AssetRiskAssessment


from pydantic import ValidationError


def test_cross_project_edge_fails_closed():
    """Attempting to construct an AssetDependencyGraph with foreign project edges raises ScopeMismatchError."""
    with pytest.raises((ScopeMismatchError, ValidationError)) as exc_info:
        AssetDependencyGraph(
            project_id="proj_alpha",
            asset_ids=["asset_A", "asset_B"],
            edges=[
                AssetDependencyEdge(
                    project_id="proj_beta",  # Foreign project edge!
                    source_asset_id="asset_A",
                    target_asset_id="asset_B",
                )
            ],
        )
    assert "does not match graph project" in str(exc_info.value)


def test_cross_project_asset_assessment_fails_closed():
    """Attempting to aggregate assets from different projects raises ScopeMismatchError."""
    aggregator = UniversalProjectAggregator()

    graph = AssetDependencyGraph(
        project_id="proj_alpha",
        asset_ids=["asset_A"],
        edges=[],
    )

    foreign_asset = AssetRiskAssessment(
        project_id="proj_beta",  # Foreign project!
        asset_id="asset_B",
        asset_type="model",
        risk_score=0.20,
        risk_level=RiskLevel.LOW,
        evidence_sufficiency=EvidenceSufficiencyStatus.SUFFICIENT,
        finding_count=1,
        evidence_count=1,
        cluster_count=1,
        contributions=[],
    )

    with pytest.raises(ScopeMismatchError) as exc_info:
        aggregator.aggregate_project(graph=graph, asset_assessments=[foreign_asset])
    assert "does not match aggregation project" in str(exc_info.value) or "!=" in str(exc_info.value)
