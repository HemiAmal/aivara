"""Tests for Aggregation Determinism & Hash Sensitivity (REQ-12-AGG-014, 015, 016)."""

from aivara.universal.aggregation.engine import UniversalProjectAggregator
from aivara.universal.aggregation.schemas import (
    AssetDependencyEdge,
    AssetDependencyGraph,
)
from aivara.universal.risk.enums import EvidenceSufficiencyStatus, RiskLevel
from aivara.universal.risk.schemas import AssetRiskAssessment


def test_repeated_project_aggregation_determinism():
    """100 repeated aggregation runs produce bit-for-bit identical hashes, scores, and sorted traces."""
    aggregator = UniversalProjectAggregator()

    graph = AssetDependencyGraph(
        project_id="proj_det_01",
        asset_ids=["ds_01", "model_01", "inf_01"],
        edges=[
            AssetDependencyEdge(project_id="proj_det_01", source_asset_id="ds_01", target_asset_id="model_01"),
            AssetDependencyEdge(project_id="proj_det_01", source_asset_id="model_01", target_asset_id="inf_01"),
        ],
    )

    assets = [
        AssetRiskAssessment(
            project_id="proj_det_01", asset_id="ds_01", asset_type="dataset",
            risk_score=0.45, risk_level=RiskLevel.MEDIUM,
            evidence_sufficiency=EvidenceSufficiencyStatus.SUFFICIENT,
            finding_count=2, evidence_count=3, cluster_count=1, contributions=[],
        ),
        AssetRiskAssessment(
            project_id="proj_det_01", asset_id="model_01", asset_type="model",
            risk_score=0.30, risk_level=RiskLevel.MEDIUM,
            evidence_sufficiency=EvidenceSufficiencyStatus.SUFFICIENT,
            finding_count=1, evidence_count=2, cluster_count=1, contributions=[],
        ),
        AssetRiskAssessment(
            project_id="proj_det_01", asset_id="inf_01", asset_type="inference",
            risk_score=0.15, risk_level=RiskLevel.LOW,
            evidence_sufficiency=EvidenceSufficiencyStatus.SUFFICIENT,
            finding_count=1, evidence_count=1, cluster_count=1, contributions=[],
        ),
    ]

    first_result = aggregator.aggregate_project(graph=graph, asset_assessments=assets)

    for _ in range(100):
        res = aggregator.aggregate_project(graph=graph, asset_assessments=assets)
        assert res.hierarchical_hash == first_result.hierarchical_hash
        assert res.project_assessment.assessment_hash == first_result.project_assessment.assessment_hash
        assert res.project_assessment.project_risk_score == first_result.project_assessment.project_risk_score


def test_hash_mutation_sensitivity():
    """Altering risk on any asset changes the hierarchical assessment hash."""
    aggregator = UniversalProjectAggregator()

    graph = AssetDependencyGraph(
        project_id="proj_sens_01",
        asset_ids=["ds_01", "model_01"],
        edges=[],
    )

    assets_1 = [
        AssetRiskAssessment(
            project_id="proj_sens_01", asset_id="ds_01", asset_type="dataset",
            risk_score=0.40, risk_level=RiskLevel.MEDIUM,
            evidence_sufficiency=EvidenceSufficiencyStatus.SUFFICIENT,
            finding_count=1, evidence_count=1, cluster_count=1, contributions=[],
        ),
    ]

    assets_2 = [
        AssetRiskAssessment(
            project_id="proj_sens_01", asset_id="ds_01", asset_type="dataset",
            risk_score=0.41,  # Mutated risk score!
            risk_level=RiskLevel.MEDIUM,
            evidence_sufficiency=EvidenceSufficiencyStatus.SUFFICIENT,
            finding_count=1, evidence_count=1, cluster_count=1, contributions=[],
        ),
    ]

    res_1 = aggregator.aggregate_project(graph=graph, asset_assessments=assets_1)
    res_2 = aggregator.aggregate_project(graph=graph, asset_assessments=assets_2)

    assert res_1.hierarchical_hash != res_2.hierarchical_hash
