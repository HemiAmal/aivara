"""Test 12.12.9: Multi-Asset Risk Aggregation & DAG Lineage Verification."""

import pytest
from aivara.universal.aggregation.engine import UniversalProjectAggregator
from aivara.universal.aggregation.schemas import AssetDependencyEdge
from aivara.universal.risk.enums import EvidenceSufficiencyStatus, RiskLevel
from aivara.universal.risk.schemas import AssetRiskAssessment


def test_aggregation_parameters():
    """Verify parameters: gamma_prop=0.25, alpha_peak=1.50, lambda_inter=0.10, lambda_intra=0.15, max_depth=5."""
    aggregator = UniversalProjectAggregator()
    cfg = aggregator.config
    assert cfg.lineage_propagation_factor == 0.25
    assert cfg.peak_dominance_exponent == 1.50
    assert cfg.inter_asset_damping == 0.10
    assert cfg.intra_cluster_damping == 0.15
    assert cfg.max_traversal_depth == 5



def test_lineage_propagation_and_peak_dominance():
    """Verify high asset risk dominates project score."""
    aggregator = UniversalProjectAggregator()

    healthy_assets = [
        AssetRiskAssessment(
            project_id="proj_peak",
            asset_id=f"asset_healthy_{i}",
            asset_type="dataset",
            risk_score=0.05,
            risk_level=RiskLevel.LOW,
            evidence_sufficiency=EvidenceSufficiencyStatus.SUFFICIENT,
            finding_count=1,
            evidence_count=1,
            cluster_count=1,
            contributions=[],
        )
        for i in range(5)
    ]

    critical_asset = AssetRiskAssessment(
        project_id="proj_peak",
        asset_id="asset_core_model",
        asset_type="model",
        risk_score=0.95,
        risk_level=RiskLevel.CRITICAL,
        evidence_sufficiency=EvidenceSufficiencyStatus.SUFFICIENT,
        finding_count=5,
        evidence_count=5,
        cluster_count=3,
        contributions=[],
    )

    project_assessment = aggregator.synthesize_project_risk(
        project_id="proj_peak",
        asset_assessments=healthy_assets + [critical_asset],
        chain_count=0,
    )

    # Project risk score reflects dominance of critical risk
    assert project_assessment.project_risk_score >= 0.95
