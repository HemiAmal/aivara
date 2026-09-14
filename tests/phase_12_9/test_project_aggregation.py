"""Tests for Project Risk Synthesis & Peak Dominance (REQ-12-AGG-008)."""

from aivara.universal.aggregation.engine import UniversalProjectAggregator
from aivara.universal.aggregation.enums import AssetRole
from aivara.universal.aggregation.schemas import AssetDependencyGraph
from aivara.universal.risk.enums import EvidenceSufficiencyStatus, RiskLevel
from aivara.universal.risk.schemas import AssetRiskAssessment


def test_peak_dominance_preservation():
    """A catastrophic risk (0.95) in a single core asset dominates the project score despite 5 healthy assets."""
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

    # Project risk score should reflect critical risk (> 0.95)
    assert project_assessment.project_risk_score >= 0.95
    assert project_assessment.peak_asset_id == "asset_core_model"
    assert project_assessment.risk_level == RiskLevel.CRITICAL


def test_empty_project_assessment():
    """Project with 0 assets evaluates to 0.0 risk and RiskLevel.NONE."""
    aggregator = UniversalProjectAggregator()
    p_ass = aggregator.synthesize_project_risk(
        project_id="proj_empty",
        asset_assessments=[],
        chain_count=0,
    )
    assert p_ass.project_risk_score == 0.0
    assert p_ass.risk_level == RiskLevel.NONE
    assert p_ass.peak_asset_id is None
