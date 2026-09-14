"""Tests for Bounded Risk Composition, Monotonicity & Ancestry Collapse (REQ-12-AGG-006, 007, 009)."""

from aivara.universal.aggregation.engine import UniversalProjectAggregator
from aivara.universal.aggregation.schemas import (
    AssetDependencyEdge,
    AssetDependencyGraph,
)
from aivara.universal.risk.enums import EvidenceSufficiencyStatus, RiskLevel
from aivara.universal.risk.schemas import AssetRiskAssessment


def test_monotonicity_with_increasing_constituent_risk():
    """Increasing upstream asset risk strictly increases (or preserves) aggregate project risk."""
    aggregator = UniversalProjectAggregator()

    graph = AssetDependencyGraph(
        project_id="proj_mono",
        asset_ids=["asset_A", "asset_B"],
        edges=[
            AssetDependencyEdge(project_id="proj_mono", source_asset_id="asset_A", target_asset_id="asset_B")
        ],
    )

    prev_project_risk = -1.0
    for r_a in [0.0, 0.20, 0.40, 0.60, 0.80, 1.00]:
        base_risks = {"asset_A": r_a, "asset_B": 0.20}
        eff = aggregator.propagate_lineage_risks(graph, base_risks)

        ass_a = AssetRiskAssessment(
            project_id="proj_mono", asset_id="asset_A", asset_type="dataset",
            risk_score=eff["asset_A"], risk_level=RiskLevel.LOW,
            evidence_sufficiency=EvidenceSufficiencyStatus.SUFFICIENT,
            finding_count=1, evidence_count=1, cluster_count=1, contributions=[],
        )
        ass_b = AssetRiskAssessment(
            project_id="proj_mono", asset_id="asset_B", asset_type="model",
            risk_score=eff["asset_B"], risk_level=RiskLevel.LOW,
            evidence_sufficiency=EvidenceSufficiencyStatus.SUFFICIENT,
            finding_count=1, evidence_count=1, cluster_count=1, contributions=[],
        )

        p_ass = aggregator.synthesize_project_risk(
            project_id="proj_mono",
            asset_assessments=[ass_a, ass_b],
            chain_count=1,
        )

        assert p_ass.project_risk_score >= prev_project_risk
        assert 0.0 <= p_ass.project_risk_score <= 1.0
        prev_project_risk = p_ass.project_risk_score


def test_sub_additive_boundedness():
    """All risk evaluations asymptotically saturate at 1.0 without ever exceeding 1.0."""
    aggregator = UniversalProjectAggregator()

    graph = AssetDependencyGraph(
        project_id="proj_bound",
        asset_ids=["asset_A", "asset_B", "asset_C"],
        edges=[
            AssetDependencyEdge(project_id="proj_bound", source_asset_id="asset_A", target_asset_id="asset_B"),
            AssetDependencyEdge(project_id="proj_bound", source_asset_id="asset_B", target_asset_id="asset_C"),
        ],
    )

    base_risks = {"asset_A": 1.0, "asset_B": 1.0, "asset_C": 1.0}
    eff = aggregator.propagate_lineage_risks(graph, base_risks)

    for a_id in ["asset_A", "asset_B", "asset_C"]:
        assert 0.0 <= eff[a_id] <= 1.0

    chains, pairwise = aggregator.extract_and_evaluate_chains(graph, eff)
    for c in chains:
        assert 0.0 <= c.chain_risk_score <= 1.0
