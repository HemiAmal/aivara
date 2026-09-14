"""Traceability, Threat Coverage, and Multi-Asset Topology Suite for Phase 12.4."""

import inspect
import math
import pytest

from aivara.domain.schemas import Severity
from aivara.universal.enums import SubsystemDomain
from aivara.universal.graph import (
    GraphEdge,
    GraphEdgeType,
    GraphNode,
    GraphNodeType,
    UniversalEvidenceGraphBuilder,
)
from aivara.universal.normalizer import UniversalEvidenceNormalizer
from aivara.universal.risk import (
    EvidenceSufficiencyStatus,
    HierarchicalRiskAggregator,
    ImmutableAggregationConfig,
    RiskLevel,
)


@pytest.fixture
def normalizer():
    return UniversalEvidenceNormalizer()


@pytest.fixture
def aggregator():
    return HierarchicalRiskAggregator()


# =====================================================================
# 1. Multi-Asset Topology: 3-Hop Asset Chain (A1 -> A2 -> A3)
# =====================================================================

def test_three_hop_asset_chain(aggregator, normalizer):
    """Verify linear 3-hop asset chain evaluates all pairwise lineage risks."""
    builder = UniversalEvidenceGraphBuilder(project_id="proj_3hop")
    
    # A1 (Dataset), A2 (Model), A3 (Inference)
    env1 = normalizer.normalize_single({"evidence_id": "ev_1", "project_id": "proj_3hop", "domain": "DATASET_INTEGRITY", "severity": "medium", "confidence": 0.9, "dataset_id": "ds_a1"}, project_id="proj_3hop")
    env2 = normalizer.normalize_single({"evidence_id": "ev_2", "project_id": "proj_3hop", "domain": "MODEL_INTEGRITY", "severity": "high", "confidence": 1.0, "model_id": "model_a2"}, project_id="proj_3hop")
    env3 = normalizer.normalize_single({"evidence_id": "ev_3", "project_id": "proj_3hop", "domain": "INFERENCE_INTEGRITY", "severity": "critical", "confidence": 1.0, "inference_id": "inf_a3"}, project_id="proj_3hop")

    builder.add_evidence_envelope(env1)
    builder.add_evidence_envelope(env2)
    builder.add_evidence_envelope(env3)

    # Lineage edges: A1 -> A2 and A2 -> A3
    builder.add_edge(GraphEdge(project_id="proj_3hop", source_node_id="node_ev_ev_1", target_node_id="node_ev_ev_2", edge_type=GraphEdgeType.LINEAGE))
    builder.add_edge(GraphEdge(project_id="proj_3hop", source_node_id="node_ev_ev_2", target_node_id="node_ev_ev_3", edge_type=GraphEdgeType.LINEAGE))

    g = builder.validate_and_build()
    res = aggregator.aggregate_hierarchy(g)

    assert len(res.asset_assessments) == 3
    assert len(res.chain_assessments) == 2
    pairs = {(c.source_asset_id, c.target_asset_id) for c in res.chain_assessments}
    assert pairs == {("ds_a1", "model_a2"), ("model_a2", "inf_a3")}


# =====================================================================
# 2. Shared Evidence Across Multiple Assets (E1 -> A1 and E1 -> A2)
# =====================================================================

def test_shared_evidence_across_multiple_assets(aggregator, normalizer):
    """Single evidence supporting findings across multiple assets is aggregated correctly per asset."""
    builder = UniversalEvidenceGraphBuilder(project_id="proj_shared_ev")
    
    # Evidence node
    builder.add_node(GraphNode(
        node_id="node_ev_ev_shared",
        project_id="proj_shared_ev",
        node_type=GraphNodeType.EVIDENCE,
        canonical_identity="ev_shared",
        canonical_hash="1" * 64,
        severity=Severity.HIGH,
        confidence=0.90,
        metadata={"primary_asset_id": "asset_1"},
    ))
    
    # Finding 1 on asset 1
    builder.add_node(GraphNode(
        node_id="node_find_f1",
        project_id="proj_shared_ev",
        node_type=GraphNodeType.FINDING,
        canonical_identity="f1",
        canonical_hash="2" * 64,
        severity=Severity.HIGH,
        confidence=0.90,
        metadata={"affected_asset_id": "asset_1"},
    ))
    
    # Finding 2 on asset 2
    builder.add_node(GraphNode(
        node_id="node_find_f2",
        project_id="proj_shared_ev",
        node_type=GraphNodeType.FINDING,
        canonical_identity="f2",
        canonical_hash="3" * 64,
        severity=Severity.MEDIUM,
        confidence=0.80,
        metadata={"affected_asset_id": "asset_2"},
    ))

    builder.add_finding_evidence_binding("f1", "ev_shared")
    builder.add_finding_evidence_binding("f2", "ev_shared")

    g = builder.validate_and_build()
    res = aggregator.aggregate_hierarchy(g)

    assert len(res.asset_assessments) == 2
    asset_ids = {a.asset_id for a in res.asset_assessments}
    assert asset_ids == {"asset_1", "asset_2"}


# =====================================================================
# 3. Missing Ancestry: Analytical Data Quality State vs No Decision Routing
# =====================================================================

def test_missing_ancestry_produces_analytical_insufficiency_not_decision(aggregator, normalizer):
    """Confirm missing or unresolvable ancestry flags INSUFFICIENT_ANCESTRY without routing to REVIEW or assigning disposition."""
    builder = UniversalEvidenceGraphBuilder(project_id="proj_unresolvable_ancestry")
    
    # Evidence node with missing ancestry
    builder.add_node(GraphNode(
        node_id="node_ev_ev_no_ancestry",
        project_id="proj_unresolvable_ancestry",
        node_type=GraphNodeType.EVIDENCE,
        canonical_identity="ev_no_ancestry",
        canonical_hash="a" * 64,
        severity=Severity.HIGH,
        confidence=0.85,
        metadata={"primary_asset_id": "asset_x"},
    ))

    g = builder.validate_and_build()
    res = aggregator.aggregate_hierarchy(g)

    # Risk is computed mathematically
    assert res.project_assessment.project_risk_score > 0.0
    
    # Analytical sufficiency status is recorded
    assert res.evidence_sufficiency == EvidenceSufficiencyStatus.INSUFFICIENT_ANCESTRY
    assert res.asset_assessments[0].evidence_sufficiency == EvidenceSufficiencyStatus.INSUFFICIENT_ANCESTRY
    assert res.asset_assessments[0].contributions[0].ancestry_status == EvidenceSufficiencyStatus.INSUFFICIENT_ANCESTRY

    # Critical Phase 12.4 Boundary Check: Zero disposition or decision attributes
    assert not hasattr(res, "disposition")
    assert not hasattr(res, "decision")
    assert not hasattr(res.project_assessment, "disposition")
    assert not hasattr(res.asset_assessments[0], "disposition")


# =====================================================================
# 4. Static Code Audit: Strict Separation of Concerns & Zero Disposition Code
# =====================================================================

def test_static_audit_no_phase_12_5_or_12_6_in_universal_risk():
    """Confirm backend.aivara.universal.risk has zero implementation of correlation damping matrix, proof overrides, or dispositions."""
    import aivara.universal.risk.aggregator as a_mod
    import aivara.universal.risk.config as c_mod
    import aivara.universal.risk.enums as e_mod
    import aivara.universal.risk.schemas as s_mod

    prohibited_terms = [
        "correlation_matrix",
        "inter_domain_damping",
        "proof_override",
        "proof_non_compensable",
        "disposition_decision",
        "seal_dossier",
        "compliance_report",
        "ACCEPT",
        "REVIEW",
        "QUARANTINE",
        "REJECT",
    ]

    for mod in [a_mod, c_mod, e_mod, s_mod]:
        source = inspect.getsource(mod)
        for term in prohibited_terms:
            assert term not in source, f"Prohibited term '{term}' discovered in {mod.__name__}"
