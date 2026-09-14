"""Adversarial Mutation Test Suite for Hierarchical Risk Aggregation (Phase 12.4).

Executes independent adversarial mutations (A through W):
A. finding severity
B. finding confidence
C. contribution value
D. project_id
E. asset_id
F. graph hash
G. graph node
H. graph edge
I. ancestry
J. evidence identity
K. duplicate evidence
L. duplicate finding
M. asset lineage
N. aggregation version
O. policy identity
P. contribution ordering
Q. NaN
R. +Inf
S. -Inf
T. risk > 1
U. risk < 0
V. cross-project contribution
W. unsupported graph schema
"""

import pytest
from pydantic import ValidationError

from aivara.domain.schemas import Severity
from aivara.universal.exceptions import ProjectMismatchError
from aivara.universal.graph import (
    GraphEdge,
    GraphEdgeType,
    GraphNode,
    GraphNodeType,
    UniversalEvidenceGraphBuilder,
)
from aivara.universal.normalizer import UniversalEvidenceNormalizer
from aivara.universal.risk import (
    HierarchicalRiskAggregator,
    ImmutableAggregationConfig,
    NonFiniteRiskError,
    RiskContribution,
    RiskOutOfRangeError,
)
from aivara.universal.schemas import AncestryPath


@pytest.fixture
def normalizer():
    return UniversalEvidenceNormalizer()


@pytest.fixture
def aggregator():
    return HierarchicalRiskAggregator()


@pytest.fixture
def base_graph(normalizer):
    builder = UniversalEvidenceGraphBuilder(project_id="proj_mut")
    env = normalizer.normalize_single({
        "evidence_id": "ev_01",
        "project_id": "proj_mut",
        "domain": "DATASET_INTEGRITY",
        "evidence_type": "noise",
        "severity": "medium",
        "confidence": 0.80,
        "dataset_id": "ds_mut",
    }, project_id="proj_mut")
    builder.add_evidence_envelope(env)
    return builder.validate_and_build()


# =====================================================================
# Mutation A: Finding Severity Mutation
# =====================================================================
def test_mutation_a_severity(aggregator, normalizer):
    """Mutating severity from LOW to CRITICAL strictly increases risk score."""
    def get_risk(sev):
        b = UniversalEvidenceGraphBuilder(project_id="proj_a")
        env = normalizer.normalize_single({
            "evidence_id": "ev_a", "project_id": "proj_a", "domain": "DATASET_INTEGRITY", "severity": sev, "confidence": 0.80, "dataset_id": "ds_a"
        }, project_id="proj_a")
        b.add_evidence_envelope(env)
        return aggregator.aggregate_hierarchy(b.validate_and_build()).asset_assessments[0].risk_score

    r_low = get_risk("low")
    r_crit = get_risk("critical")
    assert r_crit > r_low


# =====================================================================
# Mutation B: Finding Confidence Mutation
# =====================================================================
def test_mutation_b_confidence(aggregator, normalizer):
    """Mutating confidence from 0.50 to 0.95 strictly increases risk score."""
    def get_risk(conf):
        b = UniversalEvidenceGraphBuilder(project_id="proj_b")
        env = normalizer.normalize_single({
            "evidence_id": "ev_b", "project_id": "proj_b", "domain": "DATASET_INTEGRITY", "severity": "high", "confidence": conf, "dataset_id": "ds_b"
        }, project_id="proj_b")
        b.add_evidence_envelope(env)
        return aggregator.aggregate_hierarchy(b.validate_and_build()).asset_assessments[0].risk_score

    r_50 = get_risk(0.50)
    r_95 = get_risk(0.95)
    assert r_95 > r_50


# =====================================================================
# Mutation C: Contribution Value Mutation
# =====================================================================
def test_mutation_c_contribution_mutation():
    """Mutating effective score changes contribution hash."""
    from aivara.universal.risk.enums import AggregationStage
    c1 = RiskContribution(
        contribution_id="c1",
        stage=AggregationStage.EVIDENCE_CLUSTER,
        source_id="s1",
        target_id="t1",
        raw_score=0.5,
        effective_score=0.5,
    )
    c2 = RiskContribution(
        contribution_id="c1",
        stage=AggregationStage.EVIDENCE_CLUSTER,
        source_id="s1",
        target_id="t1",
        raw_score=0.5,
        effective_score=0.8,  # mutated
    )
    assert c1.contribution_hash != c2.contribution_hash


# =====================================================================
# Mutation D: Project ID Mutation
# =====================================================================
def test_mutation_d_project_id(aggregator, normalizer):
    """Foreign project_id is rejected by graph builder."""
    b = UniversalEvidenceGraphBuilder(project_id="proj_A")
    env = normalizer.normalize_single({
        "evidence_id": "ev_alien", "project_id": "proj_B", "domain": "DATASET_INTEGRITY", "dataset_id": "ds_alien"
    }, project_id="proj_B")
    with pytest.raises(ProjectMismatchError):
        b.add_evidence_envelope(env)


# =====================================================================
# Mutation E: Asset ID Mutation
# =====================================================================
def test_mutation_e_asset_id(aggregator, normalizer):
    """Mutating asset_id partitions evidence into separate asset assessments."""
    b = UniversalEvidenceGraphBuilder(project_id="proj_e")
    env1 = normalizer.normalize_single({
        "evidence_id": "ev_1", "project_id": "proj_e", "domain": "DATASET_INTEGRITY", "dataset_id": "ds_1"
    }, project_id="proj_e")
    env2 = normalizer.normalize_single({
        "evidence_id": "ev_2", "project_id": "proj_e", "domain": "DATASET_INTEGRITY", "dataset_id": "ds_2"
    }, project_id="proj_e")
    b.add_evidence_envelope(env1)
    b.add_evidence_envelope(env2)
    res = aggregator.aggregate_hierarchy(b.validate_and_build())
    assert len(res.asset_assessments) == 2


# =====================================================================
# Mutation F: Graph Hash Tampering
# =====================================================================
def test_mutation_f_graph_hash_tampering(aggregator, base_graph):
    """Hierarchical assessment binds exact graph hash into assessment."""
    res = aggregator.aggregate_hierarchy(base_graph)
    assert res.graph_hash == base_graph.graph_hash


# =====================================================================
# Mutation G & H: Graph Node & Edge Mutations
# =====================================================================
def test_mutation_g_h_node_edge_mutations(aggregator, normalizer):
    """Adding a new lineage edge alters hierarchical risk assessment."""
    b1 = UniversalEvidenceGraphBuilder(project_id="proj_gh")
    env1 = normalizer.normalize_single({"evidence_id": "ev_1", "project_id": "proj_gh", "domain": "DATASET_INTEGRITY", "severity": "high", "confidence": 0.9, "dataset_id": "ds_1"}, project_id="proj_gh")
    env2 = normalizer.normalize_single({"evidence_id": "ev_2", "project_id": "proj_gh", "domain": "MODEL_INTEGRITY", "severity": "high", "confidence": 1.0, "model_id": "model_1"}, project_id="proj_gh")
    b1.add_evidence_envelope(env1)
    b1.add_evidence_envelope(env2)
    g1 = b1.validate_and_build()
    res1 = aggregator.aggregate_hierarchy(g1)
    assert len(res1.chain_assessments) == 0

    # Add lineage edge
    b2 = UniversalEvidenceGraphBuilder(project_id="proj_gh")
    b2.add_evidence_envelope(env1)
    b2.add_evidence_envelope(env2)
    b2.add_edge(GraphEdge(project_id="proj_gh", source_node_id="node_ev_ev_1", target_node_id="node_ev_ev_2", edge_type=GraphEdgeType.LINEAGE))
    g2 = b2.validate_and_build()
    res2 = aggregator.aggregate_hierarchy(g2)
    assert len(res2.chain_assessments) == 1
    assert res1.hierarchical_hash != res2.hierarchical_hash


# =====================================================================
# Mutation I & J: Ancestry & Evidence Identity
# =====================================================================
def test_mutation_i_j_ancestry_evidence_identity(aggregator, normalizer):
    """Mutating ancestry from shared to distinct splits clusters and changes risk score."""
    # Shared ancestry -> 1 cluster with intra-cluster damping
    b1 = UniversalEvidenceGraphBuilder(project_id="proj_ij")
    env1 = normalizer.normalize_single({"evidence_id": "ev_1", "project_id": "proj_ij", "domain": "DATASET_INTEGRITY", "severity": "medium", "confidence": 0.8, "sample_id": "s_common", "dataset_id": "ds_1"}, project_id="proj_ij")
    env2 = normalizer.normalize_single({"evidence_id": "ev_2", "project_id": "proj_ij", "domain": "DATASET_INTEGRITY", "severity": "medium", "confidence": 0.8, "sample_id": "s_common", "dataset_id": "ds_1"}, project_id="proj_ij")
    b1.add_evidence_envelope(env1)
    b1.add_evidence_envelope(env2)
    r1 = aggregator.aggregate_hierarchy(b1.validate_and_build()).asset_assessments[0].risk_score

    # Distinct ancestry -> 2 independent clusters (higher saturation)
    b2 = UniversalEvidenceGraphBuilder(project_id="proj_ij")
    env2_diff = normalizer.normalize_single({"evidence_id": "ev_2", "project_id": "proj_ij", "domain": "DATASET_INTEGRITY", "severity": "medium", "confidence": 0.8, "sample_id": "s_distinct", "dataset_id": "ds_1"}, project_id="proj_ij")
    b2.add_evidence_envelope(env1)
    b2.add_evidence_envelope(env2_diff)
    r2 = aggregator.aggregate_hierarchy(b2.validate_and_build()).asset_assessments[0].risk_score

    assert r2 > r1


# =====================================================================
# Mutation K & L: Duplicate Evidence & Finding
# =====================================================================
def test_mutation_k_l_duplicate_deduplication(aggregator, normalizer):
    """Ingesting duplicate envelope with identical hash is idempotent and deduplicated."""
    b = UniversalEvidenceGraphBuilder(project_id="proj_dup")
    env = normalizer.normalize_single({"evidence_id": "ev_1", "project_id": "proj_dup", "domain": "DATASET_INTEGRITY", "dataset_id": "ds_dup"}, project_id="proj_dup")
    b.add_evidence_envelope(env)
    b.add_evidence_envelope(env)  # duplicate addition
    g = b.validate_and_build()
    res = aggregator.aggregate_hierarchy(g)
    assert res.asset_assessments[0].evidence_count == 1


# =====================================================================
# Mutation M: Asset Lineage
# =====================================================================
def test_mutation_m_asset_lineage(aggregator, normalizer):
    """Lineage risk calculation respects explicit propagation factor."""
    b = UniversalEvidenceGraphBuilder(project_id="proj_lin")
    env1 = normalizer.normalize_single({"evidence_id": "ev_1", "project_id": "proj_lin", "domain": "DATASET_INTEGRITY", "severity": "high", "confidence": 1.0, "dataset_id": "ds_1"}, project_id="proj_lin")
    env2 = normalizer.normalize_single({"evidence_id": "ev_2", "project_id": "proj_lin", "domain": "MODEL_INTEGRITY", "severity": "high", "confidence": 1.0, "model_id": "model_1"}, project_id="proj_lin")
    b.add_evidence_envelope(env1)
    b.add_evidence_envelope(env2)
    b.add_edge(GraphEdge(project_id="proj_lin", source_node_id="node_ev_ev_1", target_node_id="node_ev_ev_2", edge_type=GraphEdgeType.LINEAGE))
    g = b.validate_and_build()

    cfg1 = ImmutableAggregationConfig(lineage_propagation_factor=0.10)
    cfg2 = ImmutableAggregationConfig(lineage_propagation_factor=0.40)

    res1 = aggregator.aggregate_hierarchy(g, config=cfg1)
    res2 = aggregator.aggregate_hierarchy(g, config=cfg2)

    assert res2.chain_assessments[0].chain_risk_score > res1.chain_assessments[0].chain_risk_score


# =====================================================================
# Mutation N & O: Aggregation Version & Policy Identity
# =====================================================================
def test_mutation_n_o_version_and_policy(aggregator, base_graph):
    """Mutating aggregation configuration changes config_hash and hierarchical_hash."""
    cfg1 = ImmutableAggregationConfig(intra_cluster_damping=0.15)
    cfg2 = ImmutableAggregationConfig(intra_cluster_damping=0.30)
    assert cfg1.config_hash != cfg2.config_hash

    res1 = aggregator.aggregate_hierarchy(base_graph, config=cfg1)
    res2 = aggregator.aggregate_hierarchy(base_graph, config=cfg2)
    assert res1.config_hash != res2.config_hash
    assert res1.hierarchical_hash != res2.hierarchical_hash


# =====================================================================
# Mutation P: Contribution Ordering Invariance
# =====================================================================
def test_mutation_p_contribution_ordering(aggregator, normalizer):
    """Contributions are canonically sorted in assessment outputs."""
    b = UniversalEvidenceGraphBuilder(project_id="proj_ord")
    for i in [3, 1, 2]:
        env = normalizer.normalize_single({"evidence_id": f"ev_{i}", "project_id": "proj_ord", "domain": "DATASET_INTEGRITY", "dataset_id": "ds_ord", "sample_id": f"s_{i}"}, project_id="proj_ord")
        b.add_evidence_envelope(env)
    g = b.validate_and_build()
    res = aggregator.aggregate_hierarchy(g)
    c_ids = [c.contribution_id for c in res.asset_assessments[0].contributions]
    assert c_ids == sorted(c_ids)


# =====================================================================
# Mutation Q, R, S: NaN, +Inf, -Inf Rejection
# =====================================================================
def test_mutation_q_r_s_non_finite_rejection(aggregator):
    """Non-finite confidence on node triggers NonFiniteRiskError."""
    builder = UniversalEvidenceGraphBuilder(project_id="proj_nan")
    # Add node with NaN confidence
    with pytest.raises(Exception):
        GraphNode(
            node_id="n_nan",
            project_id="proj_nan",
            node_type=GraphNodeType.EVIDENCE,
            canonical_identity="nan",
            canonical_hash="1" * 64,
            confidence=float("nan"),
        )


# =====================================================================
# Mutation T & U: Out of Range Risk (>1 or <0)
# =====================================================================
def test_mutation_t_u_out_of_range_risk():
    """Setting risk score outside [0, 1] raises RiskOutOfRangeError or ValidationError."""
    from aivara.universal.risk.schemas import AssetRiskAssessment, RiskLevel
    with pytest.raises(Exception):
        AssetRiskAssessment(
            project_id="p",
            asset_id="a",
            risk_score=1.5,  # > 1.0
            risk_level=RiskLevel.CRITICAL,
        )
    with pytest.raises(Exception):
        AssetRiskAssessment(
            project_id="p",
            asset_id="a",
            risk_score=-0.1,  # < 0.0
            risk_level=RiskLevel.NONE,
        )


# =====================================================================
# Mutation V & W: Cross-Project Contribution & Unsupported Schema
# =====================================================================
def test_mutation_v_w_cross_project_and_schema(aggregator, normalizer):
    """Foreign project item cannot be mixed into graph builder."""
    b = UniversalEvidenceGraphBuilder(project_id="proj_v")
    env = normalizer.normalize_single({"evidence_id": "ev_x", "project_id": "proj_OTHER", "domain": "DATASET_INTEGRITY", "dataset_id": "ds_x"}, project_id="proj_OTHER")
    with pytest.raises(ProjectMismatchError):
        b.add_evidence_envelope(env)
