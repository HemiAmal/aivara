"""Comprehensive Test Suite for Hierarchical Multi-Asset Risk Aggregation Engine (Phase 12.4)."""

import math
import random
import socket
import pytest

from aivara.domain.schemas import EvidenceLayer, Severity
from aivara.universal.enums import AncestryStatus, SubsystemDomain
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
    RiskLevel,
    RiskOutOfRangeError,
)
from aivara.universal.schemas import AncestryPath


@pytest.fixture
def normalizer():
    return UniversalEvidenceNormalizer()


@pytest.fixture
def aggregator():
    return HierarchicalRiskAggregator()


# =====================================================================
# 1. Core Mathematical Bounded Composition Tests
# =====================================================================

def test_empty_graph_zero_risk(aggregator):
    """Empty graph produces exactly R=0.0 across asset, chain, and project levels."""
    builder = UniversalEvidenceGraphBuilder(project_id="proj_empty")
    graph = builder.validate_and_build()
    result = aggregator.aggregate_hierarchy(graph)

    assert result.project_assessment.project_risk_score == 0.0
    assert result.project_assessment.risk_level == RiskLevel.NONE
    assert result.project_assessment.peak_asset_risk == 0.0
    assert len(result.asset_assessments) == 0
    assert len(result.chain_assessments) == 0


def test_single_finding_asset_risk(aggregator, normalizer):
    """Single finding on an asset produces exact bounded calibrated risk score."""
    builder = UniversalEvidenceGraphBuilder(project_id="proj_single")
    env = normalizer.normalize_single({
        "evidence_id": "ev_01",
        "project_id": "proj_single",
        "domain": "DATASET_INTEGRITY",
        "evidence_type": "noise",
        "severity": "high",       # sev_mult = 0.8
        "confidence": 0.90,       # conf = 0.90
        "dataset_id": "ds_alpha",
    }, project_id="proj_single")
    builder.add_evidence_envelope(env)
    graph = builder.validate_and_build()

    result = aggregator.aggregate_hierarchy(graph)
    assert len(result.asset_assessments) == 1
    asset_res = result.asset_assessments[0]
    assert asset_res.asset_id == "ds_alpha"
    # Expected term: 1.0 * 0.90 * 0.8 = 0.72
    expected_r = pytest.approx(0.72, abs=1e-4)
    assert asset_res.risk_score == expected_r
    assert asset_res.risk_level == RiskLevel.HIGH
    assert result.project_assessment.peak_asset_risk == expected_r


def test_multiple_findings_subadditive_saturation(aggregator, normalizer):
    """Multiple independent findings accumulate sub-additively without exceeding 1.0."""
    builder = UniversalEvidenceGraphBuilder(project_id="proj_sat")
    # Two independent evidence items on different samples
    env1 = normalizer.normalize_single({
        "evidence_id": "ev_1",
        "project_id": "proj_sat",
        "domain": "DATASET_INTEGRITY",
        "evidence_type": "noise",
        "severity": "medium",     # sev_mult = 0.6
        "confidence": 0.80,       # term = 0.48
        "sample_id": "sample_1",
        "dataset_id": "ds_sat",
    }, project_id="proj_sat")
    env2 = normalizer.normalize_single({
        "evidence_id": "ev_2",
        "project_id": "proj_sat",
        "domain": "DATASET_INTEGRITY",
        "evidence_type": "noise",
        "severity": "medium",     # sev_mult = 0.6
        "confidence": 0.80,       # term = 0.48
        "sample_id": "sample_2",
        "dataset_id": "ds_sat",
    }, project_id="proj_sat")

    builder.add_evidence_envelope(env1)
    builder.add_evidence_envelope(env2)
    graph = builder.validate_and_build()

    result = aggregator.aggregate_hierarchy(graph)
    asset_res = result.asset_assessments[0]
    # R = 1 - (1 - 0.48) * (1 - 0.48) = 1 - (0.52 * 0.52) = 1 - 0.2704 = 0.7296
    assert asset_res.risk_score == pytest.approx(0.7296, abs=1e-4)
    assert asset_res.risk_score <= 1.0


def test_critical_finding_saturation(aggregator, normalizer):
    """Critical finding with 1.0 confidence saturates risk to 1.0."""
    builder = UniversalEvidenceGraphBuilder(project_id="proj_crit")
    env = normalizer.normalize_single({
        "evidence_id": "ev_crit",
        "project_id": "proj_crit",
        "domain": "MODEL_INTEGRITY",
        "evidence_type": "hash_mismatch",
        "evidence_layer": "proof",
        "severity": "critical",   # sev_mult = 1.0
        "confidence": 1.0,        # conf = 1.0
        "model_id": "model_crit",
    }, project_id="proj_crit")
    builder.add_evidence_envelope(env)
    graph = builder.validate_and_build()

    result = aggregator.aggregate_hierarchy(graph)
    asset_res = result.asset_assessments[0]
    assert asset_res.risk_score == 1.0
    assert asset_res.risk_level == RiskLevel.CRITICAL


# =====================================================================
# 2. Ancestry-Aware Intra-Cluster Damping
# =====================================================================

def test_shared_ancestry_intra_cluster_damping(aggregator, normalizer):
    """Evidence sharing identical ancestry is collapsed into one cluster with intra-cluster damping."""
    builder = UniversalEvidenceGraphBuilder(project_id="proj_damp")
    # Two evidence items sharing sample_id "common_sample"
    env1 = normalizer.normalize_single({
        "evidence_id": "ev_d1",
        "project_id": "proj_damp",
        "domain": "DATASET_INTEGRITY",
        "evidence_type": "quality",
        "severity": "high",       # term = 0.80 * 0.90 = 0.72
        "confidence": 0.90,
        "sample_id": "common_sample",
        "dataset_id": "ds_damp",
    }, project_id="proj_damp")
    env2 = normalizer.normalize_single({
        "evidence_id": "ev_d2",
        "project_id": "proj_damp",
        "domain": "DATASET_INTEGRITY",
        "evidence_type": "noise",
        "severity": "medium",     # term = 0.60 * 0.80 = 0.48
        "confidence": 0.80,
        "sample_id": "common_sample",
        "dataset_id": "ds_damp",
    }, project_id="proj_damp")

    builder.add_evidence_envelope(env1)
    builder.add_evidence_envelope(env2)
    graph = builder.validate_and_build()

    config = ImmutableAggregationConfig(intra_cluster_damping=0.15)
    result = aggregator.aggregate_hierarchy(graph, config=config)
    asset_res = result.asset_assessments[0]

    # Cluster score: max_term (0.72) + 0.15 * second_term (0.48) = 0.72 + 0.072 = 0.792
    assert asset_res.cluster_count == 1
    assert asset_res.risk_score == pytest.approx(0.792, abs=1e-4)


# =====================================================================
# 3. Cross-Asset Lineage Chain Risk (Tier 2)
# =====================================================================

def test_cross_asset_lineage_chain_risk(aggregator, normalizer):
    """Explicit DAG lineage edge produces Tier-2 compounding chain risk."""
    builder = UniversalEvidenceGraphBuilder(project_id="proj_chain")
    
    # Dataset asset with R(D) = 0.60
    env_ds = normalizer.normalize_single({
        "evidence_id": "ev_ds",
        "project_id": "proj_chain",
        "domain": "DATASET_INTEGRITY",
        "evidence_type": "noise",
        "severity": "medium",     # 0.6 * 1.0 = 0.60
        "confidence": 1.0,
        "dataset_id": "ds_parent",
    }, project_id="proj_chain")
    
    # Model asset with R(M) = 0.80
    env_m = normalizer.normalize_single({
        "evidence_id": "ev_m",
        "project_id": "proj_chain",
        "domain": "MODEL_INTEGRITY",
        "evidence_type": "quant_error",
        "severity": "high",       # 0.8 * 1.0 = 0.80
        "confidence": 1.0,
        "model_id": "model_child",
    }, project_id="proj_chain")

    builder.add_evidence_envelope(env_ds)
    builder.add_evidence_envelope(env_m)

    # Add cross-asset lineage edge: ds_parent -> model_child
    builder.add_edge(GraphEdge(
        project_id="proj_chain",
        source_node_id="node_ev_ev_ds",
        target_node_id="node_ev_ev_m",
        edge_type=GraphEdgeType.LINEAGE,
    ))

    graph = builder.validate_and_build()
    config = ImmutableAggregationConfig(lineage_propagation_factor=0.25)
    result = aggregator.aggregate_hierarchy(graph, config=config)

    assert len(result.chain_assessments) == 1
    chain = result.chain_assessments[0]
    assert chain.source_asset_id == "ds_parent"
    assert chain.target_asset_id == "model_child"
    # R_chain = 0.25 * 0.60 * 0.80 = 0.12
    assert chain.chain_risk_score == pytest.approx(0.12, abs=1e-4)


# =====================================================================
# 4. Tier-3 Project Risk Dominance Preservation
# =====================================================================

def test_project_risk_dominance_preservation(aggregator, normalizer):
    """Project risk preserves dominance of peak asset risk."""
    builder = UniversalEvidenceGraphBuilder(project_id="proj_peak")
    
    # Critical asset with R = 0.90
    env_crit = normalizer.normalize_single({
        "evidence_id": "ev_crit",
        "project_id": "proj_peak",
        "domain": "MODEL_INTEGRITY",
        "evidence_layer": "detection",
        "evidence_type": "attack",
        "severity": "critical",   # 1.0 * 0.9 = 0.90
        "confidence": 0.90,
        "model_id": "model_critical",
    }, project_id="proj_peak")

    # Low asset with R = 0.20
    env_low = normalizer.normalize_single({
        "evidence_id": "ev_low",
        "project_id": "proj_peak",
        "domain": "DATASET_INTEGRITY",
        "evidence_type": "minor_noise",
        "severity": "low",        # 0.4 * 0.5 = 0.20
        "confidence": 0.50,
        "dataset_id": "ds_clean",
    }, project_id="proj_peak")

    builder.add_evidence_envelope(env_crit)
    builder.add_evidence_envelope(env_low)
    graph = builder.validate_and_build()

    result = aggregator.aggregate_hierarchy(graph)
    proj = result.project_assessment

    # Peak asset is model_critical
    assert proj.peak_asset_id == "model_critical"
    assert proj.peak_asset_risk == pytest.approx(0.90, abs=1e-4)
    # Project risk >= peak asset risk
    assert proj.project_risk_score >= 0.90
    assert proj.project_risk_score <= 1.0


# =====================================================================
# 5. Determinism & Permutation Invariance
# =====================================================================

def test_aggregation_determinism_shuffled_inputs(aggregator, normalizer):
    """Permuting input envelope insertion order yields bit-exact identical hierarchical risk hash."""
    raw_items = [
        {"evidence_id": f"ev_{i}", "project_id": "proj_perm", "domain": "DATASET_INTEGRITY", "evidence_type": "t", "severity": "medium", "confidence": 0.85, "dataset_id": f"ds_{i%3}", "sample_id": f"s_{i}"}
        for i in range(12)
    ]

    def run_permutation(items):
        builder = UniversalEvidenceGraphBuilder(project_id="proj_perm")
        for it in items:
            builder.add_evidence_envelope(normalizer.normalize_single(it, project_id="proj_perm"))
        g = builder.validate_and_build()
        return aggregator.aggregate_hierarchy(g)

    res1 = run_permutation(raw_items)
    shuffled = list(raw_items)
    random.seed(42)
    random.shuffle(shuffled)
    res2 = run_permutation(shuffled)

    assert res1.project_assessment.project_risk_score == res2.project_assessment.project_risk_score
    assert res1.hierarchical_hash == res2.hierarchical_hash
    assert [a.assessment_hash for a in res1.asset_assessments] == [a.assessment_hash for a in res2.asset_assessments]


# =====================================================================
# 6. Monotonicity Tests
# =====================================================================

def test_monotonicity_under_additional_evidence(aggregator, normalizer):
    """Adding positive evidence monotonically increases or preserves asset risk."""
    b1 = UniversalEvidenceGraphBuilder(project_id="proj_mono")
    env1 = normalizer.normalize_single({
        "evidence_id": "ev_1", "project_id": "proj_mono", "domain": "DATASET_INTEGRITY", "severity": "medium", "confidence": 0.70, "dataset_id": "ds_mono"
    }, project_id="proj_mono")
    b1.add_evidence_envelope(env1)
    g1 = b1.validate_and_build()
    r1 = aggregator.aggregate_hierarchy(g1).asset_assessments[0].risk_score

    b2 = UniversalEvidenceGraphBuilder(project_id="proj_mono")
    env2 = normalizer.normalize_single({
        "evidence_id": "ev_2", "project_id": "proj_mono", "domain": "DATASET_INTEGRITY", "severity": "high", "confidence": 0.85, "dataset_id": "ds_mono", "sample_id": "s_new"
    }, project_id="proj_mono")
    b2.add_evidence_envelope(env1)
    b2.add_evidence_envelope(env2)
    g2 = b2.validate_and_build()
    r2 = aggregator.aggregate_hierarchy(g2).asset_assessments[0].risk_score

    assert r2 >= r1


# =====================================================================
# 7. 100% Offline Air-Gap Verification
# =====================================================================

def test_aggregator_100_percent_offline_no_sockets(aggregator, normalizer, monkeypatch):
    """Verify aggregator executes 100% offline with zero network sockets."""
    def guarded_socket(*args, **kwargs):
        raise RuntimeError("Air-gap violation: socket call attempted.")

    monkeypatch.setattr(socket, "socket", guarded_socket)

    builder = UniversalEvidenceGraphBuilder(project_id="proj_air")
    env = normalizer.normalize_single({
        "evidence_id": "ev_air", "project_id": "proj_air", "domain": "DATASET_INTEGRITY", "severity": "low", "confidence": 0.50, "dataset_id": "ds_air"
    }, project_id="proj_air")
    builder.add_evidence_envelope(env)
    g = builder.validate_and_build()

    result = aggregator.aggregate_hierarchy(g)
    assert result.hierarchical_hash is not None
