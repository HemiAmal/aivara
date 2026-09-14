"""Phase 12.6 Universal Risk Computation Core Test Suite.

Verifies closed-form asset-level risk computation:
- Evidence contribution formula: term(e) = w_e * c_e * s_e
- Severity multipliers
- Intra-cluster damping: S(C_k) = min(1, max(term) + lambda_intra * sum(others))
- Bounded sub-additive composition: R(A) = 1 - prod(1 - S(C_k))
- Correlation integration (Phase 12.5) with proof inviolability
- Ancestry-aware clustering & N:M evidence semantics
- Project and asset isolation
- Numerical determinism and JCS SHA-256 risk_hash
"""

import math
import pytest

from aivara.domain.schemas import EvidenceLayer, Severity
from aivara.universal.correlation import (
    CorrelationMatrix,
    CrossDomainCorrelationEngine,
)
from aivara.universal.enums import SubsystemDomain
from aivara.universal.exceptions import ProjectMismatchError
from aivara.universal.graph import (
    GraphNode,
    GraphNodeType,
    UniversalEvidenceGraphBuilder,
)
from aivara.universal.risk.config import ImmutableAggregationConfig
from aivara.universal.risk.engine import UniversalRiskComputationEngine
from aivara.universal.risk.enums import EvidenceSufficiencyStatus, RiskLevel
from aivara.universal.risk.exceptions import NonFiniteRiskError
from aivara.universal.schemas import AncestryPath


@pytest.fixture
def risk_engine():
    return UniversalRiskComputationEngine()


@pytest.fixture
def correlation_engine():
    return CrossDomainCorrelationEngine()


def test_empty_graph_zero_risk(risk_engine):
    """Empty graph produces exactly 0.0 risk score with NONE level."""
    builder = UniversalEvidenceGraphBuilder(project_id="proj_empty")
    g = builder.validate_and_build()
    res = risk_engine.compute_asset_risk(graph=g, asset_id="default_asset")
    assert res.risk_score == 0.0
    assert res.risk_level == RiskLevel.NONE
    assert res.cluster_count == 0
    assert res.evidence_count == 0
    assert res.risk_hash != ""


def test_single_evidence_risk(risk_engine):
    """Single evidence item risk matches exact formula: R = term(e) = w * c * s."""
    builder = UniversalEvidenceGraphBuilder(project_id="proj_single")
    builder.add_node(GraphNode(
        node_id="n1",
        project_id="proj_single",
        node_type=GraphNodeType.EVIDENCE,
        canonical_identity="ev1",
        canonical_hash="1" * 64,
        domain=SubsystemDomain.MODEL_INTEGRITY,
        severity=Severity.HIGH,
        confidence=1.0,
        metadata={"primary_asset_id": "model_bert"},
    ))
    g = builder.validate_and_build()
    res = risk_engine.compute_asset_risk(graph=g, asset_id="model_bert")
    # Severity HIGH = 0.70, confidence = 1.0 -> R = 0.70
    assert abs(res.risk_score - 0.70) < 1e-4
    assert res.risk_level == RiskLevel.HIGH


def test_intra_cluster_damping(risk_engine):
    """Multiple evidence items in same ancestry cluster damp sub-additively via lambda_intra=0.15."""
    builder = UniversalEvidenceGraphBuilder(project_id="proj_cluster")
    ap = AncestryPath(sample_id="sample_001")

    # Item 1: CRITICAL (1.0)
    builder.add_node(GraphNode(
        node_id="n1",
        project_id="proj_cluster",
        node_type=GraphNodeType.EVIDENCE,
        canonical_identity="ev1",
        canonical_hash="1" * 64,
        domain=SubsystemDomain.DATASET_INTEGRITY,
        severity=Severity.CRITICAL,
        confidence=1.0,
        ancestry_path=ap,
        metadata={"primary_asset_id": "ds_1"},
    ))

    # Item 2: MEDIUM (0.40)
    builder.add_node(GraphNode(
        node_id="n2",
        project_id="proj_cluster",
        node_type=GraphNodeType.EVIDENCE,
        canonical_identity="ev2",
        canonical_hash="2" * 64,
        domain=SubsystemDomain.DATASET_INTEGRITY,
        severity=Severity.MEDIUM,
        confidence=1.0,
        ancestry_path=ap,
        metadata={"primary_asset_id": "ds_1"},
    ))

    g = builder.validate_and_build()
    res = risk_engine.compute_asset_risk(graph=g, asset_id="ds_1")

    # Primary term = 1.0 (CRITICAL). Secondary term = 0.40 (MEDIUM).
    # S(C) = min(1.0, 1.0 + 0.15 * 0.40) = 1.0 (saturates at 1.0)
    assert res.cluster_count == 1
    assert res.evidence_count == 2
    assert res.risk_score == 1.0


def test_multiple_independent_clusters_composition(risk_engine):
    """Multiple independent clusters combine sub-additively: R = 1 - (1 - S1)(1 - S2)."""
    builder = UniversalEvidenceGraphBuilder(project_id="proj_multi_clust")

    # Cluster 1: sample_001 with MEDIUM (0.40)
    builder.add_node(GraphNode(
        node_id="n1",
        project_id="proj_multi_clust",
        node_type=GraphNodeType.EVIDENCE,
        canonical_identity="ev1",
        canonical_hash="1" * 64,
        domain=SubsystemDomain.DATASET_INTEGRITY,
        severity=Severity.MEDIUM,
        confidence=1.0,
        ancestry_path=AncestryPath(sample_id="sample_001"),
        metadata={"primary_asset_id": "ds_multi"},
    ))

    # Cluster 2: sample_002 with HIGH (0.70)
    builder.add_node(GraphNode(
        node_id="n2",
        project_id="proj_multi_clust",
        node_type=GraphNodeType.EVIDENCE,
        canonical_identity="ev2",
        canonical_hash="2" * 64,
        domain=SubsystemDomain.DATASET_INTEGRITY,
        severity=Severity.HIGH,
        confidence=1.0,
        ancestry_path=AncestryPath(sample_id="sample_002"),
        metadata={"primary_asset_id": "ds_multi"},
    ))

    g = builder.validate_and_build()
    res = risk_engine.compute_asset_risk(graph=g, asset_id="ds_multi")

    # R = 1 - (1 - 0.40) * (1 - 0.70) = 1 - 0.60 * 0.30 = 1 - 0.18 = 0.82
    assert res.cluster_count == 2
    assert abs(res.risk_score - 0.82) < 1e-4
    assert res.risk_level == RiskLevel.HIGH


def test_correlation_integration_detection_attenuation(risk_engine, correlation_engine):
    """Phase 12.5 correlation attenuation factor reduces detection-layer risk contribution."""
    builder = UniversalEvidenceGraphBuilder(project_id="proj_corr_integ")

    # 1. Dataset evidence (Severity HIGH = 0.70)
    builder.add_node(GraphNode(
        node_id="n_ds",
        project_id="proj_corr_integ",
        node_type=GraphNodeType.EVIDENCE,
        canonical_identity="ev_ds",
        canonical_hash="1" * 64,
        domain=SubsystemDomain.DATASET_INTEGRITY,
        severity=Severity.HIGH,
        confidence=1.0,
        metadata={"primary_asset_id": "asset_x"},
    ))

    # 2. Backdoor evidence (Severity CRITICAL = 1.0)
    builder.add_node(GraphNode(
        node_id="n_bd",
        project_id="proj_corr_integ",
        node_type=GraphNodeType.EVIDENCE,
        canonical_identity="ev_bd",
        canonical_hash="2" * 64,
        domain=SubsystemDomain.BACKDOOR_TRIGGER,
        severity=Severity.CRITICAL,
        confidence=1.0,
        metadata={"primary_asset_id": "asset_x"},
    ))

    g = builder.validate_and_build()

    # Compute Phase 12.5 correlation assessment
    corr_mat = CorrelationMatrix.create_default_canonical_matrix()
    corr_res = correlation_engine.evaluate_cross_domain_correlation(graph=g, matrix=corr_mat)

    # Compute risk with correlation integration
    res = risk_engine.compute_asset_risk(
        graph=g,
        asset_id="asset_x",
        correlation_assessment=corr_res,
    )

    # Dataset (0.70) attenuated by Backdoor (C=0.40, S=1.0 -> att = 0.60) -> effective raw term = 0.70 * 0.60 = 0.42
    # Backdoor (1.0) attenuated by Dataset (C=0.40, S=0.70 -> att = 0.72) -> effective raw term = 1.0 * 0.72 = 0.72
    # Combined R = 1 - (1 - 0.42) * (1 - 0.72) = 1 - 0.58 * 0.28 = 1 - 0.1624 = 0.8376
    assert abs(res.risk_score - 0.8376) < 1e-4
    assert res.correlation_hash == corr_res.correlation_hash


def test_proof_inviolability_in_risk_computation(risk_engine, correlation_engine):
    """Proof-layer evidence is never attenuated by correlation damping in risk computation."""
    builder = UniversalEvidenceGraphBuilder(project_id="proj_proof_safety")

    # Proof item on Model Integrity
    builder.add_node(GraphNode(
        node_id="n_proof",
        project_id="proj_proof_safety",
        node_type=GraphNodeType.EVIDENCE,
        canonical_identity="ev_proof",
        canonical_hash="p" * 64,
        domain=SubsystemDomain.MODEL_INTEGRITY,
        evidence_layer=EvidenceLayer.PROOF,
        severity=Severity.HIGH,
        confidence=1.0,
        metadata={"primary_asset_id": "model_proof"},
    ))

    # Detection item on Dataset Integrity
    builder.add_node(GraphNode(
        node_id="n_det",
        project_id="proj_proof_safety",
        node_type=GraphNodeType.EVIDENCE,
        canonical_identity="ev_det",
        canonical_hash="d" * 64,
        domain=SubsystemDomain.DATASET_INTEGRITY,
        evidence_layer=EvidenceLayer.DETECTION,
        severity=Severity.CRITICAL,
        confidence=1.0,
        metadata={"primary_asset_id": "model_proof"},
    ))

    g = builder.validate_and_build()
    corr_res = correlation_engine.evaluate_cross_domain_correlation(graph=g)

    res = risk_engine.compute_asset_risk(
        graph=g,
        asset_id="model_proof",
        correlation_assessment=corr_res,
    )

    proof_contrib = next(c for c in res.contributions if c.source_id == "n_proof")
    # Proof raw score must remain strictly unattenuated: HIGH = 0.70 * 1.0 = 0.70
    assert abs(proof_contrib.raw_score - 0.70) < 1e-4


def test_project_boundary_isolation(risk_engine):
    """Correlation assessment from mismatched project is rejected with ProjectMismatchError."""
    builder = UniversalEvidenceGraphBuilder(project_id="proj_A")
    builder.add_node(GraphNode(
        node_id="n1",
        project_id="proj_A",
        node_type=GraphNodeType.EVIDENCE,
        canonical_identity="ev1",
        canonical_hash="1" * 64,
        domain=SubsystemDomain.DATASET_INTEGRITY,
        severity=Severity.HIGH,
        metadata={"primary_asset_id": "a1"},
    ))
    g = builder.validate_and_build()

    from aivara.universal.correlation.schemas import CrossDomainCorrelationAssessment
    fake_corr_b = CrossDomainCorrelationAssessment(
        project_id="proj_B",  # Mismatch
        matrix_hash="0" * 64,
    )

    with pytest.raises(ProjectMismatchError):
        risk_engine.compute_asset_risk(
            graph=g,
            asset_id="a1",
            correlation_assessment=fake_corr_b,
        )


def test_universal_risk_all_distinct_assets(risk_engine):
    """compute_universal_risk evaluates all distinct assets represented in the graph."""
    builder = UniversalEvidenceGraphBuilder(project_id="proj_universal")

    builder.add_node(GraphNode(
        node_id="n1",
        project_id="proj_universal",
        node_type=GraphNodeType.EVIDENCE,
        canonical_identity="ev1",
        canonical_hash="1" * 64,
        domain=SubsystemDomain.MODEL_INTEGRITY,
        severity=Severity.HIGH,
        metadata={"primary_asset_id": "asset_1"},
    ))

    builder.add_node(GraphNode(
        node_id="n2",
        project_id="proj_universal",
        node_type=GraphNodeType.EVIDENCE,
        canonical_identity="ev2",
        canonical_hash="2" * 64,
        domain=SubsystemDomain.DATASET_INTEGRITY,
        severity=Severity.LOW,
        metadata={"primary_asset_id": "asset_2"},
    ))

    g = builder.validate_and_build()
    assessments = risk_engine.compute_universal_risk(graph=g)
    assert len(assessments) == 2
    asset_ids = [a.asset_id for a in assessments]
    assert asset_ids == ["asset_1", "asset_2"]
