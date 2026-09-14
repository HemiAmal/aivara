"""Unit and behavior tests for Cross-Domain Dependency Damping (Phase 12.5)."""

import pytest

from aivara.domain.schemas import EvidenceLayer, Severity
from aivara.universal.enums import SubsystemDomain
from aivara.universal.exceptions import ProjectMismatchError
from aivara.universal.graph import (
    GraphNode,
    GraphNodeType,
    UniversalEvidenceGraphBuilder,
)
from aivara.universal.risk import HierarchicalRiskAggregator
from aivara.universal.correlation import (
    CorrelationMatrix,
    CorrelationStatus,
    CrossDomainCorrelationEngine,
)


@pytest.fixture
def risk_aggregator():
    return HierarchicalRiskAggregator()


@pytest.fixture
def correlation_engine():
    return CrossDomainCorrelationEngine()


def test_zero_correlation_no_damping(risk_aggregator, correlation_engine):
    """Zero correlation matrix yields 1.0 attenuation factors across all domains."""
    builder = UniversalEvidenceGraphBuilder(project_id="proj_zero_corr")
    
    # Dataset node (high severity)
    builder.add_node(GraphNode(
        node_id="node_ev_ds",
        project_id="proj_zero_corr",
        node_type=GraphNodeType.EVIDENCE,
        canonical_identity="ev_ds",
        canonical_hash="1" * 64,
        domain=SubsystemDomain.DATASET_INTEGRITY,
        severity=Severity.HIGH,
        confidence=0.90,
        metadata={"primary_asset_id": "ds_1"},
    ))
    
    # Model node (critical severity)
    builder.add_node(GraphNode(
        node_id="node_ev_model",
        project_id="proj_zero_corr",
        node_type=GraphNodeType.EVIDENCE,
        canonical_identity="ev_model",
        canonical_hash="2" * 64,
        domain=SubsystemDomain.MODEL_INTEGRITY,
        severity=Severity.CRITICAL,
        confidence=0.95,
        metadata={"primary_asset_id": "model_1"},
    ))

    g = builder.validate_and_build()
    hier_risk = risk_aggregator.aggregate_hierarchy(g)

    zero_mat = CorrelationMatrix.create_zero_matrix()
    corr_res = correlation_engine.evaluate_cross_domain_correlation(
        hierarchical_assessment=hier_risk,
        graph=g,
        matrix=zero_mat,
    )

    assert corr_res.status == CorrelationStatus.VALID
    assert corr_res.overall_attenuation_factor == 1.0
    for summary in corr_res.domain_summaries:
        assert summary.attenuation_factor == 1.0


def test_inactive_domains_exert_zero_damping(risk_aggregator, correlation_engine):
    """Inactive domains (0 evidence) exert zero damping on active domains."""
    builder = UniversalEvidenceGraphBuilder(project_id="proj_inactive_domain")
    
    # Only DATASET_INTEGRITY is active
    builder.add_node(GraphNode(
        node_id="node_ev_ds",
        project_id="proj_inactive_domain",
        node_type=GraphNodeType.EVIDENCE,
        canonical_identity="ev_ds",
        canonical_hash="1" * 64,
        domain=SubsystemDomain.DATASET_INTEGRITY,
        severity=Severity.HIGH,
        confidence=0.90,
        metadata={"primary_asset_id": "ds_1"},
    ))

    g = builder.validate_and_build()
    hier_risk = risk_aggregator.aggregate_hierarchy(g)

    default_mat = CorrelationMatrix.create_default_canonical_matrix()
    corr_res = correlation_engine.evaluate_cross_domain_correlation(
        hierarchical_assessment=hier_risk,
        graph=g,
        matrix=default_mat,
    )

    ds_summary = next(s for s in corr_res.domain_summaries if s.domain == SubsystemDomain.DATASET_INTEGRITY)
    assert ds_summary.is_active is True
    # Since all other 6 domains are inactive, attenuation factor must remain 1.0
    assert ds_summary.attenuation_factor == 1.0


def test_cross_domain_attenuation_calculation(risk_aggregator, correlation_engine):
    """Active correlated domains dampen each other according to C_ij * S_bar_i."""
    builder = UniversalEvidenceGraphBuilder(project_id="proj_active_corr")
    
    # 1. Dataset evidence (Severity HIGH = 0.70, Conf = 1.0 -> S_bar = 0.70)
    builder.add_node(GraphNode(
        node_id="node_ev_ds",
        project_id="proj_active_corr",
        node_type=GraphNodeType.EVIDENCE,
        canonical_identity="ev_ds",
        canonical_hash="1" * 64,
        domain=SubsystemDomain.DATASET_INTEGRITY,
        severity=Severity.HIGH,
        confidence=1.0,
        metadata={"primary_asset_id": "ds_1"},
    ))

    # 2. Backdoor evidence (Severity CRITICAL = 1.0, Conf = 1.0 -> S_bar = 1.0)
    builder.add_node(GraphNode(
        node_id="node_ev_bd",
        project_id="proj_active_corr",
        node_type=GraphNodeType.EVIDENCE,
        canonical_identity="ev_bd",
        canonical_hash="2" * 64,
        domain=SubsystemDomain.BACKDOOR_TRIGGER,
        severity=Severity.CRITICAL,
        confidence=1.0,
        metadata={"primary_asset_id": "model_1"},
    ))

    g = builder.validate_and_build()
    hier_risk = risk_aggregator.aggregate_hierarchy(g)

    mat = CorrelationMatrix.create_default_canonical_matrix()
    corr_coeff = mat.get_correlation(SubsystemDomain.DATASET_INTEGRITY, SubsystemDomain.BACKDOOR_TRIGGER)
    assert corr_coeff == 0.40

    corr_res = correlation_engine.evaluate_cross_domain_correlation(
        hierarchical_assessment=hier_risk,
        graph=g,
        matrix=mat,
    )

    assert corr_res.status == CorrelationStatus.ATTENUATED
    
    ds_summary = next(s for s in corr_res.domain_summaries if s.domain == SubsystemDomain.DATASET_INTEGRITY)
    bd_summary = next(s for s in corr_res.domain_summaries if s.domain == SubsystemDomain.BACKDOOR_TRIGGER)

    # Dataset attenuated by Backdoor: 1.0 - (0.40 * 1.0) = 0.60
    assert abs(ds_summary.attenuation_factor - 0.60) < 1e-4

    # Backdoor attenuated by Dataset: 1.0 - (0.40 * 0.70) = 0.72
    assert abs(bd_summary.attenuation_factor - 0.72) < 1e-4

    # Trace records generated
    assert len(corr_res.traces) == 2


def test_reject_cross_project_mismatch(risk_aggregator, correlation_engine):
    """Reject evaluation when assessment project_id does not match graph project_id."""
    builder = UniversalEvidenceGraphBuilder(project_id="proj_A")
    builder.add_node(GraphNode(
        node_id="node_1",
        project_id="proj_A",
        node_type=GraphNodeType.EVIDENCE,
        canonical_identity="ev_1",
        canonical_hash="1" * 64,
        domain=SubsystemDomain.MODEL_INTEGRITY,
        severity=Severity.HIGH,
        confidence=1.0,
        metadata={"primary_asset_id": "m1"},
    ))
    g = builder.validate_and_build()
    hier_risk = risk_aggregator.aggregate_hierarchy(g)

    # Foreign graph
    builder_b = UniversalEvidenceGraphBuilder(project_id="proj_B")
    builder_b.add_node(GraphNode(
        node_id="node_2",
        project_id="proj_B",
        node_type=GraphNodeType.EVIDENCE,
        canonical_identity="ev_2",
        canonical_hash="2" * 64,
        domain=SubsystemDomain.MODEL_INTEGRITY,
        severity=Severity.HIGH,
        confidence=1.0,
        metadata={"primary_asset_id": "m1"},
    ))
    g_b = builder_b.validate_and_build()

    with pytest.raises(ProjectMismatchError):
        correlation_engine.evaluate_cross_domain_correlation(
            hierarchical_assessment=hier_risk,
            graph=g_b,
        )


def test_proof_inviolability_unattenuated_no_decision_leakage(risk_aggregator, correlation_engine):
    """Confirm REQ-12-COR-005: Proof-layer evidence is handled without decision leakage (no REJECT/ACCEPT/override)."""
    builder = UniversalEvidenceGraphBuilder(project_id="proj_proof_inv")
    
    # Proof-layer evidence on Model Integrity (binary proof invariant, e.g. cryptographic weight hash)
    builder.add_node(GraphNode(
        node_id="node_ev_proof",
        project_id="proj_proof_inv",
        node_type=GraphNodeType.EVIDENCE,
        canonical_identity="ev_proof",
        canonical_hash="p" * 64,
        domain=SubsystemDomain.MODEL_INTEGRITY,
        evidence_layer=EvidenceLayer.PROOF,
        severity=Severity.CRITICAL,
        confidence=1.0,
        metadata={"primary_asset_id": "model_proof"},
    ))

    # Detection-layer evidence on Dataset Integrity
    builder.add_node(GraphNode(
        node_id="node_ev_det",
        project_id="proj_proof_inv",
        node_type=GraphNodeType.EVIDENCE,
        canonical_identity="ev_det",
        canonical_hash="d" * 64,
        domain=SubsystemDomain.DATASET_INTEGRITY,
        evidence_layer=EvidenceLayer.DETECTION,
        severity=Severity.HIGH,
        confidence=0.90,
        metadata={"primary_asset_id": "ds_proof"},
    ))

    g = builder.validate_and_build()
    hier_risk = risk_aggregator.aggregate_hierarchy(g)

    mat = CorrelationMatrix.create_default_canonical_matrix()
    corr_res = correlation_engine.evaluate_cross_domain_correlation(
        hierarchical_assessment=hier_risk,
        graph=g,
        matrix=mat,
    )

    assert corr_res.status in (CorrelationStatus.ATTENUATED, CorrelationStatus.VALID)
    
    # Crucial Phase 12.5 Boundary Invariant:
    # Phase 12.5 computes analytical correlation metrics only.
    # It does NOT apply Phase 12.6 proof overrides (R=1.0 -> REJECT) or Phase 12.8 policy dispositions.
    assert not hasattr(corr_res, "disposition")
    assert not hasattr(corr_res, "decision")
    assert not hasattr(corr_res, "proof_override")

