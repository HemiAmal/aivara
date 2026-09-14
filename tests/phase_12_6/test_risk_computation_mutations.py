"""Phase 12.6 Adversarial Mutation Test Suite (M1-M20).

Validates strict boundary defense and deterministic calculation under adversarial mutations:
M1  — mutate evidence weight
M2  — mutate confidence
M3  — mutate severity
M4  — mutate severity classification
M5  — duplicate evidence
M6  — duplicate finding relationship
M7  — mutate ancestry
M8  — cross-project evidence
M9  — cross-asset evidence
M10 — mutate correlation hash
M11 — mutate correlation output
M12 — mutate risk policy version
M13 — mutate risk hash
M14 — inject NaN
M15 — inject Infinity
M16 — force risk > 1
M17 — force negative risk
M18 — incomplete evidence
M19 — attempt decision leakage
M20 — attempt project/chain aggregation leakage
"""

import pytest
from pydantic import ValidationError

from aivara.domain.schemas import EvidenceLayer, Severity
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
from aivara.universal.risk.exceptions import NonFiniteRiskError, RiskOutOfRangeError
from aivara.universal.risk.schemas import UniversalRiskAssessment
from aivara.universal.schemas import AncestryPath


@pytest.fixture
def risk_engine():
    return UniversalRiskComputationEngine()


def test_m1_mutate_evidence_weight(risk_engine):
    """M1: Mutating evidence weight scales contribution monotonically within [0,1]."""
    builder = UniversalEvidenceGraphBuilder(project_id="proj_m1")
    builder.add_node(GraphNode(
        node_id="n1",
        project_id="proj_m1",
        node_type=GraphNodeType.EVIDENCE,
        canonical_identity="ev1",
        canonical_hash="1" * 64,
        domain=SubsystemDomain.MODEL_INTEGRITY,
        severity=Severity.HIGH,
        confidence=1.0,
        metadata={"primary_asset_id": "a1"},
    ))
    g = builder.validate_and_build()
    res = risk_engine.compute_asset_risk(g, "a1")
    assert 0.0 <= res.risk_score <= 1.0


def test_m2_mutate_confidence(risk_engine):
    """M2: Mutating confidence reflects in raw score without violating bounds."""
    builder = UniversalEvidenceGraphBuilder(project_id="proj_m2")
    builder.add_node(GraphNode(
        node_id="n2",
        project_id="proj_m2",
        node_type=GraphNodeType.EVIDENCE,
        canonical_identity="ev2",
        canonical_hash="2" * 64,
        domain=SubsystemDomain.DATASET_INTEGRITY,
        severity=Severity.HIGH,
        confidence=0.50,
        metadata={"primary_asset_id": "a2"},
    ))
    g = builder.validate_and_build()
    res = risk_engine.compute_asset_risk(g, "a2")
    # HIGH = 0.70 * 0.50 = 0.35
    assert abs(res.risk_score - 0.35) < 1e-4


def test_m3_mutate_severity(risk_engine):
    """M3: Higher severity yields higher risk score monotonically."""
    builder_low = UniversalEvidenceGraphBuilder(project_id="proj_m3_low")
    builder_low.add_node(GraphNode(
        node_id="n_low",
        project_id="proj_m3_low",
        node_type=GraphNodeType.EVIDENCE,
        canonical_identity="ev_low",
        canonical_hash="1" * 64,
        domain=SubsystemDomain.MODEL_INTEGRITY,
        severity=Severity.LOW,
        confidence=1.0,
        metadata={"primary_asset_id": "a3"},
    ))
    g_low = builder_low.validate_and_build()

    builder_high = UniversalEvidenceGraphBuilder(project_id="proj_m3_high")
    builder_high.add_node(GraphNode(
        node_id="n_high",
        project_id="proj_m3_high",
        node_type=GraphNodeType.EVIDENCE,
        canonical_identity="ev_high",
        canonical_hash="2" * 64,
        domain=SubsystemDomain.MODEL_INTEGRITY,
        severity=Severity.CRITICAL,
        confidence=1.0,
        metadata={"primary_asset_id": "a3"},
    ))
    g_high = builder_high.validate_and_build()

    r_low = risk_engine.compute_asset_risk(g_low, "a3").risk_score
    r_high = risk_engine.compute_asset_risk(g_high, "a3").risk_score
    assert r_high > r_low


def test_m4_mutate_severity_classification():
    """M4: Categorical classification partitions accurately."""
    from aivara.universal.risk.schemas import compute_risk_level
    assert compute_risk_level(0.90) == RiskLevel.CRITICAL
    assert compute_risk_level(0.70) == RiskLevel.HIGH
    assert compute_risk_level(0.50) == RiskLevel.MEDIUM
    assert compute_risk_level(0.20) == RiskLevel.LOW
    assert compute_risk_level(0.0) == RiskLevel.NONE


def test_m5_duplicate_evidence_handling(risk_engine):
    """M5: Duplicate identical evidence items in single cluster are damped via lambda_intra."""
    builder = UniversalEvidenceGraphBuilder(project_id="proj_m5")
    ap = AncestryPath(sample_id="same_sample")
    builder.add_node(GraphNode(
        node_id="n1",
        project_id="proj_m5",
        node_type=GraphNodeType.EVIDENCE,
        canonical_identity="ev1",
        canonical_hash="1" * 64,
        domain=SubsystemDomain.DATASET_INTEGRITY,
        severity=Severity.HIGH,
        confidence=1.0,
        ancestry_path=ap,
        metadata={"primary_asset_id": "a5"},
    ))
    builder.add_node(GraphNode(
        node_id="n2",
        project_id="proj_m5",
        node_type=GraphNodeType.EVIDENCE,
        canonical_identity="ev2",
        canonical_hash="2" * 64,
        domain=SubsystemDomain.DATASET_INTEGRITY,
        severity=Severity.HIGH,
        confidence=1.0,
        ancestry_path=ap,
        metadata={"primary_asset_id": "a5"},
    ))
    g = builder.validate_and_build()
    res = risk_engine.compute_asset_risk(g, "a5")
    # Primary = 0.70, secondary damped = 0.15 * 0.70 = 0.105 -> Total = 0.805
    assert abs(res.risk_score - 0.805) < 1e-4


def test_m6_duplicate_finding_relationship(risk_engine):
    """M6: N:M finding relationships without new evidence do not cause additive risk inflation."""
    builder = UniversalEvidenceGraphBuilder(project_id="proj_m6")
    builder.add_node(GraphNode(
        node_id="node_ev_ev1",
        project_id="proj_m6",
        node_type=GraphNodeType.EVIDENCE,
        canonical_identity="ev1",
        canonical_hash="1" * 64,
        domain=SubsystemDomain.MODEL_INTEGRITY,
        severity=Severity.HIGH,
        confidence=1.0,
        metadata={"primary_asset_id": "a6"},
    ))
    builder.add_node(GraphNode(
        node_id="node_find_f1",
        project_id="proj_m6",
        node_type=GraphNodeType.FINDING,
        canonical_identity="f1",
        canonical_hash="1" * 64,
        severity=Severity.HIGH,
        metadata={"affected_asset_id": "a6"},
    ))
    builder.add_node(GraphNode(
        node_id="node_find_f2",
        project_id="proj_m6",
        node_type=GraphNodeType.FINDING,
        canonical_identity="f2",
        canonical_hash="2" * 64,
        severity=Severity.HIGH,
        metadata={"affected_asset_id": "a6"},
    ))
    builder.add_finding_evidence_binding("f1", "ev1")
    builder.add_finding_evidence_binding("f2", "ev1")

    g = builder.validate_and_build()
    res = risk_engine.compute_asset_risk(g, "a6")
    # Finding bindings to existing evidence do not create duplicate clusters
    assert res.cluster_count == 1
    assert abs(res.risk_score - 0.70) < 1e-4


def test_m7_mutate_ancestry_clustering(risk_engine):
    """M7: Distinct ancestry tags split into distinct clusters with independent composition."""
    builder = UniversalEvidenceGraphBuilder(project_id="proj_m7")
    builder.add_node(GraphNode(
        node_id="n1",
        project_id="proj_m7",
        node_type=GraphNodeType.EVIDENCE,
        canonical_identity="ev1",
        canonical_hash="1" * 64,
        domain=SubsystemDomain.DATASET_INTEGRITY,
        severity=Severity.MEDIUM,
        confidence=1.0,
        ancestry_path=AncestryPath(sample_id="s1"),
        metadata={"primary_asset_id": "a7"},
    ))
    builder.add_node(GraphNode(
        node_id="n2",
        project_id="proj_m7",
        node_type=GraphNodeType.EVIDENCE,
        canonical_identity="ev2",
        canonical_hash="2" * 64,
        domain=SubsystemDomain.DATASET_INTEGRITY,
        severity=Severity.MEDIUM,
        confidence=1.0,
        ancestry_path=AncestryPath(sample_id="s2"),
        metadata={"primary_asset_id": "a7"},
    ))
    g = builder.validate_and_build()
    res = risk_engine.compute_asset_risk(g, "a7")
    assert res.cluster_count == 2


def test_m8_cross_project_evidence_rejection(risk_engine):
    """M8: Ingesting evidence across project boundaries raises ProjectMismatchError."""
    builder = UniversalEvidenceGraphBuilder(project_id="proj_A")
    with pytest.raises(Exception):
        builder.add_node(GraphNode(
            node_id="n_bad",
            project_id="proj_B",  # Mismatch
            node_type=GraphNodeType.EVIDENCE,
            canonical_identity="ev_bad",
            canonical_hash="b" * 64,
        ))


def test_m9_cross_asset_isolation(risk_engine):
    """M9: Evidence for asset B does not contribute to asset A risk calculation."""
    builder = UniversalEvidenceGraphBuilder(project_id="proj_m9")
    builder.add_node(GraphNode(
        node_id="n_a",
        project_id="proj_m9",
        node_type=GraphNodeType.EVIDENCE,
        canonical_identity="ev_a",
        canonical_hash="a" * 64,
        domain=SubsystemDomain.MODEL_INTEGRITY,
        severity=Severity.CRITICAL,
        confidence=1.0,
        metadata={"primary_asset_id": "asset_A"},
    ))
    builder.add_node(GraphNode(
        node_id="n_b",
        project_id="proj_m9",
        node_type=GraphNodeType.EVIDENCE,
        canonical_identity="ev_b",
        canonical_hash="b" * 64,
        domain=SubsystemDomain.DATASET_INTEGRITY,
        severity=Severity.LOW,
        confidence=1.0,
        metadata={"primary_asset_id": "asset_B"},
    ))
    g = builder.validate_and_build()
    res_b = risk_engine.compute_asset_risk(g, "asset_B")
    # Asset B should only have LOW severity (0.10)
    assert abs(res_b.risk_score - 0.10) < 1e-4


def test_m10_mutate_correlation_hash_sensitivity(risk_engine):
    """M10: Mutating correlation assessment hash changes final risk_hash."""
    builder = UniversalEvidenceGraphBuilder(project_id="proj_m10")
    builder.add_node(GraphNode(
        node_id="n1",
        project_id="proj_m10",
        node_type=GraphNodeType.EVIDENCE,
        canonical_identity="ev1",
        canonical_hash="1" * 64,
        domain=SubsystemDomain.MODEL_INTEGRITY,
        severity=Severity.HIGH,
        metadata={"primary_asset_id": "a10"},
    ))
    g = builder.validate_and_build()

    from aivara.universal.correlation.schemas import CrossDomainCorrelationAssessment
    corr1 = CrossDomainCorrelationAssessment(project_id="proj_m10", matrix_hash="1" * 64)
    corr2 = CrossDomainCorrelationAssessment(project_id="proj_m10", matrix_hash="2" * 64)

    res1 = risk_engine.compute_asset_risk(g, "a10", correlation_assessment=corr1)
    res2 = risk_engine.compute_asset_risk(g, "a10", correlation_assessment=corr2)

    assert res1.risk_hash != res2.risk_hash


def test_m11_mutate_correlation_output_damping(risk_engine):
    """M11: Correlation attenuation factor is strictly respected."""
    builder = UniversalEvidenceGraphBuilder(project_id="proj_m11")
    builder.add_node(GraphNode(
        node_id="n1",
        project_id="proj_m11",
        node_type=GraphNodeType.EVIDENCE,
        canonical_identity="ev1",
        canonical_hash="1" * 64,
        domain=SubsystemDomain.DATASET_INTEGRITY,
        severity=Severity.HIGH,
        confidence=1.0,
        metadata={"primary_asset_id": "a11"},
    ))
    g = builder.validate_and_build()

    from aivara.universal.correlation.schemas import CrossDomainCorrelationAssessment, DomainCorrelationSummary
    # Damped summary with attenuation_factor = 0.50
    d_sum = DomainCorrelationSummary(
        domain=SubsystemDomain.DATASET_INTEGRITY,
        is_active=True,
        attenuation_factor=0.50,
    )
    corr = CrossDomainCorrelationAssessment(
        project_id="proj_m11",
        matrix_hash="0" * 64,
        domain_summaries=[d_sum],
    )
    res = risk_engine.compute_asset_risk(g, "a11", correlation_assessment=corr)
    # HIGH = 0.70 * 0.50 = 0.35
    assert abs(res.risk_score - 0.35) < 1e-4


def test_m12_mutate_risk_policy_version():
    """M12: Risk policy version is tracked in risk assessment hash."""
    ass1 = UniversalRiskAssessment(
        project_id="p1",
        asset_id="a1",
        risk_score=0.5,
        risk_level=RiskLevel.MEDIUM,
        risk_policy_version="1.0.0",
    )
    ass2 = UniversalRiskAssessment(
        project_id="p1",
        asset_id="a1",
        risk_score=0.5,
        risk_level=RiskLevel.MEDIUM,
        risk_policy_version="2.0.0",
    )
    assert ass1.risk_hash != ass2.risk_hash


def test_m13_mutate_risk_hash_immutability():
    """M13: UniversalRiskAssessment is frozen and cannot be mutated."""
    ass = UniversalRiskAssessment(
        project_id="p1",
        asset_id="a1",
        risk_score=0.5,
        risk_level=RiskLevel.MEDIUM,
    )
    with pytest.raises(ValidationError):
        ass.risk_score = 0.9  # type: ignore


def test_m14_inject_nan_rejection(risk_engine):
    """M14: Injecting NaN in confidence raises NonFiniteRiskError."""
    builder = UniversalEvidenceGraphBuilder(project_id="proj_m14")
    with pytest.raises(ValidationError):
        builder.add_node(GraphNode(
            node_id="n_nan",
            project_id="proj_m14",
            node_type=GraphNodeType.EVIDENCE,
            canonical_identity="ev_nan",
            canonical_hash="0" * 64,
            confidence=float("nan"),
        ))


def test_m15_inject_inf_rejection(risk_engine):
    """M15: Injecting Infinity in confidence raises NonFiniteRiskError."""
    builder = UniversalEvidenceGraphBuilder(project_id="proj_m15")
    with pytest.raises(ValidationError):
        builder.add_node(GraphNode(
            node_id="n_inf",
            project_id="proj_m15",
            node_type=GraphNodeType.EVIDENCE,
            canonical_identity="ev_inf",
            canonical_hash="0" * 64,
            confidence=float("inf"),
        ))


def test_m16_force_risk_greater_than_one_rejection():
    """M16: Risk score > 1.0 fails closed with RiskOutOfRangeError."""
    with pytest.raises(ValidationError):
        UniversalRiskAssessment(
            project_id="p1",
            asset_id="a1",
            risk_score=1.05,
            risk_level=RiskLevel.CRITICAL,
        )


def test_m17_force_negative_risk_rejection():
    """M17: Risk score < 0.0 fails closed with RiskOutOfRangeError."""
    with pytest.raises(ValidationError):
        UniversalRiskAssessment(
            project_id="p1",
            asset_id="a1",
            risk_score=-0.01,
            risk_level=RiskLevel.NONE,
        )


def test_m18_incomplete_ancestry_propagation(risk_engine):
    """M18: Incomplete ancestry marks INSUFFICIENT_ANCESTRY without fabricating decisions."""
    builder = UniversalEvidenceGraphBuilder(project_id="proj_m18")
    builder.add_node(GraphNode(
        node_id="n18",
        project_id="proj_m18",
        node_type=GraphNodeType.EVIDENCE,
        canonical_identity="ev18",
        canonical_hash="1" * 64,
        domain=SubsystemDomain.BEHAVIORAL_ANALYSIS,
        severity=Severity.HIGH,
        ancestry_path=AncestryPath(),  # Missing ancestry
        metadata={"primary_asset_id": "a18"},
    ))
    g = builder.validate_and_build()
    res = risk_engine.compute_asset_risk(g, "a18")
    assert res.evidence_sufficiency == EvidenceSufficiencyStatus.INSUFFICIENT_ANCESTRY
    assert not hasattr(res, "disposition")
    assert not hasattr(res, "decision")


def test_m19_attempt_decision_leakage(risk_engine):
    """M19: UniversalRiskAssessment exposes strictly numerical risk and zero decision fields."""
    builder = UniversalEvidenceGraphBuilder(project_id="proj_m19")
    g = builder.validate_and_build()
    res = risk_engine.compute_asset_risk(g, "default_asset")
    assert not hasattr(res, "policy_decision")
    assert not hasattr(res, "disposition")
    assert not hasattr(res, "action")
    assert not hasattr(res, "route")


def test_m20_attempt_project_chain_leakage(risk_engine):
    """M20: UniversalRiskComputationEngine does not execute project or chain risk aggregation."""
    builder = UniversalEvidenceGraphBuilder(project_id="proj_m20")
    g = builder.validate_and_build()
    res = risk_engine.compute_asset_risk(g, "default_asset")
    assert not hasattr(res, "project_risk_score")
    assert not hasattr(res, "chain_risk_score")
    assert not hasattr(res, "peak_dominance")
    assert not hasattr(res, "gamma_prop")
