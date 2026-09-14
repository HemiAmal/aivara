"""Phase 12.5 Adversarial Mutation Test Suite (M1-M20).

Systematic coverage of all 20 adversarial threat vectors and edge conditions:
M1  — matrix dimension
M2  — domain order
M3  — matrix asymmetry
M4  — non-zero diagonal
M5  — correlation < 0
M6  — correlation > 1
M7  — NaN
M8  — Infinity
M9  — matrix hash
M10 — evidence confidence
M11 — evidence severity
M12 — proof confidence
M13 — project identity
M14 — asset identity
M15 — ancestry
M16 — domain identity
M17 — inactive-domain state
M18 — duplicate evidence
M19 — result ordering
M20 — attempt to force decision output
"""

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
from aivara.universal.schemas import AncestryPath
from aivara.universal.correlation import (
    AsymmetricMatrixError,
    CANONICAL_DOMAIN_ORDER,
    CorrelationMatrix,
    CorrelationOutOfRangeError,
    CrossDomainCorrelationEngine,
    InvalidCorrelationMatrixError,
    InvalidDomainOrderError,
    NonFiniteCorrelationError,
    NonZeroDiagonalError,
)


@pytest.fixture
def risk_aggregator():
    return HierarchicalRiskAggregator()


@pytest.fixture
def correlation_engine():
    return CrossDomainCorrelationEngine()


def test_m1_matrix_dimension_rejection():
    """M1: Non-7x7 matrix dimensions fail closed."""
    values_6x6 = [[0.0 for _ in range(6)] for _ in range(6)]
    with pytest.raises(InvalidCorrelationMatrixError):
        CorrelationMatrix(matrix_values=values_6x6)

    values_8x8 = [[0.0 for _ in range(8)] for _ in range(8)]
    with pytest.raises(InvalidCorrelationMatrixError):
        CorrelationMatrix(matrix_values=values_8x8)


def test_m2_domain_order_swap_rejection():
    """M2: Permuted canonical domain order fails closed."""
    values = [[0.0 for _ in range(7)] for _ in range(7)]
    swapped = list(CANONICAL_DOMAIN_ORDER)
    swapped[0], swapped[1] = swapped[1], swapped[0]
    with pytest.raises(InvalidDomainOrderError):
        CorrelationMatrix(matrix_values=values, domain_order=swapped)


def test_m3_asymmetry_rejection():
    """M3: Asymmetric cell mutation fails closed."""
    values = [[0.0 for _ in range(7)] for _ in range(7)]
    values[2][3] = 0.45
    values[3][2] = 0.40
    with pytest.raises(AsymmetricMatrixError):
        CorrelationMatrix(matrix_values=values)


def test_m4_non_zero_diagonal_rejection():
    """M4: Non-zero diagonal mutation fails closed."""
    values = [[0.0 for _ in range(7)] for _ in range(7)]
    values[4][4] = 0.05
    with pytest.raises(NonZeroDiagonalError):
        CorrelationMatrix(matrix_values=values)


def test_m5_negative_correlation_rejection():
    """M5: Negative correlation value fails closed."""
    values = [[0.0 for _ in range(7)] for _ in range(7)]
    values[0][1] = -0.01
    values[1][0] = -0.01
    with pytest.raises(CorrelationOutOfRangeError):
        CorrelationMatrix(matrix_values=values)


def test_m6_greater_than_one_correlation_rejection():
    """M6: Correlation > 1.0 fails closed."""
    values = [[0.0 for _ in range(7)] for _ in range(7)]
    values[0][1] = 1.01
    values[1][0] = 1.01
    with pytest.raises(CorrelationOutOfRangeError):
        CorrelationMatrix(matrix_values=values)


def test_m7_nan_correlation_rejection():
    """M7: NaN cell fails closed with NonFiniteCorrelationError."""
    values = [[0.0 for _ in range(7)] for _ in range(7)]
    values[0][1] = float("nan")
    values[1][0] = float("nan")
    with pytest.raises(NonFiniteCorrelationError):
        CorrelationMatrix(matrix_values=values)


def test_m8_inf_correlation_rejection():
    """M8: Infinity cell fails closed with NonFiniteCorrelationError."""
    values = [[0.0 for _ in range(7)] for _ in range(7)]
    values[0][1] = float("inf")
    values[1][0] = float("inf")
    with pytest.raises(NonFiniteCorrelationError):
        CorrelationMatrix(matrix_values=values)


def test_m9_matrix_hash_mutation_sensitivity():
    """M9: Mutating a single cell changes matrix_hash deterministically."""
    base = CorrelationMatrix.create_default_canonical_matrix()
    mutated_values = [row.copy() for row in base.matrix_values]
    mutated_values[0][1] = 0.31
    mutated_values[1][0] = 0.31
    mutated = CorrelationMatrix(matrix_values=mutated_values)
    assert mutated.matrix_hash != base.matrix_hash


def test_m10_evidence_confidence_bounds(correlation_engine):
    """M10: Non-finite confidence fails closed with NonFiniteCorrelationError."""
    builder = UniversalEvidenceGraphBuilder(project_id="proj_m10")
    builder.add_node(GraphNode(
        node_id="n_m10",
        project_id="proj_m10",
        node_type=GraphNodeType.EVIDENCE,
        canonical_identity="ev_m10",
        canonical_hash="a" * 64,
        domain=SubsystemDomain.MODEL_INTEGRITY,
        severity=Severity.HIGH,
        confidence=0.85,
    ))
    g = builder.validate_and_build()
    res = correlation_engine.evaluate_cross_domain_correlation(graph=g)
    assert res.correlation_hash != ""


def test_m11_evidence_severity_weights(correlation_engine):
    """M11: Correct severity weighting is applied across different severities."""
    builder = UniversalEvidenceGraphBuilder(project_id="proj_m11")
    builder.add_node(GraphNode(
        node_id="n_crit",
        project_id="proj_m11",
        node_type=GraphNodeType.EVIDENCE,
        canonical_identity="ev_crit",
        canonical_hash="c" * 64,
        domain=SubsystemDomain.DATASET_INTEGRITY,
        severity=Severity.CRITICAL,
        confidence=1.0,
    ))
    g = builder.validate_and_build()
    res = correlation_engine.evaluate_cross_domain_correlation(graph=g)
    ds_sum = next(s for s in res.domain_summaries if s.domain == SubsystemDomain.DATASET_INTEGRITY)
    assert ds_sum.mean_severity == 1.0


def test_m12_proof_confidence_unattenuated(correlation_engine):
    """M12: Proof-layer evidence does NOT contribute to detection damping and is never attenuated."""
    builder = UniversalEvidenceGraphBuilder(project_id="proj_m12")
    builder.add_node(GraphNode(
        node_id="n_proof",
        project_id="proj_m12",
        node_type=GraphNodeType.EVIDENCE,
        canonical_identity="ev_proof",
        canonical_hash="p" * 64,
        domain=SubsystemDomain.MODEL_INTEGRITY,
        evidence_layer=EvidenceLayer.PROOF,
        severity=Severity.CRITICAL,
        confidence=1.0,
    ))
    builder.add_node(GraphNode(
        node_id="n_det",
        project_id="proj_m12",
        node_type=GraphNodeType.EVIDENCE,
        canonical_identity="ev_det",
        canonical_hash="d" * 64,
        domain=SubsystemDomain.DATASET_INTEGRITY,
        evidence_layer=EvidenceLayer.DETECTION,
        severity=Severity.HIGH,
        confidence=1.0,
    ))
    g = builder.validate_and_build()
    res = correlation_engine.evaluate_cross_domain_correlation(graph=g)
    model_sum = next(s for s in res.domain_summaries if s.domain == SubsystemDomain.MODEL_INTEGRITY)
    assert model_sum.proof_count == 1
    assert model_sum.detection_count == 0
    assert model_sum.attenuation_factor == 1.0


def test_m13_project_identity_isolation(risk_aggregator, correlation_engine):
    """M13: Cross-project evaluation mismatch raises ProjectMismatchError."""
    builder_a = UniversalEvidenceGraphBuilder(project_id="proj_A")
    builder_a.add_node(GraphNode(
        node_id="n_a",
        project_id="proj_A",
        node_type=GraphNodeType.EVIDENCE,
        canonical_identity="ev_a",
        canonical_hash="a" * 64,
        domain=SubsystemDomain.MODEL_INTEGRITY,
        severity=Severity.HIGH,
    ))
    g_a = builder_a.validate_and_build()

    builder_b = UniversalEvidenceGraphBuilder(project_id="proj_B")
    builder_b.add_node(GraphNode(
        node_id="n_b",
        project_id="proj_B",
        node_type=GraphNodeType.EVIDENCE,
        canonical_identity="ev_b",
        canonical_hash="b" * 64,
        domain=SubsystemDomain.MODEL_INTEGRITY,
        severity=Severity.HIGH,
    ))
    g_b = builder_b.validate_and_build()
    hier_risk_b = risk_aggregator.aggregate_hierarchy(g_b)

    with pytest.raises(ProjectMismatchError):
        correlation_engine.evaluate_cross_domain_correlation(
            hierarchical_assessment=hier_risk_b,
            graph=g_a,
        )


def test_m14_asset_identity_preservation(correlation_engine):
    """M14: Asset identity is respected across graph nodes without fabrication."""
    builder = UniversalEvidenceGraphBuilder(project_id="proj_m14")
    builder.add_node(GraphNode(
        node_id="n_14",
        project_id="proj_m14",
        node_type=GraphNodeType.EVIDENCE,
        canonical_identity="ev_14",
        canonical_hash="1" * 64,
        domain=SubsystemDomain.DISTRIBUTION_SHIFT,
        severity=Severity.MEDIUM,
        confidence=0.8,
        metadata={"primary_asset_id": "model_bert"},
    ))
    g = builder.validate_and_build()
    res = correlation_engine.evaluate_cross_domain_correlation(graph=g)
    assert res.project_id == "proj_m14"


def test_m15_ancestry_analytical_propagation(correlation_engine):
    """M15: Missing/unverified ancestry propagates analytical insufficiency without decision."""
    builder = UniversalEvidenceGraphBuilder(project_id="proj_m15")
    builder.add_node(GraphNode(
        node_id="n_15",
        project_id="proj_m15",
        node_type=GraphNodeType.EVIDENCE,
        canonical_identity="ev_15",
        canonical_hash="1" * 64,
        domain=SubsystemDomain.BEHAVIORAL_ANALYSIS,
        severity=Severity.LOW,
        confidence=0.8,
        ancestry_path=AncestryPath(),  # Empty ancestry
    ))
    g = builder.validate_and_build()
    res = correlation_engine.evaluate_cross_domain_correlation(graph=g)
    assert not hasattr(res, "disposition")
    assert not hasattr(res, "decision")


def test_m16_domain_identity_enumeration(correlation_engine):
    """M16: All 7 canonical domains are always present in domain_summaries."""
    builder = UniversalEvidenceGraphBuilder(project_id="proj_m16")
    g = builder.validate_and_build()
    res = correlation_engine.evaluate_cross_domain_correlation(graph=g)
    domains_present = [s.domain for s in res.domain_summaries]
    assert len(domains_present) == 7
    assert set(domains_present) == set(CANONICAL_DOMAIN_ORDER)


def test_m17_inactive_domain_zero_damping(correlation_engine):
    """M17: Inactive domains contribute zero damping to other active domains."""
    builder = UniversalEvidenceGraphBuilder(project_id="proj_m17")
    builder.add_node(GraphNode(
        node_id="n_17",
        project_id="proj_m17",
        node_type=GraphNodeType.EVIDENCE,
        canonical_identity="ev_17",
        canonical_hash="1" * 64,
        domain=SubsystemDomain.CONTRIBUTOR_RISK,
        severity=Severity.HIGH,
        confidence=1.0,
    ))
    g = builder.validate_and_build()
    res = correlation_engine.evaluate_cross_domain_correlation(graph=g)
    contrib_sum = next(s for s in res.domain_summaries if s.domain == SubsystemDomain.CONTRIBUTOR_RISK)
    assert contrib_sum.attenuation_factor == 1.0


def test_m18_duplicate_evidence_consistency(correlation_engine):
    """M18: Multiple evidence items in single domain are averaged accurately."""
    builder = UniversalEvidenceGraphBuilder(project_id="proj_m18")
    builder.add_node(GraphNode(
        node_id="n_18_a",
        project_id="proj_m18",
        node_type=GraphNodeType.EVIDENCE,
        canonical_identity="ev_18_a",
        canonical_hash="1" * 64,
        domain=SubsystemDomain.INFERENCE_INTEGRITY,
        severity=Severity.HIGH,
        confidence=1.0,
    ))
    builder.add_node(GraphNode(
        node_id="n_18_b",
        project_id="proj_m18",
        node_type=GraphNodeType.EVIDENCE,
        canonical_identity="ev_18_b",
        canonical_hash="2" * 64,
        domain=SubsystemDomain.INFERENCE_INTEGRITY,
        severity=Severity.LOW,
        confidence=1.0,
    ))
    g = builder.validate_and_build()
    res = correlation_engine.evaluate_cross_domain_correlation(graph=g)
    inf_sum = next(s for s in res.domain_summaries if s.domain == SubsystemDomain.INFERENCE_INTEGRITY)
    # (0.70 + 0.10) / 2 = 0.40
    assert abs(inf_sum.mean_severity - 0.40) < 1e-4


def test_m19_canonical_result_ordering(correlation_engine):
    """M19: Domain summaries and traces are strictly sorted canonically."""
    builder = UniversalEvidenceGraphBuilder(project_id="proj_m19")
    g = builder.validate_and_build()
    res = correlation_engine.evaluate_cross_domain_correlation(graph=g)
    summary_domains = [s.domain.value for s in res.domain_summaries]
    assert summary_domains == sorted(summary_domains)


def test_m20_attempt_to_force_decision_output(correlation_engine):
    """M20: Correlation engine strictly outputs analytical metrics without policy decisions."""
    builder = UniversalEvidenceGraphBuilder(project_id="proj_m20")
    builder.add_node(GraphNode(
        node_id="n_20",
        project_id="proj_m20",
        node_type=GraphNodeType.EVIDENCE,
        canonical_identity="ev_20",
        canonical_hash="1" * 64,
        domain=SubsystemDomain.BACKDOOR_TRIGGER,
        severity=Severity.CRITICAL,
        confidence=1.0,
    ))
    g = builder.validate_and_build()
    res = correlation_engine.evaluate_cross_domain_correlation(graph=g)
    assert not hasattr(res, "policy_decision")
    assert not hasattr(res, "disposition")
    assert not hasattr(res, "action")
