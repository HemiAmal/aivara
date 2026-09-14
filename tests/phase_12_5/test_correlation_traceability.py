"""Static AST audit and architectural traceability tests for Phase 12.5."""

import inspect
import pytest

from aivara.domain.schemas import Severity
from aivara.universal.enums import SubsystemDomain
from aivara.universal.graph import (
    GraphNode,
    GraphNodeType,
    UniversalEvidenceGraphBuilder,
)
from aivara.universal.risk import (
    EvidenceSufficiencyStatus,
    HierarchicalRiskAggregator,
)
from aivara.universal.correlation import (
    CorrelationMatrix,
    CrossDomainCorrelationEngine,
)


@pytest.fixture
def risk_aggregator():
    return HierarchicalRiskAggregator()


@pytest.fixture
def correlation_engine():
    return CrossDomainCorrelationEngine()


def test_static_audit_no_forbidden_responsibilities_in_correlation_engine():
    """Verify backend.aivara.universal.correlation has zero implementation of decisions, proof overrides, policy registries, or dossiers."""
    import aivara.universal.correlation.engine as eng_mod
    import aivara.universal.correlation.enums as enum_mod
    import aivara.universal.correlation.matrix as mat_mod
    import aivara.universal.correlation.schemas as sch_mod

    prohibited_terms = [
        "proof_override",
        "proof_non_compensable",
        "disposition_decision",
        "seal_dossier",
        "compliance_report",
        "policy_registry",
        "ACCEPT",
        "REVIEW",
        "QUARANTINE",
        "REJECT",
    ]

    for mod in [eng_mod, enum_mod, mat_mod, sch_mod]:
        source = inspect.getsource(mod)
        for term in prohibited_terms:
            assert term not in source, f"Prohibited term '{term}' discovered in {mod.__name__}"


def test_no_decision_or_disposition_fields_in_correlation_contracts():
    """Verify Phase 12.5 schemas expose strictly analytical data and zero decision fields."""
    import aivara.universal.correlation.schemas as sch_mod

    for name, obj in inspect.getmembers(sch_mod, inspect.isclass):
        if hasattr(obj, "model_fields"):
            fields = obj.model_fields.keys()
            assert "disposition" not in fields, f"Model {name} contains prohibited field 'disposition'"
            assert "decision" not in fields, f"Model {name} contains prohibited field 'decision'"
            assert "override" not in fields, f"Model {name} contains prohibited field 'override'"


def test_analytical_evidence_sufficiency_propagation(risk_aggregator, correlation_engine):
    """Verify analytical data quality state is preserved through correlation evaluation without decision routing."""
    builder = UniversalEvidenceGraphBuilder(project_id="proj_analytical_propagation")
    
    # Evidence node with unverified ancestry
    builder.add_node(GraphNode(
        node_id="node_1",
        project_id="proj_analytical_propagation",
        node_type=GraphNodeType.EVIDENCE,
        canonical_identity="ev_1",
        canonical_hash="1" * 64,
        domain=SubsystemDomain.MODEL_INTEGRITY,
        severity=Severity.HIGH,
        confidence=0.85,
        metadata={"primary_asset_id": "m1"},
    ))
    g = builder.validate_and_build()
    hier_risk = risk_aggregator.aggregate_hierarchy(g)
    assert hier_risk.evidence_sufficiency == EvidenceSufficiencyStatus.INSUFFICIENT_ANCESTRY

    corr_res = correlation_engine.evaluate_cross_domain_correlation(hier_risk, g)
    assert corr_res.evidence_sufficiency == EvidenceSufficiencyStatus.INSUFFICIENT_ANCESTRY
    assert not hasattr(corr_res, "disposition")
    assert not hasattr(corr_res, "decision")
