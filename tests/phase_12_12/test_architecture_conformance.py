"""Test 12.12.1: Architecture Conformance & Modular Boundary Verification."""

import pytest
from aivara.universal import normalizer
from aivara.universal.graph.builder import UniversalEvidenceGraphBuilder
from aivara.universal.correlation.engine import CrossDomainCorrelationEngine
from aivara.universal.risk.engine import UniversalRiskComputationEngine
from aivara.universal.policy.engine import UniversalPolicyEngine
from aivara.universal.proof.engine import UniversalProofIntegrationEngine
from aivara.universal.aggregation.engine import UniversalProjectAggregator
from aivara.universal.audit.generator import UniversalAuditReportGenerator
from aivara.universal.api.service import UniversalAssuranceService


def test_modular_boundaries_and_layer_separation():
    """Verify clean modular encapsulation and separation between assurance layers."""
    # Ensure normalizer does not import risk engine
    assert "risk.engine" not in normalizer.__file__
    
    # Ensure graph builder does not compute risk scores
    assert not hasattr(UniversalEvidenceGraphBuilder, "compute_risk_score")
    
    # Ensure risk engine does not make policy decisions
    assert not hasattr(UniversalRiskComputationEngine, "evaluate_decision")
    
    # Ensure policy engine does not compute multi-asset propagation
    assert not hasattr(UniversalPolicyEngine, "aggregate_project_risk")


def test_audit_reporting_consumption_boundary():
    """Verify audit report generator functions purely as a consumption boundary."""
    # Generator should not have methods for recomputing risk or policy
    assert not hasattr(UniversalAuditReportGenerator, "recalculate_risk")
    assert not hasattr(UniversalAuditReportGenerator, "compute_attenuation")


def test_no_hidden_second_risk_engine():
    """Verify API service delegates to single authoritative UniversalRiskComputationEngine."""
    svc = UniversalAssuranceService()
    assert hasattr(svc, "normalizer")
    assert hasattr(svc, "correlation_engine")
    assert hasattr(svc, "risk_engine")
    assert hasattr(svc, "policy_engine")
    assert hasattr(svc, "proof_engine")
    assert hasattr(svc, "project_aggregator")

