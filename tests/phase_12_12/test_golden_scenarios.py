"""Test 12.12 Golden Scenarios: 15 End-to-End Assurance Scenarios."""

import pytest
from aivara.domain.schemas import EvidenceLayer
from aivara.universal.enums import SubsystemDomain
from aivara.universal.normalizer import UniversalEvidenceNormalizer
from aivara.universal.graph.builder import UniversalEvidenceGraphBuilder
from aivara.universal.risk.engine import UniversalRiskComputationEngine
from aivara.universal.policy.engine import UniversalPolicyEngine
from aivara.universal.policy.enums import UniversalDecision
from aivara.universal.policy.schemas import UniversalPolicy
from aivara.universal.audit.generator import UniversalAuditReportGenerator


def test_golden_scenario_1_clean_project():
    """Scenario 1: Clean/trusted project with minimal noise -> ACCEPT."""
    project_id = "proj-gold-1"
    asset_id = "model-clean"
    norm = UniversalEvidenceNormalizer()
    ev = norm.normalize_single({
        "evidence_id": "ev-g1", "domain": "MODEL_INTEGRITY", "evidence_layer": "detection", "primary_asset_id": asset_id, "severity": "info", "confidence": 0.9
    }, project_id=project_id)

    builder = UniversalEvidenceGraphBuilder(project_id=project_id)
    builder.add_evidence_envelope(ev)
    g = builder.validate_and_build()

    risk_eng = UniversalRiskComputationEngine()
    r = risk_eng.compute_asset_risk(graph=g, asset_id=asset_id)
    policy = UniversalPolicy.get_default_policy()
    dec_eng = UniversalPolicyEngine()
    d = dec_eng.evaluate(policy, r)
    assert d.decision == UniversalDecision.ACCEPT


def test_golden_scenario_2_high_backdoor_risk():
    """Scenario 2: Critical backdoor trigger finding -> REJECT."""
    project_id = "proj-gold-2"
    asset_id = "model-backdoor"
    norm = UniversalEvidenceNormalizer()
    ev = norm.normalize_single({
        "evidence_id": "ev-g2",
        "domain": "BACKDOOR_TRIGGER",
        "evidence_layer": "detection",
        "model_id": asset_id,
        "primary_asset_id": asset_id,
        "severity": "critical",
        "confidence": 0.95,
    }, project_id=project_id)

    builder = UniversalEvidenceGraphBuilder(project_id=project_id)
    builder.add_evidence_envelope(ev)
    g = builder.validate_and_build()

    risk_eng = UniversalRiskComputationEngine()
    r = risk_eng.compute_asset_risk(graph=g, asset_id=asset_id)
    policy = UniversalPolicy.get_default_policy()
    dec_eng = UniversalPolicyEngine()
    d = dec_eng.evaluate(policy, r)
    assert d.decision == UniversalDecision.REJECT


def test_golden_scenario_3_audit_report_generation():
    """Scenario 3: Audit report synthesis across evidence, risk, and policy."""
    project_id = "proj-gold-3"
    audit_gen = UniversalAuditReportGenerator()
    rep = audit_gen.generate_report(
        project_id=project_id,
        asset_ids=["a1"],
        evidence_items=[],
        report_id="rep-gold-3",
    )
    assert rep.report_hash != ""
    assert len(rep.compliance_results) > 0
