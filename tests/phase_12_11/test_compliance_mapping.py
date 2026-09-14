"""Test Compliance Control and Regulatory Requirement Mapping (Phase 12.11)."""

import pytest
from aivara.universal.audit.compliance import (
    ComplianceEvaluationEngine,
    ComplianceControlResult,
    get_standard_compliance_controls,
)
from aivara.universal.audit.diff import compare_audit_reports
from aivara.universal.audit.enums import ComplianceFramework, ComplianceStatus
from aivara.universal.audit.generator import UniversalAuditReportGenerator
from aivara.universal.audit.integrity import compute_canonical_report_hash
from aivara.domain.schemas import EvidenceLayer
from aivara.universal.enums import SubsystemDomain


def test_missing_evidence_evaluates_to_unavailable():
    """Verify REQ-12-AUDIT-011: Absence of findings/evidence results in UNAVAILABLE, never false COMPLIANT."""
    engine = ComplianceEvaluationEngine()
    results = engine.evaluate_project_compliance(
        project_id="proj-comp-1",
        asset_ids=["asset-model-1"],
        evidence_items=[],  # Empty evidence
        findings=[],
        risk_assessments={},
        policy_decisions={},
        proof_assessments={},
    )
    assert len(results) > 0
    for r in results:
        # Must be UNAVAILABLE because no evidence was provided
        assert r.status == ComplianceStatus.UNAVAILABLE, f"Control {r.control_id} incorrectly evaluated to {r.status}"
        assert r.status != ComplianceStatus.COMPLIANT
        assert r.status != ComplianceStatus.NON_COMPLIANT


def test_positive_compliance_evaluation():
    """Verify controls are marked COMPLIANT when valid evidence covers target domains within threshold."""
    engine = ComplianceEvaluationEngine()

    mock_evidence = [
        {
            "evidence_id": "ev-drift-1",
            "domain": SubsystemDomain.DISTRIBUTION_SHIFT,
            "evidence_layer": EvidenceLayer.DETECTION,
            "primary_asset_id": "asset-1",
        },
        {
            "evidence_id": "ev-beh-1",
            "domain": SubsystemDomain.BEHAVIORAL_ANALYSIS,
            "evidence_layer": EvidenceLayer.DETECTION,
            "primary_asset_id": "asset-1",
        },
    ]

    mock_risks = {
        "asset-1": {"risk_score": 0.15, "risk_level": "LOW"}
    }

    results = engine.evaluate_project_compliance(
        project_id="proj-comp-2",
        asset_ids=["asset-1"],
        evidence_items=mock_evidence,
        findings=[],
        risk_assessments=mock_risks,
        policy_decisions={},
        proof_assessments={},
        target_frameworks={ComplianceFramework.NIST_AI_RMF},
    )

    drift_ctrl = next(r for r in results if r.control_id == "NIST-AI-MEASURE-2.3")
    assert drift_ctrl.status == ComplianceStatus.COMPLIANT
    assert drift_ctrl.max_observed_risk_score == 0.15


def test_non_compliance_on_elevated_risk():
    """Verify control is marked NON_COMPLIANT when observed risk exceeds threshold."""
    engine = ComplianceEvaluationEngine()

    mock_evidence = [
        {
            "evidence_id": "ev-drift-1",
            "domain": SubsystemDomain.DISTRIBUTION_SHIFT,
            "evidence_layer": EvidenceLayer.DETECTION,
            "primary_asset_id": "asset-1",
        },
        {
            "evidence_id": "ev-beh-1",
            "domain": SubsystemDomain.BEHAVIORAL_ANALYSIS,
            "evidence_layer": EvidenceLayer.DETECTION,
            "primary_asset_id": "asset-1",
        },
    ]

    mock_risks = {
        "asset-1": {"risk_score": 0.85, "risk_level": "CRITICAL"}
    }

    results = engine.evaluate_project_compliance(
        project_id="proj-comp-3",
        asset_ids=["asset-1"],
        evidence_items=mock_evidence,
        findings=[],
        risk_assessments=mock_risks,
        policy_decisions={},
        proof_assessments={},
        target_frameworks={ComplianceFramework.NIST_AI_RMF},
    )

    drift_ctrl = next(r for r in results if r.control_id == "NIST-AI-MEASURE-2.3")
    assert drift_ctrl.status == ComplianceStatus.NON_COMPLIANT
    assert drift_ctrl.max_observed_risk_score == 0.85


def test_unavailable_serialization_and_deserialization():
    """Verify ComplianceControlResult serialization preserves UNAVAILABLE status accurately."""
    res = ComplianceControlResult(
        control_id="CTRL-UNAVAIL-1",
        framework=ComplianceFramework.NIST_AI_RMF,
        title="Test Unavailability",
        status=ComplianceStatus.UNAVAILABLE,
        justification="Evidence missing for test domains",
        assessed_asset_ids=["asset-1"],
    )
    dumped = res.model_dump()
    assert dumped["status"] == "UNAVAILABLE"
    
    canon = res.to_canonical_dict()
    assert canon["status"] == "UNAVAILABLE"

    restored = ComplianceControlResult.model_validate(dumped)
    assert restored.status == ComplianceStatus.UNAVAILABLE


def test_semantic_diff_detects_unavailable_transitions():
    """Verify semantic diff engine detects transitions between UNAVAILABLE and COMPLIANT/NON_COMPLIANT."""
    gen = UniversalAuditReportGenerator()

    # rep1 has no evidence -> controls are UNAVAILABLE
    rep1 = gen.generate_report(
        project_id="proj-diff-unavail",
        asset_ids=["asset-1"],
        evidence_items=[],
        instance_version=1,
        report_id="rep-unavail-1",
    )

    # rep2 has evidence -> NIST-AI-MEASURE-2.3 becomes COMPLIANT
    evidence = [
        {
            "evidence_id": "ev-drift-1",
            "domain": SubsystemDomain.DISTRIBUTION_SHIFT,
            "evidence_layer": EvidenceLayer.DETECTION,
            "primary_asset_id": "asset-1",
        },
        {
            "evidence_id": "ev-beh-1",
            "domain": SubsystemDomain.BEHAVIORAL_ANALYSIS,
            "evidence_layer": EvidenceLayer.DETECTION,
            "primary_asset_id": "asset-1",
        },
    ]
    risks = {"asset-1": {"risk_score": 0.10, "risk_level": "LOW"}}

    rep2 = gen.generate_report(
        project_id="proj-diff-unavail",
        asset_ids=["asset-1"],
        evidence_items=evidence,
        risk_assessments=risks,
        instance_version=2,
        report_id="rep-unavail-2",
    )

    diff = compare_audit_reports(rep1, rep2)
    assert diff.has_changes is True
    assert "NIST-AI-MEASURE-2.3" in diff.compliance_status_changes
    c_change = diff.compliance_status_changes["NIST-AI-MEASURE-2.3"]
    assert c_change["base_status"] == "UNAVAILABLE"
    assert c_change["target_status"] == "COMPLIANT"


def test_report_hash_changes_on_compliance_status_change():
    """Verify that mutating a compliance result status changes canonical report hash."""
    gen = UniversalAuditReportGenerator()
    rep = gen.generate_report(
        project_id="proj-comp-hash",
        asset_ids=["asset-1"],
        evidence_items=[],
        report_id="rep-comp-hash",
    )

    orig_hash = rep.report_hash
    mutated_results = [
        r.model_copy(update={"status": ComplianceStatus.COMPLIANT}) if r.control_id == "NIST-AI-MEASURE-2.3" else r
        for r in rep.compliance_results
    ]
    mutated_rep = rep.model_copy(update={"compliance_results": mutated_results})
    new_hash = compute_canonical_report_hash(mutated_rep)
    assert new_hash != orig_hash
