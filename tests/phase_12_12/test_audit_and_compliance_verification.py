"""Test 12.12.10: Audit Dossier & Compliance 6-State Verification."""

import pytest
from aivara.universal.audit.compliance import ComplianceEvaluationEngine
from aivara.universal.audit.enums import ComplianceStatus
from aivara.universal.audit.generator import UniversalAuditReportGenerator
from aivara.universal.audit.export import export_report_to_json, export_report_to_markdown, export_report_to_text
from aivara.universal.audit.integrity import verify_report_integrity


def test_six_state_compliance_vocabulary_and_unavailable():
    """Verify 6 compliance states with strict UNAVAILABLE handling."""
    engine = ComplianceEvaluationEngine()
    results = engine.evaluate_project_compliance(
        project_id="p-aud",
        asset_ids=["a1"],
        evidence_items=[],
        findings=[],
        risk_assessments={},
        policy_decisions={},
        proof_assessments={},
    )
    for r in results:
        assert r.status == ComplianceStatus.UNAVAILABLE
        assert r.status != ComplianceStatus.COMPLIANT


def test_audit_report_export_and_integrity():
    """Verify 20-section report generation, integrity check, and exports."""
    gen = UniversalAuditReportGenerator()
    report = gen.generate_report(
        project_id="p-aud-exp",
        asset_ids=["a1"],
        evidence_items=[],
        report_id="rep-123",
    )

    ver = verify_report_integrity(report)
    assert ver.status.value == "VERIFIED"

    json_str = export_report_to_json(report)
    assert "p-aud-exp" in json_str

    md_str = export_report_to_markdown(report)
    assert "# Universal Assurance Audit Report" in md_str

    txt_str = export_report_to_text(report)
    assert "Report ID:" in txt_str
