"""Test Cryptographic Report Integrity and Verification (Phase 12.11)."""

import pytest
from aivara.universal.audit.enums import ReportIntegrityStatus
from aivara.universal.audit.generator import UniversalAuditReportGenerator
from aivara.universal.audit.integrity import verify_report_integrity


def test_valid_report_integrity_verification():
    """Verify an unmodified report returns VERIFIED status."""
    gen = UniversalAuditReportGenerator()
    report = gen.generate_report(
        project_id="proj-integ-1",
        asset_ids=["asset-1"],
        evidence_items=[],
        report_id="rep-integ-1",
    )
    ver_res = verify_report_integrity(report)
    assert ver_res.status == ReportIntegrityStatus.VERIFIED
    assert ver_res.declared_hash == ver_res.computed_hash


def test_tampered_report_integrity_fails_closed():
    """Verify tampering with report risk score causes verification to return TAMPERED."""
    gen = UniversalAuditReportGenerator()
    report = gen.generate_report(
        project_id="proj-integ-2",
        asset_ids=["asset-1"],
        evidence_items=[],
        report_id="rep-integ-2",
    )
    # Tamper with project risk score in risk summary
    tampered_risk_summary = report.risk_summary.model_copy(update={"project_risk_score": 0.999})
    tampered_report = report.model_copy(update={"risk_summary": tampered_risk_summary})

    ver_res = verify_report_integrity(tampered_report)
    assert ver_res.status == ReportIntegrityStatus.TAMPERED
    assert ver_res.declared_hash != ver_res.computed_hash
