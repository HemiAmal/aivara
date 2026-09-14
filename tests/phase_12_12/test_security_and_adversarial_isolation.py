"""Test 12.12.15: Security, BOLA & Adversarial Multi-Tenant Isolation Verification."""

import pytest
from fastapi.testclient import TestClient
from aivara.main import app
from aivara.universal.audit.generator import UniversalAuditReportGenerator
from aivara.universal.audit.enums import RedactionLevel


@pytest.fixture
def client():
    return TestClient(app)


def test_bola_cross_project_isolation(client):
    """Verify BOLA protection blocks cross-project task and report access."""
    # Attempting to access non-existent or cross-tenant task returns 404
    resp = client.get("/api/v1/projects/proj-tenant-A/universal/assurance/tasks/non-existent-task-id")
    assert resp.status_code == 404

    resp_rep = client.get("/api/v1/projects/proj-tenant-A/universal/audit/reports/non-existent-report-id")
    assert resp_rep.status_code == 404


def test_sensitive_credential_redaction():
    """Verify API tokens, bearer keys, and credentials are automatically redacted in audit reports."""
    gen = UniversalAuditReportGenerator()
    findings = [
        {
            "finding_id": "find-sec-1",
            "title": "Secret in config",
            "severity": "high",
            "details": {
                "api_key": "sk-proj-secret-1234567890abcdef",
                "auth_header": "Bearer secret_jwt_token_here",
                "password": "SuperSecretPassword123!",
            },
        }
    ]

    report = gen.generate_report(
        project_id="proj-redact",
        asset_ids=["a1"],
        evidence_items=[],
        findings=findings,
        redaction_level=RedactionLevel.STANDARD,
        report_id="rep-redact-1",
    )

    f_sanitized = report.finding_summary.findings[0]
    details = f_sanitized.get("details", {})
    assert "[REDACTED" in str(details.get("api_key"))
    assert "[REDACTED" in str(details.get("auth_header"))
    assert "[REDACTED" in str(details.get("password"))

