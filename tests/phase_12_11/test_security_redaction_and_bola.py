"""Test Security Redaction and Broken Object-Level Authorization (Phase 12.11)."""

import pytest
from fastapi.testclient import TestClient

from aivara.main import app
from aivara.universal.audit.enums import RedactionLevel
from aivara.universal.audit.generator import UniversalAuditReportGenerator
from aivara.universal.audit.redaction import sanitize_data_structure


@pytest.fixture
def client():
    return TestClient(app)


def test_sensitive_credentials_redaction():
    """Verify secrets, passwords, and tokens are deterministically scrubbed from report content."""
    raw_payload = {
        "finding_id": "find-101",
        "api_key": "sk-secret-1234567890",
        "password": "super_secret_password",
        "details": "User token eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.doNotLeakThis",
    }
    sanitized = sanitize_data_structure(raw_payload, level=RedactionLevel.STANDARD)
    assert "sk-secret-1234567890" not in str(sanitized)
    assert "super_secret_password" not in str(sanitized)
    assert "[REDACTED_SECRET:" in sanitized["api_key"]
    assert "[REDACTED_SECRET:" in sanitized["password"]


def test_cross_project_report_access_rejected_bola(client):
    """Verify BOLA protection: Client cannot query Project B reports using Project A URL."""
    # Create report in Project A
    resp_a = client.post(
        "/api/v1/projects/proj-tenant-A/universal/audit/reports",
        json={"project_id": "proj-tenant-A"},
    )
    assert resp_a.status_code == 201
    report_id = resp_a.json()["data"]["report_id"]

    # Attempt to access using Project B URL
    resp_b = client.get(f"/api/v1/projects/proj-tenant-B/universal/audit/reports/{report_id}")
    assert resp_b.status_code == 404
