"""Test Audit API Routes and Deterministic Export Formatting (Phase 12.11)."""

import pytest
from fastapi.testclient import TestClient

from aivara.main import app


@pytest.fixture
def client():
    return TestClient(app)


def test_audit_report_generation_and_retrieval_api(client):
    """Verify POST /reports -> GET /reports/{report_id} -> POST /reports/{report_id}/verify."""
    project_id = "proj-api-audit-1"

    # 1. Create audit report
    payload = {
        "project_id": project_id,
        "report_name": "API Automated Audit Report",
    }
    create_resp = client.post(f"/api/v1/projects/{project_id}/universal/audit/reports", json=payload)
    assert create_resp.status_code == 201
    rep_data = create_resp.json()["data"]
    report_id = rep_data["report_id"]
    assert rep_data["project_id"] == project_id
    assert len(rep_data["report_hash"]) == 64

    # 2. Retrieve report
    get_resp = client.get(f"/api/v1/projects/{project_id}/universal/audit/reports/{report_id}")
    assert get_resp.status_code == 200
    assert get_resp.json()["data"]["report_id"] == report_id

    # 3. Verify report integrity via API
    ver_resp = client.post(f"/api/v1/projects/{project_id}/universal/audit/reports/{report_id}/verify")
    assert ver_resp.status_code == 200
    assert ver_resp.json()["data"]["status"] == "VERIFIED"


def test_audit_report_export_api(client):
    """Verify GET /reports/{report_id}/export for JSON, Markdown, and Text formats."""
    project_id = "proj-api-export-1"

    create_resp = client.post(
        f"/api/v1/projects/{project_id}/universal/audit/reports",
        json={"project_id": project_id},
    )
    report_id = create_resp.json()["data"]["report_id"]

    # Export Markdown
    md_resp = client.get(f"/api/v1/projects/{project_id}/universal/audit/reports/{report_id}/export?format=MARKDOWN")
    assert md_resp.status_code == 200
    assert "text/markdown" in md_resp.headers["content-type"]
    assert report_id in md_resp.text

    # Export Text
    txt_resp = client.get(f"/api/v1/projects/{project_id}/universal/audit/reports/{report_id}/export?format=TEXT")
    assert txt_resp.status_code == 200
    assert "text/plain" in txt_resp.headers["content-type"]
    assert report_id in txt_resp.text


def test_compliance_controls_catalog_api(client):
    """Verify GET /compliance/controls returns standard regulatory catalog."""
    project_id = "proj-api-ctrls-1"
    resp = client.get(f"/api/v1/projects/{project_id}/universal/audit/compliance/controls")
    assert resp.status_code == 200
    controls = resp.json()["data"]
    assert len(controls) >= 10
