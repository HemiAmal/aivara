"""Test HTTP request validation, extra fields, and bounds for Phase 12.10."""

import pytest
from fastapi.testclient import TestClient

from aivara.main import app


@pytest.fixture
def client():
    return TestClient(app)


def test_extra_fields_forbidden(client):
    """Verify that requests containing unrecognized extra fields fail validation (422)."""
    project_id = "proj-val-1"
    payload = {
        "project_id": project_id,
        "asset_ids": ["asset-1"],
        "unexpected_extra_field": "illegal_value",
    }
    resp = client.post(f"/api/v1/projects/{project_id}/universal/assurance/tasks", json=payload)
    assert resp.status_code == 422


def test_project_id_mismatch_fails_closed(client):
    """Verify that request body project_id != route project_id fails closed (400/422)."""
    project_id = "proj-val-url"
    payload = {
        "project_id": "proj-val-body-mismatch",
        "asset_ids": ["asset-1"],
    }
    resp = client.post(f"/api/v1/projects/{project_id}/universal/assurance/tasks", json=payload)
    assert resp.status_code in (400, 422)


def test_malformed_json_payload(client):
    """Verify malformed JSON syntax is rejected."""
    project_id = "proj-val-malformed"
    resp = client.post(
        f"/api/v1/projects/{project_id}/universal/assurance/tasks",
        content="This is not valid JSON",
        headers={"Content-Type": "application/json"},
    )
    assert resp.status_code == 422
