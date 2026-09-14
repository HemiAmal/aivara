"""Test domain exception mapping to standardized HTTP responses for Phase 12.10."""

import pytest
from fastapi.testclient import TestClient

from aivara.main import app


@pytest.fixture
def client():
    return TestClient(app)


def test_scope_mismatch_error_mapping(client):
    """Verify ScopeMismatchError maps to HTTP 400."""
    resp = client.post(
        "/api/v1/projects/proj-alpha/universal/assurance/tasks",
        json={"project_id": "proj-beta", "asset_ids": ["asset-1"]},
    )
    assert resp.status_code == 400
    data = resp.json()
    assert data["status"] == "error"
    assert "error" in data
    assert "project_id" in data["error"]["message"].lower()


def test_task_not_found_error_mapping(client):
    """Verify non-existent task returns HTTP 404 with structured error envelope."""
    resp = client.get("/api/v1/projects/proj-alpha/universal/assurance/tasks/non-existent-task-id")
    assert resp.status_code == 404
    data = resp.json()
    assert data["status"] == "error"
    assert "not found" in data["error"]["message"].lower()
