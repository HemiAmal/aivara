"""Test route registration and capabilities endpoint for Phase 12.10."""

import pytest
from fastapi.testclient import TestClient

from aivara.main import app


@pytest.fixture
def client():
    return TestClient(app)


def test_capabilities_endpoints(client):
    """Verify capabilities endpoints on both project and global routes."""
    # Global route
    resp = client.get("/api/v1/universal/capabilities")
    assert resp.status_code == 200
    data = resp.json()["data"]
    assert data["service_name"] == "AIVARA Universal Assurance Engine"
    assert data["schema_version"] == "1.0"
    assert "DATASET_INTEGRITY" in data["supported_subsystems"]
    assert "MODEL_INTEGRITY" in data["supported_subsystems"]
    assert data["max_assets_per_request"] == 500
    assert data["max_chain_depth"] == 5

    # Project-scoped route
    resp_proj = client.get("/api/v1/projects/proj-test-123/universal/capabilities")
    assert resp_proj.status_code == 200
    assert resp_proj.json()["data"]["schema_version"] == "1.0"


def test_openapi_schema_contains_universal_routes(client):
    """Verify OpenAPI documentation contains the Phase 12.10 route surface."""
    openapi = app.openapi()
    paths = openapi["paths"]
    assert "/api/v1/projects/{project_id}/universal/assurance/tasks" in paths
    assert "/api/v1/projects/{project_id}/universal/assurance/tasks/{task_id}" in paths
    assert "/api/v1/projects/{project_id}/universal/assurance/tasks/{task_id}/result" in paths
    assert "/api/v1/projects/{project_id}/universal/assurance/tasks/{task_id}/cancel" in paths
    assert "/api/v1/projects/{project_id}/universal/assurance/tasks/{task_id}/events" in paths
    assert "/api/v1/projects/{project_id}/universal/risk/{risk_id}" in paths
    assert "/api/v1/projects/{project_id}/universal/decisions/{decision_id}" in paths
    assert "/api/v1/projects/{project_id}/universal/proof/{proof_id}" in paths
    assert "/api/v1/projects/{project_id}/universal/aggregation" in paths
