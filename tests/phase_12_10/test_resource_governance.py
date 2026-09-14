"""Test resource ceilings and boundary limits for Phase 12.10."""

import pytest
from fastapi.testclient import TestClient

from aivara.main import app


@pytest.fixture
def client():
    return TestClient(app)


def test_asset_count_limit_rejection(client):
    """Verify that requests exceeding max 500 assets are rejected (422)."""
    project_id = "proj-gov-1"
    excessive_assets = [f"asset-{i}" for i in range(501)]
    payload = {
        "project_id": project_id,
        "asset_ids": excessive_assets,
    }
    resp = client.post(f"/api/v1/projects/{project_id}/universal/assurance/tasks", json=payload)
    assert resp.status_code == 422


def test_edge_count_limit_rejection(client):
    """Verify that requests exceeding max 2000 dependency edges are rejected (422)."""
    project_id = "proj-gov-2"
    excessive_edges = [
        {
            "project_id": project_id,
            "source_asset_id": f"src-{i}",
            "target_asset_id": f"tgt-{i}",
            "edge_type": "DATA_FLOW",
            "propagation_weight": 0.5,
        }
        for i in range(2001)
    ]
    payload = {
        "project_id": project_id,
        "asset_ids": ["src-0", "tgt-0"],
        "dependency_edges": excessive_edges,
    }
    resp = client.post(f"/api/v1/projects/{project_id}/universal/assurance/tasks", json=payload)
    assert resp.status_code == 422
