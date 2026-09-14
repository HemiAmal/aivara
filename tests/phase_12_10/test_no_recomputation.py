"""Test that GET endpoints retrieve stored results without recomputation for Phase 12.10."""

import time
from unittest.mock import patch
import pytest
from fastapi.testclient import TestClient

from aivara.main import app
from aivara.universal.api.enums import UniversalTaskStatus


@pytest.fixture
def client():
    return TestClient(app)


def test_get_result_does_not_recompute(client):
    """Verify that multiple GET /result calls return identical stored data without re-executing pipeline."""
    project_id = "proj-norecompute-1"
    resp = client.post(
        f"/api/v1/projects/{project_id}/universal/assurance/tasks",
        json={"project_id": project_id, "asset_ids": ["asset-1"]},
    )
    task_id = resp.json()["data"]["task_id"]

    for _ in range(50):
        s = client.get(f"/api/v1/projects/{project_id}/universal/assurance/tasks/{task_id}").json()["data"]
        if s["status"] == UniversalTaskStatus.COMPLETED.value:
            break
        time.sleep(0.05)

    # Initial retrieval
    res1 = client.get(f"/api/v1/projects/{project_id}/universal/assurance/tasks/{task_id}/result").json()["data"]

    # Patch the engine to ensure it is not called during subsequent GET
    with patch("aivara.universal.aggregation.engine.UniversalProjectAggregator.aggregate_project") as mock_agg:
        res2 = client.get(f"/api/v1/projects/{project_id}/universal/assurance/tasks/{task_id}/result").json()["data"]
        assert mock_agg.call_count == 0, "aggregate_project should not be called during GET"

    assert res1["hierarchical_hash"] == res2["hierarchical_hash"]
    assert res1["project_risk_score"] == res2["project_risk_score"]
