"""Test Broken Object-Level Authorization (BOLA) and multi-tenant isolation for Phase 12.10."""

import time
import pytest
from fastapi.testclient import TestClient

from aivara.main import app
from aivara.universal.api.enums import UniversalTaskStatus


@pytest.fixture
def client():
    return TestClient(app)


def test_cross_project_task_access_rejected(client):
    """Verify that Project A cannot access Project B's tasks or results."""
    proj_a = "proj-tenant-alpha"
    proj_b = "proj-tenant-beta"

    # 1. Create task in Project A
    resp_a = client.post(
        f"/api/v1/projects/{proj_a}/universal/assurance/tasks",
        json={"project_id": proj_a, "asset_ids": ["asset-alpha"]},
    )
    assert resp_a.status_code == 202
    task_id_a = resp_a.json()["data"]["task_id"]

    # Wait for completion
    for _ in range(50):
        s = client.get(f"/api/v1/projects/{proj_a}/universal/assurance/tasks/{task_id_a}").json()["data"]
        if s["status"] == UniversalTaskStatus.COMPLETED.value:
            break
        time.sleep(0.05)

    # 2. Attempt to query Project A's task under Project B's URL -> MUST return 404
    resp_b_query = client.get(f"/api/v1/projects/{proj_b}/universal/assurance/tasks/{task_id_a}")
    assert resp_b_query.status_code == 404

    # 3. Attempt to fetch Project A's result under Project B's URL -> MUST return 404
    resp_b_result = client.get(f"/api/v1/projects/{proj_b}/universal/assurance/tasks/{task_id_a}/result")
    assert resp_b_result.status_code == 404

    # 4. Attempt to cancel Project A's task under Project B's URL -> MUST return 404
    resp_b_cancel = client.post(f"/api/v1/projects/{proj_b}/universal/assurance/tasks/{task_id_a}/cancel")
    assert resp_b_cancel.status_code == 404


def test_cross_project_entity_queries_rejected(client):
    """Verify that Project B cannot fetch stored risk or decisions created by Project A."""
    proj_a = "proj-entity-a"
    proj_b = "proj-entity-b"

    # Execute task in Project A
    resp = client.post(
        f"/api/v1/projects/{proj_a}/universal/assurance/tasks",
        json={"project_id": proj_a, "asset_ids": ["asset-a-1"]},
    )
    task_id = resp.json()["data"]["task_id"]

    for _ in range(50):
        s = client.get(f"/api/v1/projects/{proj_a}/universal/assurance/tasks/{task_id}").json()["data"]
        if s["status"] == UniversalTaskStatus.COMPLETED.value:
            break
        time.sleep(0.05)

    # Valid query in Project A
    resp_risk_a = client.get(f"/api/v1/projects/{proj_a}/universal/risk/asset-a-1")
    assert resp_risk_a.status_code == 200

    # Cross-project query in Project B -> 404
    resp_risk_b = client.get(f"/api/v1/projects/{proj_b}/universal/risk/asset-a-1")
    assert resp_risk_b.status_code == 404
