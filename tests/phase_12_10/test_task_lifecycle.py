"""Test asynchronous task lifecycle, state machine, and cancellation for Phase 12.10."""

import time
import pytest
from fastapi.testclient import TestClient

from aivara.main import app
from aivara.universal.api.enums import UniversalTaskStatus
from aivara.universal.api.service import UniversalTask, get_universal_task_manager


@pytest.fixture
def client():
    return TestClient(app)


def test_task_creation_and_successful_completion(client):
    """Verify task lifecycle from 202 Accepted -> QUEUED/RUNNING -> COMPLETED."""
    project_id = "proj-lifecycle-1"
    payload = {
        "project_id": project_id,
        "asset_ids": ["asset-model-1", "asset-dataset-1"],
        "dependency_edges": [
            {
                "project_id": project_id,
                "source_asset_id": "asset-dataset-1",
                "target_asset_id": "asset-model-1",
                "edge_type": "FEEDS",
                "propagation_weight": 0.8,
            }
        ],
        "asset_roles": {
            "asset-model-1": "CORE_DEPLOYED",
            "asset-dataset-1": "SUPPORTING_INPUT",
        },
    }

    # 1. Create task
    resp = client.post(f"/api/v1/projects/{project_id}/universal/assurance/tasks", json=payload)
    assert resp.status_code == 202
    task_data = resp.json()["data"]
    task_id = task_data["task_id"]
    assert task_data["project_id"] == project_id
    assert task_data["status"] in (UniversalTaskStatus.QUEUED.value, UniversalTaskStatus.RUNNING.value, UniversalTaskStatus.COMPLETED.value)

    # 2. Wait for completion
    completed = False
    for _ in range(50):
        status_resp = client.get(f"/api/v1/projects/{project_id}/universal/assurance/tasks/{task_id}")
        assert status_resp.status_code == 200
        status_data = status_resp.json()["data"]
        if status_data["status"] in (UniversalTaskStatus.COMPLETED.value, UniversalTaskStatus.FAILED.value):
            if status_data["status"] == UniversalTaskStatus.COMPLETED.value:
                completed = True
                assert status_data["progress_percent"] == 100.0
                assert status_data["completed_at"] is not None
            break
        time.sleep(0.05)

    print(f"\nFinal status data: {status_data}")
    assert completed, f"Task did not complete in time: status={status_data['status']}, error={status_data.get('error_message')}"

    # 3. Retrieve completed result
    res_resp = client.get(f"/api/v1/projects/{project_id}/universal/assurance/tasks/{task_id}/result")
    assert res_resp.status_code == 200
    res_data = res_resp.json()["data"]
    assert res_data["task_id"] == task_id
    assert res_data["project_id"] == project_id
    assert res_data["decision"] in ("ACCEPT", "REVIEW", "QUARANTINE", "REJECT")
    assert 0.0 <= res_data["project_risk_score"] <= 1.0
    assert len(res_data["asset_assessments"]) == 2


def test_task_cooperative_cancellation(client):
    """Verify task can be cooperatively cancelled."""
    project_id = "proj-cancel-1"
    task_manager = get_universal_task_manager()

    # Create a task directly without immediately starting execution to test cancellation
    from aivara.universal.api.schemas import UniversalAssuranceTaskCreateRequest
    req = UniversalAssuranceTaskCreateRequest(project_id=project_id, asset_ids=["asset-1"])
    task, _ = task_manager.create_task(project_id=project_id, request=req)

    # Cancel task
    cancel_resp = client.post(f"/api/v1/projects/{project_id}/universal/assurance/tasks/{task.task_id}/cancel")
    assert cancel_resp.status_code == 200
    assert cancel_resp.json()["data"]["status"] == UniversalTaskStatus.CANCELLED.value

    # Attempt to fetch result on cancelled task should yield 409
    res_resp = client.get(f"/api/v1/projects/{project_id}/universal/assurance/tasks/{task.task_id}/result")
    assert res_resp.status_code == 409
