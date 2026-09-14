"""Test 12.12.11: REST API & Asynchronous Task Orchestration Verification."""

import time
import pytest
from fastapi.testclient import TestClient
from aivara.main import app
from aivara.universal.api.enums import UniversalTaskStatus


@pytest.fixture
def client():
    return TestClient(app)


def test_api_task_submission_and_lifecycle(client):
    """Verify task submission, status progression, and result retrieval via REST API."""
    project_id = "proj-api-test"
    payload = {
        "project_id": project_id,
        "asset_ids": ["model-1"],
        "evidence_items": [
            {
                "evidence_id": "ev-api-1",
                "domain": "model_integrity",
                "evidence_layer": "detection",
                "primary_asset_id": "model-1",
                "primary_asset_type": "model",
                "severity": "low",
                "confidence": 0.9,
            }
        ],
    }

    resp = client.post(f"/api/v1/projects/{project_id}/universal/assurance/tasks", json=payload)
    assert resp.status_code == 202
    task_id = resp.json()["data"]["task_id"]

    for _ in range(50):
        status_resp = client.get(f"/api/v1/projects/{project_id}/universal/assurance/tasks/{task_id}").json()["data"]
        if status_resp["status"] in [UniversalTaskStatus.COMPLETED.value, UniversalTaskStatus.FAILED.value]:
            break
        time.sleep(0.05)

    assert status_resp["status"] == UniversalTaskStatus.COMPLETED.value

    # Fetch result
    res_resp = client.get(f"/api/v1/projects/{project_id}/universal/assurance/tasks/{task_id}/result")
    assert res_resp.status_code == 200
    assert res_resp.json()["data"]["project_id"] == project_id
