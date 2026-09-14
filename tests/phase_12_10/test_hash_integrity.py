"""Test hash preservation and canonical serialization for Phase 12.10."""

import time
import pytest
from fastapi.testclient import TestClient

from aivara.main import app
from aivara.universal.api.enums import UniversalTaskStatus


@pytest.fixture
def client():
    return TestClient(app)


def test_hash_integrity_preservation(client):
    """Verify that JSON serialization preserves exact 64-character SHA-256 hex digests."""
    project_id = "proj-hash-integ-1"
    payload = {
        "project_id": project_id,
        "asset_ids": ["asset-hash-1"],
    }
    resp = client.post(f"/api/v1/projects/{project_id}/universal/assurance/tasks", json=payload)
    task_id = resp.json()["data"]["task_id"]

    for _ in range(50):
        s = client.get(f"/api/v1/projects/{project_id}/universal/assurance/tasks/{task_id}").json()["data"]
        if s["status"] == UniversalTaskStatus.COMPLETED.value:
            break
        time.sleep(0.05)

    res_resp = client.get(f"/api/v1/projects/{project_id}/universal/assurance/tasks/{task_id}/result")
    data = res_resp.json()["data"]

    hierarchical_hash = data["hierarchical_hash"]
    assert len(hierarchical_hash) == 64
    assert all(c in "0123456789abcdefABCDEF" for c in hierarchical_hash)

    # Check asset assessment hashes
    for asset_ass in data["asset_assessments"]:
        ass_hash = asset_ass["assessment_hash"]
        assert len(ass_hash) == 64
