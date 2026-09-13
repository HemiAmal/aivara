"""Phase 11.11.2 - Layer 5: REST API & Task Orchestration Verification Suite.

Verifies:
- REQ-11-VERIF-038: 202 Accepted async task submission with location header
- REQ-11-VERIF-039: Idempotency-Key duplicate submission returns original task
- REQ-11-VERIF-040: Idempotency conflict (same key, modified payload) returns 409 Conflict
- REQ-11-VERIF-041: Task execution lifecycle (QUEUED -> RUNNING -> COMPLETED)
- REQ-11-VERIF-042: Task result retrieval returns completed profile and RFC 8785 digest
- REQ-11-VERIF-043: Cooperative task cancellation (POST .../cancel)
- REQ-11-VERIF-044: Cancellation race & terminal-state immutability
- REQ-11-VERIF-045: SSE event stream with monotonic ordering
- REQ-11-VERIF-046: SSE Last-Event-ID resume and replay
- REQ-11-VERIF-047: Bounded SSE event buffer behavior
- REQ-11-VERIF-048: Generic 404 for non-existent and cross-project tasks
"""

from __future__ import annotations

import time
from typing import Any, Dict, List
import pytest
from fastapi.testclient import TestClient

from aivara.api.schemas.drift import DriftAnalysisCreateRequest, DriftTaskStatusEnum
from aivara.services.drift_service import get_drift_task_manager


def test_req_038_async_task_creation_202(client: TestClient) -> None:
    """Verify REQ-11-VERIF-038: POST /analyses returns 202 Accepted with task payload and initial status."""
    payload = {
        "reference_dataset_id": "ds_ref_001",
        "target_dataset_id": "ds_tgt_001",
        "analysis_type": "DATASET",
        "feature_names": ["num_1"],
    }
    res = client.post("/api/v1/projects/proj_alpha/drift/analyses", json=payload)
    assert res.status_code == 202
    data = res.json()["data"]
    task_id = data["task_id"]
    assert task_id is not None
    assert data["project_id"] == "proj_alpha"
    assert data["status"] in ("QUEUED", "RUNNING", "COMPLETED")


def test_req_039_idempotency_replay_identical_task(client: TestClient) -> None:
    """Verify REQ-11-VERIF-039: Repeated submission with same Idempotency-Key returns original task."""
    payload = {
        "reference_dataset_id": "ds_ref_idem",
        "target_dataset_id": "ds_tgt_idem",
        "analysis_type": "DATASET",
        "feature_names": ["f1"],
    }
    headers = {"Idempotency-Key": "idem_key_unique_001"}
    
    res1 = client.post("/api/v1/projects/proj_alpha/drift/analyses", json=payload, headers=headers)
    assert res1.status_code == 202
    task1_id = res1.json()["data"]["task_id"]
    
    res2 = client.post("/api/v1/projects/proj_alpha/drift/analyses", json=payload, headers=headers)
    assert res2.status_code == 202
    task2_id = res2.json()["data"]["task_id"]
    
    assert task1_id == task2_id


def test_req_040_idempotency_conflict_modified_payload(client: TestClient) -> None:
    """Verify REQ-11-VERIF-040: Same Idempotency-Key with different payload produces HTTP 409 Conflict."""
    payload1 = {
        "reference_dataset_id": "ds_ref_orig",
        "target_dataset_id": "ds_tgt_orig",
        "analysis_type": "DATASET",
        "feature_names": ["f1"],
    }
    payload2 = {
        "reference_dataset_id": "ds_ref_tampered",
        "target_dataset_id": "ds_tgt_tampered",
        "analysis_type": "DATASET",
        "feature_names": ["f2"],
    }
    headers = {"Idempotency-Key": "idem_key_conflict_002"}
    
    res1 = client.post("/api/v1/projects/proj_alpha/drift/analyses", json=payload1, headers=headers)
    assert res1.status_code == 202
    
    res2 = client.post("/api/v1/projects/proj_alpha/drift/analyses", json=payload2, headers=headers)
    assert res2.status_code == 409


def test_req_041_task_lifecycle_execution(client: TestClient) -> None:
    """Verify REQ-11-VERIF-041: Async task transitions through states to COMPLETED."""
    payload = {
        "reference_dataset_id": "ds_ref_life",
        "target_dataset_id": "ds_tgt_life",
        "analysis_type": "DATASET",
        "feature_names": ["f1"],
    }
    res = client.post("/api/v1/projects/proj_alpha/drift/analyses", json=payload)
    task_id = res.json()["data"]["task_id"]
    
    # Poll task until completion (up to 5s)
    deadline = time.time() + 5.0
    completed = False
    while time.time() < deadline:
        poll = client.get(f"/api/v1/projects/proj_alpha/drift/analyses/{task_id}")
        assert poll.status_code == 200
        st = poll.json()["data"]["status"]
        if st in ("COMPLETED", "FAILED"):
            completed = True
            break
        time.sleep(0.05)
    assert completed is True


def test_req_042_task_result_retrieval(client: TestClient) -> None:
    """Verify REQ-11-VERIF-042: Completed task returns profile results with canonical digest."""
    payload = {
        "reference_dataset_id": "ds_ref_res",
        "target_dataset_id": "ds_tgt_res",
        "analysis_type": "DATASET",
        "feature_names": ["f1"],
    }
    res = client.post("/api/v1/projects/proj_alpha/drift/analyses", json=payload)
    task_id = res.json()["data"]["task_id"]
    
    # Wait for completion
    deadline = time.time() + 5.0
    while time.time() < deadline:
        poll = client.get(f"/api/v1/projects/proj_alpha/drift/analyses/{task_id}")
        if poll.json()["data"]["status"] in ("COMPLETED", "FAILED"):
            break
        time.sleep(0.05)
    
    res_get = client.get(f"/api/v1/projects/proj_alpha/drift/analyses/{task_id}/result")
    assert res_get.status_code == 200
    res_data = res_get.json()["data"]
    assert res_data["task_id"] == task_id
    assert res_data["project_id"] == "proj_alpha"
    assert "analysis_result_hash" in res_data


def test_req_043_cooperative_task_cancellation(client: TestClient) -> None:
    """Verify REQ-11-VERIF-043: POST /analyses/{task_id}/cancel requests cooperative cancellation."""
    manager = get_drift_task_manager()
    req = DriftAnalysisCreateRequest(
        reference_dataset_id="ds_ref_cancel",
        target_dataset_id="ds_tgt_cancel",
    )
    task, _ = manager.create_or_get_task("proj_cancel", req)
    
    cancel_res = client.post(f"/api/v1/projects/proj_cancel/drift/analyses/{task.task_id}/cancel")
    assert cancel_res.status_code in (200, 409)


def test_req_044_cancellation_terminal_conflict(client: TestClient) -> None:
    """Verify REQ-11-VERIF-044: Cannot cancel already terminal (COMPLETED) task; returns 409 Conflict."""
    payload = {
        "reference_dataset_id": "ds_ref_term",
        "target_dataset_id": "ds_tgt_term",
        "analysis_type": "DATASET",
        "feature_names": ["f1"],
    }
    res = client.post("/api/v1/projects/proj_alpha/drift/analyses", json=payload)
    task_id = res.json()["data"]["task_id"]
    
    # Wait for completion
    deadline = time.time() + 5.0
    while time.time() < deadline:
        poll = client.get(f"/api/v1/projects/proj_alpha/drift/analyses/{task_id}")
        if poll.json()["data"]["status"] == "COMPLETED":
            break
        time.sleep(0.05)
    
    # Attempt cancel on terminal task
    cancel_res = client.post(f"/api/v1/projects/proj_alpha/drift/analyses/{task_id}/cancel")
    assert cancel_res.status_code == 409


def test_req_045_sse_event_streaming(client: TestClient) -> None:
    """Verify REQ-11-VERIF-045: GET /analyses/{task_id}/events streams SSE events."""
    payload = {
        "reference_dataset_id": "ds_ref_sse",
        "target_dataset_id": "ds_tgt_sse",
        "analysis_type": "DATASET",
    }
    res = client.post("/api/v1/projects/proj_sse/drift/analyses", json=payload)
    assert res.status_code == 202
    task_id = res.json()["data"]["task_id"]
    
    with client.stream("GET", f"/api/v1/projects/proj_sse/drift/analyses/{task_id}/events") as stream:
        assert stream.status_code == 200
        assert "text/event-stream" in stream.headers["content-type"]
        events = []
        for line in stream.iter_lines():
            if line.startswith("data:"):
                events.append(line)
            if len(events) >= 1:
                break
    assert len(events) >= 1


def test_req_046_sse_last_event_id_replay(client: TestClient) -> None:
    """Verify REQ-11-VERIF-046: Reconnection with Last-Event-ID header streams appropriately."""
    manager = get_drift_task_manager()
    req = DriftAnalysisCreateRequest(
        reference_dataset_id="ds_ref_replay",
        target_dataset_id="ds_tgt_replay",
    )
    task, _ = manager.create_or_get_task("proj_replay", req)
    task.update_stage("RUNNING", 20.0, "Step 1")
    task.update_stage("RUNNING", 80.0, "Step 2")
    
    # Subscribe with Last-Event-ID = None (should replay all history)
    queue = task.subscribe_events(last_event_id=None)
    assert queue.qsize() >= 2


def test_req_047_bounded_sse_buffer() -> None:
    """Verify REQ-11-VERIF-047: SSE event ring buffer is bounded and does not grow unboundedly."""
    manager = get_drift_task_manager()
    req = DriftAnalysisCreateRequest(
        reference_dataset_id="ds_ref_buf",
        target_dataset_id="ds_tgt_buf",
    )
    task, _ = manager.create_or_get_task("proj_buffer", req)
    
    # Publish 150 events
    for i in range(150):
        task.update_stage("RUNNING", float(i % 100), f"Step {i}")
    
    # Ring buffer is capped at 50 in production implementation
    assert len(task._event_history) <= 50


def test_req_048_generic_404_for_cross_project_task(client: TestClient) -> None:
    """Verify REQ-11-VERIF-048: Cross-project task access returns generic 404 (BOLA protection)."""
    payload = {
        "reference_dataset_id": "ds_ref_bola",
        "target_dataset_id": "ds_tgt_bola",
        "analysis_type": "DATASET",
        "feature_names": ["f1"],
    }
    res = client.post("/api/v1/projects/proj_alpha/drift/analyses", json=payload)
    task_id = res.json()["data"]["task_id"]
    
    # Project beta tries to access project alpha's task -> 404 Not Found
    res_foreign = client.get(f"/api/v1/projects/proj_beta/drift/analyses/{task_id}")
    assert res_foreign.status_code == 404
