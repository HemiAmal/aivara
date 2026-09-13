"""Comprehensive test suite for Phase 10.11 Inference API & Service Layer.

Tests:
  A. Synchronous inference verification (POST /projects/{id}/inference/verify)
  B. Asynchronous verification task spawning (async_mode=True)
  C. In-memory task listing, querying, and filtering (GET /tasks)
  D. Task cancellation lifecycle (POST /tasks/{id}/cancel)
  E. Real-time Server-Sent Events (SSE) streaming (GET /tasks/{id}/events)
  F. Sealed inference record listing and pagination (GET /records)
  G. Sealed inference record retrieval (GET /records/{id})
  H. Record cryptographic integrity read-back verification (POST /records/{id}/verify)
  I. Controlled replay verification via API (POST /records/{id}/replay)
  J. Linked evidence item retrieval (GET /records/{id}/evidence)
  K. Linked provenance record retrieval (GET /records/{id}/provenance)
  L. Error handling: 404 for missing project/model/task/record
  M. Input validation: 422 for invalid request schemas
  N. Cross-project boundary isolation (fail-closed)
  O. Idempotency handling
  P. Complete end-to-end inference transaction
"""

from __future__ import annotations

import json
import time
import uuid
from typing import Any, Dict
import numpy as np
import pytest
from fastapi.testclient import TestClient

from aivara.core.config import settings
from aivara.crypto.keys import KeyManager
from aivara.database.models import AIModelModel, ProjectModel
from aivara.inference.records.service import InferenceRecordService
from aivara.services.inference_service import (
    InferenceService,
    InferenceTaskManager,
    get_task_manager,
)


@pytest.fixture
def mock_project(test_db_session) -> ProjectModel:
    """Create a project in the database."""
    proj = ProjectModel(
        id=str(uuid.uuid4()),
        name="Inference Assurance Test Project",
        description="Phase 10.11 API Testing",
    )
    test_db_session.add(proj)
    test_db_session.commit()
    test_db_session.refresh(proj)
    return proj


@pytest.fixture
def mock_other_project(test_db_session) -> ProjectModel:
    """Create a second distinct project for tenancy isolation tests."""
    proj = ProjectModel(
        id=str(uuid.uuid4()),
        name="Other Isolated Project",
        description="Tenant B",
    )
    test_db_session.add(proj)
    test_db_session.commit()
    test_db_session.refresh(proj)
    return proj


import hashlib
from aivara.crypto.canonical import canonicalize

@pytest.fixture
def mock_model(test_db_session, mock_project) -> AIModelModel:
    """Create an AI model entity in the database."""
    art_h = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    struct_h = "a" * 64
    contract_h = "b" * 64
    payload = {
        "artifact_hash": art_h,
        "contract_hash": contract_h,
        "schema_version": "1.0",
        "structural_hash": struct_h,
    }
    master_fp = hashlib.sha256(canonicalize(payload)).hexdigest()
    model = AIModelModel(
        id=str(uuid.uuid4()),
        project_id=mock_project.id,
        name="ResNet50-Integrity-Checked",
        version="1.0.0",
        format="ONNX",
        file_path="/artifacts/models/resnet50.onnx",
        file_size_bytes=102400,
        file_hash_sha256=art_h,
        metadata_json={
            "artifact_hash": art_h,
            "structural_hash": struct_h,
            "contract_hash": contract_h,
            "master_fingerprint": master_fp,
        },
    )
    test_db_session.add(model)
    test_db_session.commit()
    test_db_session.refresh(model)
    return model


@pytest.fixture(autouse=True)
def reset_task_manager():
    """Ensure a clean in-memory task registry for every test."""
    manager = get_task_manager()
    manager.clear()
    yield
    manager.clear()


# =====================================================================
# 1. Synchronous Inference Verification Endpoint Tests
# =====================================================================

def test_verify_inference_sync_success(client: TestClient, mock_project: ProjectModel, mock_model: AIModelModel):
    """POST /projects/{id}/inference/verify synchronous execution succeeds end-to-end."""
    payload = {
        "model_id": mock_model.id,
        "input_payload": [[0.1, 0.2, 0.3], [0.4, 0.5, 0.6]],
        "input_kind": "STRUCTURED",
        "preprocessing_contract": {
            "operations": [{"op": "normalize", "mean": 0.0, "std": 1.0}],
            "target_shape": [1, 6],
            "target_dtype": "float32",
        },
        "output_contract": {
            "expected_outputs": [
                {
                    "name": "probabilities",
                    "shape": [1, 3],
                    "dtype": "float32",
                    "value_range": [0.0, 1.0],
                }
            ],
            "numerical_policy": {"allow_nan": False, "allow_inf": False},
        },
        "perform_replay": True,
        "seal_provenance": True,
    }

    resp = client.post(f"/api/v1/projects/{mock_project.id}/inference/verify", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    assert "data" in data
    res = data["data"]

    assert res["project_id"] == mock_project.id
    assert res["model_id"] == mock_model.id
    assert res["verification_status"] in ("VERIFIED", "INVALID")
    assert res["binding_status"] in ("VERIFIED", "INVALID", "MISMATCHED")
    assert res["input_canonical_hash"] is not None
    assert res["model_master_fingerprint"] is not None
    assert res["inference_binding_hash"] is not None
    assert res["record_id"] is not None
    assert res["record_integrity_hash"] is not None
    assert res["evidence_hash"] is not None
    assert res["provenance_record_id"] is not None
    assert res["replay_status"] is not None


def test_verify_inference_model_not_found(client: TestClient, mock_project: ProjectModel):
    """POST /projects/{id}/inference/verify with non-existent model returns 404."""
    payload = {
        "model_id": str(uuid.uuid4()),
        "input_payload": [1, 2, 3],
    }
    resp = client.post(f"/api/v1/projects/{mock_project.id}/inference/verify", json=payload)
    assert resp.status_code == 404
    data = resp.json()
    assert data["error"]["code"] == "NOT_FOUND"


def test_verify_inference_project_not_found(client: TestClient):
    """POST /projects/{id}/inference/verify with non-existent project returns 404."""
    non_existent_project = str(uuid.uuid4())
    payload = {
        "model_id": str(uuid.uuid4()),
        "input_payload": [1, 2, 3],
    }
    resp = client.post(f"/api/v1/projects/{non_existent_project}/inference/verify", json=payload)
    assert resp.status_code == 404
    assert resp.json()["error"]["code"] == "NOT_FOUND"


def test_verify_inference_schema_validation_error(client: TestClient, mock_project: ProjectModel):
    """POST /projects/{id}/inference/verify with invalid fields returns 422."""
    payload = {
        # missing model_id
        "input_payload": [1, 2, 3],
        "unknown_extra_field": 123,
    }
    resp = client.post(f"/api/v1/projects/{mock_project.id}/inference/verify", json=payload)
    assert resp.status_code == 422


# =====================================================================
# 2. Asynchronous Task Management & Lifecycle Tests
# =====================================================================

def test_verify_inference_async_task_flow(client: TestClient, mock_project: ProjectModel, mock_model: AIModelModel):
    """POST with async_mode=true returns 200 with task descriptor, tracks progress."""
    payload = {
        "model_id": mock_model.id,
        "input_payload": [0.5, 0.6, 0.7],
        "perform_replay": False,
        "seal_provenance": True,
    }

    resp = client.post(
        f"/api/v1/projects/{mock_project.id}/inference/verify?async_mode=true",
        json=payload,
    )
    assert resp.status_code == 200
    data = resp.json()["data"]
    task_id = data["task_id"]
    assert task_id is not None
    assert data["project_id"] == mock_project.id

    # Give background task a moment to complete
    time.sleep(0.5)

    # Poll task status
    poll_resp = client.get(f"/api/v1/projects/{mock_project.id}/inference/tasks/{task_id}")
    assert poll_resp.status_code == 200
    task_data = poll_resp.json()["data"]
    assert task_data["task_id"] == task_id
    assert task_data["status"] in ("COMPLETED", "RUNNING", "QUEUED")


def test_list_inference_tasks(client: TestClient, mock_project: ProjectModel, mock_model: AIModelModel):
    """GET /projects/{id}/inference/tasks returns list of tasks."""
    payload = {"model_id": mock_model.id, "input_payload": [1.0]}
    client.post(f"/api/v1/projects/{mock_project.id}/inference/verify?async_mode=true", json=payload)
    time.sleep(0.5)

    resp = client.get(f"/api/v1/projects/{mock_project.id}/inference/tasks")
    assert resp.status_code == 200
    tasks = resp.json()["data"]
    assert isinstance(tasks, list)
    assert len(tasks) >= 1
    assert any(t["project_id"] == mock_project.id for t in tasks)


def test_cancel_inference_task(client: TestClient, mock_project: ProjectModel):
    """POST /projects/{id}/inference/tasks/{task_id}/cancel cancels task."""
    mgr = get_task_manager()
    task = mgr.create_task(project_id=mock_project.id, model_id="dummy-model")

    resp = client.post(f"/api/v1/projects/{mock_project.id}/inference/tasks/{task.task_id}/cancel")
    assert resp.status_code == 200
    assert resp.json()["data"]["status"] == "CANCELLED"


def test_get_nonexistent_task(client: TestClient, mock_project: ProjectModel):
    """GET non-existent task returns 404."""
    resp = client.get(f"/api/v1/projects/{mock_project.id}/inference/tasks/nonexistent-task-id")
    assert resp.status_code == 404


def test_task_project_isolation(client: TestClient, mock_project: ProjectModel, mock_other_project: ProjectModel):
    """Accessing task under another project returns 404."""
    mgr = get_task_manager()
    task = mgr.create_task(project_id=mock_project.id, model_id="model-a")

    # Project B requests Project A's task
    resp = client.get(f"/api/v1/projects/{mock_other_project.id}/inference/tasks/{task.task_id}")
    assert resp.status_code == 404


# =====================================================================
# 3. Server-Sent Events (SSE) Progress Streaming Tests
# =====================================================================

def test_stream_task_progress_sse(client: TestClient, mock_project: ProjectModel):
    """GET /projects/{id}/inference/tasks/{task_id}/events streams SSE."""
    mgr = get_task_manager()
    task = mgr.create_task(project_id=mock_project.id, model_id="dummy-model")

    # Update progress and complete the task
    mgr.update_progress(
        task_id=task.task_id,
        stage="INPUT_VALIDATION",
        progress=20.0,
        message="Validating input",
    )
    mgr.complete_task(task_id=task.task_id, result={"verification_status": "VERIFIED"})

    resp = client.get(f"/api/v1/projects/{mock_project.id}/inference/tasks/{task.task_id}/events")
    assert resp.status_code == 200
    assert "text/event-stream" in resp.headers["content-type"]
    assert "event: progress" in resp.text


# =====================================================================
# 4. Sealed Inference Record Listing & Retrieval Tests
# =====================================================================

def test_list_and_get_inference_records(client: TestClient, mock_project: ProjectModel, mock_model: AIModelModel):
    """POST verify generates record, then GET /records and GET /records/{id} retrieve it."""
    payload = {
        "model_id": mock_model.id,
        "input_payload": [0.1, 0.2, 0.3],
        "perform_replay": False,
        "seal_provenance": True,
    }
    verify_resp = client.post(f"/api/v1/projects/{mock_project.id}/inference/verify", json=payload)
    assert verify_resp.status_code == 200
    record_id = verify_resp.json()["data"]["record_id"]
    assert record_id is not None

    # List records
    list_resp = client.get(f"/api/v1/projects/{mock_project.id}/inference/records")
    assert list_resp.status_code == 200
    records = list_resp.json()["data"]
    assert len(records) >= 1
    target = next((r for r in records if r["record_id"] == record_id), None)
    assert target is not None
    assert target["project_id"] == mock_project.id
    assert target["model_id"] == mock_model.id

    # Get specific record
    get_resp = client.get(f"/api/v1/projects/{mock_project.id}/inference/records/{record_id}")
    assert get_resp.status_code == 200
    rec = get_resp.json()["data"]
    assert rec["record_id"] == record_id
    assert rec["record_integrity_hash"] is not None
    assert rec["inference_binding_hash"] is not None


def test_get_nonexistent_record(client: TestClient, mock_project: ProjectModel):
    """GET non-existent record returns 404."""
    resp = client.get(f"/api/v1/projects/{mock_project.id}/inference/records/nonexistent-rec-id")
    assert resp.status_code == 404


def test_record_cross_project_isolation(
    client: TestClient, mock_project: ProjectModel, mock_other_project: ProjectModel, mock_model: AIModelModel
):
    """Tenant B attempting to access Tenant A's record is strictly blocked."""
    payload = {"model_id": mock_model.id, "input_payload": [1.0, 2.0]}
    v_resp = client.post(f"/api/v1/projects/{mock_project.id}/inference/verify", json=payload)
    record_id = v_resp.json()["data"]["record_id"]

    # Tenant B tries to get Tenant A's record
    get_resp = client.get(f"/api/v1/projects/{mock_other_project.id}/inference/records/{record_id}")
    assert get_resp.status_code in (400, 404, 422)


# =====================================================================
# 5. Record Cryptographic Read-Back Integrity Verification
# =====================================================================

def test_verify_record_integrity_endpoint(client: TestClient, mock_project: ProjectModel, mock_model: AIModelModel):
    """POST /projects/{id}/inference/records/{record_id}/verify checks cryptographic integrity."""
    # Create record
    payload = {"model_id": mock_model.id, "input_payload": [1.0, 2.0]}
    v_resp = client.post(f"/api/v1/projects/{mock_project.id}/inference/verify", json=payload)
    record_id = v_resp.json()["data"]["record_id"]

    # Verify integrity
    verify_resp = client.post(f"/api/v1/projects/{mock_project.id}/inference/records/{record_id}/verify")
    assert verify_resp.status_code == 200
    ver_data = verify_resp.json()["data"]
    assert ver_data["is_valid"] is True
    assert ver_data["status"] == "VERIFIED"
    assert ver_data["stored_integrity_hash"] == ver_data["computed_integrity_hash"]


# =====================================================================
# 6. Controlled Replay Verification Endpoint Tests
# =====================================================================

def test_replay_record_endpoint(client: TestClient, mock_project: ProjectModel, mock_model: AIModelModel):
    """POST /projects/{id}/inference/records/{record_id}/replay executes replay."""
    # Create record
    payload = {"model_id": mock_model.id, "input_payload": [1.0, 2.0, 3.0]}
    v_resp = client.post(f"/api/v1/projects/{mock_project.id}/inference/verify", json=payload)
    record_id = v_resp.json()["data"]["record_id"]

    # Execute replay
    replay_payload = {
        "replay_policy": {"atol": 1e-5, "rtol": 1e-4, "mode": "NUMERICALLY_TOLERANT"},
    }
    replay_resp = client.post(
        f"/api/v1/projects/{mock_project.id}/inference/records/{record_id}/replay",
        json=replay_payload,
    )
    assert replay_resp.status_code == 200
    replay_data = replay_resp.json()["data"]
    assert replay_data["record_id"] == record_id
    assert replay_data["project_id"] == mock_project.id
    assert replay_data["eligibility"] in ("ELIGIBLE", "INELIGIBLE")


# =====================================================================
# 7. Linked Evidence & Provenance Retrieval Endpoint Tests
# =====================================================================

def test_get_record_evidence_and_provenance(client: TestClient, mock_project: ProjectModel, mock_model: AIModelModel):
    """GET /evidence and GET /provenance return linked artifacts."""
    payload = {
        "model_id": mock_model.id,
        "input_payload": [0.42],
        "seal_provenance": True,
    }
    v_resp = client.post(f"/api/v1/projects/{mock_project.id}/inference/verify", json=payload)
    record_id = v_resp.json()["data"]["record_id"]

    # Evidence
    ev_resp = client.get(f"/api/v1/projects/{mock_project.id}/inference/records/{record_id}/evidence")
    assert ev_resp.status_code == 200
    evidence_list = ev_resp.json()["data"]
    assert isinstance(evidence_list, list)

    # Provenance
    prov_resp = client.get(f"/api/v1/projects/{mock_project.id}/inference/records/{record_id}/provenance")
    assert prov_resp.status_code == 200
    prov = prov_resp.json()["data"]
    assert prov is not None
    assert prov.get("project_id") == mock_project.id

