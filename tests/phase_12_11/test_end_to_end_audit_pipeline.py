"""Test End-to-End Pipeline from Task Evaluation to Audit Report Generation (Phase 12.11)."""

import time
import pytest
from fastapi.testclient import TestClient

from aivara.main import app
from aivara.universal.api.enums import UniversalTaskStatus


@pytest.fixture
def client():
    return TestClient(app)


def test_full_pipeline_task_to_audit_report(client):
    """Verify task submission -> execution -> audit report generation -> compliance evaluation -> export."""
    project_id = "proj-e2e-audit-1"

    # 1. Initiate Assurance Task
    task_payload = {
        "project_id": project_id,
        "asset_ids": ["model-weights-v1", "dataset-v1"],
        "evidence_items": [
            {
                "evidence_id": "ev-drift-101",
                "domain": "distribution_shift",
                "evidence_layer": "detection",
                "primary_asset_id": "dataset-v1",
                "primary_asset_type": "dataset",
                "severity": "low",
                "confidence": 0.95,
                "ancestry_path": {"sample_id": "sample-001"},
            },
            {
                "evidence_id": "ev-proof-102",
                "domain": "model_integrity",
                "evidence_layer": "proof",
                "primary_asset_id": "model-weights-v1",
                "primary_asset_type": "model",
                "severity": "info",
                "confidence": 1.0,
                "ancestry_path": {"model_fingerprint": "fp_sha256_model_001"},
            },
        ],
        "dependency_edges": [
            {
                "project_id": project_id,
                "source_asset_id": "dataset-v1",
                "target_asset_id": "model-weights-v1",
                "edge_type": "FEEDS",
                "propagation_weight": 0.8,
            }
        ],
        "asset_roles": {
            "model-weights-v1": "CORE_DEPLOYED",
            "dataset-v1": "SUPPORTING_INPUT",
        },
    }

    resp = client.post(f"/api/v1/projects/{project_id}/universal/assurance/tasks", json=task_payload)
    assert resp.status_code == 202
    task_id = resp.json()["data"]["task_id"]

    # 2. Wait for completion
    completed = False
    for _ in range(50):
        s = client.get(f"/api/v1/projects/{project_id}/universal/assurance/tasks/{task_id}").json()["data"]
        if s["status"] in (UniversalTaskStatus.COMPLETED.value, UniversalTaskStatus.FAILED.value):
            if s["status"] == UniversalTaskStatus.COMPLETED.value:
                completed = True
            break
        time.sleep(0.05)

    assert completed, f"Task failed: {s}"

    # 3. Generate Audit Report referencing completed task
    report_resp = client.post(
        f"/api/v1/projects/{project_id}/universal/audit/reports",
        json={"project_id": project_id, "task_id": task_id, "report_name": "E2E Audit Report"},
    )
    assert report_resp.status_code == 201
    rep = report_resp.json()["data"]
    report_id = rep["report_id"]
    assert len(rep["report_hash"]) == 64
    assert rep["risk_summary"]["asset_count"] == 2
    assert len(rep["compliance_results"]) > 0

    # 4. Verify Cryptographic Integrity
    ver_resp = client.post(f"/api/v1/projects/{project_id}/universal/audit/reports/{report_id}/verify")
    assert ver_resp.status_code == 200
    assert ver_resp.json()["data"]["status"] == "VERIFIED"

    # 5. Export Report to Markdown
    export_resp = client.get(f"/api/v1/projects/{project_id}/universal/audit/reports/{report_id}/export?format=MARKDOWN")
    assert export_resp.status_code == 200
    assert "## 1. Executive Summary & Disposition" in export_resp.text
    assert "## 4. Compliance Framework Evaluation" in export_resp.text
