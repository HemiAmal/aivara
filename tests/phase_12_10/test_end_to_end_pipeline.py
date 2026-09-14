"""End-to-end full universal assurance pipeline test for Phase 12.10."""

import time
import pytest
from fastapi.testclient import TestClient

from aivara.main import app
from aivara.universal.api.enums import UniversalTaskStatus


@pytest.fixture
def client():
    return TestClient(app)


def test_full_pipeline_with_multiple_assets_and_edges(client):
    """Verify full end-to-end flow across multi-domain evidence, graph, risk, policy, proof, and aggregation."""
    project_id = "proj-e2e-universal"

    # Multi-asset pipeline: Dataset -> Model -> Inference
    payload = {
        "project_id": project_id,
        "asset_ids": ["dataset-v1", "model-weights-v1", "inference-pipeline-v1"],
        "evidence_items": [
            {
                "evidence_id": "ev-data-1",
                "project_id": project_id,
                "source_subsystem": "DATASET_INTEGRITY",
                "evidence_layer": "detection",
                "evidence_type": "LABEL_ANOMALY",
                "severity": "high",
                "confidence": 0.90,
                "primary_asset_type": "dataset",
                "primary_asset_id": "dataset-v1",
                "ancestry_keys": {"dataset_version_id": "dv-1"},
                "data_json": {"anomaly_score": 0.85},
            },
            {
                "evidence_id": "ev-model-1",
                "project_id": project_id,
                "source_subsystem": "MODEL_INTEGRITY",
                "evidence_layer": "proof",
                "evidence_type": "WEIGHT_FINGERPRINT",
                "severity": "critical",
                "confidence": 1.0,
                "primary_asset_type": "model",
                "primary_asset_id": "model-weights-v1",
                "ancestry_keys": {"model_fingerprint": "fp-123"},
                "data_json": {"fingerprint_verified": True},
            },
        ],
        "dependency_edges": [
            {
                "project_id": project_id,
                "source_asset_id": "dataset-v1",
                "target_asset_id": "model-weights-v1",
                "edge_type": "FEEDS",
                "propagation_weight": 0.9,
            },
            {
                "project_id": project_id,
                "source_asset_id": "model-weights-v1",
                "target_asset_id": "inference-pipeline-v1",
                "edge_type": "DEPENDS_ON",
                "propagation_weight": 1.0,
            },
        ],
        "asset_roles": {
            "model-weights-v1": "CORE_DEPLOYED",
            "dataset-v1": "SUPPORTING_INPUT",
            "inference-pipeline-v1": "PERIPHERAL_SAMPLE",
        },
    }

    # 1. Create task
    resp = client.post(f"/api/v1/projects/{project_id}/universal/assurance/tasks", json=payload)
    assert resp.status_code == 202
    task_id = resp.json()["data"]["task_id"]

    # 2. Wait for execution completion
    completed = False
    for _ in range(50):
        s = client.get(f"/api/v1/projects/{project_id}/universal/assurance/tasks/{task_id}").json()["data"]
        if s["status"] in (UniversalTaskStatus.COMPLETED.value, UniversalTaskStatus.FAILED.value):
            if s["status"] == UniversalTaskStatus.COMPLETED.value:
                completed = True
            break
        time.sleep(0.05)

    assert completed, f"Task failed to complete: status={s['status']}, error={s.get('error_message')}"

    # 3. Retrieve completed result
    res_resp = client.get(f"/api/v1/projects/{project_id}/universal/assurance/tasks/{task_id}/result")
    assert res_resp.status_code == 200
    res = res_resp.json()["data"]

    assert res["status"] == UniversalTaskStatus.COMPLETED.value
    assert res["asset_count"] == 3
    assert res["chain_count"] == 2
    assert res["decision"] in ("ACCEPT", "REVIEW", "QUARANTINE", "REJECT")
    assert len(res["asset_assessments"]) == 3
    assert len(res["chain_assessments"]) == 2

    # 4. Check read-back endpoints
    agg_resp = client.get(f"/api/v1/projects/{project_id}/universal/aggregation")
    assert agg_resp.status_code == 200
    assert agg_resp.json()["data"]["project_id"] == project_id
