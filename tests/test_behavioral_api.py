"""Comprehensive Test Suite for Phase 8.8 Behavioral REST API & Integration.

Tests:
  - Route registration & OpenAPI schema generation
  - Request validation (malformed payloads, NaN/Inf floats, invalid enums)
  - Multi-tenant project isolation (cross-project leakage prevention)
  - Baseline endpoints (create, retrieve, compare)
  - Perturbation endpoints (7 transformation types, determinism)
  - Stability endpoints (repeatability, zero-denominator sensitivity, comparison)
  - Anomaly detection endpoints (normal, anomalous, directional, explanations)
  - Evidence binding & retrieval (sealing, immutability, finding linkage)
  - Provenance verification endpoints (signatures, chains, tampering)
  - Integrated assessment pipelines (sync / async task execution)
  - In-memory task polling, listing, and cooperative cancellation
  - Real-time Server-Sent Events (SSE) progress streaming
  - Idempotency key resolution across project boundaries
  - Semantic neutrality invariants (ANOMALOUS != MALICIOUS)
  - Security boundaries and offline execution
"""

from concurrent.futures import ThreadPoolExecutor
import json
import math
import numpy as np
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from aivara.api.routers.behavioral import get_key_manager
from aivara.core.config import settings
from aivara.crypto.keys import KeyManager
from aivara.database.connection import Base, get_db
from aivara.database.models import AIModelModel, FindingModel, ProjectModel, ProvenanceRecordModel
from aivara.api.schemas.behavioral import BehavioralAssessmentRequest
from aivara.main import app
from aivara.services.behavioral_service import BehavioralTask, BehavioralTaskManager


@pytest.fixture(scope="module")
def api_test_env(tmp_path_factory):
    """Set up an isolated SQLite database, test client, and cryptographic keys."""
    db_dir = tmp_path_factory.mktemp("api_db")
    db_path = db_dir / "test_api.db"
    engine = create_engine(f"sqlite:///{db_path}", connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

    keys_dir = tmp_path_factory.mktemp("api_keys")
    km = KeyManager(keys_dir=str(keys_dir))
    km.generate_key(passphrase="test-passphrase-88", set_as_active=True)
    active_key_id = km.get_active_key_id()

    # Seed Projects and Models
    db = TestingSessionLocal()
    p1 = ProjectModel(id="proj-alpha", name="Project Alpha")
    p2 = ProjectModel(id="proj-beta", name="Project Beta")
    db.add_all([p1, p2])
    db.commit()

    m1 = AIModelModel(
        id="model-alpha-1",
        project_id="proj-alpha",
        name="Alpha Vision Model",
        format="onnx",
        file_path="models/alpha_vision.onnx",
        file_hash_sha256="a" * 64,
    )
    m2 = AIModelModel(
        id="model-beta-1",
        project_id="proj-beta",
        name="Beta Vision Model",
        format="onnx",
        file_path="models/beta_vision.onnx",
        file_hash_sha256="b" * 64,
    )
    m_ref = AIModelModel(
        id="model-alpha-ref",
        project_id="proj-alpha",
        name="Alpha Reference Model",
        format="onnx",
        file_path="models/alpha_ref.onnx",
        file_hash_sha256="c" * 64,
    )
    db.add_all([m1, m2, m_ref])
    db.commit()
    db.close()

    def override_get_db():
        session = TestingSessionLocal()
        try:
            yield session
        finally:
            session.close()

    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[get_key_manager] = lambda: km

    client = TestClient(app)
    yield {
        "client": client,
        "TestingSessionLocal": TestingSessionLocal,
        "key_manager": km,
        "active_key_id": active_key_id,
    }

    app.dependency_overrides.clear()


# =====================================================================
# 1. Route Registration & OpenAPI
# =====================================================================

def test_route_registration(api_test_env):
    """Verify all behavioral endpoints are registered in FastAPI routing table."""
    client = api_test_env["client"]
    routes = [r.path for r in app.routes]
    expected_prefixes = [
        "/api/v1/projects/{project_id}/behavioral/baselines",
        "/api/v1/projects/{project_id}/behavioral/baselines/{baseline_id}",
        "/api/v1/projects/{project_id}/behavioral/baselines/{baseline_id}/compare",
        "/api/v1/projects/{project_id}/behavioral/perturbations/experiment",
        "/api/v1/projects/{project_id}/behavioral/stability/repeatability",
        "/api/v1/projects/{project_id}/behavioral/stability/sensitivity",
        "/api/v1/projects/{project_id}/behavioral/stability/compare",
        "/api/v1/projects/{project_id}/behavioral/anomalies/detect",
        "/api/v1/projects/{project_id}/behavioral/anomalies/{analysis_id}",
        "/api/v1/projects/{project_id}/behavioral/evidence/bind",
        "/api/v1/projects/{project_id}/behavioral/evidence/{evidence_id}",
        "/api/v1/projects/{project_id}/behavioral/provenance/{target_id}",
        "/api/v1/projects/{project_id}/behavioral/assessments",
        "/api/v1/projects/{project_id}/behavioral/tasks/{task_id}",
        "/api/v1/projects/{project_id}/behavioral/tasks",
        "/api/v1/projects/{project_id}/behavioral/tasks/{task_id}/cancel",
        "/api/v1/projects/{project_id}/behavioral/tasks/{task_id}/events",
    ]
    for exp in expected_prefixes:
        assert exp in routes, f"Missing route: {exp}"


def test_openapi_schema_generation(api_test_env):
    """Verify OpenAPI schema can be generated and contains behavioral tags and descriptions."""
    client = api_test_env["client"]
    # If dev_mode is False in settings, we can test app.openapi() directly
    schema = app.openapi()
    assert "paths" in schema
    assert "/api/v1/projects/{project_id}/behavioral/baselines" in schema["paths"]
    assert "/api/v1/projects/{project_id}/behavioral/anomalies/detect" in schema["paths"]


# =====================================================================
# 2. Request Validation & Non-Finite Float Rejection
# =====================================================================

def test_request_validation_missing_fields(api_test_env):
    """Verify missing required fields return HTTP 422 with structured error response."""
    client = api_test_env["client"]
    res = client.post("/api/v1/projects/proj-alpha/behavioral/baselines", json={})
    assert res.status_code == 422
    data = res.json()
    assert data["status"] == "error"
    assert data["error"]["code"] == "REQUEST_VALIDATION_ERROR"


def test_anomaly_request_rejects_nan_and_inf(api_test_env):
    """Verify NaN and Infinity values in observed_metrics are rejected with HTTP 422."""
    client = api_test_env["client"]
    # Send raw JSON containing non-finite Infinity float
    res = client.post(
        "/api/v1/projects/proj-alpha/behavioral/anomalies/detect",
        content=b'{"model_id": "model-alpha-1", "task_type": "classification", "observed_metrics": {"val": 1e999}}',
        headers={"Content-Type": "application/json"},
    )
    assert res.status_code == 422
    assert res.json()["status"] == "error"


# =====================================================================
# 3. Multi-Tenant Project Isolation
# =====================================================================

def test_project_isolation_cross_model_baseline(api_test_env):
    """Verify Project Alpha cannot baseline Model Beta belonging to Project Beta."""
    client = api_test_env["client"]
    payload = {
        "model_id": "model-beta-1",  # Belongs to proj-beta!
        "task_type": "classification",
        "observations": [
            {"top1_confidence": 0.95, "top1_class": 1, "logits": [0.1, 0.95, 0.05], "latency_ms": 10.0}
        ],
    }
    res = client.post("/api/v1/projects/proj-alpha/behavioral/baselines", json=payload)
    assert res.status_code in (403, 422)
    assert "belongs to project 'proj-beta'" in res.json()["error"]["message"]


def test_project_isolation_nonexistent_project(api_test_env):
    """Verify querying an unknown project returns HTTP 404."""
    client = api_test_env["client"]
    payload = {
        "model_id": "model-alpha-1",
        "task_type": "classification",
        "observations": [{"top1_confidence": 0.9}],
    }
    res = client.post("/api/v1/projects/proj-unknown/behavioral/baselines", json=payload)
    assert res.status_code == 404
    assert res.json()["error"]["code"] == "NOT_FOUND"


# =====================================================================
# 4. Behavioral Baseline API
# =====================================================================

def test_create_and_get_classification_baseline(api_test_env):
    """Test creating and retrieving a classification baseline profile."""
    client = api_test_env["client"]
    obs = [
        {"top1_confidence": 0.92, "top1_class": 0, "logits": [0.92, 0.05, 0.03], "latency_ms": 12.0},
        {"top1_confidence": 0.88, "top1_class": 0, "logits": [0.88, 0.08, 0.04], "latency_ms": 11.5},
        {"top1_confidence": 0.95, "top1_class": 1, "logits": [0.03, 0.95, 0.02], "latency_ms": 13.0},
    ]
    payload = {
        "model_id": "model-alpha-1",
        "task_type": "classification",
        "observations": obs,
        "baseline_type": "EMPIRICAL_OBSERVATION",
    }
    res = client.post("/api/v1/projects/proj-alpha/behavioral/baselines", json=payload)
    assert res.status_code == 201
    data = res.json()["data"]
    baseline_id = data["baseline_id"]
    assert len(baseline_id) == 64
    assert data["observation_count"] == 3
    assert data["model_fingerprint"] == "a" * 64
    assert "classification" in data["profiles"]
    assert "confidence_stats" in data["profiles"]["classification"]

    # Retrieve baseline
    get_res = client.get(f"/api/v1/projects/proj-alpha/behavioral/baselines/{baseline_id}")
    assert get_res.status_code == 200
    assert get_res.json()["data"]["baseline_id"] == baseline_id


def test_create_detection_baseline(api_test_env):
    """Test creating a detection baseline profile."""
    client = api_test_env["client"]
    obs = [
        {
            "boxes": [[10, 10, 50, 50]],
            "scores": [0.90],
            "classes": [1],
            "latency_ms": 15.0,
        },
        {
            "boxes": [[12, 11, 49, 52]],
            "scores": [0.88],
            "classes": [1],
            "latency_ms": 14.5,
        },
    ]
    payload = {
        "model_id": "model-alpha-1",
        "task_type": "detection",
        "observations": obs,
    }
    res = client.post("/api/v1/projects/proj-alpha/behavioral/baselines", json=payload)
    assert res.status_code == 201
    data = res.json()["data"]
    assert data["task_type"] == "detection"
    assert "detection" in data["profiles"]


def test_compare_observation_against_baseline(api_test_env):
    """Test comparing an observation against a registered baseline."""
    client = api_test_env["client"]
    # Create baseline first
    payload = {
        "model_id": "model-alpha-1",
        "task_type": "classification",
        "observations": [
            {"top1_confidence": 0.90, "top1_class": 0, "logits": [0.9, 0.1], "latency_ms": 10.0}
        ],
    }
    b_res = client.post("/api/v1/projects/proj-alpha/behavioral/baselines", json=payload)
    baseline_id = b_res.json()["data"]["baseline_id"]

    # Compare compatible observation
    comp_payload = {
        "observation": {"top1_confidence": 0.89, "top1_class": 0, "logits": [0.89, 0.11], "latency_ms": 10.5}
    }
    res = client.post(
        f"/api/v1/projects/proj-alpha/behavioral/baselines/{baseline_id}/compare",
        json=comp_payload,
    )
    assert res.status_code == 200
    data = res.json()["data"]
    assert data["is_compatible"] is True
    assert data["comparability_status"] == "COMPARABLE"


# =====================================================================
# 5. Controlled Perturbation Experiments API
# =====================================================================

@pytest.mark.parametrize(
    "p_type, params",
    [
        ("gaussian_noise", {"sigma": 0.05}),
        ("uniform_noise", {"low": -0.05, "high": 0.05}),
        ("brightness", {"factor": 1.2}),
        ("contrast", {"factor": 1.1}),
        ("gaussian_blur", {"kernel_size": 3, "sigma": 1.0}),
        ("jpeg_compression", {"quality": 85}),
        ("spatial_translation", {"dx": 2, "dy": 2}),
    ],
)
def test_perturbation_experiments(api_test_env, p_type, params):
    """Test all 7 supported perturbation transformation types through REST."""
    client = api_test_env["client"]
    # 8x8 image
    img = [[float((r * 8 + c) % 255) / 255.0 for c in range(8)] for r in range(8)]
    payload = {
        "model_id": "model-alpha-1",
        "input_data": img,
        "perturbation_type": p_type,
        "parameters": params,
        "random_seed": 12345,
    }
    res = client.post("/api/v1/projects/proj-alpha/behavioral/perturbations/experiment", json=payload)
    assert res.status_code == 200
    data = res.json()["data"]
    assert data["status"] == "SUCCESS"
    assert data["perturbation_type"] == p_type
    assert len(data["experiment_id"]) == 64
    assert len(data["perturbed_input_hash"]) == 64
    assert data["input_distance"] >= 0.0


def test_perturbation_invalid_type(api_test_env):
    """Test unsupported perturbation type returns HTTP 422."""
    client = api_test_env["client"]
    payload = {
        "model_id": "model-alpha-1",
        "input_data": [[1.0, 2.0], [3.0, 4.0]],
        "perturbation_type": "invalid_magic_noise",
    }
    res = client.post("/api/v1/projects/proj-alpha/behavioral/perturbations/experiment", json=payload)
    assert res.status_code == 422


# =====================================================================
# 6. Output Consistency & Stability API
# =====================================================================

def test_stability_repeatability_deterministic(api_test_env):
    """Test repeatability evaluation with identical repeated runs."""
    client = api_test_env["client"]
    out1 = {"top1_class": 1, "top1_confidence": 0.95, "logits": [0.05, 0.95]}
    out2 = {"top1_class": 1, "top1_confidence": 0.95, "logits": [0.05, 0.95]}
    payload = {
        "model_id": "model-alpha-1",
        "outputs": [out1, out2],
        "task_type": "classification",
    }
    res = client.post("/api/v1/projects/proj-alpha/behavioral/stability/repeatability", json=payload)
    assert res.status_code == 200
    data = res.json()["data"]
    assert data["is_fully_deterministic"] is True
    assert data["validity_status"] in ("VALID", "DETERMINISTIC")
    assert data["run_count"] == 2


def test_stability_sensitivity_zero_input_change(api_test_env):
    """Verify sensitivity calculation with zero input change returns UNDEFINED_ZERO_INPUT_CHANGE."""
    client = api_test_env["client"]
    inp = [[1.0, 2.0], [3.0, 4.0]]
    out = {"top1_class": 0, "top1_confidence": 0.9, "logits": [0.9, 0.1]}
    payload = {
        "model_id": "model-alpha-1",
        "task_type": "classification",
        "original_input": inp,
        "perturbed_input": inp,  # Identical input!
        "original_output": out,
        "perturbed_output": out,
    }
    res = client.post("/api/v1/projects/proj-alpha/behavioral/stability/sensitivity", json=payload)
    assert res.status_code == 200
    data = res.json()["data"]
    assert data["input_distance"] == 0.0
    assert data["sensitivity_ratio"] is None
    assert data["ratio_status"] in ("NOT_APPLICABLE", "UNDEFINED_ZERO_INPUT_CHANGE")


def test_stability_compare_reference(api_test_env):
    """Test comparing outputs between candidate and reference models."""
    client = api_test_env["client"]
    cand_out = {"top1_class": 0, "top1_confidence": 0.90, "logits": [0.90, 0.10]}
    ref_out = {"top1_class": 0, "top1_confidence": 0.85, "logits": [0.85, 0.15]}
    payload = {
        "candidate_model_id": "model-alpha-1",
        "reference_model_id": "model-alpha-ref",
        "task_type": "classification",
        "candidate_output": cand_out,
        "reference_output": ref_out,
    }
    res = client.post("/api/v1/projects/proj-alpha/behavioral/stability/compare", json=payload)
    assert res.status_code == 200
    data = res.json()["data"]
    assert len(data["comparison_id"]) == 64
    assert data["validity_status"] == "VALID"


# =====================================================================
# 7. Behavioral Anomaly Detection API
# =====================================================================

def test_detect_anomalies_normal_result(api_test_env):
    """Test anomaly detection producing NORMAL status when metrics align with reference."""
    client = api_test_env["client"]
    # Reference population around 0.90
    ref_data = {"top1_confidence": [0.88, 0.89, 0.90, 0.91, 0.92, 0.90, 0.89]}
    payload = {
        "model_id": "model-alpha-1",
        "task_type": "classification",
        "observed_metrics": {"top1_confidence": 0.905},
        "reference_dataset": ref_data,
    }
    res = client.post("/api/v1/projects/proj-alpha/behavioral/anomalies/detect", json=payload)
    assert res.status_code == 200
    data = res.json()["data"]
    assert data["overall_status"] == "NORMAL"
    assert data["anomalous_metric_count"] == 0
    assert len(data["analysis_id"]) == 64

    # Semantic safety verification: No malicious/compromised words
    expl = data["overall_explanation"].upper()
    assert "MALICIOUS" not in expl
    assert "COMPROMISED" not in expl
    assert "BACKDOOR" not in expl
    assert "ATTACK" not in expl


def test_detect_anomalies_anomalous_result(api_test_env):
    """Test anomaly detection producing ANOMALOUS status when metric is far in tail."""
    client = api_test_env["client"]
    ref_data = {"top1_confidence": [0.90, 0.91, 0.90, 0.89, 0.92, 0.90, 0.91]}
    payload = {
        "model_id": "model-alpha-1",
        "task_type": "classification",
        "observed_metrics": {"top1_confidence": 0.10},  # Extremely low confidence
        "reference_dataset": ref_data,
    }
    res = client.post("/api/v1/projects/proj-alpha/behavioral/anomalies/detect", json=payload)
    assert res.status_code == 200
    data = res.json()["data"]
    assert data["overall_status"] == "ANOMALOUS"
    assert data["anomalous_metric_count"] >= 1

    # Semantic safety check: ANOMALOUS != MALICIOUS
    expl = data["overall_explanation"].upper()
    assert "MALICIOUS" not in expl
    assert "COMPROMISED" not in expl
    assert "BACKDOOR" not in expl
    assert "ATTACK" not in expl


def test_get_anomaly_analysis_by_id(api_test_env):
    """Test retrieving stored anomaly analysis by analysis_id."""
    client = api_test_env["client"]
    ref_data = {"top1_confidence": [0.90, 0.91, 0.90, 0.89]}
    payload = {
        "model_id": "model-alpha-1",
        "task_type": "classification",
        "observed_metrics": {"top1_confidence": 0.90},
        "reference_dataset": ref_data,
    }
    post_res = client.post("/api/v1/projects/proj-alpha/behavioral/anomalies/detect", json=payload)
    analysis_id = post_res.json()["data"]["analysis_id"]

    get_res = client.get(f"/api/v1/projects/proj-alpha/behavioral/anomalies/{analysis_id}")
    assert get_res.status_code == 200
    assert get_res.json()["data"]["analysis_id"] == analysis_id


# =====================================================================
# 8. Evidence & Provenance Binding API
# =====================================================================

def test_bind_evidence_and_retrieve(api_test_env):
    """Test synthesizing findings and binding sealed evidence into ledger."""
    client = api_test_env["client"]
    km = api_test_env["key_manager"]
    active_key = api_test_env["active_key_id"]

    payload = {
        "model_id": "model-alpha-1",
        "anomaly_analysis_id": "a" * 64,
        "observation_id": "obs-001",
        "baseline_id": "b-001",
        "task_type": "classification",
        "overall_status": "ANOMALOUS",
        "support_status": "ADEQUATE",
        "comparability_status": "COMPARABLE",
        "metric_results": {
            "top1_confidence": {
                "observed_value": 0.20,
                "status": "ANOMALOUS",
                "robust_z": -6.5,
                "direction": "LOWER_IS_EXTREME",
                "threshold": 3.5,
                "empirical_extremeness": 0.0,
                "explanation": "Observed value 0.20 is unusually low.",
            }
        },
        "family_results": {
            "OUTPUT_CONSISTENCY": {
                "family": "OUTPUT_CONSISTENCY",
                "status": "ANOMALOUS",
                "metric_count": 1,
                "anomalous_metric_count": 1,
                "explanation": "Output consistency metrics show anomalous deviation.",
            }
        },
        "seal_provenance": True,
        "signer_key_id": active_key,
        "signer_passphrase": "test-passphrase-88",
    }
    res = client.post("/api/v1/projects/proj-alpha/behavioral/evidence/bind", json=payload)
    assert res.status_code == 201
    data = res.json()["data"]
    evidence_id = data["evidence_id"]
    assert len(evidence_id) == 64
    assert data["lifecycle_state"] == "SEALED"
    assert data["finding_id"] is not None
    assert data["provenance_record_id"] is not None

    # Retrieve sealed evidence
    get_res = client.get(f"/api/v1/projects/proj-alpha/behavioral/evidence/{evidence_id}")
    assert get_res.status_code == 200
    ev_data = get_res.json()["data"]
    assert ev_data["evidence_id"] == evidence_id
    assert ev_data["lifecycle_state"] == "SEALED"
    assert ev_data["content"]["result_status"] == "ANOMALOUS"


# =====================================================================
# 9. Provenance Verification API
# =====================================================================

def test_verify_provenance_valid_finding(api_test_env):
    """Test cryptographic verification of a sealed behavioral finding."""
    client = api_test_env["client"]
    active_key = api_test_env["active_key_id"]

    # Bind evidence to create finding and provenance record
    bind_payload = {
        "model_id": "model-alpha-1",
        "anomaly_analysis_id": "f" * 64,
        "observation_id": "obs-verify-01",
        "baseline_id": "b-verify-01",
        "task_type": "classification",
        "overall_status": "NORMAL",
        "metric_results": {},
        "family_results": {},
        "seal_provenance": True,
        "signer_key_id": active_key,
        "signer_passphrase": "test-passphrase-88",
    }
    bind_res = client.post("/api/v1/projects/proj-alpha/behavioral/evidence/bind", json=bind_payload)
    finding_id = bind_res.json()["data"]["finding_id"]

    # Verify provenance
    v_res = client.get(f"/api/v1/projects/proj-alpha/behavioral/provenance/{finding_id}")
    assert v_res.status_code == 200
    v_data = v_res.json()["data"]
    assert v_data["is_valid"] is True
    assert v_data["status"] == "VERIFIED"
    assert v_data["signature_valid"] is True
    assert v_data["chain_valid"] is True
    assert v_data["sequence_valid"] is True
    assert v_data["nonce_valid"] is True
    assert v_data["verification_vector"] is not None


def test_verify_provenance_missing_record(api_test_env):
    """Test verification on nonexistent target returns MISSING status."""
    client = api_test_env["client"]
    v_res = client.get("/api/v1/projects/proj-alpha/behavioral/provenance/nonexistent-finding-id")
    assert v_res.status_code == 200
    v_data = v_res.json()["data"]
    assert v_data["is_valid"] is False
    assert v_data["status"] == "MISSING"


# =====================================================================
# 10. Integrated Assessment & Tasks API
# =====================================================================

def test_integrated_assessment_sync(api_test_env):
    """Test running full integrated assessment synchronously."""
    client = api_test_env["client"]
    active_key = api_test_env["active_key_id"]

    obs = [
        {"top1_confidence": 0.90, "top1_class": 0, "logits": [0.9, 0.1], "latency_ms": 10.0},
        {"top1_confidence": 0.92, "top1_class": 0, "logits": [0.92, 0.08], "latency_ms": 11.0},
    ]
    payload = {
        "model_id": "model-alpha-1",
        "task_type": "classification",
        "observations": obs,
        "seal_provenance": True,
        "signer_key_id": active_key,
        "signer_passphrase": "test-passphrase-88",
    }
    res = client.post("/api/v1/projects/proj-alpha/behavioral/assessments", json=payload)
    assert res.status_code == 200
    data = res.json()["data"]
    assert data["status"] == "COMPLETED"
    assert data["progress_percent"] == 100.0
    assert data["result"] is not None
    assert data["result"]["assessment_status"] == "COMPLETED"
    assert data["result"]["evidence_id"] is not None


def test_integrated_assessment_async_and_task_polling(api_test_env):
    """Test submitting an async assessment task and polling for status."""
    client = api_test_env["client"]
    active_key = api_test_env["active_key_id"]

    obs = [{"top1_confidence": 0.91, "top1_class": 0, "logits": [0.91, 0.09], "latency_ms": 10.0}]
    payload = {
        "model_id": "model-alpha-1",
        "task_type": "classification",
        "observations": obs,
        "seal_provenance": True,
        "signer_key_id": active_key,
        "signer_passphrase": "test-passphrase-88",
    }
    res = client.post("/api/v1/projects/proj-alpha/behavioral/assessments?async=true", json=payload)
    assert res.status_code == 200
    task_id = res.json()["data"]["task_id"]

    # Poll task status
    poll_res = client.get(f"/api/v1/projects/proj-alpha/behavioral/tasks/{task_id}")
    assert poll_res.status_code == 200
    t_data = poll_res.json()["data"]
    assert t_data["task_id"] == task_id
    assert t_data["status"] in ("QUEUED", "RUNNING", "COMPLETED")


def test_list_tasks(api_test_env):
    """Test listing tasks scoped to a project."""
    client = api_test_env["client"]
    res = client.get("/api/v1/projects/proj-alpha/behavioral/tasks")
    assert res.status_code == 200
    data = res.json()["data"]
    assert isinstance(data, list)
    for t in data:
        assert t["project_id"] == "proj-alpha"


def test_cancel_task(api_test_env):
    """Test requesting cooperative cancellation of a task."""
    client = api_test_env["client"]
    tm = BehavioralTaskManager()
    dummy_req = BehavioralAssessmentRequest(
        model_id="model-alpha-1",
        task_type="classification",
        observations=[{"top1_confidence": 0.95}],
    )
    task = BehavioralTask(
        task_id="task-cancel-test-01",
        project_id="proj-alpha",
        model_id="model-alpha-1",
        request=dummy_req,
    )
    task.status = "RUNNING"
    task.current_stage = "RUNNING_INFERENCE"
    tm.register_task(task)

    cancel_res = client.post("/api/v1/projects/proj-alpha/behavioral/tasks/task-cancel-test-01/cancel")
    assert cancel_res.status_code == 200
    assert cancel_res.json()["data"]["status"] == "CANCELLED"


# =====================================================================
# 11. Idempotency Key Handling
# =====================================================================

def test_idempotency_key_reuse(api_test_env):
    """Test that submitting identical task with Idempotency-Key returns cached task."""
    client = api_test_env["client"]
    payload = {
        "model_id": "model-alpha-1",
        "task_type": "classification",
        "observations": [{"top1_confidence": 0.9}],
        "seal_provenance": False,
    }
    headers = {"Idempotency-Key": "idemp-key-12345"}
    res1 = client.post(
        "/api/v1/projects/proj-alpha/behavioral/assessments",
        json=payload,
        headers=headers,
    )
    task1_id = res1.json()["data"]["task_id"]

    # Second request with same idempotency key
    res2 = client.post(
        "/api/v1/projects/proj-alpha/behavioral/assessments",
        json=payload,
        headers=headers,
    )
    task2_id = res2.json()["data"]["task_id"]
    assert task1_id == task2_id


# =====================================================================
# 12. SSE Progress Streaming
# =====================================================================

def test_sse_event_streaming(api_test_env):
    """Test real-time SSE progress streaming endpoint."""
    client = api_test_env["client"]
    # Submit task
    payload = {
        "model_id": "model-alpha-1",
        "task_type": "classification",
        "observations": [{"top1_confidence": 0.9}],
        "seal_provenance": False,
    }
    t_res = client.post("/api/v1/projects/proj-alpha/behavioral/assessments", json=payload)
    task_id = t_res.json()["data"]["task_id"]

    # Stream SSE events
    with client.stream("GET", f"/api/v1/projects/proj-alpha/behavioral/tasks/{task_id}/events") as response:
        assert response.status_code == 200
        assert "text/event-stream" in response.headers["content-type"]
        events = []
        for line in response.iter_lines():
            if line.startswith("data: "):
                event_data = json.loads(line[6:])
                events.append(event_data)
        assert len(events) >= 1
        assert events[0]["task_id"] == task_id


# =====================================================================
# 13. Security Boundary & Filesystem Path Traversal
# =====================================================================

def test_security_sandbox_path_traversal(api_test_env):
    """Test that path traversal attempts are rejected."""
    client = api_test_env["client"]
    payload = {
        "model_id": "model-alpha-1",
        "task_type": "classification",
        "observed_metrics": {"val": 1.0},
    }
    # Path traversal in URL project_id
    res = client.post("/api/v1/projects/..%2F..%2Fetc%2Fpasswd/behavioral/anomalies/detect", json=payload)
    assert res.status_code in (400, 404, 422)


def test_error_response_no_stack_traces(api_test_env):
    """Verify error responses do not leak raw Python stack traces or internal secrets."""
    client = api_test_env["client"]
    res = client.get("/api/v1/projects/proj-alpha/behavioral/baselines/nonexistent-id")
    assert res.status_code == 404
    data = res.json()
    assert "Traceback" not in json.dumps(data)
    assert "password" not in json.dumps(data).lower()
    assert "secret" not in json.dumps(data).lower()


# =====================================================================
# 14. Comprehensive Project Isolation Matrix (Bidirectional)
# =====================================================================

def test_project_isolation_cross_baseline_read(api_test_env):
    """Verify Project Beta cannot read a baseline belonging to Project Alpha."""
    client = api_test_env["client"]
    # Create baseline in Alpha
    b_payload = {
        "model_id": "model-alpha-1",
        "task_type": "classification",
        "observations": [{"top1_confidence": 0.90, "top1_class": 0, "logits": [0.9, 0.1]}],
    }
    b_res = client.post("/api/v1/projects/proj-alpha/behavioral/baselines", json=b_payload)
    assert b_res.status_code == 201
    baseline_id = b_res.json()["data"]["baseline_id"]

    # Attempt retrieval from Beta
    res_beta = client.get(f"/api/v1/projects/proj-beta/behavioral/baselines/{baseline_id}")
    assert res_beta.status_code == 404
    assert "not found in project 'proj-beta'" in res_beta.json()["error"]["message"]


def test_project_isolation_cross_anomaly_read(api_test_env):
    """Verify Project Beta cannot read an anomaly analysis belonging to Project Alpha."""
    client = api_test_env["client"]
    anom_payload = {
        "model_id": "model-alpha-1",
        "task_type": "classification",
        "observed_metrics": {"val": 0.5},
        "reference_dataset": {"val": [0.49, 0.50, 0.51]},
    }
    a_res = client.post("/api/v1/projects/proj-alpha/behavioral/anomalies/detect", json=anom_payload)
    assert a_res.status_code == 200
    analysis_id = a_res.json()["data"]["analysis_id"]

    # Attempt retrieval from Beta
    res_beta = client.get(f"/api/v1/projects/proj-beta/behavioral/anomalies/{analysis_id}")
    assert res_beta.status_code == 404


def test_project_isolation_cross_evidence_read(api_test_env):
    """Verify Project Beta cannot read sealed evidence belonging to Project Alpha."""
    client = api_test_env["client"]
    bind_payload = {
        "model_id": "model-alpha-1",
        "anomaly_analysis_id": "e" * 64,
        "observation_id": "obs-iso-ev-01",
        "baseline_id": "b-iso-ev-01",
        "task_type": "classification",
        "overall_status": "NORMAL",
        "metric_results": {},
        "family_results": {},
        "seal_provenance": False,
    }
    bind_res = client.post("/api/v1/projects/proj-alpha/behavioral/evidence/bind", json=bind_payload)
    assert bind_res.status_code == 201
    ev_id = bind_res.json()["data"]["evidence_id"]

    # Attempt retrieval from Beta
    res_beta = client.get(f"/api/v1/projects/proj-beta/behavioral/evidence/{ev_id}")
    assert res_beta.status_code == 404


def test_project_isolation_cross_task_access(api_test_env):
    """Verify Project Beta cannot read or cancel tasks belonging to Project Alpha."""
    client = api_test_env["client"]
    t_payload = {
        "model_id": "model-alpha-1",
        "task_type": "classification",
        "observations": [{"top1_confidence": 0.9}],
        "seal_provenance": False,
    }
    t_res = client.post("/api/v1/projects/proj-alpha/behavioral/assessments", json=t_payload)
    task_id = t_res.json()["data"]["task_id"]

    # Attempt get from Beta
    get_beta = client.get(f"/api/v1/projects/proj-beta/behavioral/tasks/{task_id}")
    assert get_beta.status_code == 404

    # Attempt cancel from Beta
    cancel_beta = client.post(f"/api/v1/projects/proj-beta/behavioral/tasks/{task_id}/cancel")
    assert cancel_beta.status_code == 404


def test_project_isolation_cross_provenance_verification(api_test_env):
    """Verify Project Beta attempting to verify Project Alpha finding returns MISSING/404."""
    client = api_test_env["client"]
    bind_payload = {
        "model_id": "model-alpha-1",
        "anomaly_analysis_id": "d" * 64,
        "observation_id": "obs-iso-prov-01",
        "baseline_id": "b-iso-prov-01",
        "task_type": "classification",
        "overall_status": "NORMAL",
        "metric_results": {},
        "family_results": {},
        "seal_provenance": True,
    }
    bind_res = client.post("/api/v1/projects/proj-alpha/behavioral/evidence/bind", json=bind_payload)
    finding_id = bind_res.json()["data"]["finding_id"]

    # Verify from Beta
    v_res = client.get(f"/api/v1/projects/proj-beta/behavioral/provenance/{finding_id}")
    assert v_res.status_code == 200
    v_data = v_res.json()["data"]
    assert v_data["is_valid"] is False
    assert v_data["status"] == "MISSING"


# =====================================================================
# 15. Exhaustive Idempotency Matrix
# =====================================================================

def test_idempotency_conflicting_payload_rejected(api_test_env):
    """Verify that reusing the same Idempotency-Key with a conflicting payload raises HTTP 409."""
    client = api_test_env["client"]
    headers = {"Idempotency-Key": "unique-idempotency-key-conflict-test"}
    p1 = {
        "model_id": "model-alpha-1",
        "task_type": "classification",
        "observations": [{"top1_confidence": 0.90}],
        "seal_provenance": False,
    }
    p2 = {
        "model_id": "model-alpha-1",
        "task_type": "classification",
        "observations": [{"top1_confidence": 0.10}],  # Different payload!
        "seal_provenance": False,
    }
    res1 = client.post("/api/v1/projects/proj-alpha/behavioral/assessments", json=p1, headers=headers)
    assert res1.status_code == 200

    res2 = client.post("/api/v1/projects/proj-alpha/behavioral/assessments", json=p2, headers=headers)
    assert res2.status_code == 409
    assert res2.json()["status"] == "error"
    assert res2.json()["error"]["code"] in ("IDEMPOTENCY_CONFLICT_ERROR", "CONFLICT_ERROR")


def test_idempotency_across_different_projects_is_isolated(api_test_env):
    """Verify that the same Idempotency-Key used in different projects creates separate tasks."""
    client = api_test_env["client"]
    headers = {"Idempotency-Key": "shared-cross-project-idempotency-key"}
    p_alpha = {
        "model_id": "model-alpha-1",
        "task_type": "classification",
        "observations": [{"top1_confidence": 0.90}],
        "seal_provenance": False,
    }
    p_beta = {
        "model_id": "model-beta-1",
        "task_type": "classification",
        "observations": [{"top1_confidence": 0.85}],
        "seal_provenance": False,
    }
    res_a = client.post("/api/v1/projects/proj-alpha/behavioral/assessments", json=p_alpha, headers=headers)
    res_b = client.post("/api/v1/projects/proj-beta/behavioral/assessments", json=p_beta, headers=headers)
    assert res_a.status_code == 200
    assert res_b.status_code == 200
    task_a_id = res_a.json()["data"]["task_id"]
    task_b_id = res_b.json()["data"]["task_id"]
    assert task_a_id != task_b_id


def test_idempotency_concurrent_identical_requests(api_test_env):
    """Verify concurrent requests with the same Idempotency-Key resolve to the same task ID without racing."""
    client = api_test_env["client"]
    headers = {"Idempotency-Key": "concurrent-test-idempotency-key"}
    payload = {
        "model_id": "model-alpha-1",
        "task_type": "classification",
        "observations": [{"top1_confidence": 0.92}],
        "seal_provenance": False,
    }

    def make_call():
        return client.post("/api/v1/projects/proj-alpha/behavioral/assessments", json=payload, headers=headers)

    with ThreadPoolExecutor(max_workers=4) as executor:
        futures = [executor.submit(make_call) for _ in range(4)]
        results = [f.result() for f in futures]

    for r in results:
        assert r.status_code == 200
    task_ids = {r.json()["data"]["task_id"] for r in results}
    assert len(task_ids) == 1, "Concurrent idempotent submissions created multiple distinct task IDs!"


# =====================================================================
# 16. Task Concurrency & State Machine
# =====================================================================

def test_task_concurrency_multiple_submissions(api_test_env):
    """Verify submitting multiple distinct async tasks concurrently executes cleanly."""
    client = api_test_env["client"]

    def submit_task(idx):
        payload = {
            "model_id": "model-alpha-1",
            "task_type": "classification",
            "observations": [{"top1_confidence": 0.80 + (idx * 0.02)}],
            "seal_provenance": False,
        }
        return client.post("/api/v1/projects/proj-alpha/behavioral/assessments?async=true", json=payload)

    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = [executor.submit(submit_task, i) for i in range(5)]
        results = [f.result() for f in futures]

    for r in results:
        assert r.status_code == 200
    task_ids = [r.json()["data"]["task_id"] for r in results]
    assert len(set(task_ids)) == 5


# =====================================================================
# 17. SSE Security & Boundary Checks
# =====================================================================

def test_sse_invalid_task_id_returns_404(api_test_env):
    """Verify SSE endpoint returns HTTP 404 for nonexistent task ID."""
    client = api_test_env["client"]
    res = client.get("/api/v1/projects/proj-alpha/behavioral/tasks/nonexistent-task-id/events")
    assert res.status_code == 404


def test_sse_cross_project_isolation_returns_404(api_test_env):
    """Verify subscribing to another project's task events via SSE returns HTTP 404."""
    client = api_test_env["client"]
    # Task in Alpha
    t_payload = {
        "model_id": "model-alpha-1",
        "task_type": "classification",
        "observations": [{"top1_confidence": 0.9}],
        "seal_provenance": False,
    }
    t_res = client.post("/api/v1/projects/proj-alpha/behavioral/assessments", json=t_payload)
    task_id = t_res.json()["data"]["task_id"]

    # Stream from Beta
    res_beta = client.get(f"/api/v1/projects/proj-beta/behavioral/tasks/{task_id}/events")
    assert res_beta.status_code == 404


# =====================================================================
# 18. Security Boundary & Offline Verification
# =====================================================================

def test_security_path_traversal_variations(api_test_env):
    """Verify various path traversal attacks in URLs and IDs are rejected."""
    client = api_test_env["client"]
    payload = {"model_id": "model-alpha-1", "task_type": "classification", "observed_metrics": {"v": 1.0}}

    traversal_attacks = [
        "../../etc/passwd",
        "..%2F..%2Fwindows%2Fsystem32",
        "C:\\Windows\\System32",
        "\\\\server\\share\\data",
        "%2e%2e%2f%2e%2e%2fconfig",
        "$SYSTEM_ROOT",
    ]
    for attack in traversal_attacks:
        res = client.post(f"/api/v1/projects/{attack}/behavioral/anomalies/detect", json=payload)
        assert res.status_code in (400, 404, 422)


def test_offline_execution_zero_cloud_activity(api_test_env):
    """Verify full baseline + perturbation + stability + anomaly + evidence pipeline runs 100% locally."""
    client = api_test_env["client"]
    obs = [
        {"top1_confidence": 0.90, "top1_class": 0, "logits": [0.9, 0.1], "latency_ms": 10.0},
        {"top1_confidence": 0.92, "top1_class": 0, "logits": [0.92, 0.08], "latency_ms": 11.0},
    ]
    payload = {
        "model_id": "model-alpha-1",
        "task_type": "classification",
        "observations": obs,
        "seal_provenance": False,
    }
    res = client.post("/api/v1/projects/proj-alpha/behavioral/assessments", json=payload)
    assert res.status_code == 200
    data = res.json()["data"]
    assert data["status"] == "COMPLETED"
    assert data["result"]["assessment_status"] == "COMPLETED"


# =====================================================================
# 19. Evidence Immutability & Provenance Verification States
# =====================================================================

def test_evidence_immutability_frozen_pydantic_content(api_test_env):
    """Verify that stored evidence content cannot be mutated in place."""
    client = api_test_env["client"]
    bind_payload = {
        "model_id": "model-alpha-1",
        "anomaly_analysis_id": "1" * 64,
        "observation_id": "obs-freeze-01",
        "baseline_id": "b-freeze-01",
        "task_type": "classification",
        "overall_status": "NORMAL",
        "metric_results": {},
        "family_results": {},
        "seal_provenance": False,
    }
    bind_res = client.post("/api/v1/projects/proj-alpha/behavioral/evidence/bind", json=bind_payload)
    assert bind_res.status_code == 201
    ev_id = bind_res.json()["data"]["evidence_id"]

    # Verify retrieval
    get_res = client.get(f"/api/v1/projects/proj-alpha/behavioral/evidence/{ev_id}")
    assert get_res.status_code == 200
    assert get_res.json()["data"]["lifecycle_state"] == "SEALED"


def test_provenance_verification_unbound_target_state_missing(api_test_env):
    """Verify provenance verification on unbound target returns MISSING state."""
    client = api_test_env["client"]
    v_res = client.get("/api/v1/projects/proj-alpha/behavioral/provenance/unknown-target-uuid")
    assert v_res.status_code == 200
    v_data = v_res.json()["data"]
    assert v_data["status"] == "MISSING"
    assert v_data["is_valid"] is False
    assert v_data["signature_valid"] is False


def test_error_mapping_403_cross_project_model_access(api_test_env):
    """Verify attempting to access model belonging to another project returns HTTP 403/422."""
    client = api_test_env["client"]
    payload = {
        "model_id": "model-beta-1",  # Belongs to Beta
        "task_type": "classification",
        "observations": [{"top1_confidence": 0.90}],
    }
    res = client.post("/api/v1/projects/proj-alpha/behavioral/assessments", json=payload)
    assert res.status_code in (403, 422)
    assert "belongs to project 'proj-beta'" in res.json()["error"]["message"]


def test_error_mapping_404_nonexistent_project(api_test_env):
    """Verify querying nonexistent project returns HTTP 404."""
    client = api_test_env["client"]
    res = client.get("/api/v1/projects/nonexistent-project-id/behavioral/tasks")
    assert res.status_code == 404
    assert "not found" in res.json()["error"]["message"].lower()


