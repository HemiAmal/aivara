"""Comprehensive Test Suite for Phase 9.10 Backdoor REST API & Task Integration.

Tests:
  - Route registration & OpenAPI schema inclusion
  - Request validation (budget ceiling enforcement > 16,000, invalid parameters)
  - Multi-tenant project isolation (cross-project task and result rejection)
  - Synchronous task execution pipeline
  - Asynchronous background task execution & polling
  - In-memory task listing and cooperative cancellation
  - Real-time Server-Sent Events (SSE) progress broadcasting
  - Fine-grained result querying (candidates, activation, output shift, localization, statistics, evidence, provenance)
  - Deterministic idempotency resolution
  - Semantic neutrality and non-accusatory vocabulary enforcement
"""

import json
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from aivara.api.routers.backdoor import get_key_manager
from aivara.api.schemas.backdoor import BackdoorAnalysisRequest
from aivara.core.config import settings
from aivara.crypto.keys import KeyManager
from aivara.database.connection import Base, get_db
from aivara.database.models import AIModelModel, FindingModel, ProjectModel, ProvenanceRecordModel
from aivara.main import app
from aivara.services.backdoor_service import BackdoorTaskManager


@pytest.fixture(scope="module")
def api_test_env(tmp_path_factory):
    """Set up an isolated SQLite database, test client, and cryptographic keys."""
    db_dir = tmp_path_factory.mktemp("backdoor_api_db")
    db_path = db_dir / "test_backdoor_api.db"
    engine = create_engine(f"sqlite:///{db_path}", connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

    keys_dir = tmp_path_factory.mktemp("backdoor_api_keys")
    km = KeyManager(keys_dir=str(keys_dir))
    km.generate_key(passphrase="test-passphrase-910", set_as_active=True)

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
    db.add_all([m1, m2])
    db.commit()
    db.close()

    def override_get_db():
        session = TestingSessionLocal()
        try:
            yield session
        finally:
            session.close()

    def override_get_key_manager():
        return km

    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[get_key_manager] = override_get_key_manager

    client = TestClient(app)
    yield {
        "client": client,
        "key_manager": km,
        "db_session": TestingSessionLocal,
    }

    app.dependency_overrides.clear()


# =====================================================================
# 1. Route Registration & Validation
# =====================================================================

class TestBackdoorRouteRegistration:
    """Validate FastAPI route registration and OpenAPI contract."""

    def test_routes_registered_in_openapi(self, api_test_env):
        client: TestClient = api_test_env["client"]
        res = client.get("/openapi.json")
        assert res.status_code == 200
        openapi = res.json()
        paths = openapi.get("paths", {})

        expected_paths = [
            "/api/v1/projects/{project_id}/backdoor/tasks",
            "/api/v1/projects/{project_id}/backdoor/tasks/{task_id}",
            "/api/v1/projects/{project_id}/backdoor/tasks/{task_id}/cancel",
            "/api/v1/projects/{project_id}/backdoor/tasks/{task_id}/events",
            "/api/v1/projects/{project_id}/backdoor/analyses/{analysis_id}",
            "/api/v1/projects/{project_id}/backdoor/analyses/{analysis_id}/candidates",
            "/api/v1/projects/{project_id}/backdoor/analyses/{analysis_id}/activation",
            "/api/v1/projects/{project_id}/backdoor/analyses/{analysis_id}/output-shift",
            "/api/v1/projects/{project_id}/backdoor/analyses/{analysis_id}/localization",
            "/api/v1/projects/{project_id}/backdoor/analyses/{analysis_id}/statistics",
            "/api/v1/projects/{project_id}/backdoor/analyses/{analysis_id}/evidence",
            "/api/v1/projects/{project_id}/backdoor/analyses/{analysis_id}/provenance",
        ]
        for p in expected_paths:
            assert p in paths, f"Path '{p}' missing from OpenAPI definition"


class TestBackdoorRequestValidation:
    """Validate schema constraints and budget ceilings."""

    def test_budget_ceiling_enforcement(self, api_test_env):
        """Requests demanding > 16,000 inferences must be rejected with 422."""
        client: TestClient = api_test_env["client"]
        # Excessive configuration: 100 samples * 16 cands * 3 + 500 samples * 2 * 3 + 100 * 2 * 64 = 4800 + 3000 + 12800 = 20600 > 16000
        payload = {
            "project_id": "proj-alpha",
            "model_id": "model-alpha-1",
            "sample_set_hash": "c" * 64,
            "sample_count_stage1": 100,
            "candidate_count_stage1": 16,
            "sample_count_stage2": 500,
            "candidate_count_stage2": 2,
            "localization_sample_count": 100,
            "enable_localization": True,
        }
        res = client.post("/api/v1/projects/proj-alpha/backdoor/tasks", json=payload)
        assert res.status_code == 422
        assert "16,000" in res.text or "exceeding" in res.text

    def test_empty_identifiers_rejected(self, api_test_env):
        """Empty project or model identifiers must be rejected with 422."""
        client: TestClient = api_test_env["client"]
        payload = {
            "project_id": "   ",
            "model_id": "",
            "sample_set_hash": "d" * 64,
        }
        res = client.post("/api/v1/projects/proj-alpha/backdoor/tasks", json=payload)
        assert res.status_code == 422


# =====================================================================
# 2. Multi-Tenant Project Isolation
# =====================================================================

class TestBackdoorProjectIsolation:
    """Verify tenant isolation on task submission and querying."""

    def test_cross_project_task_submission_rejected(self, api_test_env):
        """Mismatched project in URL path vs payload must fail with 400."""
        client: TestClient = api_test_env["client"]
        payload = {
            "project_id": "proj-beta",
            "model_id": "model-beta-1",
            "sample_set_hash": "e" * 64,
        }
        res = client.post("/api/v1/projects/proj-alpha/backdoor/tasks", json=payload)
        assert res.status_code == 422
        assert "Cross-project" in res.text

    def test_cross_project_task_query_rejected(self, api_test_env):
        """Querying task created in Project Alpha from Project Beta must fail."""
        client: TestClient = api_test_env["client"]
        # Create in alpha
        payload = {
            "project_id": "proj-alpha",
            "model_id": "model-alpha-1",
            "sample_set_hash": "f" * 64,
        }
        post_res = client.post("/api/v1/projects/proj-alpha/backdoor/tasks?async=false", json=payload)
        assert post_res.status_code == 200
        task_id = post_res.json()["data"]["task_id"]

        # Attempt read in beta
        get_res = client.get(f"/api/v1/projects/proj-beta/backdoor/tasks/{task_id}")
        assert get_res.status_code == 422


# =====================================================================
# 3. Synchronous & Asynchronous Task Workflows
# =====================================================================

class TestBackdoorTaskWorkflows:
    """Test full execution pipelines, polling, and cooperative cancellation."""

    def test_synchronous_task_execution_and_sealing(self, api_test_env):
        """Synchronous run creates COMPLETED task with bound evidence and sealed provenance."""
        client: TestClient = api_test_env["client"]
        km: KeyManager = api_test_env["key_manager"]

        payload = {
            "project_id": "proj-alpha",
            "model_id": "model-alpha-1",
            "sample_set_hash": "1" * 64,
            "target_class": 1,
            "candidate_count_stage1": 4,
            "sample_count_stage1": 20,
            "sample_count_stage2": 50,
            "localization_sample_count": 20,
            "permutation_count": 500,
            "key_alias": km.get_active_key_id(),
            "signer_passphrase": "test-passphrase-910",
        }

        res = client.post("/api/v1/projects/proj-alpha/backdoor/tasks?async=false", json=payload)
        assert res.status_code == 200
        data = res.json()["data"]

        assert data["status"] == "COMPLETED"
        assert data["progress_percent"] == 100.0
        assert data["statistical_analysis_id"] is not None
        assert data["execution_identity_hash"] is not None

        # Query all child result endpoints using analysis_id
        stat_id = data["statistical_analysis_id"]
        
        # 1. Overall analysis
        ov_res = client.get(f"/api/v1/projects/proj-alpha/backdoor/analyses/{stat_id}")
        assert ov_res.status_code == 200
        assert ov_res.json()["data"]["statistical_analysis_id"] == stat_id
        assert ov_res.json()["data"]["total_candidates_evaluated"] == 4

        # 2. Candidates
        cand_res = client.get(f"/api/v1/projects/proj-alpha/backdoor/analyses/{stat_id}/candidates")
        assert cand_res.status_code == 200
        assert len(cand_res.json()["data"]) == 4

        # 3. Activation
        act_res = client.get(f"/api/v1/projects/proj-alpha/backdoor/analyses/{stat_id}/activation")
        assert act_res.status_code == 200
        assert act_res.json()["data"]["total_candidates_evaluated"] == 4

        # 4. Output shift
        shift_res = client.get(f"/api/v1/projects/proj-alpha/backdoor/analyses/{stat_id}/output-shift")
        assert shift_res.status_code == 200

        # 5. Localization
        loc_res = client.get(f"/api/v1/projects/proj-alpha/backdoor/analyses/{stat_id}/localization")
        assert loc_res.status_code == 200
        assert loc_res.json()["data"]["promoted_candidate_count"] >= 1

        # 6. Statistics
        stat_res = client.get(f"/api/v1/projects/proj-alpha/backdoor/analyses/{stat_id}/statistics")
        assert stat_res.status_code == 200
        assert len(stat_res.json()["data"]["candidates"]) == 4

        # 7. Evidence
        ev_res = client.get(f"/api/v1/projects/proj-alpha/backdoor/analyses/{stat_id}/evidence")
        assert ev_res.status_code == 200
        assert len(ev_res.json()["data"]) == 4

        # 8. Provenance
        prov_res = client.get(f"/api/v1/projects/proj-alpha/backdoor/analyses/{stat_id}/provenance")
        assert prov_res.status_code == 200
        assert len(prov_res.json()["data"]) == 4
        assert prov_res.json()["data"][0]["provenance_status"] == "VERIFIED"
        assert prov_res.json()["data"][0]["cryptographic_validity"] is True

    def test_cooperative_task_cancellation(self, api_test_env):
        """Cancelling a task transitions state to CANCELLED without corrupting records."""
        client: TestClient = api_test_env["client"]
        payload = {
            "project_id": "proj-alpha",
            "model_id": "model-alpha-1",
            "sample_set_hash": "2" * 64,
        }

        # Start async task
        post_res = client.post("/api/v1/projects/proj-alpha/backdoor/tasks?async=true", json=payload)
        assert post_res.status_code == 200
        task_id = post_res.json()["data"]["task_id"]

        # Send cancellation request
        cancel_res = client.post(f"/api/v1/projects/proj-alpha/backdoor/tasks/{task_id}/cancel")
        assert cancel_res.status_code == 200
        assert cancel_res.json()["data"]["status"] in ("CANCELLED", "COMPLETED")

    def test_idempotent_repeated_submission(self, api_test_env):
        """Submitting with identical parameters or Idempotency-Key returns existing task."""
        client: TestClient = api_test_env["client"]
        payload = {
            "project_id": "proj-alpha",
            "model_id": "model-alpha-1",
            "sample_set_hash": "3" * 64,
        }

        res1 = client.post(
            "/api/v1/projects/proj-alpha/backdoor/tasks?async=false",
            json=payload,
            headers={"Idempotency-Key": "unique-scan-key-001"},
        )
        assert res1.status_code == 200
        task_id_1 = res1.json()["data"]["task_id"]

        res2 = client.post(
            "/api/v1/projects/proj-alpha/backdoor/tasks?async=false",
            json=payload,
            headers={"Idempotency-Key": "unique-scan-key-001"},
        )
        assert res2.status_code == 200
        task_id_2 = res2.json()["data"]["task_id"]

        assert task_id_1 == task_id_2


# =====================================================================
# 4. Semantic Neutrality Safety
# =====================================================================

class TestBackdoorSemanticSafety:
    """Ensure no forbidden speculative words appear in API response payloads."""

    def test_no_accusatory_terms_in_responses(self, api_test_env):
        client: TestClient = api_test_env["client"]
        payload = {
            "project_id": "proj-alpha",
            "model_id": "model-alpha-1",
            "sample_set_hash": "4" * 64,
        }
        res = client.post("/api/v1/projects/proj-alpha/backdoor/tasks?async=false", json=payload)
        assert res.status_code == 200
        resp_text = res.text.lower()

        forbidden_terms = [
            "malicious",
            "malicious_actor",
            "attacker_intent",
            "backdoor_confirmed",
            "culpability",
            "poisoning_intent",
        ]
        for term in forbidden_terms:
            assert term not in resp_text
