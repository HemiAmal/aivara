"""Tests for Phase 3 API CRUD endpoints."""


FAKE_SHA256 = "a" * 64


# =====================================================================
# Projects API
# =====================================================================

class TestProjectsAPI:
    def test_create_and_get_project(self, client):
        r = client.post("/api/v1/projects", json={"name": "API Test", "description": "Desc"})
        assert r.status_code == 201
        project_id = r.json()["data"]["id"]

        r = client.get(f"/api/v1/projects/{project_id}")
        assert r.status_code == 200
        assert r.json()["data"]["name"] == "API Test"

    def test_list_projects(self, client):
        client.post("/api/v1/projects", json={"name": "P1"})
        client.post("/api/v1/projects", json={"name": "P2"})
        r = client.get("/api/v1/projects")
        assert r.status_code == 200
        assert len(r.json()["data"]) >= 2

    def test_update_project(self, client):
        r = client.post("/api/v1/projects", json={"name": "Before"})
        pid = r.json()["data"]["id"]
        r = client.patch(f"/api/v1/projects/{pid}", json={"name": "After"})
        assert r.status_code == 200
        assert r.json()["data"]["name"] == "After"

    def test_get_nonexistent_project(self, client):
        r = client.get("/api/v1/projects/nonexistent-id")
        assert r.status_code == 404
        assert r.json()["status"] == "error"


# =====================================================================
# Contributors API
# =====================================================================

class TestContributorsAPI:
    def _make_project(self, client) -> str:
        r = client.post("/api/v1/projects", json={"name": "Contrib Test"})
        return r.json()["data"]["id"]

    def test_create_and_get_contributor(self, client):
        pid = self._make_project(client)
        r = client.post("/api/v1/contributors", json={
            "project_id": pid, "external_id": "ann-1", "name": "Annotator 1"
        })
        assert r.status_code == 201
        cid = r.json()["data"]["id"]

        r = client.get(f"/api/v1/contributors/{cid}")
        assert r.status_code == 200
        assert r.json()["data"]["external_id"] == "ann-1"

    def test_list_contributors(self, client):
        pid = self._make_project(client)
        client.post("/api/v1/contributors", json={"project_id": pid, "external_id": "c1"})
        client.post("/api/v1/contributors", json={"project_id": pid, "external_id": "c2"})
        r = client.get(f"/api/v1/contributors?project_id={pid}")
        assert r.status_code == 200
        assert len(r.json()["data"]) >= 2


# =====================================================================
# Datasets API
# =====================================================================

class TestDatasetsAPI:
    def _make_project(self, client) -> str:
        r = client.post("/api/v1/projects", json={"name": "DS Test"})
        return r.json()["data"]["id"]

    def test_create_and_get_dataset(self, client):
        pid = self._make_project(client)
        r = client.post("/api/v1/datasets", json={
            "project_id": pid, "name": "COCO Val", "format": "coco"
        })
        assert r.status_code == 201
        did = r.json()["data"]["id"]

        r = client.get(f"/api/v1/datasets/{did}")
        assert r.status_code == 200
        assert r.json()["data"]["format"] == "coco"

    def test_create_dataset_version(self, client):
        pid = self._make_project(client)
        r = client.post("/api/v1/datasets", json={
            "project_id": pid, "name": "Test", "format": "yolo"
        })
        did = r.json()["data"]["id"]
        r = client.post(f"/api/v1/datasets/{did}/versions", json={
            "dataset_id": did, "version_label": "v1.0", "sample_count": 1000
        })
        assert r.status_code == 201
        assert r.json()["data"]["version_label"] == "v1.0"

    def test_invalid_dataset_format(self, client):
        pid = self._make_project(client)
        r = client.post("/api/v1/datasets", json={
            "project_id": pid, "name": "Bad", "format": "xlsx"
        })
        assert r.status_code == 422


# =====================================================================
# Models API
# =====================================================================

class TestModelsAPI:
    def _make_project(self, client) -> str:
        r = client.post("/api/v1/projects", json={"name": "Model Test"})
        return r.json()["data"]["id"]

    def test_create_and_get_model(self, client):
        pid = self._make_project(client)
        r = client.post("/api/v1/models", json={
            "project_id": pid,
            "name": "EfficientNet-B0",
            "format": "onnx",
            "file_path": "models/efficientnet_b0.onnx",
            "file_hash_sha256": FAKE_SHA256,
            "file_size_bytes": 20000000,
        })
        assert r.status_code == 201
        mid = r.json()["data"]["id"]

        r = client.get(f"/api/v1/models/{mid}")
        assert r.status_code == 200
        assert r.json()["data"]["name"] == "EfficientNet-B0"

    def test_invalid_model_format(self, client):
        pid = self._make_project(client)
        r = client.post("/api/v1/models", json={
            "project_id": pid, "name": "Bad", "format": "tensorflow",
            "file_path": "m.tf", "file_hash_sha256": FAKE_SHA256,
        })
        assert r.status_code == 422


# =====================================================================
# Error Format Consistency
# =====================================================================

class TestErrorFormat:
    def test_all_errors_have_envelope(self, client):
        """Every error must return {status, error: {code, message}, meta}."""
        r = client.get("/api/v1/projects/no-such-id")
        body = r.json()
        assert body["status"] == "error"
        assert "code" in body["error"]
        assert "message" in body["error"]
        assert "request_id" in body["meta"]
