"""Tests for standardized API error response format."""


def test_404_not_found_envelope(client):
    """Verify non-existent project returns standard ApiErrorResponse envelope."""
    response = client.get("/api/v1/projects/non-existent-uuid-12345")
    assert response.status_code == 404
    data = response.json()
    assert data["status"] == "error"
    assert "error" in data
    assert data["error"]["code"] == "NOT_FOUND"
    assert "not found" in data["error"]["message"].lower()
    assert "meta" in data
    assert "request_id" in data["meta"]


def test_422_validation_error_envelope(client):
    """Verify malformed payload returns standard validation error envelope."""
    # Sending invalid body (name must not be empty string)
    response = client.post("/api/v1/projects", json={"name": ""})
    assert response.status_code == 422
    data = response.json()
    assert data["status"] == "error"
    assert data["error"]["code"] == "REQUEST_VALIDATION_ERROR"
    assert "details" in data["error"]
    assert "meta" in data


def test_project_creation_and_retrieval(client):
    """Verify end-to-end Project API routing."""
    create_res = client.post("/api/v1/projects", json={"name": "Engagement 101", "description": "CV Audit"})
    assert create_res.status_code == 201
    created = create_res.json()
    assert created["status"] == "success"
    project_id = created["data"]["id"]
    assert created["data"]["name"] == "Engagement 101"

    get_res = client.get(f"/api/v1/projects/{project_id}")
    assert get_res.status_code == 200
    retrieved = get_res.json()
    assert retrieved["status"] == "success"
    assert retrieved["data"]["id"] == project_id
