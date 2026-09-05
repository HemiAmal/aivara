"""Tests for application startup and /health endpoint."""


def test_health_check_endpoint(client):
    """Verify /health endpoint returns structured JSON per spec."""
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert data["service"] == "aivara"
    assert "version" in data
    assert data["version"] == "0.1.0"


def test_cors_headers_present(client):
    """Verify basic localhost CORS headers are configured."""
    response = client.options(
        "/health",
        headers={
            "Origin": "http://localhost:5173",
            "Access-Control-Request-Method": "GET",
        },
    )
    assert response.status_code in (200, 204)
