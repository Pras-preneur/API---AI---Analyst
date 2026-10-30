"""Focused tests for CORS configuration."""

from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)


def test_cors_preflight_allowed_for_localhost_5173():
    """Vite dev server on localhost:5173 receives allowed CORS preflight headers."""
    response = client.options(
        "/parse-openapi",
        headers={
            "Origin": "http://localhost:5173",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "X-Session-ID, Content-Type",
        },
    )
    assert response.status_code == 200
    assert response.headers.get("access-control-allow-origin") == "http://localhost:5173"
    assert "POST" in response.headers.get("access-control-allow-methods", "")
    assert "X-Session-ID" in response.headers.get("access-control-allow-headers", "")


def test_cors_preflight_allowed_for_127_0_0_1_5173():
    """Vite dev server on 127.0.0.1:5173 receives allowed CORS preflight headers."""
    response = client.options(
        "/health",
        headers={
            "Origin": "http://127.0.0.1:5173",
            "Access-Control-Request-Method": "GET",
        },
    )
    assert response.status_code == 200
    assert response.headers.get("access-control-allow-origin") == "http://127.0.0.1:5173"


def test_cors_rejects_unauthorized_external_origin():
    """Untrusted origins are not granted Access-Control-Allow-Origin headers."""
    response = client.options(
        "/health",
        headers={
            "Origin": "http://malicious-site.com",
            "Access-Control-Request-Method": "GET",
        },
    )
    assert response.headers.get("access-control-allow-origin") != "http://malicious-site.com"


def test_cors_exposes_x_session_id():
    """CORS response exposes X-Session-ID so browser JS can read the session header."""
    response = client.get(
        "/health",
        headers={"Origin": "http://localhost:5173"},
    )
    assert response.status_code == 200
    assert response.headers.get("access-control-allow-origin") == "http://localhost:5173"
    expose_headers = response.headers.get("access-control-expose-headers", "")
    assert "X-Session-ID" in expose_headers

