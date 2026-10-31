import base64
from fastapi.testclient import TestClient

from app.mock_api import mock_app, users_store, _INITIAL_USERS

client = TestClient(mock_app)

def _basic_auth(username: str, password: str) -> dict:
    token = base64.b64encode(f"{username}:{password}".encode()).decode()
    return {"Authorization": f"Basic {token}"}

def test_health():
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}

def test_expose_all_vulnerable():
    resp = client.get("/vuln/expose-all")
    assert resp.status_code == 200
    data = resp.json()
    assert isinstance(data["users"], list)
    # Should contain three users
    usernames = {u["username"] for u in data["users"]}
    assert usernames == {"user_a", "user_b", "admin"}

def test_profile_authenticated():
    headers = _basic_auth("user_a", "passwordA")
    resp = client.get("/profile", headers=headers)
    assert resp.status_code == 200
    json = resp.json()
    assert json["username"] == "user_a"
    assert "profile" in json

def test_admin_endpoint_secure():
    # Normal admin endpoint should reject non‑admin
    headers = _basic_auth("user_a", "passwordA")
    resp = client.get("/admin/data", headers=headers)
    assert resp.status_code == 403
    # Admin can access
    admin_hdr = _basic_auth("admin", "adminPass")
    resp = client.get("/admin/data", headers=admin_hdr)
    assert resp.status_code == 200
    assert resp.json()["secret"] == "admin‑only data"

def test_admin_endpoint_vulnerable():
    # Vulnerable admin endpoint accessible to any authenticated user
    headers = _basic_auth("user_b", "passwordB")
    resp = client.get("/vuln/admin/data", headers=headers)
    assert resp.status_code == 200
    assert resp.json()["secret"] == "admin‑only data (insecure)"

def test_bola_secure_and_vulnerable():
    # Secure endpoint: user_a cannot fetch user_b
    headers = _basic_auth("user_a", "passwordA")
    resp = client.get("/users/user_b", headers=headers)
    assert resp.status_code == 403
    # Vulnerable endpoint returns user_b data
    resp = client.get("/vuln/users/user_b")
    assert resp.status_code == 200
    assert resp.json()["username"] == "user_b"

def test_mass_assignment_update():
    headers = _basic_auth("user_a", "passwordA")
    payload = {"extra": "value", "bio": "new bio"}
    resp = client.patch("/profile", json=payload, headers=headers)
    assert resp.status_code == 200
    data = resp.json()
    # Verify that extra field was added to profile (mass‑assignment vulnerability)
    assert data["profile"]["extra"] == "value"
    assert data["profile"]["bio"] == "new bio"

def test_reset_only_localhost_and_effect():
    # Change something first
    headers = _basic_auth("user_a", "passwordA")
    client.patch("/profile", json={"extra": "temp"}, headers=headers)
    # Ensure change applied
    resp = client.get("/profile", headers=headers)
    assert resp.json()["profile"]["extra"] == "temp"
    # Reset via localhost (TestClient runs locally)
    resp = client.post("/reset")
    assert resp.status_code == 200
    # After reset, extra field should be gone
    resp = client.get("/profile", headers=headers)
    assert "extra" not in resp.json()["profile"]

