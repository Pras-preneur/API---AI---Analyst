# tests/test_execution_endpoint.py
"""Integration tests for the new execution endpoint and findings listing.
These tests exercise the FastAPI routes defined in ``app.main`` and rely on the
execution engine logic in ``app.security.execution_engine``.  The HTTP client
used by the engine is monkey‑patched with a deterministic mock that returns
pre‑canned responses for the local mock API.
"""

import asyncio
import json
import uuid
from datetime import datetime
from typing import Any, Dict, List

import pytest
from fastapi.testclient import TestClient

# Import the FastAPI app
from app.main import app

# Import models and the in‑memory session store
from app.models import (
    session_store,
    ProposedTest,
    TestStatus,
    EndpointModel,
)

# ---------------------------------------------------------------------------
# Mock httpx.AsyncClient (same as in ``tests/test_execution_engine.py``)
# ---------------------------------------------------------------------------

class _MockRequest:
    def __init__(self, headers: Dict[str, Any]):
        self.headers = headers

class _MockResponse:
    def __init__(self, *, url: str, method: str, status_code: int, json_data: Any = None, headers: Dict[str, Any] = None):
        self.url = url
        self.method = method
        self.status_code = status_code
        self._json = json_data
        self.headers = headers or {}
        self.request = _MockRequest(self.headers)

    def json(self):
        if self._json is None:
            raise ValueError("No JSON data")
        return self._json

class _MockAsyncClient:
    def __init__(self, *, timeout: float, follow_redirects: bool):
        self.timeout = timeout
        self.follow_redirects = follow_redirects

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    async def get(self, url: str, auth: Any = None):
        # Simple routing based on URL path – mirrors the behaviour used in the engine tests.
        if "vuln/users/user_b" in url:
            return _MockResponse(
                url=url,
                method="GET",
                status_code=200,
                json_data={"username": "user_b", "email": "b@example.com", "token": "secret-token"},
                headers={"authorization": "Basic dummy"},
            )
        if "vuln/admin/data" in url:
            return _MockResponse(
                url=url,
                method="GET",
                status_code=200,
                json_data={"secret": "admin-secret", "api_key": "abc123"},
                headers={"authorization": "Basic dummy"},
            )
        if "vuln/expose-all" in url:
            return _MockResponse(
                url=url,
                method="GET",
                status_code=200,
                json_data={
                    "users": [
                        {"username": "user_a", "email": "a@example.com"},
                        {"username": "user_b", "email": "b@example.com"},
                        {"username": "admin", "email": "admin@example.com"},
                    ]
                },
                headers={},
            )
        if "admin/data" in url and "vuln" not in url:
            return _MockResponse(
                url=url,
                method="GET",
                status_code=403,
                json_data={"detail": "Forbidden"},
                headers={},
            )
        if "profile" in url:
            return _MockResponse(
                url=url,
                method="PATCH",
                status_code=200,
                json_data={"msg": "profile updated", "profile": {"bio": "injected", "email": "a@example.com"}},
                headers={"authorization": "Basic dummy"},
            )
        # Default fallback – not found
        return _MockResponse(url=url, method="GET", status_code=404, json_data={"detail": "Not found"}, headers={})

    async def patch(self, url: str, json: Any = None, auth: Any = None):
        return await self.get(url, auth=auth)

# ---------------------------------------------------------------------------
# Pytest fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def reset_store():
    """Clear the in‑memory store before each test to avoid cross‑test bleed."""
    session_store._sessions.clear()
    yield
    session_store._sessions.clear()

@pytest.fixture
def client():
    return TestClient(app)

@pytest.fixture
def httpx_patch(monkeypatch):
    """Monkey‑patch the httpx.AsyncClient used by the execution engine."""
    monkeypatch.setattr(
        "app.security.execution_engine.httpx.AsyncClient",
        _MockAsyncClient,
    )
    yield

def make_endpoint(path: str = "/vuln/users/{username}") -> EndpointModel:
    return EndpointModel.parse_obj({
        "path": path,
        "method": "get",
        "responses": {"200": {"description": "OK"}},
    })

def create_proposal(test_type: str, status: TestStatus = TestStatus.PROPOSED) -> ProposedTest:
    return ProposedTest(
        endpoint=make_endpoint(),
        test_type=test_type,
        description="test",
        severity="Low",
        status=status,
    )

# ---------------------------------------------------------------------------
# Test scenarios
# ---------------------------------------------------------------------------

def test_execute_endpoint_success(httpx_patch, client):
    # Setup session and an approved proposal
    sid = session_store.create_session()
    prop = create_proposal("BOLA")
    session_store.add_proposal(sid, prop)
    # Approve the proposal via the store (bypassing the route for speed)
    prop.status = TestStatus.APPROVED

    response = client.post(
        "/tests/execute",
        json={"proposal_ids": [prop.test_id], "target": "http://127.0.0.1:8001"},
        headers={"X-Session-ID": sid},
    )
    assert response.status_code == 200
    findings = response.json()
    assert isinstance(findings, list) and len(findings) == 1
    notes = json.loads(findings[0].get("notes") or "{}")
    assert notes.get("confidence") == 1.0

def test_execute_endpoint_rejects_unapproved(httpx_patch, client):
    sid = session_store.create_session()
    prop = create_proposal("BFLA", status=TestStatus.PROPOSED)
    session_store.add_proposal(sid, prop)
    response = client.post(
        "/tests/execute",
        json={"proposal_ids": [prop.test_id], "target": "http://127.0.0.1:8001"},
        headers={"X-Session-ID": sid},
    )
    assert response.status_code == 403
    assert "not approved" in response.json()["detail"].lower()

def test_execute_endpoint_cross_session(httpx_patch, client):
    sid1 = session_store.create_session()
    sid2 = session_store.create_session()
    prop = create_proposal("MissingAuth")
    session_store.add_proposal(sid1, prop)
    prop.status = TestStatus.APPROVED
    response = client.post(
        "/tests/execute",
        json={"proposal_ids": [prop.test_id], "target": "http://127.0.0.1:8001"},
        headers={"X-Session-ID": sid2},
    )
    assert response.status_code == 403
    assert "does not belong to session" in response.json()["detail"].lower()

def test_execute_endpoint_invalid_target(httpx_patch, client):
    sid = session_store.create_session()
    prop = create_proposal("BOLA")
    session_store.add_proposal(sid, prop)
    prop.status = TestStatus.APPROVED
    # Disallowed host
    resp = client.post(
        "/tests/execute",
        json={"proposal_ids": [prop.test_id], "target": "http://example.com"},
        headers={"X-Session-ID": sid},
    )
    assert resp.status_code == 403
    # Wrong port on allowed host
    resp2 = client.post(
        "/tests/execute",
        json={"proposal_ids": [prop.test_id], "target": "http://127.0.0.1:9000"},
        headers={"X-Session-ID": sid},
    )
    assert resp2.status_code == 403
    # Valid target works
    resp_ok = client.post(
        "/tests/execute",
        json={"proposal_ids": [prop.test_id], "target": "http://127.0.0.1:8001"},
        headers={"X-Session-ID": sid},
    )
    assert resp_ok.status_code == 200
    assert len(resp_ok.json()) == 1

def test_findings_endpoint(httpx_patch, client):
    sid = session_store.create_session()
    prop = create_proposal("BFLA")
    session_store.add_proposal(sid, prop)
    prop.status = TestStatus.APPROVED
    # Execute first to generate a finding
    exec_resp = client.post(
        "/tests/execute",
        json={"proposal_ids": [prop.test_id], "target": "http://127.0.0.1:8001"},
        headers={"X-Session-ID": sid},
    )
    assert exec_resp.status_code == 200
    # Retrieve findings via the new endpoint
    find_resp = client.get(
        "/findings",
        headers={"X-Session-ID": sid},
    )
    assert find_resp.status_code == 200
    findings = find_resp.json()
    assert isinstance(findings, list) and len(findings) == 1
    assert findings[0]["test_id"] == prop.test_id

def test_findings_endpoint_unknown_session(client):
    fake_sid = str(uuid.uuid4())
    resp = client.get("/findings", headers={"X-Session-ID": fake_sid})
    assert resp.status_code == 404
    assert "session not found" in resp.json()["detail"].lower()

