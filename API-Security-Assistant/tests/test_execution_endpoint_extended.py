# tests/test_execution_endpoint_extended.py
"""Additional integration tests for execution endpoint covering edge‑cases and security aspects.
These tests complement the original suite and verify proper handling of missing headers,
unknown sessions/proposals, repeat execution, evidence sanitisation, unsupported test types,
execution failures, empty request bodies and atomic behaviour for mixed proposal lists.
"""

import json
import uuid
from typing import Any, Dict

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.models import (
    session_store,
    ProposedTest,
    TestStatus,
    EndpointModel,
)

# ---------------------------------------------------------------------------
# Mock httpx.AsyncClient (same as in existing tests)
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
        self.fail_on = None

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    async def get(self, url: str, auth: Any = None):
        if self.fail_on and self.fail_on in url:
            raise RuntimeError("Simulated network failure")
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
                json_data={"users": [{"username": "user_a", "email": "a@example.com"}, {"username": "user_b", "email": "b@example.com"}, {"username": "admin", "email": "admin@example.com"}]},
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
        return _MockResponse(url=url, method="GET", status_code=404, json_data={"detail": "Not found"}, headers={})

    async def patch(self, url: str, json: Any = None, auth: Any = None):
        return await self.get(url, auth=auth)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def reset_store():
    session_store._sessions.clear()
    yield
    session_store._sessions.clear()

@pytest.fixture
def client():
    return TestClient(app)

@pytest.fixture
def httpx_patch(monkeypatch):
    monkeypatch.setattr(
        "app.security.execution_engine.httpx.AsyncClient",
        _MockAsyncClient,
    )
    yield

def make_endpoint(path: str = "/vuln/users/{username}") -> EndpointModel:
    return EndpointModel.model_validate({
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
# 1. Missing X-Session-ID header
# ---------------------------------------------------------------------------

def test_missing_session_header_execute(httpx_patch, client):
    response = client.post(
        "/tests/execute",
        json={"proposal_ids": [], "target": "http://127.0.0.1:8001"},
    )
    assert response.status_code == 422

def test_missing_session_header_findings(httpx_patch, client):
    response = client.get("/findings")
    assert response.status_code == 422

# ---------------------------------------------------------------------------
# 2. Unknown session returns 404
# ---------------------------------------------------------------------------

def test_unknown_session_execute(httpx_patch, client):
    fake_sid = str(uuid.uuid4())
    response = client.post(
        "/tests/execute",
        json={"proposal_ids": ["any"], "target": "http://127.0.0.1:8001"},
        headers={"X-Session-ID": fake_sid},
    )
    assert response.status_code == 404
    assert "session not found" in response.json()["detail"].lower()

def test_unknown_session_findings(httpx_patch, client):
    fake_sid = str(uuid.uuid4())
    response = client.get("/findings", headers={"X-Session-ID": fake_sid})
    assert response.status_code == 404
    assert "session not found" in response.json()["detail"].lower()

# ---------------------------------------------------------------------------
# 3. Unknown proposal ID rejected (KeyError leads to 500)
# ---------------------------------------------------------------------------

def test_unknown_proposal_id(httpx_patch, client):
    sid = session_store.create_session()
    response = client.post(
        "/tests/execute",
        json={"proposal_ids": [str(uuid.uuid4())], "target": "http://127.0.0.1:8001"},
        headers={"X-Session-ID": sid},
    )
    assert response.status_code == 500

# ---------------------------------------------------------------------------
# 4. Repeated execution rejected
# ---------------------------------------------------------------------------

def test_repeat_execution_rejected(httpx_patch, client):
    sid = session_store.create_session()
    prop = create_proposal("BOLA")
    session_store.add_proposal(sid, prop)
    prop.status = TestStatus.APPROVED
    first = client.post(
        "/tests/execute",
        json={"proposal_ids": [prop.test_id], "target": "http://127.0.0.1:8001"},
        headers={"X-Session-ID": sid},
    )
    assert first.status_code == 200
    second = client.post(
        "/tests/execute",
        json={"proposal_ids": [prop.test_id], "target": "http://127.0.0.1:8001"},
        headers={"X-Session-ID": sid},
    )
    assert second.status_code == 403
    assert "already been executed" in second.json()["detail"].lower()

# ---------------------------------------------------------------------------
# 5. Findings isolation across sessions
# ---------------------------------------------------------------------------

def test_findings_isolation(httpx_patch, client):
    sid1 = session_store.create_session()
    sid2 = session_store.create_session()
    prop = create_proposal("BFLA")
    session_store.add_proposal(sid1, prop)
    prop.status = TestStatus.APPROVED
    exec_resp = client.post(
        "/tests/execute",
        json={"proposal_ids": [prop.test_id], "target": "http://127.0.0.1:8001"},
        headers={"X-Session-ID": sid1},
    )
    assert exec_resp.status_code == 200
    find_resp = client.get("/findings", headers={"X-Session-ID": sid2})
    assert find_resp.status_code == 200
    assert find_resp.json() == []

# ---------------------------------------------------------------------------
# 6. Sensitive evidence sanitisation
# ---------------------------------------------------------------------------

def test_evidence_sanitisation(httpx_patch, client):
    sid = session_store.create_session()
    prop = create_proposal("BOLA")
    session_store.add_proposal(sid, prop)
    prop.status = TestStatus.APPROVED
    exec_resp = client.post(
        "/tests/execute",
        json={"proposal_ids": [prop.test_id], "target": "http://127.0.0.1:8001"},
        headers={"X-Session-ID": sid},
    )
    finding = exec_resp.json()[0]
    evidence = finding["evidence"]
    assert "authorization" not in (evidence.get("request") or {})
    body = evidence.get("response", {}).get("body", {})
    assert "[redacted]" in json.dumps(body).lower()
    assert "@" not in json.dumps(body)

# ---------------------------------------------------------------------------
# 7. Unsupported test type produces NOT_EXECUTED
# ---------------------------------------------------------------------------

def test_unsupported_test_type(httpx_patch, client):
    sid = session_store.create_session()
    prop = create_proposal("UNKNOWN", status=TestStatus.APPROVED)
    session_store.add_proposal(sid, prop)
    resp = client.post(
        "/tests/execute",
        json={"proposal_ids": [prop.test_id], "target": "http://127.0.0.1:8001"},
        headers={"X-Session-ID": sid},
    )
    assert resp.status_code == 200
    finding = resp.json()[0]
    assert finding["status"] == "NotExecuted"
    notes = json.loads(finding.get("notes") or "{}")
    assert notes.get("reason") == "Unsupported test type"

# ---------------------------------------------------------------------------
# 8. Execution failure does not expose credentials
# ---------------------------------------------------------------------------

def test_execution_failure_no_credentials_leak(httpx_patch, client, monkeypatch):
    class FailingMockClient(_MockAsyncClient):
        async def get(self, url: str, auth: Any = None):
            if "vuln/admin/data" in url:
                raise RuntimeError("Simulated failure")
            return await super().get(url, auth)
    monkeypatch.setattr(
        "app.security.execution_engine.httpx.AsyncClient",
        FailingMockClient,
    )
    sid = session_store.create_session()
    prop = create_proposal("BFLA")
    session_store.add_proposal(sid, prop)
    prop.status = TestStatus.APPROVED
    resp = client.post(
        "/tests/execute",
        json={"proposal_ids": [prop.test_id], "target": "http://127.0.0.1:8001"},
        headers={"X-Session-ID": sid},
    )
    assert resp.status_code == 200
    finding = resp.json()[0]
    assert finding["evidence"]["request"] == {}
    assert finding["evidence"]["response"] == {}
    notes = json.loads(finding.get("notes") or "{}")
    assert "error" in notes
    assert "Simulated failure" in notes["error"]

# ---------------------------------------------------------------------------
# 9. Empty proposal list and malformed request handling
# ---------------------------------------------------------------------------

def test_empty_proposal_list(httpx_patch, client):
    sid = session_store.create_session()
    resp = client.post(
        "/tests/execute",
        json={"proposal_ids": [], "target": "http://127.0.0.1:8001"},
        headers={"X-Session-ID": sid},
    )
    assert resp.status_code == 400
    assert "empty proposal list" in resp.json()["detail"].lower()

def test_malformed_request_missing_fields(httpx_patch, client):
    sid = session_store.create_session()
    resp = client.post(
        "/tests/execute",
        json={"proposal_ids": ["dummy"]},
        headers={"X-Session-ID": sid},
    )
    assert resp.status_code == 422

# ---------------------------------------------------------------------------
# 10. Atomic behaviour for mixed approval list
# ---------------------------------------------------------------------------

def test_atomic_mixed_approval(httpx_patch, client):
    sid = session_store.create_session()
    approved = create_proposal("BOLA", status=TestStatus.APPROVED)
    unapproved = create_proposal("BFLA", status=TestStatus.PROPOSED)
    session_store.add_proposal(sid, approved)
    session_store.add_proposal(sid, unapproved)
    resp = client.post(
        "/tests/execute",
        json={"proposal_ids": [approved.test_id, unapproved.test_id], "target": "http://127.0.0.1:8001"},
        headers={"X-Session-ID": sid},
    )
    assert resp.status_code == 403
    findings = client.get("/findings", headers={"X-Session-ID": sid}).json()
    assert findings == []

