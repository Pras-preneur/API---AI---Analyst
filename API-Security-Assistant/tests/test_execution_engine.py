# tests/test_execution_engine.py
"""Tests for the execution engine (app/security/execution_engine.py).
The tests use a monkey‑patched httpx.AsyncClient that returns deterministic
responses for the mock API routes. No real network traffic is performed.
"""

import asyncio
import json
import uuid
from datetime import datetime
from typing import Any, Dict

import pytest

# Import the engine and models
from app.security.execution_engine import execute_proposals
from app.models import (
    session_store,
    ProposedTest,
    Finding,
    TestStatus,
    EndpointModel,
)

# ---------------------------------------------------------------------------
# Mock httpx.AsyncClient
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
        return _MockResponse(url=url, method="GET", status_code=404, json_data={"detail": "Not found"}, headers={})

    async def patch(self, url: str, json: Any = None, auth: Any = None):
        return await self.get(url, auth=auth)

# ---------------------------------------------------------------------------
# Pytest fixtures
# ---------------------------------------------------------------------------
@pytest.fixture(autouse=True)
def reset_store():
    """Reset the in‑memory session store before each test."""
    session_store._sessions.clear()
    yield
    session_store._sessions.clear()

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

@pytest.fixture
def patch_httpx(monkeypatch):
    monkeypatch.setattr(
        "app.security.execution_engine.httpx.AsyncClient",
        _MockAsyncClient,
    )
    yield

# ---------------------------------------------------------------------------
# Test cases (synchronous wrappers around async engine)
# ---------------------------------------------------------------------------
def test_approved_proposal_executes_successfully(patch_httpx):
    sid = session_store.create_session()
    proposal = create_proposal("BOLA")
    session_store.add_proposal(sid, proposal)
    proposal.status = TestStatus.APPROVED
    findings = asyncio.run(execute_proposals(sid, [proposal.test_id], "http://127.0.0.1:8001"))
    assert len(findings) == 1
    f = findings[0]
    assert isinstance(f, Finding)
    notes = json.loads(f.notes or "{}")
    assert notes.get("confidence") == 1.0
    stored = session_store.get_proposal(sid, proposal.test_id)
    assert stored.executed_at is not None

def test_proposed_proposal_rejected(patch_httpx):
    sid = session_store.create_session()
    proposal = create_proposal("BFLA", status=TestStatus.PROPOSED)
    session_store.add_proposal(sid, proposal)
    with pytest.raises(PermissionError):
        asyncio.run(execute_proposals(sid, [proposal.test_id], "http://127.0.0.1:8001"))

def test_rejected_proposal_cannot_execute(patch_httpx):
    sid = session_store.create_session()
    proposal = create_proposal("MissingAuth", status=TestStatus.REJECTED)
    session_store.add_proposal(sid, proposal)
    with pytest.raises(PermissionError):
        asyncio.run(execute_proposals(sid, [proposal.test_id], "http://127.0.0.1:8001"))

def test_unknown_proposal_is_rejected(patch_httpx):
    sid = session_store.create_session()
    with pytest.raises(KeyError):
        asyncio.run(execute_proposals(sid, [str(uuid.uuid4())], "http://127.0.0.1:8001"))

def test_cross_session_proposal_access_is_rejected(patch_httpx):
    sid1 = session_store.create_session()
    sid2 = session_store.create_session()
    proposal = create_proposal("BOLA")
    session_store.add_proposal(sid1, proposal)
    proposal.status = TestStatus.APPROVED
    with pytest.raises(PermissionError):
        asyncio.run(execute_proposals(sid2, [proposal.test_id], "http://127.0.0.1:8001"))

def test_unknown_session_is_rejected(patch_httpx):
    real_sid = session_store.create_session()
    proposal = create_proposal("BOLA")
    session_store.add_proposal(real_sid, proposal)
    proposal.status = TestStatus.APPROVED
    fake_sid = str(uuid.uuid4())
    with pytest.raises(KeyError):
        asyncio.run(execute_proposals(fake_sid, [proposal.test_id], "http://127.0.0.1:8001"))

def test_target_validation_allows_only_localhost(patch_httpx):
    sid = session_store.create_session()
    prop = create_proposal("BOLA")
    session_store.add_proposal(sid, prop)
    prop.status = TestStatus.APPROVED
    with pytest.raises(PermissionError):
        asyncio.run(execute_proposals(sid, [prop.test_id], "http://example.com"))
    with pytest.raises(PermissionError):
        asyncio.run(execute_proposals(sid, [prop.test_id], "http://127.0.0.1:9000"))
    findings = asyncio.run(execute_proposals(sid, [prop.test_id], "http://127.0.0.1:8001"))
    assert len(findings) == 1
