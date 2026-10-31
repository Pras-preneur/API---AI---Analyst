"""Tests for the human‑approval workflow endpoints.

The workflow consists of:
- POST /tests/{test_id}/approve
- POST /tests/{test_id}/reject
- GET  /tests/{test_id}

All endpoints require the ``X-Session-ID`` header.
"""

import uuid

import pytest
from fastapi.testclient import TestClient

from app.main import app, session_store
from app.models import ProposedTest, TestStatus
from app.parser.openapi_parser import EndpointModel
from app.security.proposal_engine import generate_proposals

client = TestClient(app)

def make_endpoint(**overrides):
    """Create a minimal valid ``EndpointModel`` instance.
    ``overrides`` can replace any field values.
    """
    base = {
        "path": "/example",
        "method": "get",
        "responses": {"200": {"description": "OK"}},
    }
    base.update(overrides)
    # ``parse_obj`` is used in the existing code; pydantic V2 deprecation warnings are acceptable for tests.
    return EndpointModel.model_validate(base)

def create_session_with_one_proposal():
    """Helper that creates a session, generates a single proposal and stores it.
    Returns the session id and the stored ``ProposedTest`` instance.
    """
    sid = session_store.create_session()
    proposal = generate_proposals([make_endpoint()])[0]
    session_store.add_proposal(sid, proposal)
    return sid, proposal

def test_get_proposal_success():
    sid, proposal = create_session_with_one_proposal()
    resp = client.get(f"/tests/{proposal.test_id}", headers={"X-Session-ID": sid})
    assert resp.status_code == 200
    data = resp.json()
    assert data["test_id"] == proposal.test_id
    assert data["status"] == TestStatus.PROPOSED

def test_approve_success():
    sid, proposal = create_session_with_one_proposal()
    resp = client.post(
        f"/tests/{proposal.test_id}/approve",
        headers={"X-Session-ID": sid},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == TestStatus.APPROVED
    assert "approved_at" in data
    # Verify the stored object was updated
    stored = session_store.get_proposal(sid, proposal.test_id)
    assert stored.status == TestStatus.APPROVED
    assert stored.approved_at is not None

def test_reject_success():
    sid, proposal = create_session_with_one_proposal()
    resp = client.post(
        f"/tests/{proposal.test_id}/reject",
        headers={"X-Session-ID": sid},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == TestStatus.REJECTED
    assert "rejected_at" in data
    stored = session_store.get_proposal(sid, proposal.test_id)
    assert stored.status == TestStatus.REJECTED
    assert stored.rejected_at is not None

def test_invalid_session_returns_404():
    sid, proposal = create_session_with_one_proposal()
    # Use a non‑existent session id
    bad_sid = str(uuid.uuid4())
    resp = client.post(
        f"/tests/{proposal.test_id}/approve",
        headers={"X-Session-ID": bad_sid},
    )
    assert resp.status_code == 404
    assert resp.json()["detail"] == "Session not found"

def test_invalid_proposal_returns_404():
    sid = session_store.create_session()
    bad_test_id = str(uuid.uuid4())
    resp = client.post(
        f"/tests/{bad_test_id}/approve",
        headers={"X-Session-ID": sid},
    )
    assert resp.status_code == 404
    assert resp.json()["detail"] == "Proposal not found"

def test_approve_invalid_state_returns_400():
    sid, proposal = create_session_with_one_proposal()
    # First approve successfully
    client.post(f"/tests/{proposal.test_id}/approve", headers={"X-Session-ID": sid})
    # Second approval should fail because status is now APPROVED
    resp = client.post(
        f"/tests/{proposal.test_id}/approve",
        headers={"X-Session-ID": sid},
    )
    assert resp.status_code == 400
    assert "Only PROPOSED proposals can be approved" in resp.json()["detail"]

def test_reject_invalid_state_returns_400():
    sid, proposal = create_session_with_one_proposal()
    # Approve first
    client.post(f"/tests/{proposal.test_id}/approve", headers={"X-Session-ID": sid})
    # Now reject – should be disallowed
    resp = client.post(
        f"/tests/{proposal.test_id}/reject",
        headers={"X-Session-ID": sid},
    )
    assert resp.status_code == 400
    assert "Only PROPOSED proposals can be rejected" in resp.json()["detail"]

