"""Tests for the security test proposal engine and related API endpoints.

These tests verify that the deterministic proposal generation logic produces the
expected categories and that the session‑aware FastAPI routes store and retrieve
proposals correctly.
"""

import uuid

import pytest
from fastapi.testclient import TestClient

from app.main import app, session_store
from app.models import ProposedTest
from app.parser.openapi_parser import EndpointModel
from app.security.proposal_engine import generate_proposals

client = TestClient(app)

# Helper to build a minimal valid EndpointModel via ``parse_obj``.
def make_endpoint(**overrides):
    base = {
        "path": "/example",
        "method": "get",
        "responses": {"200": {"description": "OK"}},
    }
    base.update(overrides)
    return EndpointModel.model_validate(base)

def test_bola_proposal_generated():
    ep = make_endpoint(path="/users/{user_id}")
    proposals = generate_proposals([ep])
    types = {p.test_type for p in proposals}
    assert "BOLA" in types
    # Verify description includes path
    bola = next(p for p in proposals if p.test_type == "BOLA")
    assert "/users/{user_id}" in bola.description

def test_bfla_proposal_generated():
    ep = make_endpoint(path="/admin/panel", tags=["admin"])
    proposals = generate_proposals([ep])
    types = {p.test_type for p in proposals}
    assert "BFLA" in types
    bfla = next(p for p in proposals if p.test_type == "BFLA")
    assert "admin" in bfla.description.lower()

def test_mass_assignment_proposal_generated():
    ep = make_endpoint(
        request_body={
            "content": {
                "application/json": {
                    "schema": {
                        "type": "object",
                        "properties": {"name": {"type": "string"}},
                        "additionalProperties": True,
                    }
                }
            }
        }
    )
    proposals = generate_proposals([ep])
    types = {p.test_type for p in proposals}
    assert "MassAssignment" in types

def test_excessive_data_proposal_generated():
    # response schema with >5 properties triggers the rule
    ep = make_endpoint(
        responses={
            "200": {
                "description": "OK",
                "content": {
                    "application/json": {
                        "schema": {
                            "type": "object",
                            "properties": {
                                "a": {"type": "string"},
                                "b": {"type": "string"},
                                "c": {"type": "string"},
                                "d": {"type": "string"},
                                "e": {"type": "string"},
                                "f": {"type": "string"},
                            },
                        }
                    }
                },
            }
        }
    )
    proposals = generate_proposals([ep])
    types = {p.test_type for p in proposals}
    assert "ExcessiveData" in types

def test_missing_auth_proposal_generated():
    ep = make_endpoint()
    proposals = generate_proposals([ep])
    types = {p.test_type for p in proposals}
    assert "MissingAuth" in types

def test_no_irrelevant_proposals():
    # This endpoint has security defined and no other triggers.
    ep = make_endpoint(
        path="/static/info",
        security=[{"apiKey": []}],
    )
    proposals = generate_proposals([ep])
    # Only MissingAuth should be excluded because security is present.
    types = {p.test_type for p in proposals}
    assert types == set()

def test_unique_proposal_ids():
    ep1 = make_endpoint(path="/users/{id}")
    ep2 = make_endpoint(path="/admin")
    proposals = generate_proposals([ep1, ep2])
    ids = [p.test_id for p in proposals]
    assert len(ids) == len(set(ids))

def test_session_isolation_and_storage():
    sid1 = session_store.create_session()
    sid2 = session_store.create_session()
    ep = make_endpoint(path="/users/{id}")
    proposals = generate_proposals([ep])
    # Store in first session only
    for p in proposals:
        session_store.add_proposal(sid1, p)
    # Ensure second session cannot retrieve them
    with pytest.raises(KeyError):
        session_store.get_proposal(sid2, proposals[0].test_id)
    # First session can retrieve
    retrieved = session_store.get_proposal(sid1, proposals[0].test_id)
    assert retrieved.test_id == proposals[0].test_id

def test_propose_endpoint_success_and_retrieval():
    sid = session_store.create_session()
    # Build endpoint inventory JSON (using the same data we used for generation)
    ep_json = [
        {
            "path": "/users/{id}",
            "method": "get",
            "responses": {"200": {"description": "OK"}},
        }
    ]
    response = client.post(
        "/tests/propose",
        json=ep_json,
        headers={"X-Session-ID": sid},
    )
    assert response.status_code == 200
    proposals = response.json()
    assert any(p["test_type"] == "BOLA" for p in proposals)
    # Retrieve one of the proposals via GET
    test_id = proposals[0]["test_id"]
    get_resp = client.get(f"/tests/{test_id}", headers={"X-Session-ID": sid})
    assert get_resp.status_code == 200
    assert get_resp.json()["test_id"] == test_id

def test_propose_endpoint_empty_inventory():
    sid = session_store.create_session()
    resp = client.post("/tests/propose", json=[], headers={"X-Session-ID": sid})
    assert resp.status_code == 400

def test_propose_endpoint_oversized_inventory():
    sid = session_store.create_session()
    large_payload = [
        {
            "path": f"/item/{i}",
            "method": "get",
            "responses": {"200": {"description": "OK"}},
        }
        for i in range(1001)
    ]
    resp = client.post("/tests/propose", json=large_payload, headers={"X-Session-ID": sid})
    assert resp.status_code == 413

def test_get_unknown_proposal_returns_404():
    sid = session_store.create_session()
    unknown_id = str(uuid.uuid4())
    resp = client.get(f"/tests/{unknown_id}", headers={"X-Session-ID": sid})
    assert resp.status_code == 404

