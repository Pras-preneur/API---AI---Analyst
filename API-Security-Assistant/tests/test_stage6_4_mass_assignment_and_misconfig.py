"""Stage 6.4 & 6.5: Mass Assignment, Security Misconfiguration, Bounded Uploads & Concurrency Hardening.

Verifies:
1. Mass Assignment detection on vulnerable mock endpoint (PATCH /profile).
2. Mass Assignment rejection on protected endpoint (PATCH /secure/profile).
3. Security headers middleware presence (X-Content-Type-Options, X-Frame-Options, Referrer-Policy).
4. Bounded OpenAPI upload stream enforcement (413 Payload Too Large when > 5MB).
5. Thread-safe concurrent operations on Session and SessionStore.
6. Assessment outcome reviewer notes governance validation.
"""

import threading
import io
import pytest
from fastapi.testclient import TestClient

from app.main import app
import app.mock_api as mock_api_module
from app.mock_api import mock_app
from app.models import (
    AssessmentOutcome,
    EndpointModel,
    ExecutionStatus,
    FindingStatus,
    ProposedTest,
    Session,
    TestStatus,
    session_store,
    validate_assessment_outcome,
)

client = TestClient(app)
mock_client = TestClient(mock_app)


@pytest.fixture(autouse=True)
def reset_mock_users():
    """Reset mock users state before and after each test."""
    mock_api_module.users_store["user_a"]["role"] = "user"
    mock_api_module.users_store["user_a"]["is_admin"] = False
    mock_api_module.users_store["user_a"]["profile"] = {"bio": "Hello world", "email": "a@example.com"}
    mock_api_module.users_store["user_b"]["role"] = "user"
    mock_api_module.users_store["user_b"]["is_admin"] = False
    mock_api_module.users_store["user_b"]["profile"] = {"bio": "Hey there", "email": "b@example.com"}
    yield
    mock_api_module.users_store["user_a"]["role"] = "user"
    mock_api_module.users_store["user_a"]["is_admin"] = False
    mock_api_module.users_store["user_a"]["profile"] = {"bio": "Hello world", "email": "a@example.com"}
    mock_api_module.users_store["user_b"]["role"] = "user"
    mock_api_module.users_store["user_b"]["is_admin"] = False
    mock_api_module.users_store["user_b"]["profile"] = {"bio": "Hey there", "email": "b@example.com"}


def test_mass_assignment_vulnerable_endpoint():
    """Test that PATCH /profile accepts restricted fields (role, is_admin) when authenticated."""
    payload = {
        "bio": "Security Researcher",
        "role": "admin",
        "is_admin": True
    }
    resp = mock_client.patch("/profile", json=payload, auth=("user_a", "passwordA"))
    assert resp.status_code == 200
    data = resp.json()
    assert data["role"] == "admin"


def test_mass_assignment_protected_endpoint():
    """Test that PATCH /secure/profile rejects restricted fields with 422 even when authenticated."""
    payload = {
        "bio": "Security Researcher",
        "role": "admin",
        "is_admin": True
    }
    resp = mock_client.patch("/secure/profile", json=payload, auth=("user_a", "passwordA"))
    assert resp.status_code == 422
    assert "restricted" in resp.json()["detail"].lower()

    # Allowed fields only
    valid_payload = {"bio": "Just a bio"}
    valid_resp = mock_client.patch("/secure/profile", json=valid_payload, auth=("user_a", "passwordA"))
    assert valid_resp.status_code == 200
    assert valid_resp.json()["profile"]["bio"] == "Just a bio"
    assert valid_resp.json()["role"] == "user"


def test_mass_assignment_execution_endpoint_workflow():
    """Test executing a MassAssignment proposed test via /tests/execute against mock API."""
    session_id = session_store.create_session()
    endpoint = EndpointModel(
        path="/profile",
        method="PATCH",
        summary="Update profile",
        tags=["Profile"],
        request_body=None,
        responses={},
    )
    proposal = ProposedTest(
        test_id="test-ma-001",
        endpoint=endpoint,
        test_type="MassAssignment",
        severity="Medium",
        status=TestStatus.APPROVED,
        description="Mass assignment on /profile",
    )
    session_store.add_proposal(session_id, proposal)

    response = client.post(
        "/tests/execute",
        json={"proposal_ids": ["test-ma-001"], "target": "http://127.0.0.1:8001"},
        headers={"X-Session-ID": session_id},
    )
    assert response.status_code == 200
    findings = response.json()
    assert len(findings) == 1
    ma_finding = findings[0]
    assert ma_finding["test_id"] == "test-ma-001"
    assert ma_finding["status"] == FindingStatus.SUSPECTED.value


def test_security_headers_middleware():
    """Verify production security headers on FastAPI responses."""
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.headers.get("x-content-type-options") == "nosniff"
    assert resp.headers.get("x-frame-options") == "DENY"
    assert resp.headers.get("referrer-policy") == "strict-origin-when-cross-origin"


def test_bounded_chunked_upload_rejection():
    """Verify that file uploads streaming > 5MB are terminated with 413."""
    session_id = session_store.create_session()
    
    # 5.5MB dummy content
    dummy_data = b"A" * 65536 * 85  # ~5.5MB

    resp = client.post(
        "/parse-openapi",
        files={"file": ("large_spec.json", io.BytesIO(dummy_data), "application/json")},
        headers={"X-Session-ID": session_id},
    )
    assert resp.status_code == 413
    assert "large" in resp.json()["detail"].lower() or "exceeds" in resp.json()["detail"].lower()


def test_session_store_thread_safety():
    """Verify concurrent thread modifications on Session and SessionStore are thread-safe."""
    session_id = session_store.create_session()
    session = session_store.get_session(session_id)
    assert session is not None

    def worker(i: int):
        endpoint = EndpointModel(
            path=f"/resource/{i}",
            method="GET",
            summary=f"Get resource {i}",
            responses={},
        )
        prop = ProposedTest(
            test_id=f"test-prop-{i}",
            endpoint=endpoint,
            test_type="BOLA",
            severity="Medium",
            description=f"Test prop {i}",
            status=TestStatus.PROPOSED,
        )
        session_store.add_proposal(session_id, prop)
        session_store.set_proposal_status(session_id, f"test-prop-{i}", TestStatus.APPROVED)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(20)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    session = session_store.get_session(session_id)
    assert len(session.proposals) == 20
    for prop in session.proposals.values():
        assert prop.status == TestStatus.APPROVED


def test_reviewer_notes_validation():
    """Verify human review governance invariants on CONFIRMED findings."""
    # Automated attempt to set CONFIRMED raises ValueError
    with pytest.raises(ValueError, match="requires explicit human review"):
        validate_assessment_outcome(
            AssessmentOutcome.CONFIRMED,
            is_human_review=False,
            reviewer_notes="Confirmed vulnerability in production test"
        )

    # Valid human review with notes (>= 5 chars) succeeds
    validate_assessment_outcome(
        AssessmentOutcome.CONFIRMED,
        is_human_review=True,
        reviewer_notes="Confirmed vulnerability in production test"
    )

    # Human review with short notes (< 5 chars) raises ValueError
    with pytest.raises(ValueError, match="at least 5 characters"):
        validate_assessment_outcome(
            AssessmentOutcome.CONFIRMED,
            is_human_review=True,
            reviewer_notes="No"
        )
