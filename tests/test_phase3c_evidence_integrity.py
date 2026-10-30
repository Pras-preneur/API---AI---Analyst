"""Focused regression and evidence integrity tests for Phase 3C.

Verifies:
- Structured HTTP response evidence validation.
- Valid HTTP status code extraction and range enforcement.
- Handling of legitimate empty response bodies (e.g. HTTP 204).
- Rejection of arbitrary non-evidence metadata dictionaries.
- Rejection of INCONCLUSIVE or ACCESS_DENIED findings for confirmation.
- Safe human confirmation of valid SUSPECTED findings.
- Preservation of FALSE_POSITIVE review on non-confirmed findings.
- Rejection of cross-session review attempts.
- Evidence compatibility across Stage 5 synthetic models and all three Stage 6 differential engines:
  BOLA (Stage 6.1), BFLA (Stage 6.2), Broken Authentication (Stage 6.3).
"""

import json
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.models import (
    AssessmentOutcome,
    EndpointModel,
    Evidence,
    ExecutionStatus,
    Finding,
    FindingStatus,
    HumanReviewOutcome,
    session_store,
)
from app.security.evidence_validator import (
    extract_http_status_code,
    validate_human_review_evidence,
)


@pytest.fixture(autouse=True)
def clean_sessions():
    session_store._sessions.clear()
    yield
    session_store._sessions.clear()


@pytest.fixture
def client():
    return TestClient(app)


def _make_endpoint(path: str = "/api/v1/resource", method: str = "GET") -> EndpointModel:
    return EndpointModel.model_validate({
        "path": path,
        "method": method,
        "summary": "Test Endpoint",
        "responses": {"200": {"description": "OK"}},
    })


def _create_test_session():
    return session_store.create_session()


# ---------------------------------------------------------------------------
# 1. Valid HTTP Response Evidence
# ---------------------------------------------------------------------------

def test_01_valid_http_response_evidence_direct_status(client):
    """Direct status_code and body dictionary in evidence.response is valid."""
    session_id = _create_test_session()
    finding = Finding(
        test_id="test-val-1",
        endpoint=_make_endpoint(),
        evidence=Evidence(
            request={"method": "GET", "url": "http://127.0.0.1:8001/api/v1/resource"},
            response={"status_code": 200, "body": {"id": 1, "data": "confidential"}},
        ),
        severity="High",
        status=FindingStatus.SUSPECTED,
        execution_status=ExecutionStatus.COMPLETED,
        assessment_outcome=AssessmentOutcome.SUSPECTED,
    )
    session = session_store.get_session(session_id)
    session.add_finding(finding)

    res = client.post(
        f"/findings/{finding.finding_id}/review",
        headers={"X-Session-ID": session_id},
        json={"outcome": "CONFIRMED", "reviewer_id": "auditor-1", "reviewer_notes": "Confirmed valid evidence."},
    )
    assert res.status_code == 200
    data = res.json()
    assert data["assessment_outcome"] == "CONFIRMED"
    assert data["status"] == "Confirmed"
    assert data["is_human_reviewed"] is True
    assert data["reviewer_id"] == "auditor-1"


# ---------------------------------------------------------------------------
# 2. Legitimate Empty Body (e.g. HTTP 204 No Content)
# ---------------------------------------------------------------------------

def test_02_valid_http_response_empty_body_204(client):
    """Legitimate HTTP 204 response with empty body is valid for human review."""
    session_id = _create_test_session()
    finding = Finding(
        test_id="test-204",
        endpoint=_make_endpoint(),
        evidence=Evidence(
            request={"method": "DELETE", "url": "http://127.0.0.1:8001/api/v1/resource"},
            response={"status_code": 204, "body": {}},
        ),
        severity="Medium",
        status=FindingStatus.SUSPECTED,
        execution_status=ExecutionStatus.COMPLETED,
        assessment_outcome=AssessmentOutcome.SUSPECTED,
    )
    session = session_store.get_session(session_id)
    session.add_finding(finding)

    res = client.post(
        f"/findings/{finding.finding_id}/review",
        headers={"X-Session-ID": session_id},
        json={"outcome": "CONFIRMED", "reviewer_id": "auditor-1", "reviewer_notes": "Confirmed deletion without auth."},
    )
    assert res.status_code == 200
    assert res.json()["assessment_outcome"] == "CONFIRMED"


# ---------------------------------------------------------------------------
# 3. Missing Status Code
# ---------------------------------------------------------------------------

def test_03_missing_status_code_rejected(client):
    """Finding with missing HTTP status code across all evidence paths cannot be confirmed."""
    session_id = _create_test_session()
    finding = Finding(
        test_id="test-missing-status",
        endpoint=_make_endpoint(),
        evidence=Evidence(
            request={"method": "GET", "url": "/test"},
            response={"body": {"some": "data"}},  # No status_code
        ),
        severity="High",
        status=FindingStatus.SUSPECTED,
        execution_status=ExecutionStatus.COMPLETED,
        assessment_outcome=AssessmentOutcome.SUSPECTED,
    )
    session = session_store.get_session(session_id)
    session.add_finding(finding)

    res = client.post(
        f"/findings/{finding.finding_id}/review",
        headers={"X-Session-ID": session_id},
        json={"outcome": "CONFIRMED", "reviewer_id": "auditor-1", "reviewer_notes": "Attempting confirmation"},
    )
    assert res.status_code == 400
    assert "missing or unverifiable http status code" in res.json()["detail"].lower()


# ---------------------------------------------------------------------------
# 4. Invalid Status Code (Range & Type)
# ---------------------------------------------------------------------------

def test_04_invalid_status_code_out_of_range(client):
    """Status code outside [100, 599] is rejected."""
    session_id = _create_test_session()
    finding = Finding(
        test_id="test-invalid-status-99",
        endpoint=_make_endpoint(),
        evidence=Evidence(
            request={"method": "GET", "url": "/test"},
            response={"status_code": 99, "body": {"foo": "bar"}},
        ),
        severity="High",
        status=FindingStatus.SUSPECTED,
        execution_status=ExecutionStatus.COMPLETED,
        assessment_outcome=AssessmentOutcome.SUSPECTED,
    )
    session = session_store.get_session(session_id)
    session.add_finding(finding)

    res = client.post(
        f"/findings/{finding.finding_id}/review",
        headers={"X-Session-ID": session_id},
        json={"outcome": "CONFIRMED", "reviewer_id": "auditor-1", "reviewer_notes": "Attempting confirmation"},
    )
    assert res.status_code == 400
    assert "invalid http status code" in res.json()["detail"].lower()


def test_04b_invalid_status_code_600(client):
    """Status code 600 is rejected."""
    session_id = _create_test_session()
    finding = Finding(
        test_id="test-invalid-status-600",
        endpoint=_make_endpoint(),
        evidence=Evidence(
            request={"method": "GET", "url": "/test"},
            response={"status_code": 600, "body": {"foo": "bar"}},
        ),
        severity="High",
        status=FindingStatus.SUSPECTED,
        execution_status=ExecutionStatus.COMPLETED,
        assessment_outcome=AssessmentOutcome.SUSPECTED,
    )
    session = session_store.get_session(session_id)
    session.add_finding(finding)

    res = client.post(
        f"/findings/{finding.finding_id}/review",
        headers={"X-Session-ID": session_id},
        json={"outcome": "CONFIRMED", "reviewer_id": "auditor-1", "reviewer_notes": "Attempting confirmation"},
    )
    assert res.status_code == 400
    assert "invalid http status code" in res.json()["detail"].lower()


# ---------------------------------------------------------------------------
# 5. Arbitrary Non-Empty Metadata Dictionary Rejection
# ---------------------------------------------------------------------------

def test_05_arbitrary_metadata_dict_rejected(client):
    """An arbitrary non-empty dictionary that does not represent HTTP response evidence is rejected."""
    session_id = _create_test_session()
    finding = Finding(
        test_id="test-arbitrary",
        endpoint=_make_endpoint(),
        evidence=Evidence(
            request={"method": "GET", "url": "/test"},
            response={"client_meta": "random_data", "unrelated_field": 12345},
        ),
        severity="High",
        status=FindingStatus.SUSPECTED,
        execution_status=ExecutionStatus.COMPLETED,
        assessment_outcome=AssessmentOutcome.SUSPECTED,
    )
    session = session_store.get_session(session_id)
    session.add_finding(finding)

    res = client.post(
        f"/findings/{finding.finding_id}/review",
        headers={"X-Session-ID": session_id},
        json={"outcome": "CONFIRMED", "reviewer_id": "auditor-1", "reviewer_notes": "Attempting confirmation"},
    )
    assert res.status_code == 400
    assert "valid http response evidence" in res.json()["detail"].lower()


# ---------------------------------------------------------------------------
# 6. Missing Execution-Step Evidence
# ---------------------------------------------------------------------------

def test_06_unexecuted_finding_rejected(client):
    """Finding with execution_status NOT_EXECUTED or FAILED cannot be confirmed."""
    session_id = _create_test_session()
    finding = Finding(
        test_id="test-unexec",
        endpoint=_make_endpoint(),
        evidence=Evidence(
            request={},
            response={"status_code": 200, "body": {"data": "test"}},
        ),
        severity="High",
        status=FindingStatus.NOT_EXECUTED,
        execution_status=ExecutionStatus.NOT_EXECUTED,
        assessment_outcome=AssessmentOutcome.INCONCLUSIVE,
    )
    session = session_store.get_session(session_id)
    session.add_finding(finding)

    res = client.post(
        f"/findings/{finding.finding_id}/review",
        headers={"X-Session-ID": session_id},
        json={"outcome": "CONFIRMED", "reviewer_id": "auditor-1", "reviewer_notes": "Premature confirmation"},
    )
    assert res.status_code == 400
    assert "only completed executions can be confirmed" in res.json()["detail"].lower()


# ---------------------------------------------------------------------------
# 7. Malformed / Empty Response Evidence
# ---------------------------------------------------------------------------

def test_07_empty_response_dict_rejected(client):
    """Empty response dictionary `{}` is rejected for confirmation."""
    session_id = _create_test_session()
    finding = Finding(
        test_id="test-empty-resp",
        endpoint=_make_endpoint(),
        evidence=Evidence(
            request={"method": "GET", "url": "/test"},
            response={},
        ),
        severity="High",
        status=FindingStatus.SUSPECTED,
        execution_status=ExecutionStatus.COMPLETED,
        assessment_outcome=AssessmentOutcome.SUSPECTED,
    )
    session = session_store.get_session(session_id)
    session.add_finding(finding)

    res = client.post(
        f"/findings/{finding.finding_id}/review",
        headers={"X-Session-ID": session_id},
        json={"outcome": "CONFIRMED", "reviewer_id": "auditor-1", "reviewer_notes": "Confirmation attempt"},
    )
    assert res.status_code == 400
    assert "valid http response evidence" in res.json()["detail"].lower()


# ---------------------------------------------------------------------------
# 8. INCONCLUSIVE Outcome Confirmation Rejection
# ---------------------------------------------------------------------------

def test_08_inconclusive_outcome_confirmation_rejected(client):
    """Finding with assessment_outcome INCONCLUSIVE cannot be confirmed."""
    session_id = _create_test_session()
    finding = Finding(
        test_id="test-inconclusive",
        endpoint=_make_endpoint(),
        evidence=Evidence(
            request={"method": "GET", "url": "/test"},
            response={"status_code": 200, "body": {"user": "guest"}},
        ),
        severity="Low",
        status=FindingStatus.NOT_EXECUTED,
        execution_status=ExecutionStatus.COMPLETED,
        assessment_outcome=AssessmentOutcome.INCONCLUSIVE,
    )
    session = session_store.get_session(session_id)
    session.add_finding(finding)

    res = client.post(
        f"/findings/{finding.finding_id}/review",
        headers={"X-Session-ID": session_id},
        json={"outcome": "CONFIRMED", "reviewer_id": "auditor-1", "reviewer_notes": "Confirmation attempt"},
    )
    assert res.status_code == 400
    assert "inconclusive" in res.json()["detail"].lower()


# ---------------------------------------------------------------------------
# 9. ACCESS_DENIED Outcome Confirmation Rejection
# ---------------------------------------------------------------------------

def test_09_access_denied_outcome_confirmation_rejected(client):
    """Finding with assessment_outcome ACCESS_DENIED cannot be confirmed as a vulnerability."""
    session_id = _create_test_session()
    finding = Finding(
        test_id="test-access-denied",
        endpoint=_make_endpoint(),
        evidence=Evidence(
            request={"method": "GET", "url": "/test"},
            response={"status_code": 403, "body": {"error": "Forbidden"}},
            notes="Access denied to cross-tenant probe (HTTP 403)",
        ),
        severity="Low",
        status=FindingStatus.NOT_EXECUTED,
        execution_status=ExecutionStatus.COMPLETED,
        assessment_outcome=AssessmentOutcome.ACCESS_DENIED,
    )
    session = session_store.get_session(session_id)
    session.add_finding(finding)

    res = client.post(
        f"/findings/{finding.finding_id}/review",
        headers={"X-Session-ID": session_id},
        json={"outcome": "CONFIRMED", "reviewer_id": "auditor-1", "reviewer_notes": "Trying to confirm protected endpoint"},
    )
    assert res.status_code == 400
    assert "access was denied" in res.json()["detail"].lower()


# ---------------------------------------------------------------------------
# 10. Valid SUSPECTED Finding Confirmation by Human Review
# ---------------------------------------------------------------------------

def test_10_valid_suspected_finding_confirmed(client):
    """Valid SUSPECTED finding can be confirmed by human review with reviewer ID and rationale."""
    session_id = _create_test_session()
    finding = Finding(
        test_id="test-suspected-ok",
        endpoint=_make_endpoint("/accounts/{id}/balance"),
        evidence=Evidence(
            request={"method": "GET", "url": "http://127.0.0.1:8001/accounts/101/balance"},
            response={"status_code": 200, "body": {"account_id": "101", "balance": 9999.50}},
        ),
        severity="High",
        status=FindingStatus.SUSPECTED,
        execution_status=ExecutionStatus.COMPLETED,
        assessment_outcome=AssessmentOutcome.SUSPECTED,
    )
    session = session_store.get_session(session_id)
    session.add_finding(finding)

    res = client.post(
        f"/findings/{finding.finding_id}/review",
        headers={"X-Session-ID": session_id},
        json={
            "outcome": "CONFIRMED",
            "reviewer_id": "lead-sec-auditor-10",
            "reviewer_notes": "Confirmed unauthorized tenant balance disclosure.",
        },
    )
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "Confirmed"
    assert data["assessment_outcome"] == "CONFIRMED"
    assert data["is_human_reviewed"] is True
    assert data["reviewer_id"] == "lead-sec-auditor-10"


# ---------------------------------------------------------------------------
# 11. False-Positive Review Behavior
# ---------------------------------------------------------------------------

def test_11_false_positive_allowed_on_any_outcome(client):
    """Marking a finding as FALSE_POSITIVE is permitted even on inconclusive, failed, or suspected findings."""
    session_id = _create_test_session()
    finding = Finding(
        test_id="test-fp-inconclusive",
        endpoint=_make_endpoint(),
        evidence=Evidence(request={}, response={}),
        severity="Low",
        status=FindingStatus.NOT_EXECUTED,
        execution_status=ExecutionStatus.FAILED,
        assessment_outcome=AssessmentOutcome.INCONCLUSIVE,
    )
    session = session_store.get_session(session_id)
    session.add_finding(finding)

    res = client.post(
        f"/findings/{finding.finding_id}/review",
        headers={"X-Session-ID": session_id},
        json={
            "outcome": "FALSE_POSITIVE",
            "reviewer_id": "analyst-2",
            "reviewer_notes": "Expected failure on deprecated endpoint.",
        },
    )
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "FalsePositive"
    assert data["assessment_outcome"] == "FALSE_POSITIVE"
    assert data["is_human_reviewed"] is True


# ---------------------------------------------------------------------------
# 12. Cross-Session Review Rejection
# ---------------------------------------------------------------------------

def test_12_cross_session_review_rejected(client):
    """Attempting to review a finding belonging to a different session returns 404."""
    session1 = _create_test_session()
    session2 = _create_test_session()

    finding = Finding(
        test_id="test-session-iso",
        endpoint=_make_endpoint(),
        evidence=Evidence(
            request={"method": "GET", "url": "/test"},
            response={"status_code": 200, "body": {"user": "123"}},
        ),
        severity="High",
        status=FindingStatus.SUSPECTED,
        execution_status=ExecutionStatus.COMPLETED,
        assessment_outcome=AssessmentOutcome.SUSPECTED,
    )
    session_store.get_session(session1).add_finding(finding)

    # Session 2 tries to review Session 1's finding
    res = client.post(
        f"/findings/{finding.finding_id}/review",
        headers={"X-Session-ID": session2},
        json={"outcome": "CONFIRMED", "reviewer_id": "hacker", "reviewer_notes": "Unauthorized review attempt"},
    )
    assert res.status_code == 404
    assert "finding not found" in res.json()["detail"].lower()


# ---------------------------------------------------------------------------
# 13. Existing Stage 5 Synthetic Evidence Compatibility
# ---------------------------------------------------------------------------

def test_13_stage5_synthetic_evidence_compatibility(client):
    """Stage 5 synthetic evidence structure `{"status_code": 200, "body": ...}` validates smoothly."""
    session_id = _create_test_session()
    finding = Finding(
        test_id="test-stage5-compat",
        endpoint=_make_endpoint(),
        evidence=Evidence(
            request={"method": "GET", "url": "http://127.0.0.1:8001/users/1", "headers": {}},
            response={"status_code": 200, "body": {"account_id": "123", "owner": "alice"}},
        ),
        severity="High",
        status=FindingStatus.SUSPECTED,
        execution_status=ExecutionStatus.COMPLETED,
        assessment_outcome=AssessmentOutcome.SUSPECTED,
    )
    session_store.get_session(session_id).add_finding(finding)

    res = client.post(
        f"/findings/{finding.finding_id}/review",
        headers={"X-Session-ID": session_id},
        json={"outcome": "CONFIRMED", "reviewer_id": "stage5-auditor", "reviewer_notes": "Stage 5 structure verified."},
    )
    assert res.status_code == 200
    assert res.json()["assessment_outcome"] == "CONFIRMED"


# ---------------------------------------------------------------------------
# 14. Stage 6 Differential Engine Evidence Compatibility
# ---------------------------------------------------------------------------

def test_14a_stage6_1_bola_evidence_compatibility(client):
    """BOLA engine evidence format (response dictionary containing status_code and sanitized body) validates."""
    session_id = _create_test_session()
    step_logs = {
        "cross_tenant_probe": {"status_code": 200, "content_type": "application/json", "body_present": True},
        "owner_baseline": {"status_code": 200, "content_type": "application/json", "body_present": True},
    }
    notes_payload = {
        "outcome": "SUSPECTED",
        "reason": "BOLA exposure confirmed: cross-tenant probe retrieved owner object.",
        "steps": step_logs,
    }
    finding = Finding(
        test_id="test-bola-compat",
        endpoint=_make_endpoint("/api/v1/accounts/{id}/statement"),
        evidence=Evidence(
            request={"method": "GET", "url": "http://127.0.0.1:8001/api/v1/accounts/101/statement", "headers": {}},
            response={"status_code": 200, "body": {"account_id": 101, "statement": "secret-tx-data"}},
            notes="Cross-tenant probe retrieved owner object",
        ),
        severity="High",
        status=FindingStatus.SUSPECTED,
        execution_status=ExecutionStatus.COMPLETED,
        assessment_outcome=AssessmentOutcome.SUSPECTED,
        notes=json.dumps(notes_payload),
    )
    session_store.get_session(session_id).add_finding(finding)

    res = client.post(
        f"/findings/{finding.finding_id}/review",
        headers={"X-Session-ID": session_id},
        json={"outcome": "CONFIRMED", "reviewer_id": "bola-auditor", "reviewer_notes": "Confirmed BOLA data leak."},
    )
    assert res.status_code == 200
    assert res.json()["assessment_outcome"] == "CONFIRMED"


def test_14b_stage6_2_bfla_evidence_compatibility(client):
    """BFLA engine evidence format (response body with step logs in finding.notes) validates."""
    session_id = _create_test_session()
    step_logs = {
        "lower_privileged_probe": {"status_code": 200, "content_type": "application/json", "body_present": True},
        "privileged_baseline": {"status_code": 200, "content_type": "application/json", "body_present": True},
    }
    notes_payload = {
        "probe_status": 200,
        "privileged_status": 200,
        "steps": step_logs,
    }
    finding = Finding(
        test_id="test-bfla-compat",
        endpoint=_make_endpoint("/admin/data"),
        evidence=Evidence(
            request={"method": "GET", "url": "http://127.0.0.1:8001/admin/data", "headers": {}},
            response={"adminonly": "secret privileged records"},
            notes="Privileged baseline returned 200; lower-privileged probe returned 200",
        ),
        severity="High",
        status=FindingStatus.SUSPECTED,
        execution_status=ExecutionStatus.COMPLETED,
        assessment_outcome=AssessmentOutcome.SUSPECTED,
        notes=json.dumps(notes_payload),
    )
    session_store.get_session(session_id).add_finding(finding)

    res = client.post(
        f"/findings/{finding.finding_id}/review",
        headers={"X-Session-ID": session_id},
        json={"outcome": "CONFIRMED", "reviewer_id": "bfla-auditor", "reviewer_notes": "Confirmed BFLA access bypass."},
    )
    assert res.status_code == 200
    assert res.json()["assessment_outcome"] == "CONFIRMED"


def test_14c_stage6_3_auth_evidence_compatibility(client):
    """Broken Authentication engine evidence format (response body with step logs in finding.notes) validates."""
    session_id = _create_test_session()
    step_logs = {
        "unauthenticated_probe": {"status_code": 200, "content_type": "application/json", "body_present": True},
        "authenticated_baseline": {"status_code": 200, "content_type": "application/json", "body_present": True},
    }
    notes_payload = {
        "probe_status": 200,
        "baseline_status": 200,
        "steps": step_logs,
    }
    finding = Finding(
        test_id="test-auth-compat",
        endpoint=_make_endpoint("/auth/vulnerable/profile"),
        evidence=Evidence(
            request={"method": "GET", "url": "http://127.0.0.1:8001/auth/vulnerable/profile", "headers": {}},
            response={"id": "alice", "profile": "confidential user data"},
            notes="Authenticated baseline returned 200; unauthenticated probe returned 200",
        ),
        severity="High",
        status=FindingStatus.SUSPECTED,
        execution_status=ExecutionStatus.COMPLETED,
        assessment_outcome=AssessmentOutcome.SUSPECTED,
        notes=json.dumps(notes_payload),
    )
    session_store.get_session(session_id).add_finding(finding)

    res = client.post(
        f"/findings/{finding.finding_id}/review",
        headers={"X-Session-ID": session_id},
        json={"outcome": "CONFIRMED", "reviewer_id": "auth-auditor", "reviewer_notes": "Confirmed missing auth."},
    )
    assert res.status_code == 200
    assert res.json()["assessment_outcome"] == "CONFIRMED"
