"""Regression tests verifying remediation of the Stage 5 Security Audit findings (SEC-01 through SEC-08).

Project: API Security Testing Assistant
Audit Scope:
- SEC-01: Reviewer identity audit-identifier semantics.
- SEC-02: Preservation of reviewed findings and audit history upon re-execution.
- SEC-03: Strict guards against confirming unexecuted, failed, inconclusive, or evidence-less findings.
- SEC-04: Immutable review history preserving decision toggles and audit trail.
- SEC-05: Robust key-value string credential value masking without breaking keys.
- SEC-06: URL basic-auth stripping and sanitized exception reporting.
- SEC-07: Accurate report statistics strictly separating completed, failed, and not executed tests.
- SEC-08: Review request outcome schema validation (only CONFIRMED or FALSE_POSITIVE allowed).
"""

import json
import uuid
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.models import (
    AssessmentOutcome,
    EndpointModel,
    Evidence,
    ExecutionConfig,
    ExecutionMode,
    ExecutionStatus,
    Finding,
    FindingReviewRequest,
    FindingStatus,
    HumanReviewOutcome,
    ProposedTest,
    Report,
    ReviewRecord,
    Session,
    TestStatus,
    session_store,
)
from app.security.report_engine import generate_report
from app.security.request_builder import PreparedRequest
from app.security.sanitization import (
    REDACTED_MARKER,
    sanitize_data,
    sanitize_error_message,
    sanitize_string,
    sanitize_url,
)


@pytest.fixture(autouse=True)
def clean_store():
    session_store._sessions.clear()
    yield
    session_store._sessions.clear()


@pytest.fixture
def client():
    return TestClient(app)


def _make_endpoint(path: str = "/api/v1/accounts/{id}", method: str = "get") -> EndpointModel:
    return EndpointModel.model_validate({
        "path": path,
        "method": method,
        "summary": "Account endpoint",
        "responses": {"200": {"description": "OK"}},
    })


def _make_finding(
    test_id: str,
    execution_status: ExecutionStatus = ExecutionStatus.COMPLETED,
    assessment_outcome: AssessmentOutcome = AssessmentOutcome.SUSPECTED,
    has_evidence_response: bool = True,
) -> Finding:
    response_data = {"status_code": 200, "body": {"account_id": "123", "owner": "alice"}} if has_evidence_response else {}
    return Finding(
        test_id=test_id,
        endpoint=_make_endpoint(),
        evidence=Evidence(
            request={"method": "GET", "url": "http://127.0.0.1:8001/api/v1/accounts/123", "headers": {}},
            response=response_data,
            notes="Observed cross-tenant access",
        ),
        severity="High",
        status=FindingStatus.SUSPECTED,
        execution_status=execution_status,
        assessment_outcome=assessment_outcome,
        assessment_reason="Differential response indicates unauthorized access",
        remediation="Enforce object-level access controls",
        is_human_reviewed=False,
    )


# ---------------------------------------------------------------------------
# SEC-01 & SEC-04: Reviewer Identity & Audit History Trail
# ---------------------------------------------------------------------------

def test_sec01_reviewer_id_recorded_in_review_record(client):
    """SEC-01: reviewer_id is stored in immutable ReviewRecord as client-asserted audit identifier."""
    session_id = session_store.create_session()
    finding = _make_finding("test-sec01")
    session = session_store.get_session(session_id)
    session.add_finding(finding)

    resp = client.post(
        f"/findings/{finding.finding_id}/review",
        headers={"X-Session-ID": session_id},
        json={
            "outcome": "CONFIRMED",
            "reviewer_notes": "Verified against staging database",
            "reviewer_id": "analyst-sec-team-42",
        },
    )
    assert resp.status_code == 200
    data = resp.json()

    assert data["is_human_reviewed"] is True
    assert data["reviewer_id"] == "analyst-sec-team-42"
    assert data["assessment_outcome"] == "CONFIRMED"
    assert len(data["review_history"]) == 1
    assert data["review_history"][0]["reviewer_id"] == "analyst-sec-team-42"
    assert data["review_history"][0]["decision"] == "CONFIRMED"
    assert data["review_history"][0]["notes"] == "Verified against staging database"


def test_sec04_multiple_reviews_preserve_history_trail(client):
    """SEC-04: Multiple review decisions append to review_history and maintain full audit trail."""
    session_id = session_store.create_session()
    finding = _make_finding("test-sec04")
    session = session_store.get_session(session_id)
    session.add_finding(finding)

    # 1. First review: CONFIRMED
    resp1 = client.post(
        f"/findings/{finding.finding_id}/review",
        headers={"X-Session-ID": session_id},
        json={"outcome": "CONFIRMED", "reviewer_notes": "Looks vulnerable", "reviewer_id": "alice"},
    )
    assert resp1.status_code == 200
    assert resp1.json()["assessment_outcome"] == "CONFIRMED"

    # 2. Second review: toggle to FALSE_POSITIVE
    resp2 = client.post(
        f"/findings/{finding.finding_id}/review",
        headers={"X-Session-ID": session_id},
        json={"outcome": "FALSE_POSITIVE", "reviewer_notes": "Resource is actually public by design", "reviewer_id": "bob"},
    )
    assert resp2.status_code == 200
    data2 = resp2.json()
    assert data2["assessment_outcome"] == "FALSE_POSITIVE"
    assert len(data2["review_history"]) == 2
    assert data2["review_history"][0]["decision"] == "CONFIRMED"
    assert data2["review_history"][0]["reviewer_id"] == "alice"
    assert data2["review_history"][1]["decision"] == "FALSE_POSITIVE"
    assert data2["review_history"][1]["reviewer_id"] == "bob"

    # 3. Third review: back to CONFIRMED
    resp3 = client.post(
        f"/findings/{finding.finding_id}/review",
        headers={"X-Session-ID": session_id},
        json={"outcome": "CONFIRMED", "reviewer_notes": "Re-verified; resource is private", "reviewer_id": "lead-sec"},
    )
    assert resp3.status_code == 200
    data3 = resp3.json()
    assert data3["assessment_outcome"] == "CONFIRMED"
    assert len(data3["review_history"]) == 3
    assert [r["decision"] for r in data3["review_history"]] == ["CONFIRMED", "FALSE_POSITIVE", "CONFIRMED"]


# ---------------------------------------------------------------------------
# SEC-02: Preservation of Reviewed Findings on Re-execution
# ---------------------------------------------------------------------------

def test_sec02_reexecution_preserves_finding_identity_and_history_sets_requires_re_review():
    """SEC-02: Re-execution of a reviewed finding preserves finding_id & history, clears stale confirmation, sets requires_re_review."""
    session = Session(session_id="test-sec02-sess")
    finding = _make_finding("test-reexec-1")
    session.add_finding(finding)

    # Human reviews and confirms
    review_rec = ReviewRecord(
        decision=HumanReviewOutcome.CONFIRMED,
        reviewer_id="human-reviewer",
        notes="Verified BOLA leak",
    )
    finding.review_history.append(review_rec)
    finding.is_human_reviewed = True
    finding.reviewer_id = "human-reviewer"
    finding.assessment_outcome = AssessmentOutcome.CONFIRMED

    orig_finding_id = finding.finding_id
    orig_created_at = finding.timestamp

    # New execution produces fresh finding for the same test_id
    new_finding = _make_finding("test-reexec-1")
    new_finding.evidence.notes = "Re-execution run 2"

    session.add_finding(new_finding)

    # In session findings, the existing finding is retained and updated safely
    stored = session.findings[orig_finding_id]
    assert stored.finding_id == orig_finding_id
    assert stored.timestamp == orig_created_at
    assert len(stored.review_history) == 1
    assert stored.review_history[0].decision == HumanReviewOutcome.CONFIRMED
    # Automated re-execution MUST NOT retain CONFIRMED status or claim human review
    assert stored.is_human_reviewed is False
    assert stored.reviewer_id is None
    assert stored.reviewed_at is None
    assert stored.requires_re_review is True
    assert stored.evidence.notes == "Re-execution run 2"


# ---------------------------------------------------------------------------
# SEC-03: Guards against confirming unexecuted, failed, or inconclusive findings
# ---------------------------------------------------------------------------

def test_sec03_review_rejects_confirmation_of_failed_execution(client):
    """SEC-03: Review route must reject CONFIRMED outcome if execution_status == FAILED."""
    session_id = session_store.create_session()
    finding = _make_finding("f-failed", execution_status=ExecutionStatus.FAILED, assessment_outcome=AssessmentOutcome.INCONCLUSIVE)
    session = session_store.get_session(session_id)
    session.add_finding(finding)

    resp = client.post(
        f"/findings/{finding.finding_id}/review",
        headers={"X-Session-ID": session_id},
        json={"outcome": "CONFIRMED", "reviewer_id": "analyst"},
    )
    assert resp.status_code == 400
    assert "only completed executions can be confirmed" in resp.json()["detail"].lower()


def test_sec03_review_rejects_confirmation_of_inconclusive_outcome(client):
    """SEC-03: Review route must reject CONFIRMED outcome if assessment_outcome == INCONCLUSIVE."""
    session_id = session_store.create_session()
    finding = _make_finding("f-inconcl", execution_status=ExecutionStatus.COMPLETED, assessment_outcome=AssessmentOutcome.INCONCLUSIVE)
    session = session_store.get_session(session_id)
    session.add_finding(finding)

    resp = client.post(
        f"/findings/{finding.finding_id}/review",
        headers={"X-Session-ID": session_id},
        json={"outcome": "CONFIRMED", "reviewer_id": "analyst"},
    )
    assert resp.status_code == 400
    assert "inconclusive" in resp.json()["detail"].lower()


def test_sec03_review_rejects_confirmation_of_access_denied(client):
    """SEC-03: Review route must reject CONFIRMED outcome if assessment_outcome == ACCESS_DENIED."""
    session_id = session_store.create_session()
    finding = _make_finding("f-denied", execution_status=ExecutionStatus.COMPLETED, assessment_outcome=AssessmentOutcome.ACCESS_DENIED)
    session = session_store.get_session(session_id)
    session.add_finding(finding)

    resp = client.post(
        f"/findings/{finding.finding_id}/review",
        headers={"X-Session-ID": session_id},
        json={"outcome": "CONFIRMED", "reviewer_id": "analyst"},
    )
    assert resp.status_code == 400
    assert "access was denied" in resp.json()["detail"].lower()


def test_sec03_review_rejects_confirmation_with_empty_response_evidence(client):
    """SEC-03: Review route must reject CONFIRMED outcome if response evidence is empty."""
    session_id = session_store.create_session()
    finding = _make_finding("f-empty", execution_status=ExecutionStatus.COMPLETED, assessment_outcome=AssessmentOutcome.SUSPECTED, has_evidence_response=False)
    session = session_store.get_session(session_id)
    session.add_finding(finding)

    resp = client.post(
        f"/findings/{finding.finding_id}/review",
        headers={"X-Session-ID": session_id},
        json={"outcome": "CONFIRMED", "reviewer_id": "analyst"},
    )
    assert resp.status_code == 400
    assert "valid http response evidence" in resp.json()["detail"].lower()


def test_sec03_false_positive_allowed_on_inconclusive_or_failed(client):
    """SEC-03: Marking as FALSE_POSITIVE is permitted even for inconclusive or failed runs."""
    session_id = session_store.create_session()
    finding = _make_finding("f-fp", execution_status=ExecutionStatus.FAILED, assessment_outcome=AssessmentOutcome.INCONCLUSIVE)
    session = session_store.get_session(session_id)
    session.add_finding(finding)

    resp = client.post(
        f"/findings/{finding.finding_id}/review",
        headers={"X-Session-ID": session_id},
        json={"outcome": "FALSE_POSITIVE", "reviewer_notes": "Server error was expected in this test", "reviewer_id": "analyst"},
    )
    assert resp.status_code == 200
    assert resp.json()["assessment_outcome"] == "FALSE_POSITIVE"


# ---------------------------------------------------------------------------
# SEC-05: Key-Value Credential Masking in Strings
# ---------------------------------------------------------------------------

def test_sec05_sanitize_data_masks_key_value_secrets():
    """SEC-05: Strings containing key-value secrets have values redacted while preserving keys and non-secrets."""
    payload = {
        "log_entry": "connect string: username=admin;password=SuperSecretPassword123;host=localhost",
        "header_text": "Authorization: Bearer super-secret-bearer-token-12345",
        "query_string": 'api_key="my-api-key-999"&format=json',
        "debug_info": "token: my-secret-token-value",
        "safe_query": "action=view&item_id=123&status=success",
    }
    sanitized = sanitize_data(payload)

    assert REDACTED_MARKER in sanitized["log_entry"]
    assert "SuperSecretPassword123" not in sanitized["log_entry"]
    assert "username=admin" in sanitized["log_entry"]
    assert "host=localhost" in sanitized["log_entry"]

    assert "super-secret-bearer-token-12345" not in sanitized["header_text"]
    assert "Bearer [REDACTED]" in sanitized["header_text"]

    assert "my-api-key-999" not in sanitized["query_string"]
    assert 'api_key="[REDACTED]"' in sanitized["query_string"]
    assert "format=json" in sanitized["query_string"]

    assert "my-secret-token-value" not in sanitized["debug_info"]
    assert f"token: {REDACTED_MARKER}" in sanitized["debug_info"]
    assert sanitized["safe_query"] == "action=view&item_id=123&status=success"


# ---------------------------------------------------------------------------
# SEC-06: URL and Exception Sanitization
# ---------------------------------------------------------------------------

def test_sec06_sanitize_url_strips_basic_auth_and_redacts_tokens():
    """SEC-06: sanitize_url scrubs basic auth from netloc and redacts sensitive query parameters."""
    raw_url = "http://admin:secretPass123@127.0.0.1:8001/api/v1/users?token=tok-abc-123&page=2"
    cleaned = sanitize_url(raw_url)

    assert "secretPass123" not in cleaned
    assert "admin:[REDACTED]" in cleaned
    assert "tok-abc-123" not in cleaned
    assert "page=2" in cleaned


def test_sec06_prepared_request_scrubs_url():
    """SEC-06: PreparedRequest.to_evidence_dict() scrubs credentials and sensitive query tokens from url."""
    req = PreparedRequest(
        method="GET",
        url="http://deployer:mypassword@127.0.0.1:8001/api/v1/keys?api_key=secret-key-123",
        headers={"Authorization": "Bearer secret-token-456", "X-Custom": "safe-value"},
    )
    ev = req.to_evidence_dict()
    assert "mypassword" not in ev["url"]
    assert "secret-key-123" not in ev["url"]
    assert "deployer:[REDACTED]" in ev["url"]
    # Authorization header is stripped entirely from sanitized evidence dictionary
    assert "Authorization" not in ev["headers"]
    assert ev["headers"].get("X-Custom") == "safe-value"


def test_sec06_sanitize_error_message_redacts_credentials():
    """SEC-06: sanitize_error_message removes sensitive credentials embedded in error strings."""
    err = "Connection refused to http://127.0.0.1:8001/auth?client_secret=ultra_private_secret_99"
    sanitized = sanitize_error_message(err)
    assert "ultra_private_secret_99" not in sanitized
    assert REDACTED_MARKER in sanitized


# ---------------------------------------------------------------------------
# SEC-07: Accurate Report Statistics Partitioning
# ---------------------------------------------------------------------------

def test_sec07_report_strictly_separates_completed_failed_not_executed():
    """SEC-07: Report generation partitions findings into completed, failed, and not executed without double counting."""
    session = Session(session_id="test-sec07-session")

    # 1. Completed finding
    f_completed = _make_finding("p-comp", execution_status=ExecutionStatus.COMPLETED, assessment_outcome=AssessmentOutcome.SUSPECTED)
    # 2. Failed finding
    f_failed = _make_finding("p-fail", execution_status=ExecutionStatus.FAILED, assessment_outcome=AssessmentOutcome.INCONCLUSIVE)
    # 3. Not executed finding
    f_not_exec = _make_finding("p-not", execution_status=ExecutionStatus.NOT_EXECUTED, assessment_outcome=AssessmentOutcome.INCONCLUSIVE)
    f_not_exec.status = FindingStatus.NOT_EXECUTED

    session.add_finding(f_completed)
    session.add_finding(f_failed)
    session.add_finding(f_not_exec)

    # Proposals corresponding to each
    p1 = ProposedTest(test_id="p-comp", endpoint=_make_endpoint(), test_type="BOLA", description="", severity="High", status=TestStatus.APPROVED)
    p2 = ProposedTest(test_id="p-fail", endpoint=_make_endpoint(), test_type="BOLA", description="", severity="High", status=TestStatus.APPROVED)
    p3 = ProposedTest(test_id="p-not", endpoint=_make_endpoint(), test_type="BOLA", description="", severity="High", status=TestStatus.PROPOSED)
    session.proposals[p1.test_id] = p1
    session.proposals[p2.test_id] = p2
    session.proposals[p3.test_id] = p3

    report = generate_report(session, target_base_url="http://127.0.0.1:8001")

    stats = report.execution_statistics
    assert stats["total_proposals"] == 3
    assert stats["total_findings"] == 3
    assert stats["completed_tests"] == 1
    assert stats["failed_tests"] == 1
    assert stats["not_executed_tests"] == 1

    assert len(report.finding_details) == 1
    assert len(report.failed_tests) == 1
    assert len(report.not_executed_tests) == 1
    assert report.failed_tests == [f_failed.finding_id]
    assert report.not_executed_tests == [f_not_exec.finding_id]

    # Sum of counts matches total findings
    assert (stats["completed_tests"] + stats["failed_tests"] + stats["not_executed_tests"]) == stats["total_findings"]


# ---------------------------------------------------------------------------
# SEC-08: Review Request Outcome Schema Restriction
# ---------------------------------------------------------------------------

def test_sec08_review_endpoint_rejects_invalid_outcomes_via_pydantic_schema(client):
    """SEC-08: Review endpoint rejects outcomes other than CONFIRMED or FALSE_POSITIVE with HTTP 422."""
    session_id = session_store.create_session()
    finding = _make_finding("f-sec08")
    session = session_store.get_session(session_id)
    session.add_finding(finding)

    # Try setting SUSPECTED via review endpoint
    resp_suspected = client.post(
        f"/findings/{finding.finding_id}/review",
        headers={"X-Session-ID": session_id},
        json={"outcome": "SUSPECTED", "reviewer_id": "analyst"},
    )
    assert resp_suspected.status_code == 422

    # Try setting INCONCLUSIVE via review endpoint
    resp_inconcl = client.post(
        f"/findings/{finding.finding_id}/review",
        headers={"X-Session-ID": session_id},
        json={"outcome": "INCONCLUSIVE", "reviewer_id": "analyst"},
    )
    assert resp_inconcl.status_code == 422

    # Try valid outcomes
    resp_confirmed = client.post(
        f"/findings/{finding.finding_id}/review",
        headers={"X-Session-ID": session_id},
        json={"outcome": "CONFIRMED", "reviewer_id": "analyst"},
    )
    assert resp_confirmed.status_code == 200

    resp_fp = client.post(
        f"/findings/{finding.finding_id}/review",
        headers={"X-Session-ID": session_id},
        json={"outcome": "FALSE_POSITIVE", "reviewer_id": "analyst"},
    )
    assert resp_fp.status_code == 200
