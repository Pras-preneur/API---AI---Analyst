"""Unit and integration tests for Stage 5: Evidence, Findings, Reporting & AI Integration Readiness.

Covers:
1. Proposal-to-finding traceability (proposal_id, test_id, endpoint, execution_status, assessment_outcome).
2. Assessment-state separation (execution_status vs assessment_outcome).
3. Human-review enforcement (vulnerability confirmation strictly requires human sign-off; machines cannot confirm).
4. Review workflow endpoint (/findings/{id}/review) with reviewer tracking and error handling.
5. In-depth evidence sanitization (nested structures, sensitive headers, query tokens, emails, error messages).
6. Duplicate finding handling (updating existing finding for same test_id without duplication).
7. Report generation and statistics (execution_stats, severity grouping, limitations, pending review count).
8. Report behavior when proposals or findings are unavailable/missing.
9. AI integration boundary schemas, validation, advisory-only invariants, and input scrubbing.
10. Existing API compatibility and error handling.
"""

import json
import uuid
from datetime import datetime, timezone
from typing import Any, Dict

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
    FindingDetail,
    FindingReviewRequest,
    FindingStatus,
    ProposedTest,
    Report,
    Session,
    SeverityCounts,
    TestStatus,
    session_store,
    validate_assessment_outcome,
)
from app.security.ai_boundary import (
    AIFindingAnalysisInput,
    AIFindingAnalysisOutput,
    AIFindingAnalyzer,
    prepare_ai_input_from_finding,
)
from app.security.report_engine import generate_report
from app.security.sanitization import (
    REDACTED_MARKER,
    sanitize_data,
    sanitize_error_message,
    sanitize_headers,
    sanitize_request,
    sanitize_response,
    sanitize_string,
    sanitize_url,
)


# ---------------------------------------------------------------------------
# Test Fixtures & Helpers
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def reset_store():
    session_store._sessions.clear()
    yield
    session_store._sessions.clear()


@pytest.fixture
def client():
    return TestClient(app)


def _create_endpoint(path: str = "/api/v1/users/{id}", method: str = "get") -> EndpointModel:
    return EndpointModel.model_validate({
        "path": path,
        "method": method,
        "summary": "User Resource",
        "responses": {"200": {"description": "Success"}},
    })


def _create_proposal(
    endpoint: EndpointModel,
    test_type: str = "BOLA",
    severity: str = "High",
    status: TestStatus = TestStatus.PROPOSED,
) -> ProposedTest:
    return ProposedTest(
        endpoint=endpoint,
        test_type=test_type,
        description=f"Test for {test_type} on {endpoint.path}",
        severity=severity,
        status=status,
    )


# ---------------------------------------------------------------------------
# 1. Traceability: Finding to Proposal & Endpoints
# ---------------------------------------------------------------------------

def test_finding_traceability_to_proposal():
    """Each finding must maintain full traceability to proposal, endpoint, and assessment status."""
    endpoint = _create_endpoint()
    proposal = _create_proposal(endpoint, test_type="BOLA", severity="High")

    finding = Finding(
        test_id=proposal.test_id,
        endpoint=endpoint,
        evidence=Evidence(
            request={"method": "GET", "url": "http://127.0.0.1:8001/users/1", "headers": {}},
            response={"status_code": 200, "body": {"user": "1"}},
        ),
        severity=proposal.severity,
        status=FindingStatus.SUSPECTED,
        execution_status=ExecutionStatus.COMPLETED,
        assessment_outcome=AssessmentOutcome.SUSPECTED,
        assessment_reason="Cross-tenant access observed on object 1",
        remediation="Implement object-level access controls.",
    )

    assert finding.test_id == proposal.test_id
    assert finding.proposal_id == proposal.test_id
    assert finding.endpoint.path == endpoint.path
    assert finding.execution_status == ExecutionStatus.COMPLETED
    assert finding.assessment_outcome == AssessmentOutcome.SUSPECTED
    assert finding.assessment_reason == "Cross-tenant access observed on object 1"
    assert finding.is_human_reviewed is False
    assert finding.reviewed_at is None
    assert finding.reviewer_id is None


# ---------------------------------------------------------------------------
# 2. Separation of Execution Status and Assessment Outcome
# ---------------------------------------------------------------------------

def test_execution_and_assessment_state_separation():
    """ExecutionStatus and AssessmentOutcome must represent distinct lifecycle dimensions."""
    # NOT_EXECUTED test
    not_exec_finding = Finding(
        test_id="test-1",
        endpoint=_create_endpoint(),
        evidence=Evidence(request={}, response={}),
        severity="Medium",
        status=FindingStatus.NOT_EXECUTED,
        execution_status=ExecutionStatus.NOT_EXECUTED,
        assessment_outcome=AssessmentOutcome.INCONCLUSIVE,
        assessment_reason="Budget exhausted before request dispatched",
    )
    assert not_exec_finding.execution_status == ExecutionStatus.NOT_EXECUTED
    assert not_exec_finding.assessment_outcome == AssessmentOutcome.INCONCLUSIVE

    # Execution succeeded but access was denied (target is secure against probe)
    denied_finding = Finding(
        test_id="test-2",
        endpoint=_create_endpoint(),
        evidence=Evidence(
            request={"method": "GET", "url": "http://127.0.0.1:8001/users/2", "headers": {}},
            response={"status_code": 403, "body": {"detail": "Forbidden"}},
        ),
        severity="High",
        status=FindingStatus.NOT_EXECUTED,
        execution_status=ExecutionStatus.COMPLETED,
        assessment_outcome=AssessmentOutcome.ACCESS_DENIED,
        assessment_reason="Cross-tenant probe returned HTTP 403 Forbidden",
    )
    assert denied_finding.execution_status == ExecutionStatus.COMPLETED
    assert denied_finding.assessment_outcome == AssessmentOutcome.ACCESS_DENIED


def test_automated_confirmation_strictly_prevented():
    """Attempting to construct or assign CONFIRMED outcome without human review raises ValueError."""
    endpoint = _create_endpoint()
    evidence = Evidence(request={}, response={})

    # Model validator rejects automated CONFIRMED
    with pytest.raises(ValueError, match="CONFIRMED.*requires explicit human review"):
        Finding(
            test_id="test-3",
            endpoint=endpoint,
            evidence=evidence,
            severity="High",
            assessment_outcome=AssessmentOutcome.CONFIRMED,
            is_human_reviewed=False,
        )

    # Valid human review confirmation succeeds
    reviewed_finding = Finding(
        test_id="test-3",
        endpoint=endpoint,
        evidence=evidence,
        severity="High",
        status=FindingStatus.CONFIRMED,
        assessment_outcome=AssessmentOutcome.CONFIRMED,
        is_human_reviewed=True,
        reviewed_at=datetime.now(timezone.utc),
        reviewer_id="sec_ops_lead",
        reviewer_notes="Confirmed vulnerability in staging reproduction.",
    )
    assert reviewed_finding.assessment_outcome == AssessmentOutcome.CONFIRMED
    assert reviewed_finding.reviewer_id == "sec_ops_lead"


# ---------------------------------------------------------------------------
# 3. Duplicate Finding Handling
# ---------------------------------------------------------------------------

def test_session_deduplicates_findings_for_same_test_id():
    """When a proposal is processed more than once, its finding record is updated without duplication."""
    session = Session()
    endpoint = _create_endpoint()
    test_id = "test-uuid-999"

    finding_v1 = Finding(
        test_id=test_id,
        endpoint=endpoint,
        evidence=Evidence(request={}, response={"status_code": 200, "body": "initial"}),
        severity="Medium",
        status=FindingStatus.SUSPECTED,
        assessment_outcome=AssessmentOutcome.SUSPECTED,
    )
    fid1 = session.add_finding(finding_v1)
    assert len(session.findings) == 1
    original_timestamp = finding_v1.timestamp

    # Second execution/processing of the same proposal
    finding_v2 = Finding(
        test_id=test_id,
        endpoint=endpoint,
        evidence=Evidence(request={}, response={"status_code": 200, "body": "updated"}),
        severity="High",
        status=FindingStatus.SUSPECTED,
        assessment_outcome=AssessmentOutcome.SUSPECTED,
        assessment_reason="Re-evaluated with stronger evidence",
    )
    fid2 = session.add_finding(finding_v2)

    # Must preserve stable finding_id and avoid duplicate records
    assert fid2 == fid1
    assert len(session.findings) == 1
    assert session.get_finding(fid1).severity == "High"
    assert session.get_finding(fid1).assessment_reason == "Re-evaluated with stronger evidence"
    assert session.get_finding(fid1).timestamp == original_timestamp

    # Lookup by test_id
    retrieved = session.get_finding_by_test_id(test_id)
    assert retrieved is not None
    assert retrieved.finding_id == fid1


# ---------------------------------------------------------------------------
# 4. Evidence Sanitization: Deep Nesting, Headers, URLs, PII
# ---------------------------------------------------------------------------

def test_sanitize_nested_data_structures():
    """Sanitizer must recurse into arbitrary nested dicts, lists, and strings to strip credentials."""
    payload = {
        "user": {
            "name": "Alice",
            "email": "alice.smith@corp.example.com",
            "password": "SuperSecretPassword123!",
            "tokens": [
                {"type": "jwt", "access_token": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abc"},
                {"type": "refresh", "secret_key": "refresh-secret-999"},
            ],
            "metadata": {
                "session_id": "sess-xyz-888",
                "notes": "Contact user at support@example.com for password reset",
            },
        },
        "public_flag": True,
        "count": 42,
    }

    sanitized = sanitize_data(payload)

    # Sensitive keys replaced
    assert sanitized["user"]["password"] == REDACTED_MARKER
    assert sanitized["user"]["tokens"][0]["access_token"] == REDACTED_MARKER
    assert sanitized["user"]["tokens"][1]["secret_key"] == REDACTED_MARKER
    assert sanitized["user"]["metadata"]["session_id"] == REDACTED_MARKER

    # Strings with email and tokens replaced
    assert "@" not in sanitized["user"]["email"]
    assert sanitized["user"]["email"] == REDACTED_MARKER
    assert "@" not in sanitized["user"]["metadata"]["notes"]
    assert "SuperSecretPassword" not in json.dumps(sanitized)

    # Safe primitives preserved
    assert sanitized["user"]["name"] == "Alice"
    assert sanitized["public_flag"] is True
    assert sanitized["count"] == 42


def test_sanitize_headers_and_urls():
    """Headers and URL query strings must be scrubbed of authentication and tokens."""
    headers = {
        "Authorization": "Bearer eyJhbGciOiJIUzI1NiJ9.tok",
        "X-API-Key": "my-secret-key-123",
        "Cookie": "session=abcde12345; user=alice",
        "X-Custom-Env": "testing-staging",
        "Content-Type": "application/json",
    }
    safe_headers = sanitize_headers(headers)

    # Raw Authorization header strictly removed
    assert "Authorization" not in safe_headers
    assert "authorization" not in safe_headers

    # Sensitive headers masked
    assert safe_headers["X-API-Key"] == REDACTED_MARKER
    assert safe_headers["Cookie"] == REDACTED_MARKER

    # Safe headers preserved
    assert safe_headers["X-Custom-Env"] == "testing-staging"
    assert safe_headers["Content-Type"] == "application/json"

    # URL query scrubbing
    url = "http://127.0.0.1:8001/api/data?token=secret123&api_key=key456&category=audit&user_id=alice"
    clean_url = sanitize_url(url)
    assert "secret123" not in clean_url
    assert "key456" not in clean_url
    assert "token=%5BREDACTED%5D" in clean_url or "token=[REDACTED]" in clean_url
    assert "category=audit" in clean_url
    assert "user_id=alice" in clean_url


def test_sanitize_error_message():
    """Error messages containing passwords, tokens, or emails must be masked."""
    raw_error = "Connection failed for user test@example.com with password=MySecretPass! and Bearer eyJabc.def.ghi"
    scrubbed = sanitize_error_message(raw_error)
    assert "@" not in scrubbed
    assert "MySecretPass!" not in scrubbed
    assert "Bearer [REDACTED]" in scrubbed


# ---------------------------------------------------------------------------
# 5. Human Review Workflow via API
# ---------------------------------------------------------------------------

def test_human_review_finding_flow(client):
    """Review endpoint allows human confirmation with reviewer metadata and rejects invalid operations."""
    sid = session_store.create_session()
    endpoint = _create_endpoint()
    prop = _create_proposal(endpoint, test_type="BOLA", status=TestStatus.APPROVED)
    session_store.add_proposal(sid, prop)

    # Record a suspected finding
    finding = Finding(
        test_id=prop.test_id,
        endpoint=endpoint,
        evidence=Evidence(request={}, response={"status_code": 200, "body": {"user": "alice"}}),
        severity="High",
        status=FindingStatus.SUSPECTED,
        execution_status=ExecutionStatus.COMPLETED,
        assessment_outcome=AssessmentOutcome.SUSPECTED,
        assessment_reason="Cross-tenant access detected",
    )
    fid = session_store.add_finding(sid, finding)

    # 1. Retrieve single finding by ID
    get_res = client.get(f"/findings/{fid}", headers={"X-Session-ID": sid})
    assert get_res.status_code == 200
    assert get_res.json()["finding_id"] == fid
    assert get_res.json()["is_human_reviewed"] is False

    # 2. Human reviews and confirms the finding
    review_payload = {
        "outcome": "CONFIRMED",
        "reviewer_id": "lead_security_architect",
        "reviewer_notes": "Manually verified cross-tenant read of owner account record.",
    }
    rev_res = client.post(
        f"/findings/{fid}/review",
        json=review_payload,
        headers={"X-Session-ID": sid},
    )
    assert rev_res.status_code == 200
    updated_finding = rev_res.json()
    assert updated_finding["status"] == "Confirmed"
    assert updated_finding["assessment_outcome"] == "CONFIRMED"
    assert updated_finding["is_human_reviewed"] is True
    assert updated_finding["reviewer_id"] == "lead_security_architect"
    assert updated_finding["reviewer_notes"] == "Manually verified cross-tenant read of owner account record."
    assert updated_finding["reviewed_at"] is not None


def test_human_review_cannot_confirm_unexecuted_test(client):
    """An unexecuted test cannot be marked CONFIRMED by human review."""
    sid = session_store.create_session()
    endpoint = _create_endpoint()
    prop = _create_proposal(endpoint, test_type="BOLA", status=TestStatus.APPROVED)
    session_store.add_proposal(sid, prop)

    unexec_finding = Finding(
        test_id=prop.test_id,
        endpoint=endpoint,
        evidence=Evidence(request={}, response={}),
        severity="Medium",
        status=FindingStatus.NOT_EXECUTED,
        execution_status=ExecutionStatus.NOT_EXECUTED,
        assessment_outcome=AssessmentOutcome.INCONCLUSIVE,
        assessment_reason="Budget exceeded before request",
    )
    fid = session_store.add_finding(sid, unexec_finding)

    res = client.post(
        f"/findings/{fid}/review",
        json={"outcome": "CONFIRMED", "reviewer_id": "analyst_1", "reviewer_notes": "Attempt"},
        headers={"X-Session-ID": sid},
    )
    assert res.status_code == 400
    assert "NOT_EXECUTED" in res.json()["detail"]


def test_human_review_mark_false_positive(client):
    """Human review can classify a suspected finding as FALSE_POSITIVE."""
    sid = session_store.create_session()
    endpoint = _create_endpoint()
    prop = _create_proposal(endpoint, test_type="BOLA", status=TestStatus.APPROVED)
    session_store.add_proposal(sid, prop)

    finding = Finding(
        test_id=prop.test_id,
        endpoint=endpoint,
        evidence=Evidence(request={}, response={"status_code": 200}),
        severity="Low",
        status=FindingStatus.SUSPECTED,
        execution_status=ExecutionStatus.COMPLETED,
        assessment_outcome=AssessmentOutcome.SUSPECTED,
    )
    fid = session_store.add_finding(sid, finding)

    res = client.post(
        f"/findings/{fid}/review",
        json={
            "outcome": "FALSE_POSITIVE",
            "reviewer_id": "appsec_analyst",
            "reviewer_notes": "Resource is intended to be publicly readable.",
        },
        headers={"X-Session-ID": sid},
    )
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "FalsePositive"
    assert data["assessment_outcome"] == "FALSE_POSITIVE"
    assert data["is_human_reviewed"] is True


# ---------------------------------------------------------------------------
# 6. Reporting Pipeline and Execution Statistics
# ---------------------------------------------------------------------------

def test_report_generation_with_statistics_and_remediation():
    """Reports must calculate execution statistics, severity counts, and include remediation."""
    session = Session()
    ep1 = _create_endpoint("/users/{id}")
    ep2 = _create_endpoint("/admin/secret")

    prop1 = _create_proposal(ep1, test_type="BOLA", severity="High")
    prop2 = _create_proposal(ep2, test_type="BFLA", severity="Critical")
    session.add_proposal(prop1)
    session.add_proposal(prop2)

    # Finding 1: Suspected and awaiting review
    f1 = Finding(
        test_id=prop1.test_id,
        endpoint=ep1,
        evidence=Evidence(
            request={"method": "GET", "url": "http://127.0.0.1:8001/users/1", "headers": {}},
            response={"status_code": 200, "body": {"user": "1"}},
        ),
        severity="High",
        status=FindingStatus.SUSPECTED,
        execution_status=ExecutionStatus.COMPLETED,
        assessment_outcome=AssessmentOutcome.SUSPECTED,
        assessment_reason="Cross-tenant read successful",
    )
    session.add_finding(f1)

    # Finding 2: Not executed due to missing role config
    f2 = Finding(
        test_id=prop2.test_id,
        endpoint=ep2,
        evidence=Evidence(request={}, response={}),
        severity="Critical",
        status=FindingStatus.NOT_EXECUTED,
        execution_status=ExecutionStatus.NOT_EXECUTED,
        assessment_outcome=AssessmentOutcome.INCONCLUSIVE,
        assessment_reason="Missing administrative identity fixture",
    )
    session.add_finding(f2)

    report = generate_report(session, "http://127.0.0.1:8001")

    assert report.session_id == session.session_id
    assert report.target_base_url == "http://127.0.0.1:8001"
    assert len(report.finding_details) == 1
    assert len(report.not_executed_tests) == 1

    # Severity counts reflect executed findings
    assert report.severity_counts.high == 1
    assert report.severity_counts.critical == 0

    # Execution statistics
    stats = report.execution_statistics
    assert stats["total_proposals"] == 2
    assert stats["total_findings"] == 2
    assert stats["executed_tests"] == 1
    assert stats["not_executed_tests"] == 1
    assert stats["completed_tests"] == 1
    assert stats["pending_review"] == 1
    assert report.pending_review_count == 1

    # Detail contains remediation and limitations
    detail = report.finding_details[0]
    assert detail.test_category == "BOLA"
    assert "object-level authorization" in detail.recommended_remediation.lower()
    assert "manual review" in detail.limitations.lower()
    assert detail.execution_status == "COMPLETED"
    assert detail.assessment_outcome == "SUSPECTED"


def test_report_fallback_when_proposal_is_unavailable():
    """Report engine must use documented sentinel category when proposal is missing."""
    session = Session()
    ep = _create_endpoint("/orphaned/test")

    # Finding inserted without corresponding proposal in session
    orphan_finding = Finding(
        test_id="orphan-uuid",
        endpoint=ep,
        evidence=Evidence(
            request={"method": "GET", "url": "http://127.0.0.1:8001/orphaned", "headers": {}},
            response={"status_code": 200, "body": {}},
        ),
        severity="Low",
        status=FindingStatus.SUSPECTED,
        execution_status=ExecutionStatus.COMPLETED,
        assessment_outcome=AssessmentOutcome.SUSPECTED,
    )
    session.add_finding(orphan_finding)

    report = generate_report(session, "http://127.0.0.1:8001")
    assert len(report.finding_details) == 1
    detail = report.finding_details[0]
    assert detail.test_category == "Unresolved (proposal unavailable)"
    assert "not found in the session" in detail.limitations


# ---------------------------------------------------------------------------
# 7. AI Integration Boundary
# ---------------------------------------------------------------------------

def test_ai_boundary_input_scrubbing_and_validation():
    """AI input payload preparation strictly scrubs credentials and enforces advisory constraints."""
    raw_finding_dict = {
        "finding_id": "find-101",
        "severity": "High",
        "execution_status": "COMPLETED",
        "assessment_outcome": "SUSPECTED",
        "endpoint": {"path": "/users/{id}", "method": "GET"},
        "evidence": {
            "request": {
                "headers": {"Authorization": "Bearer leaked-jwt-secret", "Cookie": "session=123"},
                "url": "http://127.0.0.1:8001/users/5?api_key=secret-key-abc",
            },
            "response": {
                "status_code": 200,
                "body": {
                    "username": "victim",
                    "email": "victim@example.com",
                    "password_hash": "hash_secret_value",
                },
            },
        },
    }

    ai_input = prepare_ai_input_from_finding(
        raw_finding_dict,
        test_type="BOLA",
        observed_behavior="Cross-tenant IDOR access to user profile",
    )

    # Input validation
    assert ai_input.finding_id == "find-101"
    assert ai_input.test_type == "BOLA"
    assert ai_input.endpoint_path == "/users/{id}"

    # Verify that evidence passed into AI boundary is completely sanitized
    scrubbed_evidence = ai_input.sanitized_evidence
    evidence_str = json.dumps(scrubbed_evidence)
    assert "@" not in evidence_str
    assert "leaked-jwt-secret" not in evidence_str
    assert "secret-key-abc" not in evidence_str
    assert "password_hash" in scrubbed_evidence["response"]["body"]
    assert scrubbed_evidence["response"]["body"]["password_hash"] == REDACTED_MARKER


def test_ai_boundary_output_enforces_advisory_constraint():
    """AI analysis outputs must enforce is_advisory_only=True."""
    output = AIFindingAnalysisOutput(
        finding_id="find-101",
        explanation="Endpoint returns object data for non-owner principals without authorization check.",
        evidence_references=["HTTP 200 on cross-tenant probe", "matching owner object body"],
        uncertainty_and_limitations="Assumes user ID 5 belongs exclusively to owner persona.",
        suggested_remediation="Verify current principal matches resource owner in authorization middleware.",
        confidence_score=0.92,
        is_advisory_only=True,
    )
    assert output.is_advisory_only is True
    assert output.confidence_score == 0.92

    # Attempting to bypass advisory restriction raises ValidationError
    with pytest.raises(Exception):
        AIFindingAnalysisOutput(
            finding_id="find-101",
            explanation="Explanation",
            uncertainty_and_limitations="Limitations",
            is_advisory_only=False,
        )


def test_ai_analyzer_protocol_compliance():
    """Verify that an advisory analyzer satisfies the AIFindingAnalyzer protocol."""
    class DummyAdvisoryAnalyzer:
        def analyze_finding(self, input_data: AIFindingAnalysisInput) -> AIFindingAnalysisOutput:
            return AIFindingAnalysisOutput(
                finding_id=input_data.finding_id,
                explanation=f"Advisory review of {input_data.test_type} on {input_data.endpoint_path}",
                evidence_references=["HTTP status code"],
                uncertainty_and_limitations="Automated heuristics only.",
                confidence_score=0.85,
            )

    analyzer = DummyAdvisoryAnalyzer()
    assert isinstance(analyzer, AIFindingAnalyzer)

    sample_input = AIFindingAnalysisInput(
        finding_id="f-1",
        test_type="BOLA",
        endpoint_path="/users/1",
        endpoint_method="GET",
        severity="High",
        execution_status="COMPLETED",
        assessment_outcome="SUSPECTED",
        sanitized_evidence={},
    )
    res = analyzer.analyze_finding(sample_input)
    assert res.finding_id == "f-1"
    assert res.is_advisory_only is True

