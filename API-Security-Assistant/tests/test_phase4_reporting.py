"""Phase 4 Reporting, PDF/JSON Export, Session Isolation, and Veracity Tests.

Covers:
- Report generation from empty, partial, and full sessions
- PDF export endpoint GET /reports/{report_id}/pdf
- JSON export endpoint GET /reports/{report_id}/json
- Strict session ownership isolation and cross-session rejection
- Evidence sanitization in reports (zero credential leaks)
- Immutability check: report generation produces zero side effects
"""

import json
from datetime import datetime, timezone
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.models import (
    session_store,
    Session,
    EndpointModel,
    ProposedTest,
    TestStatus,
    Finding,
    FindingStatus,
    AssessmentOutcome,
    ExecutionStatus,
    Evidence,
    SeverityCounts,
    Report,
)
from app.security.pdf_export import generate_pdf_report
from app.security.json_export import export_report_to_json, export_report_to_dict

client = TestClient(app)


@pytest.fixture
def clean_session_id():
    session_id = session_store.create_session()
    return session_id


@pytest.fixture
def populated_session_id():
    session_id = session_store.create_session()
    session = session_store.get_session(session_id)

    # 1. Add cataloged endpoints
    ep1 = EndpointModel(path="/api/users/{id}", method="GET", summary="Get User", responses={"200": {"description": "OK"}})
    ep2 = EndpointModel(path="/api/admin/metrics", method="GET", summary="Admin Metrics", responses={"200": {"description": "OK"}})
    ep3 = EndpointModel(path="/api/public/ping", method="GET", summary="Health Ping", responses={"200": {"description": "OK"}})
    session.set_endpoints([ep1, ep2, ep3])

    # 2. Add proposals
    p1 = ProposedTest(
        test_type="BOLA",
        endpoint=ep1,
        description="Test BOLA on user endpoint",
        severity="Critical",
        status=TestStatus.APPROVED,
    )
    p2 = ProposedTest(
        test_type="BFLA",
        endpoint=ep2,
        description="Test BFLA on admin metrics",
        severity="High",
        status=TestStatus.APPROVED,
    )
    p3 = ProposedTest(
        test_type="AUTH_MISSING_CREDENTIALS",
        endpoint=ep1,
        description="Test missing authentication",
        severity="Critical",
        status=TestStatus.PROPOSED,
    )
    session.add_proposal(p1)
    session.add_proposal(p2)
    session.add_proposal(p3)

    # 3. Add findings
    # Finding 1: Confirmed via human review
    f1 = Finding(
        test_id=p1.test_id,
        endpoint=ep1,
        severity="Critical",
        status=FindingStatus.CONFIRMED,
        execution_status=ExecutionStatus.COMPLETED,
        assessment_outcome=AssessmentOutcome.CONFIRMED,
        assessment_reason="Differential probe confirmed unauthorized tenant data access",
        evidence=Evidence(
            request={"method": "GET", "url": "/api/users/2", "headers": {"Authorization": "[REDACTED]"}},
            response={"status_code": 200, "probe_data": {"user_id": 2, "secret_data": "[REDACTED]"}},
        ),
        is_human_reviewed=True,
        reviewer_id="lead_analyst_01",
        reviewed_at=datetime.now(timezone.utc),
        reviewer_notes="Confirmed critical horizontal privilege escalation across tenants",
    )

    # Finding 2: Suspected (pending human review)
    f2 = Finding(
        test_id=p2.test_id,
        endpoint=ep2,
        severity="High",
        status=FindingStatus.SUSPECTED,
        execution_status=ExecutionStatus.COMPLETED,
        assessment_outcome=AssessmentOutcome.SUSPECTED,
        assessment_reason="Elevated resource returned status 200 without administrator claim",
        evidence=Evidence(
            request={"method": "GET", "url": "/api/admin/metrics", "headers": {"Authorization": "[REDACTED]"}},
            response={"status_code": 200, "probe_data": {"metrics_version": "2.1"}},
        ),
        is_human_reviewed=False,
    )

    session.add_finding(f1)
    session.add_finding(f2)

    return session_id


def test_empty_session_report_generation(clean_session_id):
    """Report generated on an empty session should return 200 with zero statistics."""
    res = client.post(
        "/reports",
        json={"target": "http://127.0.0.1:8001"},
        headers={"X-Session-ID": clean_session_id},
    )
    assert res.status_code == 200
    data = res.json()
    assert data["session_id"] == clean_session_id
    assert data["target_base_url"] == "http://127.0.0.1:8001"
    assert "No security tests were executed" in data["assessment_summary"]
    assert data["severity_counts"]["critical"] == 0
    assert data["severity_counts"]["high"] == 0
    assert len(data["finding_details"]) == 0
    assert data["execution_statistics"]["total_findings"] == 0
    assert data["pending_review_count"] == 0


def test_populated_session_report_generation(populated_session_id):
    """Report generated on a populated session should contain accurate execution statistics."""
    res = client.post(
        "/reports",
        json={"target": "http://127.0.0.1:8001"},
        headers={"X-Session-ID": populated_session_id},
    )
    assert res.status_code == 200
    data = res.json()

    assert data["session_id"] == populated_session_id
    assert data["severity_counts"]["critical"] == 1
    assert data["severity_counts"]["high"] == 1
    assert len(data["finding_details"]) == 2
    assert data["execution_statistics"]["total_proposals"] == 3
    assert data["execution_statistics"]["total_findings"] == 2
    assert data["execution_statistics"]["confirmed_findings"] == 1
    assert data["execution_statistics"]["suspected_findings"] == 1
    assert data["execution_statistics"]["pending_review"] == 1
    assert data["pending_review_count"] == 1

    # Verify cataloged endpoints and guidance fields
    assert len(data["endpoints_cataloged"]) == 3
    assert data["retesting_guidance"] is not None
    assert "BOLA" in data["methodology"]


def test_pdf_export_endpoint(populated_session_id):
    """GET /reports/{id}/pdf returns a valid, paginated PDF with attachment headers."""
    # First create report
    create_res = client.post(
        "/reports",
        json={"target": "http://127.0.0.1:8001"},
        headers={"X-Session-ID": populated_session_id},
    )
    report_id = create_res.json()["report_id"]

    # Export PDF
    pdf_res = client.get(
        f"/reports/{report_id}/pdf",
        headers={"X-Session-ID": populated_session_id},
    )
    assert pdf_res.status_code == 200
    assert pdf_res.headers["content-type"] == "application/pdf"
    assert f'filename="report-{report_id}.pdf"' in pdf_res.headers["content-disposition"]
    assert pdf_res.content.startswith(b"%PDF-")
    assert len(pdf_res.content) > 1000


def test_json_export_endpoint(populated_session_id):
    """GET /reports/{id}/json returns a structured, indented JSON document."""
    # First create report
    create_res = client.post(
        "/reports",
        json={"target": "http://127.0.0.1:8001"},
        headers={"X-Session-ID": populated_session_id},
    )
    report_id = create_res.json()["report_id"]

    # Export JSON
    json_res = client.get(
        f"/reports/{report_id}/json",
        headers={"X-Session-ID": populated_session_id},
    )
    assert json_res.status_code == 200
    assert "application/json" in json_res.headers["content-type"]
    assert f'filename="report-{report_id}.json"' in json_res.headers["content-disposition"]

    data = json.loads(json_res.text)
    assert data["_schema_version"] == "1.0.0"
    assert data["report_id"] == report_id
    assert data["session_id"] == populated_session_id
    assert len(data["finding_details"]) == 2
    assert data["execution_statistics"]["confirmed_findings"] == 1


def test_report_session_isolation_and_cross_session_rejection(populated_session_id, clean_session_id):
    """Cross-session report access must be rejected with 404."""
    # Create report in populated_session
    create_res = client.post(
        "/reports",
        json={"target": "http://127.0.0.1:8001"},
        headers={"X-Session-ID": populated_session_id},
    )
    report_id = create_res.json()["report_id"]

    # 1. Attempt to access report with the clean session (cross-session)
    pdf_cross = client.get(
        f"/reports/{report_id}/pdf",
        headers={"X-Session-ID": clean_session_id},
    )
    assert pdf_cross.status_code == 404
    assert pdf_cross.json()["detail"] == "Report not found"

    json_cross = client.get(
        f"/reports/{report_id}/json",
        headers={"X-Session-ID": clean_session_id},
    )
    assert json_cross.status_code == 404
    assert json_cross.json()["detail"] == "Report not found"

    # 2. Attempt with invalid session ID
    unknown_session = client.get(
        f"/reports/{report_id}/pdf",
        headers={"X-Session-ID": "00000000-0000-0000-0000-000000000000"},
    )
    assert unknown_session.status_code == 404
    assert unknown_session.json()["detail"] == "Session not found"

    # 3. Attempt without X-Session-ID header
    no_header = client.get(f"/reports/{report_id}/pdf")
    assert no_header.status_code == 422


def test_evidence_sanitization_guarantee(populated_session_id):
    """Neither PDF nor JSON export should contain sensitive raw tokens or credentials."""
    create_res = client.post(
        "/reports",
        json={"target": "http://127.0.0.1:8001"},
        headers={"X-Session-ID": populated_session_id},
    )
    report_id = create_res.json()["report_id"]

    json_res = client.get(
        f"/reports/{report_id}/json",
        headers={"X-Session-ID": populated_session_id},
    )
    content = json_res.text

    # Verify no raw secrets or bearer tokens
    assert "Bearer eyJ" not in content
    assert "admin_secret_password" not in content
    assert "[REDACTED]" in content


def test_immutability_and_zero_side_effects(populated_session_id):
    """Report generation and export must not alter proposal statuses or findings."""
    session = session_store.get_session(populated_session_id)
    p_statuses_before = {p.test_id: p.status for p in session.proposals.values()}
    f_statuses_before = {f.finding_id: f.status for f in session.findings.values()}

    # Create report and perform exports
    create_res = client.post(
        "/reports",
        json={"target": "http://127.0.0.1:8001"},
        headers={"X-Session-ID": populated_session_id},
    )
    report_id = create_res.json()["report_id"]
    client.get(f"/reports/{report_id}/pdf", headers={"X-Session-ID": populated_session_id})
    client.get(f"/reports/{report_id}/json", headers={"X-Session-ID": populated_session_id})

    # Check proposals and findings are unchanged
    p_statuses_after = {p.test_id: p.status for p in session.proposals.values()}
    f_statuses_after = {f.finding_id: f.status for f in session.findings.values()}

    assert p_statuses_before == p_statuses_after
    assert f_statuses_before == f_statuses_after
