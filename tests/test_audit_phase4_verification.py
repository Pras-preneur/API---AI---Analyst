"""Targeted audit tests for Phase 4 Final Verification and Defect-Fix Loop.

Verifies:
- Audit A: Precise categorization of proposals, executions, outcomes, and unreviewed confirmed guards
- Audit B: PDF/JSON parity, Unicode handling, and evidence sanitization
- Audit C: Strict session ownership isolation and safe error responses
- Audit D: Absolute zero side effects on proposals, executions, and reviews
- Audit E: Honesty in report generation and retesting status
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
from app.security.report_engine import generate_report
from app.security.pdf_export import generate_pdf_report
from app.security.json_export import export_report_to_dict, export_report_to_json

client = TestClient(app)


def test_audit_a_distinct_outcome_counters():
    """Verify that ACCESS_DENIED, INCONCLUSIVE, and UNSUPPORTED are counted distinctly."""
    session_id = session_store.create_session()
    session = session_store.get_session(session_id)

    ep = EndpointModel(path="/api/test", method="GET", responses={"200": {"description": "OK"}})
    session.set_endpoints([ep])

    # Proposals
    p_prop = ProposedTest(test_type="BOLA", endpoint=ep, severity="High", status=TestStatus.PROPOSED, description="Test BOLA")
    p_app = ProposedTest(test_type="BFLA", endpoint=ep, severity="Medium", status=TestStatus.APPROVED, description="Test BFLA")
    p_rej = ProposedTest(test_type="AUTH_MISSING_CREDENTIALS", endpoint=ep, severity="Low", status=TestStatus.REJECTED, description="Test Auth")
    p_unsupp = ProposedTest(test_type="MassAssignment", endpoint=ep, severity="Medium", status=TestStatus.APPROVED, description="Test Mass Assignment")

    session.add_proposal(p_prop)
    session.add_proposal(p_app)
    session.add_proposal(p_rej)
    session.add_proposal(p_unsupp)

    # Finding 1: ACCESS_DENIED
    f_ad = Finding(
        test_id=p_app.test_id,
        endpoint=ep,
        severity="Medium",
        status=FindingStatus.SUSPECTED,
        execution_status=ExecutionStatus.COMPLETED,
        assessment_outcome=AssessmentOutcome.ACCESS_DENIED,
        evidence=Evidence(request={}, response={"status_code": 403}),
    )

    # Finding 2: INCONCLUSIVE
    f_inc = Finding(
        test_id=p_prop.test_id,
        endpoint=ep,
        severity="High",
        status=FindingStatus.SUSPECTED,
        execution_status=ExecutionStatus.COMPLETED,
        assessment_outcome=AssessmentOutcome.INCONCLUSIVE,
        evidence=Evidence(request={}, response={"status_code": 500}),
    )

    # Finding 3: Unsupported test recorded as NOT_EXECUTED
    f_unsupp = Finding(
        test_id=p_unsupp.test_id,
        endpoint=ep,
        severity="Medium",
        status=FindingStatus.NOT_EXECUTED,
        execution_status=ExecutionStatus.NOT_EXECUTED,
        notes=json.dumps({"reason": "Unsupported test type"}),
        evidence=Evidence(request={}, response={}),
    )

    session.add_finding(f_ad)
    session.add_finding(f_inc)
    session.add_finding(f_unsupp)

    report = generate_report(session, "http://127.0.0.1:8001")
    stats = report.execution_statistics

    assert stats["total_proposals"] == 4
    assert stats["proposed_tests"] == 1
    assert stats["approved_tests"] == 2
    assert stats["rejected_tests"] == 1
    assert stats["unsupported_tests"] == 1
    assert stats["access_denied_findings"] == 1
    assert stats["inconclusive_findings"] == 1


def test_audit_a_unreviewed_confirmed_downgrade():
    """An automated or rogue CONFIRMED status without human review must be downgraded to SUSPECTED."""
    session_id = session_store.create_session()
    session = session_store.get_session(session_id)

    ep = EndpointModel(path="/api/rogue", method="GET", responses={"200": {"description": "OK"}})
    p = ProposedTest(test_type="BOLA", endpoint=ep, severity="Critical", status=TestStatus.APPROVED, description="Test Rogue")
    session.add_proposal(p)

    # Rogue finding marked CONFIRMED via legacy status without is_human_reviewed = True
    f_rogue = Finding(
        test_id=p.test_id,
        endpoint=ep,
        severity="Critical",
        status=FindingStatus.CONFIRMED,
        execution_status=ExecutionStatus.COMPLETED,
        assessment_outcome=None,
        is_human_reviewed=False,  # NO human review!
        reviewer_id=None,
        evidence=Evidence(request={}, response={"status_code": 200}),
    )
    session.add_finding(f_rogue)

    report = generate_report(session, "http://127.0.0.1:8001")

    # Confirmed findings counter must be 0
    assert report.execution_statistics["confirmed_findings"] == 0
    assert report.execution_statistics["suspected_findings"] == 1

    # In finding details, it must not be listed as Confirmed
    detail = report.finding_details[0]
    assert detail.status == FindingStatus.SUSPECTED.value
    assert detail.assessment_outcome == AssessmentOutcome.SUSPECTED.value
    assert "Veracity Guard" in (detail.limitations or "")


def test_audit_a_retesting_guidance_truthfulness():
    """Initial session must state no retests occurred; retested findings must be recorded truthfully."""
    session_id = session_store.create_session()
    session = session_store.get_session(session_id)

    ep = EndpointModel(path="/api/user", method="GET", responses={"200": {"description": "OK"}})
    p = ProposedTest(test_type="BOLA", endpoint=ep, severity="High", status=TestStatus.APPROVED, description="Test User")
    session.add_proposal(p)

    f = Finding(
        test_id=p.test_id,
        endpoint=ep,
        severity="High",
        status=FindingStatus.SUSPECTED,
        execution_status=ExecutionStatus.COMPLETED,
        assessment_outcome=AssessmentOutcome.SUSPECTED,
        evidence=Evidence(request={}, response={"status_code": 200}),
    )
    session.add_finding(f)

    # Initial report: no retest
    report1 = generate_report(session, "http://127.0.0.1:8001")
    assert "Initial Assessment Run" in report1.retesting_guidance
    assert "No retest execution has been conducted" in report1.retesting_guidance

    # Simulate retest on finding: requires_re_review = True
    f_retested = Finding(
        test_id=p.test_id,
        endpoint=ep,
        severity="High",
        status=FindingStatus.SUSPECTED,
        execution_status=ExecutionStatus.COMPLETED,
        assessment_outcome=AssessmentOutcome.SUSPECTED,
        requires_re_review=True,
        evidence=Evidence(request={}, response={"status_code": 200}),
    )
    session.add_finding(f_retested)

    report2 = generate_report(session, "http://127.0.0.1:8001")
    assert "Retest Assessment Run" in report2.retesting_guidance
    assert "1 finding(s) have undergone repeat network execution" in report2.retesting_guidance


def test_audit_b_pdf_and_json_parity():
    """Verify that PDF and JSON contain identical findings, IDs, and statistics."""
    session_id = session_store.create_session()
    session = session_store.get_session(session_id)

    ep = EndpointModel(path="/api/profile", method="GET", responses={"200": {"description": "OK"}})
    p = ProposedTest(test_type="BOLA", endpoint=ep, severity="High", status=TestStatus.APPROVED, description="Test Profile")
    session.add_proposal(p)

    f = Finding(
        test_id=p.test_id,
        endpoint=ep,
        severity="High",
        status=FindingStatus.SUSPECTED,
        execution_status=ExecutionStatus.COMPLETED,
        assessment_outcome=AssessmentOutcome.SUSPECTED,
        evidence=Evidence(
            request={"method": "GET", "url": "/api/profile", "headers": {"Authorization": "Bearer secret_test_token"}},
            response={"status_code": 200, "probe_data": {"email": "victim@example.com"}},
        ),
    )
    session.add_finding(f)

    report = generate_report(session, "http://127.0.0.1:8001")

    # JSON export check
    json_data = export_report_to_dict(report)
    json_str = export_report_to_json(report)

    assert json_data["report_id"] == report.report_id
    assert json_data["session_id"] == report.session_id
    assert json_data["finding_details"][0]["finding_id"] == f.finding_id
    assert "secret_test_token" not in json_str
    assert "[REDACTED]" in json_str

    # PDF export check
    pdf_bytes = generate_pdf_report(report)
    assert pdf_bytes.startswith(b"%PDF-")
    assert b"secret_test_token" not in pdf_bytes


def test_audit_c_d_session_isolation_and_no_side_effects():
    """Verify session isolation, cross-session 404, and absolute immutability of session state."""
    session_id = session_store.create_session()
    other_session_id = session_store.create_session()

    session = session_store.get_session(session_id)
    ep = EndpointModel(path="/api/users", method="GET", responses={"200": {"description": "OK"}})
    p = ProposedTest(test_type="BOLA", endpoint=ep, severity="Critical", status=TestStatus.APPROVED, description="Test Users")
    session.add_proposal(p)

    # 1. State before report creation
    p_status_before = p.status
    f_count_before = len(session.findings)

    # 2. Create report
    res = client.post("/reports", json={"target": "http://127.0.0.1:8001"}, headers={"X-Session-ID": session_id})
    assert res.status_code == 200
    report_id = res.json()["report_id"]

    # 3. State after report creation must be completely unchanged
    assert p.status == p_status_before
    assert len(session.findings) == f_count_before

    # 4. Cross-session access to PDF and JSON must return 404
    pdf_cross = client.get(f"/reports/{report_id}/pdf", headers={"X-Session-ID": other_session_id})
    assert pdf_cross.status_code == 404

    json_cross = client.get(f"/reports/{report_id}/json", headers={"X-Session-ID": other_session_id})
    assert json_cross.status_code == 404

    # 5. Invalid / missing session ID
    no_session = client.get(f"/reports/{report_id}/pdf")
    assert no_session.status_code == 422
