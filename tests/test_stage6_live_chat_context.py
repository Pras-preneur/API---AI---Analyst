"""Stage 6: Live Assessment Chat Integration Tests.

Validates:
1. Explanations do not attach unsolicited proposal cards or fabricate findings (BOLA vs BFLA, 401 vs 403).
2. Live session context drives chat answers (discovered endpoints, pending tests, executed tests, findings, evidence, summaries).
3. Session isolation (Session A state does not leak to Session B).
4. Empty and inactive session handling (clear "Not tested" / "No endpoints" messages without fabricating results).
5. All 10 mandated prompts match actual live session state.
"""

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.models import (
    AssessmentOutcome,
    EndpointModel,
    Evidence,
    Finding,
    FindingStatus,
    ProposedTest,
    TestStatus,
    session_store,
)

client = TestClient(app)


@pytest.fixture
def populated_session():
    """Create a populated session with endpoints, proposals (proposed, approved, executed), and findings."""
    session_id = session_store.create_session()
    
    # Endpoints
    ep1 = EndpointModel(path="/api/v1/accounts/{id}", method="GET", summary="Fetch account", tags=["Accounts"], responses={})
    ep2 = EndpointModel(path="/api/v1/admin/users", method="POST", summary="Create admin user", tags=["Admin"], responses={})
    ep3 = EndpointModel(path="/api/v1/profile", method="PATCH", summary="Update profile", tags=["Profile"], responses={})
    session_store.set_endpoints(session_id, [ep1, ep2, ep3])

    # Proposals: 1 Proposed, 1 Approved, 1 Executed
    p1 = ProposedTest(
        test_id="prop-bola-001",
        endpoint=ep1,
        test_type="BOLA",
        severity="High",
        status=TestStatus.PROPOSED,
        description="Verify tenant boundary on account retrieval",
    )
    p2 = ProposedTest(
        test_id="prop-bfla-002",
        endpoint=ep2,
        test_type="BFLA",
        severity="Critical",
        status=TestStatus.APPROVED,
        description="Verify unprivileged user cannot create admin",
    )
    p3 = ProposedTest(
        test_id="prop-mass-003",
        endpoint=ep3,
        test_type="MassAssignment",
        severity="Medium",
        status=TestStatus.EXECUTED,
        description="Verify profile does not accept role elevation",
    )
    session_store.add_proposal(session_id, p1)
    session_store.add_proposal(session_id, p2)
    session_store.add_proposal(session_id, p3)

    # Finding for executed test
    finding = Finding(
        test_id="prop-mass-003",
        endpoint=ep3,
        evidence=Evidence(
            request={"method": "PATCH", "url": "http://127.0.0.1:8001/profile", "headers": {"Authorization": "Basic [REDACTED]"}},
            response={"status_code": 200, "body": '{"msg": "profile updated", "role": "admin"}'},
            notes="Injected role=admin reflected in 200 response"
        ),
        severity="Medium",
        status=FindingStatus.SUSPECTED,
        assessment_outcome=AssessmentOutcome.SUSPECTED,
        assessment_reason="Object profile was updated with client-supplied fields without allowlisting",
    )
    session_store.add_finding(session_id, finding)

    return session_id


def test_prompt_1_bola_vs_bfla_conceptual_no_proposals():
    """Prompt 1: Explain difference between BOLA and BFLA. Must not attach proposal cards."""
    resp = client.post("/api/v1/chat", json={"message": "Explain the difference between BOLA and BFLA."})
    assert resp.status_code == 200
    data = resp.json()
    assert "Broken Object Level Authorization" in data["message"]
    assert "Broken Function Level Authorization" in data["message"]
    # Invariant: No proposal cards attached to conceptual explanation
    assert all(a.get("type") != "show_test_proposals" for a in data.get("ui_actions", []))


def test_prompt_10_http_401_vs_403_conceptual():
    """Prompt 10: Explain HTTP 401 versus 403."""
    resp = client.post("/api/v1/chat", json={"message": "Explain HTTP 401 versus 403."})
    assert resp.status_code == 200
    data = resp.json()
    assert "401 Unauthorized" in data["message"]
    assert "403 Forbidden" in data["message"]
    assert all(a.get("type") != "show_test_proposals" for a in data.get("ui_actions", []))


def test_prompt_2_discovered_endpoints(populated_session):
    """Prompt 2: What endpoints have been discovered in my current session?"""
    resp = client.post(
        "/api/v1/chat",
        headers={"X-Session-ID": populated_session},
        json={"message": "What endpoints have been discovered in my current session?"}
    )
    assert resp.status_code == 200
    data = resp.json()
    assert "/api/v1/accounts/{id}" in data["message"]
    assert "/api/v1/admin/users" in data["message"]
    assert "/api/v1/profile" in data["message"]
    assert "3" in data["message"]


def test_prompt_3_waiting_for_approval(populated_session):
    """Prompt 3: Which security tests are waiting for approval?"""
    resp = client.post(
        "/api/v1/chat",
        headers={"X-Session-ID": populated_session},
        json={"message": "Which security tests are waiting for approval?"}
    )
    assert resp.status_code == 200
    data = resp.json()
    assert "prop-bola-001" in data["message"]
    assert "BOLA" in data["message"]
    # Only pending proposals, not approved or executed ones
    assert "prop-bfla-002" not in data["message"]


def test_prompt_4_actually_executed(populated_session):
    """Prompt 4: Which tests have actually executed?"""
    resp = client.post(
        "/api/v1/chat",
        headers={"X-Session-ID": populated_session},
        json={"message": "Which tests have actually executed?"}
    )
    assert resp.status_code == 200
    data = resp.json()
    assert "prop-mass-003" in data["message"]
    assert "1" in data["message"]


def test_prompt_5_show_findings(populated_session):
    """Prompt 5: Show the findings from the latest execution."""
    resp = client.post(
        "/api/v1/chat",
        headers={"X-Session-ID": populated_session},
        json={"message": "Show the findings from the latest execution."}
    )
    assert resp.status_code == 200
    data = resp.json()
    assert "MassAssignment" in data["message"] or "Security Finding" in data["message"]
    assert "SUSPECTED" in data["message"]
    assert "/api/v1/profile" in data["message"]


def test_prompt_6_evidence_highest_severity(populated_session):
    """Prompt 6: What evidence supports the highest-severity finding?"""
    resp = client.post(
        "/api/v1/chat",
        headers={"X-Session-ID": populated_session},
        json={"message": "What evidence supports the highest-severity finding?"}
    )
    assert resp.status_code == 200
    data = resp.json()
    assert "HTTP/1.1 200" in data["message"]
    assert "role" in data["message"]
    assert "Sanitized" in data["message"]


def test_prompt_7_what_should_i_test_next(populated_session):
    """Prompt 7: What should I test next?"""
    resp = client.post(
        "/api/v1/chat",
        headers={"X-Session-ID": populated_session},
        json={"message": "What should I test next?"}
    )
    assert resp.status_code == 200
    data = resp.json()
    assert "prop-bola-001" in data["message"] or "Review Pending" in data["message"]


def test_prompt_8_and_9_assessment_and_executive_summary(populated_session):
    """Prompts 8 & 9: Summarize my current assessment / Generate an executive security summary."""
    resp8 = client.post(
        "/api/v1/chat",
        headers={"X-Session-ID": populated_session},
        json={"message": "Summarize my current assessment."}
    )
    assert resp8.status_code == 200
    data8 = resp8.json()
    assert "Executive Security Summary" in data8["message"]
    assert populated_session in data8["message"]
    assert "Discovered Endpoints" in data8["message"]

    resp9 = client.post(
        "/api/v1/chat",
        headers={"X-Session-ID": populated_session},
        json={"message": "Generate an executive security summary."}
    )
    assert resp9.status_code == 200
    data9 = resp9.json()
    assert "Executive Security Summary" in data9["message"]
    assert populated_session in data9["message"]


def test_empty_session_and_cross_session_isolation(populated_session):
    """Verify empty session reports 0 data and does not leak from another session."""
    empty_session_id = session_store.create_session()

    # Query empty session
    resp = client.post(
        "/api/v1/chat",
        headers={"X-Session-ID": empty_session_id},
        json={"message": "What endpoints have been discovered in my current session?"}
    )
    assert resp.status_code == 200
    assert "No endpoints have been discovered" in resp.json()["message"]

    # Invariant: populated session endpoints must NOT leak to empty session
    assert "/api/v1/accounts/{id}" not in resp.json()["message"]

    # Executed tests query on empty session must report "Not tested"
    resp_exec = client.post(
        "/api/v1/chat",
        headers={"X-Session-ID": empty_session_id},
        json={"message": "Which tests have actually executed?"}
    )
    assert resp_exec.status_code == 200
    assert "Not tested" in resp_exec.json()["message"]


def test_no_session_handling():
    """Verify clean handling when no session header or context is provided."""
    resp = client.post(
        "/api/v1/chat",
        json={"message": "Which security tests are waiting for approval?"}
    )
    assert resp.status_code == 200
    assert "No active assessment session" in resp.json()["message"]

