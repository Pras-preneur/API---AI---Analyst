# tests/test_report_endpoints.py
"""Integration tests for Phase 2C: POST /reports and GET /reports/{report_id}.

These tests use only in-memory fixtures and do not require any external service.
The mock AsyncClient prevents any real HTTP activity during report generation.
"""

import json
import uuid
from typing import Any, Dict

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.models import (
    Evidence,
    Finding,
    FindingStatus,
    ProposedTest,
    TestStatus,
    session_store,
    EndpointModel,
)


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _make_endpoint(path: str = "/vuln/users/{username}", method: str = "get") -> EndpointModel:
    return EndpointModel.model_validate({
        "path": path,
        "method": method,
        "responses": {"200": {"description": "OK"}},
    })


def _make_finding(
    severity: str = "High",
    status: FindingStatus = FindingStatus.SUSPECTED,
    test_type_hint: str = "BOLA",
) -> Finding:
    ep = _make_endpoint()
    return Finding(
        test_id=str(uuid.uuid4()),
        endpoint=ep,
        evidence=Evidence(
            request={"method": "GET", "url": "http://127.0.0.1:8001/vuln/users/user_b", "headers": {}},
            response={"status_code": 200, "body": {"username": "user_b"}},
        ),
        severity=severity,
        status=status,
        notes=json.dumps({"confidence": 1.0}),
    )


def _make_not_executed_finding() -> Finding:
    ep = _make_endpoint(path="/vuln/unknown")
    return Finding(
        test_id=str(uuid.uuid4()),
        endpoint=ep,
        evidence=Evidence(request={}, response={}),
        severity="Low",
        status=FindingStatus.NOT_EXECUTED,
        notes=json.dumps({"reason": "Unsupported test type"}),
    )


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def reset_store():
    session_store._sessions.clear()
    yield
    session_store._sessions.clear()


@pytest.fixture
def client():
    return TestClient(app)


# ---------------------------------------------------------------------------
# 1. Successful report generation (session with findings)
# ---------------------------------------------------------------------------

def test_create_report_success(client):
    sid = session_store.create_session()
    finding = _make_finding(severity="High")
    session_store.add_finding(sid, finding)

    resp = client.post(
        "/reports",
        json={"target": "http://127.0.0.1:8001"},
        headers={"X-Session-ID": sid},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert "report_id" in data
    assert data["session_id"] == sid
    assert data["target_base_url"] == "http://127.0.0.1:8001"
    assert "assessment_summary" in data
    assert isinstance(data["finding_details"], list)
    assert len(data["finding_details"]) == 1


# ---------------------------------------------------------------------------
# 2. Report generation with zero findings
# ---------------------------------------------------------------------------

def test_create_report_zero_findings(client):
    sid = session_store.create_session()

    resp = client.post(
        "/reports",
        json={"target": "http://127.0.0.1:8001"},
        headers={"X-Session-ID": sid},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["finding_details"] == []
    assert data["not_executed_tests"] == []
    # Summary should indicate nothing was executed
    assert "no security tests" in data["assessment_summary"].lower()


# ---------------------------------------------------------------------------
# 3. Report retrieval by the same session
# ---------------------------------------------------------------------------

def test_get_report_same_session(client):
    sid = session_store.create_session()

    create_resp = client.post(
        "/reports",
        json={"target": "http://127.0.0.1:8001"},
        headers={"X-Session-ID": sid},
    )
    assert create_resp.status_code == 200
    report_id = create_resp.json()["report_id"]

    get_resp = client.get(f"/reports/{report_id}", headers={"X-Session-ID": sid})
    assert get_resp.status_code == 200
    assert get_resp.json()["report_id"] == report_id


# ---------------------------------------------------------------------------
# 4. Unknown session returns 404
# ---------------------------------------------------------------------------

def test_create_report_unknown_session(client):
    resp = client.post(
        "/reports",
        json={"target": "http://127.0.0.1:8001"},
        headers={"X-Session-ID": str(uuid.uuid4())},
    )
    assert resp.status_code == 404
    assert "session not found" in resp.json()["detail"].lower()


def test_get_report_unknown_session(client):
    resp = client.get(
        f"/reports/{uuid.uuid4()}",
        headers={"X-Session-ID": str(uuid.uuid4())},
    )
    assert resp.status_code == 404
    assert "session not found" in resp.json()["detail"].lower()


# ---------------------------------------------------------------------------
# 5. Unknown report ID returns 404
# ---------------------------------------------------------------------------

def test_get_report_unknown_report_id(client):
    sid = session_store.create_session()
    resp = client.get(
        f"/reports/{uuid.uuid4()}",
        headers={"X-Session-ID": sid},
    )
    assert resp.status_code == 404
    assert "report not found" in resp.json()["detail"].lower()


# ---------------------------------------------------------------------------
# 6. Cross-session report access is rejected
# ---------------------------------------------------------------------------

def test_get_report_cross_session_rejected(client):
    sid1 = session_store.create_session()
    sid2 = session_store.create_session()

    # Generate a report in session 1
    create_resp = client.post(
        "/reports",
        json={"target": "http://127.0.0.1:8001"},
        headers={"X-Session-ID": sid1},
    )
    assert create_resp.status_code == 200
    report_id = create_resp.json()["report_id"]

    # Attempt to access it from session 2 — must return 404
    get_resp = client.get(f"/reports/{report_id}", headers={"X-Session-ID": sid2})
    assert get_resp.status_code == 404


# ---------------------------------------------------------------------------
# 7. Severity counts match stored findings
# ---------------------------------------------------------------------------

def test_severity_counts(client):
    sid = session_store.create_session()
    for sev in ["Critical", "High", "High", "Medium", "Low"]:
        session_store.add_finding(sid, _make_finding(severity=sev))

    resp = client.post(
        "/reports",
        json={"target": "http://127.0.0.1:8001"},
        headers={"X-Session-ID": sid},
    )
    assert resp.status_code == 200
    counts = resp.json()["severity_counts"]
    assert counts["critical"] == 1
    assert counts["high"] == 2
    assert counts["medium"] == 1
    assert counts["low"] == 1


# ---------------------------------------------------------------------------
# 8. Evidence sanitization — no secrets in report
# ---------------------------------------------------------------------------

def test_report_evidence_no_secrets(client):
    sid = session_store.create_session()
    # Simulate a finding whose evidence already passed through the sanitizer.
    finding = Finding(
        test_id=str(uuid.uuid4()),
        endpoint=_make_endpoint(),
        evidence=Evidence(
            request={"method": "GET", "url": "http://127.0.0.1:8001/vuln/users/user_b", "headers": {}},
            response={
                "status_code": 200,
                "body": {
                    "username": "user_b",
                    "email": "[REDACTED]",
                    "token": "[REDACTED]",
                },
            },
        ),
        severity="High",
        status=FindingStatus.SUSPECTED,
    )
    session_store.add_finding(sid, finding)

    resp = client.post(
        "/reports",
        json={"target": "http://127.0.0.1:8001"},
        headers={"X-Session-ID": sid},
    )
    assert resp.status_code == 200
    report_json = json.dumps(resp.json())
    # Real secrets must not appear
    for secret in ["passwordA", "Basic dummy", "secret-token", "abc123"]:
        assert secret not in report_json


# ---------------------------------------------------------------------------
# 9. NOT_EXECUTED tests are not reported as confirmed vulnerabilities
# ---------------------------------------------------------------------------

def test_not_executed_not_confirmed(client):
    sid = session_store.create_session()
    not_exec = _make_not_executed_finding()
    session_store.add_finding(sid, not_exec)

    resp = client.post(
        "/reports",
        json={"target": "http://127.0.0.1:8001"},
        headers={"X-Session-ID": sid},
    )
    assert resp.status_code == 200
    data = resp.json()

    # NOT_EXECUTED finding must NOT appear in finding_details
    assert data["finding_details"] == []
    # It must appear in not_executed_tests
    assert not_exec.finding_id in data["not_executed_tests"]
    # Severity counts must be zero (NOT_EXECUTED are excluded)
    counts = data["severity_counts"]
    assert counts["critical"] == counts["high"] == counts["medium"] == counts["low"] == 0


# ---------------------------------------------------------------------------
# 10. Report generation does not execute any security tests
# ---------------------------------------------------------------------------

def test_report_generation_makes_no_http_requests(client, monkeypatch):
    """Ensure generate_report() never calls httpx.AsyncClient."""
    calls = []

    class _SpyClient:
        def __init__(self, **kw):
            calls.append("instantiated")

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def get(self, *a, **kw):
            calls.append("get")

        async def patch(self, *a, **kw):
            calls.append("patch")

    monkeypatch.setattr("app.security.execution_engine.httpx.AsyncClient", _SpyClient)

    sid = session_store.create_session()
    # Pre-populate a finding so the report has something to render
    session_store.add_finding(sid, _make_finding())

    resp = client.post(
        "/reports",
        json={"target": "http://127.0.0.1:8001"},
        headers={"X-Session-ID": sid},
    )
    assert resp.status_code == 200
    # The spy must never have been instantiated
    assert calls == [], f"Expected no HTTP calls but got: {calls}"


# ---------------------------------------------------------------------------
# 11. Missing X-Session-ID header returns 422
# ---------------------------------------------------------------------------

def test_create_report_missing_session_header(client):
    resp = client.post("/reports", json={"target": "http://127.0.0.1:8001"})
    assert resp.status_code == 422


def test_get_report_missing_session_header(client):
    resp = client.get(f"/reports/{uuid.uuid4()}")
    assert resp.status_code == 422


# ---------------------------------------------------------------------------
# 12. Report contains scope and limitations disclosure
# ---------------------------------------------------------------------------

def test_report_contains_scope_limitations(client):
    sid = session_store.create_session()
    resp = client.post(
        "/reports",
        json={"target": "http://127.0.0.1:8001"},
        headers={"X-Session-ID": sid},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert "scope_and_limitations" in data
    assert len(data["scope_and_limitations"]) > 20


# ---------------------------------------------------------------------------
# 13. Finding with matching proposal reports the correct category
# ---------------------------------------------------------------------------

def test_finding_with_matching_proposal_reports_category(client):
    """When a ProposedTest exists for a finding's test_id, the report must
    reflect its exact test_type (e.g. 'BOLA'), not 'Unknown' or 'Unmatched'.
    """
    sid = session_store.create_session()
    ep = _make_endpoint()

    proposal = ProposedTest(
        endpoint=ep,
        test_type="BOLA",
        description="BOLA check",
        severity="High",
        status=TestStatus.APPROVED,
    )
    session_store.add_proposal(sid, proposal)

    # Attach a finding whose test_id matches the proposal
    finding = Finding(
        test_id=proposal.test_id,        # same UUID — key invariant
        endpoint=ep,
        evidence=Evidence(
            request={"method": "GET", "url": "http://127.0.0.1:8001/vuln/users/user_b", "headers": {}},
            response={"status_code": 200, "body": {"username": "user_b"}},
        ),
        severity="High",
        status=FindingStatus.SUSPECTED,
        notes=json.dumps({"confidence": 1.0}),
    )
    session_store.add_finding(sid, finding)

    resp = client.post(
        "/reports",
        json={"target": "http://127.0.0.1:8001"},
        headers={"X-Session-ID": sid},
    )
    assert resp.status_code == 200
    details = resp.json()["finding_details"]
    assert len(details) == 1
    assert details[0]["test_category"] == "BOLA"


# ---------------------------------------------------------------------------
# 14. Finding without matching proposal uses documented fallback
# ---------------------------------------------------------------------------

def test_finding_without_matching_proposal_uses_fallback(client):
    """When no ProposedTest matches a finding's test_id, the report must use
    the documented fallback category 'Unresolved (proposal unavailable)' rather than inventing one.
    """
    sid = session_store.create_session()
    # Add a finding with a random test_id that has no corresponding proposal
    finding = _make_finding(severity="Medium")   # test_id is a fresh uuid4
    session_store.add_finding(sid, finding)

    resp = client.post(
        "/reports",
        json={"target": "http://127.0.0.1:8001"},
        headers={"X-Session-ID": sid},
    )
    assert resp.status_code == 200
    details = resp.json()["finding_details"]
    assert len(details) == 1
    assert details[0]["test_category"] == "Unresolved (proposal unavailable)"


# ---------------------------------------------------------------------------
# 15. Category-specific remediation is included for known categories
# ---------------------------------------------------------------------------

def test_category_specific_remediation(client):
    """Findings with a known category must receive category-specific remediation
    text, not the generic OWASP fallback.
    """
    sid = session_store.create_session()
    ep = _make_endpoint()

    for test_type in ["BOLA", "BFLA", "MissingAuth", "ExcessiveData", "MassAssignment"]:
        proposal = ProposedTest(
            endpoint=ep,
            test_type=test_type,
            description=f"{test_type} check",
            severity="High",
            status=TestStatus.APPROVED,
        )
        session_store.add_proposal(sid, proposal)
        finding = Finding(
            test_id=proposal.test_id,
            endpoint=ep,
            evidence=Evidence(
                request={"method": "GET", "url": "http://127.0.0.1:8001/test", "headers": {}},
                response={"status_code": 200, "body": {}},
            ),
            severity="High",
            status=FindingStatus.SUSPECTED,
        )
        session_store.add_finding(sid, finding)

    resp = client.post(
        "/reports",
        json={"target": "http://127.0.0.1:8001"},
        headers={"X-Session-ID": sid},
    )
    assert resp.status_code == 200
    details = resp.json()["finding_details"]
    # Every detail must have non-empty, category-specific remediation
    generic = "OWASP API Security Top 10"
    for detail in details:
        cat = detail["test_category"]
        remediation = detail["recommended_remediation"]
        assert remediation, f"Empty remediation for category {cat}"
        # Known categories get tailored text (not the generic fallback)
        assert generic not in remediation, (
            f"Category {cat} got generic fallback remediation: {remediation}"
        )


# ---------------------------------------------------------------------------
# 16. NOT_EXECUTED findings remain separate; severity counts stay at zero
# ---------------------------------------------------------------------------

def test_not_executed_separate_from_executed_counts(client):
    """A mix of executed and NOT_EXECUTED findings must be partitioned correctly:
    severity counts reflect only executed findings; not_executed_tests lists the rest.
    """
    sid = session_store.create_session()

    executed_finding = _make_finding(severity="Critical", status=FindingStatus.SUSPECTED)
    not_exec_finding = _make_not_executed_finding()
    session_store.add_finding(sid, executed_finding)
    session_store.add_finding(sid, not_exec_finding)

    resp = client.post(
        "/reports",
        json={"target": "http://127.0.0.1:8001"},
        headers={"X-Session-ID": sid},
    )
    assert resp.status_code == 200
    data = resp.json()

    # Executed finding appears in finding_details
    assert len(data["finding_details"]) == 1
    assert data["finding_details"][0]["status"] == "Suspected"

    # NOT_EXECUTED finding appears only in not_executed_tests
    assert not_exec_finding.finding_id in data["not_executed_tests"]

    # Severity counts reflect only the executed Critical finding
    counts = data["severity_counts"]
    assert counts["critical"] == 1
    assert counts["high"] == counts["medium"] == counts["low"] == 0

