"""Stage 6.3.4: Broken Authentication Mock API Integration & End-to-End Validation.

Tests cover the complete 12-step specification-driven workflow:
1. OpenAPI specification parsing for auth demo API.
2. Proposal generation for secure and vulnerable endpoints (AUTH_MISSING_CREDENTIALS).
3. Human approval gating and state transitions.
4. Secure endpoint differential assessment (ACCESS_DENIED).
5. Vulnerable endpoint differential assessment (SUSPECTED).
6. Baseline failure early-halt behavior (1 request consumed).
7. Correct outcome classification (never automatically CONFIRMED).
8. Evidence and log sanitization (no credential leakage).
9. Traceability between proposals, findings, and reports.
10. Structured report generation with accurate remediation advice.
11. Request-budget accounting and preflight enforcement.
12. Compatibility with existing BOLA and BFLA differential assessments.
"""

import json
import pytest
import httpx
from fastapi.testclient import TestClient

from app.main import app
from app.mock_api import mock_app
from app.models import (
    AssessmentOutcome,
    AuthTestType,
    AuthenticationMutation,
    EndpointModel,
    Evidence,
    ExecutionConfig,
    ExecutionMode,
    ExecutionStatus,
    Finding,
    FindingStatus,
    ParameterFixtures,
    ProposedTest,
    Report,
    RequestBudget,
    Session,
    TestIdentity,
    TestStatus,
    session_store,
    validate_assessment_outcome,
)
from app.parser.openapi_parser import parse_openapi_spec
from app.security.authentication_engine import (
    AUTH_REMEDIATION,
    run_authentication_test,
)
from app.security.execution_engine import execute_proposals
from app.security.proposal_engine import (
    generate_auth_proposals,
    generate_proposals,
)
from app.security.report_engine import generate_report


SPEC_PATH = "sample_specs/auth_demo_api.yaml"
TARGET_URL = "http://127.0.0.1:8001"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def auth_spec():
    return parse_openapi_spec(SPEC_PATH)


@pytest.fixture
def valid_identity():
    return TestIdentity(
        identity_id="alice",
        username="alice",
        token="test-bearer-token-alice-98765",
        credentials_verified=True,
        roles=["user"],
    )


@pytest.fixture
def spec_driven_config(valid_identity):
    return ExecutionConfig(
        target_base_url=TARGET_URL,
        mode=ExecutionMode.SPEC_DRIVEN,
        authenticated_identity=valid_identity,
        parameters=ParameterFixtures(),
        budget=RequestBudget(max_requests=10),
    )


# ---------------------------------------------------------------------------
# 1. OpenAPI Specification Parsing
# ---------------------------------------------------------------------------

def test_01_openapi_parsing_auth_spec(auth_spec):
    """OpenAPI specification parsing identifies secure and vulnerable endpoints as protected."""
    assert len(auth_spec.endpoints) == 2

    secure_ep = next((ep for ep in auth_spec.endpoints if ep.path == "/auth/secure/profile"), None)
    vuln_ep = next((ep for ep in auth_spec.endpoints if ep.path == "/auth/vulnerable/profile"), None)

    assert secure_ep is not None, "Secure profile endpoint missing from spec"
    assert vuln_ep is not None, "Vulnerable profile endpoint missing from spec"

    assert secure_ep.method.lower() == "get"
    assert vuln_ep.method.lower() == "get"

    # Both must declare effective security schemes
    assert len(secure_ep.effective_security) == 1
    assert secure_ep.effective_security[0].scheme_name == "BearerAuth"
    assert secure_ep.effective_security[0].http_scheme == "bearer"

    assert len(vuln_ep.effective_security) == 1
    assert vuln_ep.effective_security[0].scheme_name == "BearerAuth"
    assert vuln_ep.effective_security[0].http_scheme == "bearer"


# ---------------------------------------------------------------------------
# 2. Proposal Generation
# ---------------------------------------------------------------------------

def test_02_proposal_generation(auth_spec):
    """Proposal engine generates AUTH_MISSING_CREDENTIALS proposals for both endpoints."""
    proposals = generate_auth_proposals(auth_spec.endpoints)
    assert len(proposals) == 2

    types = {p.test_type for p in proposals}
    assert types == {AuthTestType.AUTH_MISSING_CREDENTIALS.value}

    paths = {p.endpoint.path for p in proposals}
    assert paths == {"/auth/secure/profile", "/auth/vulnerable/profile"}

    for p in proposals:
        assert p.status == TestStatus.PROPOSED
        assert p.severity == "High"
        assert "omitted credentials" in p.description.lower() or "missing" in p.description.lower()

    # Also test generate_proposals with include_auth_tests=True
    all_proposals = generate_proposals(auth_spec.endpoints, include_auth_tests=True)
    auth_props = [p for p in all_proposals if p.test_type == AuthTestType.AUTH_MISSING_CREDENTIALS.value]
    assert len(auth_props) == 2


# ---------------------------------------------------------------------------
# 3. Approval Gating & State Machine
# ---------------------------------------------------------------------------

@pytest.mark.anyio
async def test_03_approval_gating(auth_spec, spec_driven_config):
    """Unapproved proposal cannot be executed; approval enables execution."""
    proposals = generate_auth_proposals(auth_spec.endpoints)
    proposal = proposals[0]
    assert proposal.status == TestStatus.PROPOSED

    # Must raise PermissionError when status is PROPOSED
    with pytest.raises(PermissionError, match="not approved"):
        await run_authentication_test(proposal, spec_driven_config)

    assert spec_driven_config.budget.current_count == 0

    # Transition to APPROVED
    proposal.status = TestStatus.APPROVED
    assert proposal.status == TestStatus.APPROVED


# ---------------------------------------------------------------------------
# 4. Mock API Direct Behavior Validation
# ---------------------------------------------------------------------------

def test_04_mock_api_direct_behavior():
    """Verify mock API response contracts directly using FastAPI TestClient."""
    client = TestClient(mock_app)

    # Scenario A: Secure endpoint without credentials -> 401
    resp_secure_unauth = client.get("/auth/secure/profile")
    assert resp_secure_unauth.status_code == 401
    assert "credentials" in resp_secure_unauth.json().get("detail", "").lower()

    # Scenario A: Secure endpoint with Bearer token -> 200 with profile
    resp_secure_auth = client.get(
        "/auth/secure/profile",
        headers={"Authorization": "Bearer test-valid-token"},
    )
    assert resp_secure_auth.status_code == 200
    sec_data = resp_secure_auth.json()
    assert sec_data["user_id"] == "usr_alice"
    assert sec_data["profile_data"] == "confidential_user_profile_data"

    # Scenario B: Vulnerable endpoint with Bearer token -> 200
    resp_vuln_auth = client.get(
        "/auth/vulnerable/profile",
        headers={"Authorization": "Bearer test-valid-token"},
    )
    assert resp_vuln_auth.status_code == 200

    # Scenario B: Vulnerable endpoint WITHOUT credentials -> incorrectly returns 200!
    resp_vuln_unauth = client.get("/auth/vulnerable/profile")
    assert resp_vuln_unauth.status_code == 200
    vuln_data = resp_vuln_unauth.json()
    assert vuln_data["user_id"] == "usr_alice"
    assert vuln_data["profile_data"] == "confidential_user_profile_data"
    assert "fixture_note" in vuln_data


# ---------------------------------------------------------------------------
# 5. End-to-End Workflow: Secure Endpoint Assessment (ACCESS_DENIED)
# ---------------------------------------------------------------------------

@pytest.mark.anyio
async def test_05_e2e_secure_endpoint_access_denied(auth_spec, spec_driven_config):
    """End-to-end execution on /auth/secure/profile produces ACCESS_DENIED."""
    secure_ep = next(ep for ep in auth_spec.endpoints if ep.path == "/auth/secure/profile")
    proposal = ProposedTest(
        test_id="AUTH-SEC-01",
        endpoint=secure_ep,
        test_type=AuthTestType.AUTH_MISSING_CREDENTIALS.value,
        description="Verify secure profile enforces authentication",
        status=TestStatus.APPROVED,
        severity="High",
        rationale="Enforce credentials on secure profile",
    )

    transport = httpx.ASGITransport(app=mock_app)
    async with httpx.AsyncClient(transport=transport, base_url=TARGET_URL) as client:
        finding = await run_authentication_test(proposal, spec_driven_config, client=client)

    assert finding.test_id == "AUTH-SEC-01"
    assert finding.assessment_outcome == AssessmentOutcome.ACCESS_DENIED
    assert finding.status == FindingStatus.NOT_EXECUTED
    assert finding.execution_status == ExecutionStatus.COMPLETED
    assert "HTTP 401" in finding.assessment_reason
    assert spec_driven_config.budget.current_count == 2

    # Evidence inspection
    assert finding.evidence.response.get("detail") == "Missing or invalid authentication credentials"
    assert finding.remediation == AUTH_REMEDIATION


# ---------------------------------------------------------------------------
# 6. End-to-End Workflow: Vulnerable Endpoint Assessment (SUSPECTED)
# ---------------------------------------------------------------------------

@pytest.mark.anyio
async def test_06_e2e_vulnerable_endpoint_suspected(auth_spec, spec_driven_config):
    """End-to-end execution on /auth/vulnerable/profile produces SUSPECTED."""
    vuln_ep = next(ep for ep in auth_spec.endpoints if ep.path == "/auth/vulnerable/profile")
    proposal = ProposedTest(
        test_id="AUTH-VULN-01",
        endpoint=vuln_ep,
        test_type=AuthTestType.AUTH_MISSING_CREDENTIALS.value,
        description="Verify vulnerable profile enforces authentication",
        status=TestStatus.APPROVED,
        severity="High",
        rationale="Enforce credentials on vulnerable profile",
    )

    transport = httpx.ASGITransport(app=mock_app)
    async with httpx.AsyncClient(transport=transport, base_url=TARGET_URL) as client:
        finding = await run_authentication_test(proposal, spec_driven_config, client=client)

    assert finding.test_id == "AUTH-VULN-01"
    assert finding.assessment_outcome == AssessmentOutcome.SUSPECTED
    assert finding.status == FindingStatus.SUSPECTED
    assert finding.execution_status == ExecutionStatus.COMPLETED
    assert "Authentication failure" in finding.assessment_reason
    assert "usr_alice" in finding.assessment_reason
    assert "confidential_user_profile_data" in finding.assessment_reason
    assert spec_driven_config.budget.current_count == 2

    # Verify notes contain steps audit trail
    notes_data = json.loads(finding.notes)
    assert "steps" in notes_data
    assert "authenticated_baseline" in notes_data["steps"]
    assert "unauthenticated_probe" in notes_data["steps"]
    assert notes_data["authenticated_baseline_status"] == 200
    assert notes_data["probe_status"] == 200
    assert notes_data["mutation"] == AuthenticationMutation.MISSING_CREDENTIALS.value


# ---------------------------------------------------------------------------
# 7. Baseline Failure Halts Sequence (1 Request Consumed)
# ---------------------------------------------------------------------------

@pytest.mark.anyio
async def test_07_baseline_failure_halts_immediately(auth_spec):
    """If authenticated baseline credentials are rejected, halt sequence without probe."""
    secure_ep = next(ep for ep in auth_spec.endpoints if ep.path == "/auth/secure/profile")
    proposal = ProposedTest(
        test_id="AUTH-FAIL-01",
        endpoint=secure_ep,
        test_type=AuthTestType.AUTH_MISSING_CREDENTIALS.value,
        description="Verify baseline failure halts execution",
        status=TestStatus.APPROVED,
        severity="High",
    )

    # Identity with invalid token triggers 401 on baseline in secure endpoint
    bad_identity = TestIdentity(
        identity_id="bad_user",
        token="   ",  # invalid whitespace token
        credentials_verified=True,
    )
    bad_config = ExecutionConfig(
        target_base_url=TARGET_URL,
        mode=ExecutionMode.SPEC_DRIVEN,
        authenticated_identity=bad_identity,
        budget=RequestBudget(max_requests=10),
    )

    transport = httpx.ASGITransport(app=mock_app)
    async with httpx.AsyncClient(transport=transport, base_url=TARGET_URL) as client:
        finding = await run_authentication_test(proposal, bad_config, client=client)

    assert finding.assessment_outcome == AssessmentOutcome.INCONCLUSIVE
    assert finding.status == FindingStatus.NOT_EXECUTED
    assert "cannot establish authorized baseline" in finding.assessment_reason
    assert bad_config.budget.current_count == 1  # Exactly 1 request consumed, probe never called


# ---------------------------------------------------------------------------
# 8. Evidence and Credential Sanitization
# ---------------------------------------------------------------------------

@pytest.mark.anyio
async def test_08_evidence_and_credential_sanitization(auth_spec, spec_driven_config):
    """Evidence models, finding notes, and step logs must never contain raw tokens or secrets."""
    secret_token = spec_driven_config.authenticated_identity.token
    vuln_ep = next(ep for ep in auth_spec.endpoints if ep.path == "/auth/vulnerable/profile")
    proposal = ProposedTest(
        test_id="AUTH-SAN-01",
        endpoint=vuln_ep,
        test_type=AuthTestType.AUTH_MISSING_CREDENTIALS.value,
        description="Sanitization test",
        status=TestStatus.APPROVED,
        severity="High",
    )

    transport = httpx.ASGITransport(app=mock_app)
    async with httpx.AsyncClient(transport=transport, base_url=TARGET_URL) as client:
        finding = await run_authentication_test(proposal, spec_driven_config, client=client)

    finding_json = json.dumps(finding.model_dump(), default=str)
    assert secret_token not in finding_json, "Raw bearer token leaked into finding or evidence"

    # Verify sanitized headers in evidence
    req_evidence = finding.evidence.request
    assert "authorization" not in [k.lower() for k in req_evidence.get("headers", {})]


# ---------------------------------------------------------------------------
# 9. Full End-to-End Workflow Integration via Execution Engine & Reports
# ---------------------------------------------------------------------------

@pytest.mark.anyio
async def test_09_full_workflow_execution_engine_and_report(auth_spec, spec_driven_config):
    """Full workflow: propose -> approve -> execute -> report generation."""
    session_store._sessions.clear()
    sid = session_store.create_session()

    # Step 1 & 2: Generate proposals for auth demo spec
    proposals = generate_auth_proposals(auth_spec.endpoints)
    for p in proposals:
        session_store.add_proposal(sid, p)

    # Step 3: Human approval
    for p in proposals:
        p.status = TestStatus.APPROVED

    # Step 4: Execute via execution_engine
    transport = httpx.ASGITransport(app=mock_app)
    with pytest.MonkeyPatch.context() as mp:
        orig = httpx.AsyncClient.__init__
        def m_init(self, *args, **kwargs):
            kwargs["transport"] = transport
            orig(self, *args, **kwargs)
        mp.setattr(httpx.AsyncClient, "__init__", m_init)

        findings = await execute_proposals(
            session_id=sid,
            proposal_ids=[p.test_id for p in proposals],
            target=TARGET_URL,
            config=spec_driven_config,
        )

    assert len(findings) == 2

    # Step 5: Verify finding outcomes
    finding_by_path = {f.endpoint.path: f for f in findings}
    assert finding_by_path["/auth/secure/profile"].assessment_outcome == AssessmentOutcome.ACCESS_DENIED
    assert finding_by_path["/auth/vulnerable/profile"].assessment_outcome == AssessmentOutcome.SUSPECTED

    # Invariant: Neither finding is automatically CONFIRMED
    for f in findings:
        assert f.assessment_outcome != AssessmentOutcome.CONFIRMED

    # Step 6: Generate structured assessment report
    session = session_store.get_session(sid)
    report: Report = generate_report(session, target_base_url=TARGET_URL)

    assert report.session_id == sid
    assert report.target_base_url == TARGET_URL
    assert len(report.finding_details) == 2

    # Verify report summaries and categorization
    report_by_path = {fd.endpoint_path: fd for fd in report.finding_details}
    sec_report = report_by_path["/auth/secure/profile"]
    vuln_report = report_by_path["/auth/vulnerable/profile"]

    assert sec_report.test_category == AuthTestType.AUTH_MISSING_CREDENTIALS.value
    assert sec_report.assessment_outcome == AssessmentOutcome.ACCESS_DENIED.value
    assert sec_report.status == FindingStatus.NOT_EXECUTED.value

    assert vuln_report.test_category == AuthTestType.AUTH_MISSING_CREDENTIALS.value
    assert vuln_report.assessment_outcome == AssessmentOutcome.SUSPECTED.value
    assert vuln_report.status == FindingStatus.SUSPECTED.value
    assert vuln_report.recommended_remediation == AUTH_REMEDIATION

    # Summary verification
    assert "1 finding(s) are SUSPECTED" in report.assessment_summary
    assert "All evidence has been sanitized" in report.assessment_summary


# ---------------------------------------------------------------------------
# 10. Request Budget Accounting & Preflight
# ---------------------------------------------------------------------------

@pytest.mark.anyio
async def test_10_request_budget_preflight(auth_spec, valid_identity):
    """Budget < 2 requests rejects execution before sending any requests."""
    vuln_ep = next(ep for ep in auth_spec.endpoints if ep.path == "/auth/vulnerable/profile")
    proposal = ProposedTest(
        test_id="AUTH-BUDGET-01",
        endpoint=vuln_ep,
        test_type=AuthTestType.AUTH_MISSING_CREDENTIALS.value,
        description="Budget preflight test",
        status=TestStatus.APPROVED,
        severity="High",
    )

    low_budget_config = ExecutionConfig(
        target_base_url=TARGET_URL,
        mode=ExecutionMode.SPEC_DRIVEN,
        authenticated_identity=valid_identity,
        budget=RequestBudget(max_requests=1),  # Needs 2
    )

    finding = await run_authentication_test(proposal, low_budget_config)
    assert finding.status == FindingStatus.NOT_EXECUTED
    assert finding.execution_status == ExecutionStatus.NOT_EXECUTED
    assert "Execution budget exceeded before sending request" in finding.assessment_reason
    assert low_budget_config.budget.current_count == 0


# ---------------------------------------------------------------------------
# 11. Regression Check: Existing BOLA and BFLA Integrity
# ---------------------------------------------------------------------------

def test_11_legacy_proposals_integrity():
    """Verify legacy demo_api.yaml still produces exact 5 non-auth proposals by default."""
    legacy_spec = parse_openapi_spec("sample_specs/demo_api.yaml")
    legacy_proposals = generate_proposals(legacy_spec.endpoints, include_auth_tests=False)
    assert len(legacy_proposals) == 5

    # With include_auth_tests=True, adds auth proposals without changing existing 5
    enhanced_proposals = generate_proposals(legacy_spec.endpoints, include_auth_tests=True)
    auth_props = [p for p in enhanced_proposals if p.test_type == AuthTestType.AUTH_MISSING_CREDENTIALS.value]
    non_auth_props = [p for p in enhanced_proposals if p.test_type != AuthTestType.AUTH_MISSING_CREDENTIALS.value]
    assert len(non_auth_props) == 5
    assert len(auth_props) > 0


# ---------------------------------------------------------------------------
# 12. Full FastAPI REST API End-to-End Workflow via TestClient(app)
# ---------------------------------------------------------------------------

def test_12_complete_rest_api_workflow(valid_identity):
    """Complete REST API workflow through FastAPI app:
    /parse-openapi -> /tests/propose -> /tests/approve -> /tests/execute -> /reports -> /reports/{id}.
    """
    client = TestClient(app)

    # 1. Parse auth OpenAPI specification
    with open(SPEC_PATH, "rb") as f:
        upload_res = client.post(
            "/parse-openapi",
            files={"file": ("auth_demo_api.yaml", f.read(), "application/octet-stream")},
        )
    assert upload_res.status_code == 200
    session_id = upload_res.headers.get("X-Session-ID")
    assert session_id is not None
    endpoints = upload_res.json()
    assert len(endpoints) == 2

    # 2. Generate proposals with include_auth=true
    propose_res = client.post(
        "/tests/propose?include_auth=true",
        headers={"X-Session-ID": session_id},
    )
    assert propose_res.status_code == 200
    proposals = propose_res.json()
    assert len(proposals) == 2
    for p in proposals:
        assert p["test_type"] == AuthTestType.AUTH_MISSING_CREDENTIALS.value
        assert p["status"] == TestStatus.PROPOSED.value

    # 3. Approve both proposals
    approved_ids = []
    for p in proposals:
        t_id = p["test_id"]
        approve_res = client.post(
            f"/tests/{t_id}/approve",
            headers={"X-Session-ID": session_id},
        )
        assert approve_res.status_code == 200
        assert approve_res.json()["status"] == TestStatus.APPROVED.value
        approved_ids.append(t_id)

    # 4. Execute proposals against live mock API
    exec_payload = {
        "proposal_ids": approved_ids,
        "target": TARGET_URL,
        "config": {
            "mode": ExecutionMode.SPEC_DRIVEN.value,
            "target_base_url": TARGET_URL,
            "authenticated_identity": valid_identity.model_dump(),
            "budget": {"max_requests": 10},
        },
    }
    exec_res = client.post(
        "/tests/execute",
        headers={"X-Session-ID": session_id},
        json=exec_payload,
    )
    assert exec_res.status_code == 200
    findings = exec_res.json()
    assert len(findings) == 2

    findings_by_path = {f["endpoint"]["path"]: f for f in findings}
    assert findings_by_path["/auth/secure/profile"]["assessment_outcome"] == AssessmentOutcome.ACCESS_DENIED.value
    assert findings_by_path["/auth/vulnerable/profile"]["assessment_outcome"] == AssessmentOutcome.SUSPECTED.value

    # 5. List findings via GET /findings
    list_res = client.get("/findings", headers={"X-Session-ID": session_id})
    assert list_res.status_code == 200
    assert len(list_res.json()) == 2

    # 6. Generate report via POST /reports
    report_res = client.post(
        "/reports",
        headers={"X-Session-ID": session_id},
        json={"target": TARGET_URL},
    )
    assert report_res.status_code == 200
    report = report_res.json()
    report_id = report["report_id"]
    assert report["session_id"] == session_id
    assert len(report["finding_details"]) == 2

    report_details_by_path = {fd["endpoint_path"]: fd for fd in report["finding_details"]}
    assert report_details_by_path["/auth/secure/profile"]["assessment_outcome"] == AssessmentOutcome.ACCESS_DENIED.value
    assert report_details_by_path["/auth/vulnerable/profile"]["assessment_outcome"] == AssessmentOutcome.SUSPECTED.value
    assert report_details_by_path["/auth/vulnerable/profile"]["status"] == FindingStatus.SUSPECTED.value

    # 7. Retrieve report via GET /reports/{report_id}
    get_rep_res = client.get(f"/reports/{report_id}", headers={"X-Session-ID": session_id})
    assert get_rep_res.status_code == 200
    assert get_rep_res.json()["report_id"] == report_id


# ---------------------------------------------------------------------------
# 13. Outcome Invariant: Never Automatically CONFIRMED
# ---------------------------------------------------------------------------

def test_13_invariant_no_automatic_confirmed():
    """Verify that CONFIRMED outcome can NEVER be assigned without human review."""
    with pytest.raises(ValueError, match="requires explicit human review"):
        validate_assessment_outcome(AssessmentOutcome.CONFIRMED, is_human_review=False)

    # Validated outcomes without human review:
    validate_assessment_outcome(AssessmentOutcome.SUSPECTED, is_human_review=False)
    validate_assessment_outcome(AssessmentOutcome.ACCESS_DENIED, is_human_review=False)
    validate_assessment_outcome(AssessmentOutcome.INCONCLUSIVE, is_human_review=False)

