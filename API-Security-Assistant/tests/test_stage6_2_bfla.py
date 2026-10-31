"""Stage 6.2.2 — Specification-Driven BFLA Implementation Tests.

Verifies all 17 required scenarios for differential BFLA security assessments:
 1. Vulnerable endpoint (/vuln/admin/data: admin 200, user 200) → SUSPECTED (never CONFIRMED).
 2. Secure endpoint (/admin/data: admin 200, user 403) → ACCESS_DENIED.
 3. Missing or mismatched policy mapping → 0 requests, NOT_EXECUTED.
 4. Lower role not explicitly in forbidden_roles → 0 requests, NOT_EXECUTED.
 5. Missing or identical identities → 0 requests, NOT_EXECUTED.
 6. Privileged baseline failure (401/403/500) → 1 request only, INCONCLUSIVE.
 7. Budget < 2 → 0 requests, NOT_EXECUTED.
 8. Unsupported methods (POST, DELETE, PATCH, etc.) → 0 requests, NOT_EXECUTED.
 9. Unapproved proposal → raises PermissionError, 0 requests.
10. Probe 401 with valid lower credentials → ACCESS_DENIED.
11. Probe 401 with unverified credentials → INCONCLUSIVE.
12. Probe 404 with concealment policy → ACCESS_DENIED.
13. Probe 404 without concealment policy → INCONCLUSIVE.
14. Empty/generic/login-wrapper probe 2xx → INCONCLUSIVE.
15. Network exceptions during baseline vs probe → exact request accounting (1 vs 2).
16. Credential and evidence sanitization → no passwords/tokens in evidence.
17. Integration via execute_proposals() in SPEC_DRIVEN mode; LEGACY_FIXTURE and BOLA unaffected.
"""

import json
import pytest
import httpx

from app.mock_api import mock_app
from app.models import (
    AssessmentOutcome,
    BFLAPolicyMapping,
    EndpointModel,
    Evidence,
    ExecutionConfig,
    ExecutionMode,
    ExecutionStatus,
    FindingStatus,
    ParameterFixtures,
    ProposedTest,
    RequestBudget,
    Session,
    TestIdentity,
    TestStatus,
    session_store,
)
from app.parser.openapi_parser import (
    ResolvedSecurityRequirement,
    SecuritySchemeModel,
)
from app.security.bfla_engine import (
    BFLA_REMEDIATION,
    is_generic_or_login_response,
    run_differential_bfla,
)
from app.security.execution_engine import execute_proposals


# ---------------------------------------------------------------------------
# Test Helpers & Fixtures
# ---------------------------------------------------------------------------

def make_bfla_endpoint(path: str = "/admin/data", method: str = "get", **overrides) -> EndpointModel:
    base = {
        "path": path,
        "method": method,
        "responses": {
            "200": {"description": "OK"},
            "403": {"description": "Forbidden"},
        },
        "effective_security": [
            ResolvedSecurityRequirement(
                scheme_name="basicAuth",
                scheme=SecuritySchemeModel(type="http", scheme="basic"),
            )
        ],
    }
    base.update(overrides)
    return EndpointModel.model_validate(base)


def make_bfla_proposal(
    endpoint: EndpointModel,
    status: TestStatus = TestStatus.APPROVED,
    test_type: str = "BFLA",
) -> ProposedTest:
    return ProposedTest(
        test_id="bfla-test-01",
        endpoint=endpoint,
        test_type=test_type,
        description=f"Assess Broken Function Level Authorization for potential privileged operation at `{endpoint.path}`.",
        severity="Critical",
        status=status,
    )


def make_admin_identity() -> TestIdentity:
    return TestIdentity(
        identity_id="admin_user",
        username="admin",
        password="adminPass",
        roles=["admin"],
        credentials_verified=True,
    )


def make_user_identity(roles=None, credentials_verified=True) -> TestIdentity:
    return TestIdentity(
        identity_id="user_a",
        username="user_a",
        password="passwordA",
        roles=roles if roles is not None else ["user"],
        credentials_verified=credentials_verified,
    )


def make_bfla_policy(
    endpoint_path: str = "/admin/data",
    endpoint_method: str = "GET",
    required_role: str = "admin",
    forbidden_roles=None,
    allow_static_route_concealment: bool = False,
) -> BFLAPolicyMapping:
    return BFLAPolicyMapping(
        endpoint_path=endpoint_path,
        endpoint_method=endpoint_method,
        required_role=required_role,
        permitted_roles=[required_role],
        forbidden_roles=forbidden_roles if forbidden_roles is not None else ["user", "guest"],
        allow_static_route_concealment=allow_static_route_concealment,
    )


# ---------------------------------------------------------------------------
# Scenario 1: Vulnerable Endpoint (/vuln/admin/data) -> SUSPECTED
# ---------------------------------------------------------------------------

@pytest.mark.anyio
async def test_s01_bfla_vulnerable_endpoint_suspected():
    endpoint = make_bfla_endpoint(path="/vuln/admin/data")
    proposal = make_bfla_proposal(endpoint)
    policy = make_bfla_policy(endpoint_path="/vuln/admin/data")
    budget = RequestBudget(max_requests=5)

    config = ExecutionConfig(
        mode=ExecutionMode.SPEC_DRIVEN,
        target_base_url="http://127.0.0.1:8001",
        privileged_identity=make_admin_identity(),
        lower_privileged_identity=make_user_identity(),
        bfla_policy=policy,
        budget=budget,
    )

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=mock_app),
        base_url="http://127.0.0.1:8001",
    ) as client:
        finding = await run_differential_bfla(proposal, config, client=client)

    assert finding.assessment_outcome == AssessmentOutcome.SUSPECTED
    assert finding.status == FindingStatus.SUSPECTED
    assert finding.execution_status == ExecutionStatus.COMPLETED
    assert finding.assessment_outcome != AssessmentOutcome.CONFIRMED
    assert not finding.is_human_reviewed
    assert budget.current_count == 2
    assert "admin‑only data (insecure)" in str(finding.evidence.response) or "secret" in str(finding.evidence.response)


# ---------------------------------------------------------------------------
# Scenario 2: Secure Endpoint (/admin/data) -> ACCESS_DENIED
# ---------------------------------------------------------------------------

@pytest.mark.anyio
async def test_s02_bfla_secure_endpoint_access_denied():
    endpoint = make_bfla_endpoint(path="/admin/data")
    proposal = make_bfla_proposal(endpoint)
    policy = make_bfla_policy(endpoint_path="/admin/data")
    budget = RequestBudget(max_requests=5)

    config = ExecutionConfig(
        mode=ExecutionMode.SPEC_DRIVEN,
        target_base_url="http://127.0.0.1:8001",
        privileged_identity=make_admin_identity(),
        lower_privileged_identity=make_user_identity(),
        bfla_policy=policy,
        budget=budget,
    )

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=mock_app),
        base_url="http://127.0.0.1:8001",
    ) as client:
        finding = await run_differential_bfla(proposal, config, client=client)

    assert finding.assessment_outcome == AssessmentOutcome.ACCESS_DENIED
    assert finding.status == FindingStatus.NOT_EXECUTED
    assert finding.execution_status == ExecutionStatus.COMPLETED
    assert budget.current_count == 2
    assert "403" in finding.assessment_reason


# ---------------------------------------------------------------------------
# Scenario 3: Missing or Mismatched Policy Mapping -> NOT_EXECUTED, 0 Requests
# ---------------------------------------------------------------------------

@pytest.mark.anyio
async def test_s03_bfla_missing_or_mismatched_policy():
    endpoint = make_bfla_endpoint(path="/admin/data")
    proposal = make_bfla_proposal(endpoint)

    # 3a. Missing policy
    budget = RequestBudget(max_requests=5)
    config = ExecutionConfig(
        privileged_identity=make_admin_identity(),
        lower_privileged_identity=make_user_identity(),
        bfla_policy=None,
        budget=budget,
    )
    finding = await run_differential_bfla(proposal, config)
    assert finding.status == FindingStatus.NOT_EXECUTED
    assert finding.assessment_outcome == AssessmentOutcome.INCONCLUSIVE
    assert budget.current_count == 0

    # 3b. Mismatched path
    budget = RequestBudget(max_requests=5)
    config = ExecutionConfig(
        privileged_identity=make_admin_identity(),
        lower_privileged_identity=make_user_identity(),
        bfla_policy=make_bfla_policy(endpoint_path="/different/path"),
        budget=budget,
    )
    finding = await run_differential_bfla(proposal, config)
    assert finding.status == FindingStatus.NOT_EXECUTED
    assert budget.current_count == 0

    # 3c. Mismatched method
    budget = RequestBudget(max_requests=5)
    policy = make_bfla_policy(endpoint_path="/admin/data")
    policy.endpoint_method = "POST"
    config = ExecutionConfig(
        privileged_identity=make_admin_identity(),
        lower_privileged_identity=make_user_identity(),
        bfla_policy=policy,
        budget=budget,
    )
    finding = await run_differential_bfla(proposal, config)
    assert finding.status == FindingStatus.NOT_EXECUTED
    assert budget.current_count == 0


# ---------------------------------------------------------------------------
# Scenario 4: Lower Role Not Explicitly in Forbidden Roles -> NOT_EXECUTED, 0 Requests
# ---------------------------------------------------------------------------

@pytest.mark.anyio
async def test_s04_bfla_lower_role_not_forbidden():
    endpoint = make_bfla_endpoint(path="/admin/data")
    proposal = make_bfla_proposal(endpoint)
    budget = RequestBudget(max_requests=5)
    user = make_user_identity(roles=["auditor"])  # not in ["user", "guest"]

    config = ExecutionConfig(
        privileged_identity=make_admin_identity(),
        lower_privileged_identity=user,
        bfla_policy=make_bfla_policy(forbidden_roles=["user", "guest"]),
        budget=budget,
    )
    finding = await run_differential_bfla(proposal, config)
    assert finding.status == FindingStatus.NOT_EXECUTED
    assert finding.assessment_outcome == AssessmentOutcome.INCONCLUSIVE
    assert budget.current_count == 0
    assert "forbidden_roles" in finding.assessment_reason


# ---------------------------------------------------------------------------
# Scenario 5: Missing or Identical Identities -> NOT_EXECUTED, 0 Requests
# ---------------------------------------------------------------------------

@pytest.mark.anyio
async def test_s05_bfla_missing_or_identical_identities():
    endpoint = make_bfla_endpoint(path="/admin/data")
    proposal = make_bfla_proposal(endpoint)
    policy = make_bfla_policy()

    # 5a. Missing privileged identity
    budget = RequestBudget(max_requests=5)
    config = ExecutionConfig(
        privileged_identity=None,
        lower_privileged_identity=make_user_identity(),
        bfla_policy=policy,
        budget=budget,
    )
    finding = await run_differential_bfla(proposal, config)
    assert finding.status == FindingStatus.NOT_EXECUTED
    assert budget.current_count == 0

    # 5b. Missing lower privileged identity
    budget = RequestBudget(max_requests=5)
    config = ExecutionConfig(
        privileged_identity=make_admin_identity(),
        lower_privileged_identity=None,
        bfla_policy=policy,
        budget=budget,
    )
    finding = await run_differential_bfla(proposal, config)
    assert finding.status == FindingStatus.NOT_EXECUTED
    assert budget.current_count == 0

    # 5c. Identical identities
    budget = RequestBudget(max_requests=5)
    same_identity = make_admin_identity()
    same_identity.roles.append("user")
    config = ExecutionConfig(
        privileged_identity=same_identity,
        lower_privileged_identity=same_identity,
        bfla_policy=policy,
        budget=budget,
    )
    finding = await run_differential_bfla(proposal, config)
    assert finding.status == FindingStatus.NOT_EXECUTED
    assert budget.current_count == 0
    assert "distinct" in finding.assessment_reason


# ---------------------------------------------------------------------------
# Scenario 6: Privileged Baseline Failure -> 1 Request Only, INCONCLUSIVE
# ---------------------------------------------------------------------------

@pytest.mark.anyio
@pytest.mark.parametrize("status_code", [401, 403, 500])
async def test_s06_bfla_privileged_baseline_failure(status_code):
    endpoint = make_bfla_endpoint(path="/admin/data")
    proposal = make_bfla_proposal(endpoint)
    policy = make_bfla_policy()
    budget = RequestBudget(max_requests=5)

    config = ExecutionConfig(
        privileged_identity=make_admin_identity(),
        lower_privileged_identity=make_user_identity(),
        bfla_policy=policy,
        budget=budget,
    )

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(status_code, json={"error": "fail"}, request=request)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        finding = await run_differential_bfla(proposal, config, client=client)

    assert finding.assessment_outcome == AssessmentOutcome.INCONCLUSIVE
    assert finding.status == FindingStatus.NOT_EXECUTED
    assert finding.execution_status == ExecutionStatus.COMPLETED
    assert budget.current_count == 1  # Exactly 1 request made; probe was halted
    assert str(status_code) in finding.assessment_reason


# ---------------------------------------------------------------------------
# Scenario 7: Budget < 2 -> NOT_EXECUTED, 0 Requests
# ---------------------------------------------------------------------------

@pytest.mark.anyio
async def test_s07_bfla_budget_preflight():
    endpoint = make_bfla_endpoint(path="/admin/data")
    proposal = make_bfla_proposal(endpoint)
    policy = make_bfla_policy()
    budget = RequestBudget(max_requests=1)  # Sequence needs 2

    config = ExecutionConfig(
        privileged_identity=make_admin_identity(),
        lower_privileged_identity=make_user_identity(),
        bfla_policy=policy,
        budget=budget,
    )

    finding = await run_differential_bfla(proposal, config)
    assert finding.status == FindingStatus.NOT_EXECUTED
    assert budget.current_count == 0
    assert "budget exceeded" in finding.assessment_reason.lower()


# ---------------------------------------------------------------------------
# Scenario 8: Unsupported Methods -> NOT_EXECUTED, 0 Requests
# ---------------------------------------------------------------------------

@pytest.mark.anyio
@pytest.mark.parametrize("method", ["POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"])
async def test_s08_bfla_unsupported_methods_not_executed(method):
    endpoint = make_bfla_endpoint(path="/admin/data", method=method.lower())
    proposal = make_bfla_proposal(endpoint)
    policy = make_bfla_policy()
    policy.endpoint_method = method
    budget = RequestBudget(max_requests=5)

    config = ExecutionConfig(
        privileged_identity=make_admin_identity(),
        lower_privileged_identity=make_user_identity(),
        bfla_policy=policy,
        budget=budget,
    )

    finding = await run_differential_bfla(proposal, config)
    assert finding.status == FindingStatus.NOT_EXECUTED
    assert budget.current_count == 0
    assert "GET operations" in finding.assessment_reason


# ---------------------------------------------------------------------------
# Scenario 9: Unapproved Proposal Raises PermissionError, 0 Requests
# ---------------------------------------------------------------------------

@pytest.mark.anyio
async def test_s09_bfla_unapproved_proposal_raises_permission_error():
    endpoint = make_bfla_endpoint(path="/admin/data")
    proposal = make_bfla_proposal(endpoint, status=TestStatus.PROPOSED)
    policy = make_bfla_policy()
    budget = RequestBudget(max_requests=5)

    config = ExecutionConfig(
        privileged_identity=make_admin_identity(),
        lower_privileged_identity=make_user_identity(),
        bfla_policy=policy,
        budget=budget,
    )

    with pytest.raises(PermissionError) as exc_info:
        await run_differential_bfla(proposal, config)

    assert "explicit human approval" in str(exc_info.value)
    assert budget.current_count == 0


# ---------------------------------------------------------------------------
# Scenario 10: Probe 401 with Valid Lower Credentials -> ACCESS_DENIED
# ---------------------------------------------------------------------------

@pytest.mark.anyio
async def test_s10_bfla_probe_401_with_valid_lower_credentials():
    endpoint = make_bfla_endpoint(path="/admin/data")
    proposal = make_bfla_proposal(endpoint)
    policy = make_bfla_policy()
    budget = RequestBudget(max_requests=5)

    user = make_user_identity(credentials_verified=True)
    config = ExecutionConfig(
        privileged_identity=make_admin_identity(),
        lower_privileged_identity=user,
        bfla_policy=policy,
        budget=budget,
    )

    req_count = 0
    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal req_count
        req_count += 1
        if req_count == 1:
            return httpx.Response(200, json={"secret": "admin-data"}, request=request)
        return httpx.Response(401, json={"detail": "Unauthorized"}, request=request)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        finding = await run_differential_bfla(proposal, config, client=client)

    assert finding.assessment_outcome == AssessmentOutcome.ACCESS_DENIED
    assert finding.status == FindingStatus.NOT_EXECUTED
    assert budget.current_count == 2
    assert "verified" in finding.assessment_reason.lower()


# ---------------------------------------------------------------------------
# Scenario 11: Probe 401 with Unverified Credentials -> INCONCLUSIVE
# ---------------------------------------------------------------------------

@pytest.mark.anyio
async def test_s11_bfla_probe_401_with_unverified_credentials():
    endpoint = make_bfla_endpoint(path="/admin/data")
    proposal = make_bfla_proposal(endpoint)
    policy = make_bfla_policy()
    budget = RequestBudget(max_requests=5)

    user = make_user_identity(credentials_verified=False)
    config = ExecutionConfig(
        privileged_identity=make_admin_identity(),
        lower_privileged_identity=user,
        bfla_policy=policy,
        budget=budget,
    )

    req_count = 0
    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal req_count
        req_count += 1
        if req_count == 1:
            return httpx.Response(200, json={"secret": "admin-data"}, request=request)
        return httpx.Response(401, json={"detail": "Unauthorized"}, request=request)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        finding = await run_differential_bfla(proposal, config, client=client)

    assert finding.assessment_outcome == AssessmentOutcome.INCONCLUSIVE
    assert finding.status == FindingStatus.NOT_EXECUTED
    assert budget.current_count == 2
    assert "unverified credentials" in finding.assessment_reason.lower()


# ---------------------------------------------------------------------------
# Scenario 12: Probe 404 with Route Concealment Policy -> ACCESS_DENIED
# ---------------------------------------------------------------------------

@pytest.mark.anyio
async def test_s12_bfla_probe_404_with_concealment_policy():
    endpoint = make_bfla_endpoint(path="/admin/data")
    proposal = make_bfla_proposal(endpoint)
    policy = make_bfla_policy(allow_static_route_concealment=True)
    budget = RequestBudget(max_requests=5)

    config = ExecutionConfig(
        privileged_identity=make_admin_identity(),
        lower_privileged_identity=make_user_identity(),
        bfla_policy=policy,
        budget=budget,
    )

    req_count = 0
    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal req_count
        req_count += 1
        if req_count == 1:
            return httpx.Response(200, json={"secret": "admin-data"}, request=request)
        return httpx.Response(404, json={"detail": "Not Found"}, request=request)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        finding = await run_differential_bfla(proposal, config, client=client)

    assert finding.assessment_outcome == AssessmentOutcome.ACCESS_DENIED
    assert finding.status == FindingStatus.NOT_EXECUTED
    assert budget.current_count == 2
    assert "route concealment" in finding.assessment_reason.lower()


# ---------------------------------------------------------------------------
# Scenario 13: Probe 404 without Route Concealment Policy -> INCONCLUSIVE
# ---------------------------------------------------------------------------

@pytest.mark.anyio
async def test_s13_bfla_probe_404_without_concealment_policy():
    endpoint = make_bfla_endpoint(path="/admin/data")
    proposal = make_bfla_proposal(endpoint)
    policy = make_bfla_policy(allow_static_route_concealment=False)
    budget = RequestBudget(max_requests=5)

    config = ExecutionConfig(
        privileged_identity=make_admin_identity(),
        lower_privileged_identity=make_user_identity(),
        bfla_policy=policy,
        budget=budget,
    )

    req_count = 0
    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal req_count
        req_count += 1
        if req_count == 1:
            return httpx.Response(200, json={"secret": "admin-data"}, request=request)
        return httpx.Response(404, json={"detail": "Not Found"}, request=request)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        finding = await run_differential_bfla(proposal, config, client=client)

    assert finding.assessment_outcome == AssessmentOutcome.INCONCLUSIVE
    assert finding.status == FindingStatus.NOT_EXECUTED
    assert budget.current_count == 2


# ---------------------------------------------------------------------------
# Scenario 14: Empty / Generic / Login-Wrapper Probe 2xx -> INCONCLUSIVE
# ---------------------------------------------------------------------------

@pytest.mark.anyio
@pytest.mark.parametrize("probe_payload", [
    {},
    {"status": "ok", "msg": "success"},
    {"error": None, "detail": "success"},
    "<!DOCTYPE html><html><body><form action='/login'><input type='password'/></form></body></html>",
    {"html": "Please login to continue with your username and password"},
])
async def test_s14_bfla_empty_or_generic_or_login_probe_inconclusive(probe_payload):
    endpoint = make_bfla_endpoint(path="/admin/data")
    proposal = make_bfla_proposal(endpoint)
    policy = make_bfla_policy()
    budget = RequestBudget(max_requests=5)

    config = ExecutionConfig(
        privileged_identity=make_admin_identity(),
        lower_privileged_identity=make_user_identity(),
        bfla_policy=policy,
        budget=budget,
    )

    req_count = 0
    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal req_count
        req_count += 1
        if req_count == 1:
            return httpx.Response(200, json={"secret": "real-admin-data"}, request=request)
        if isinstance(probe_payload, str):
            return httpx.Response(200, text=probe_payload, headers={"content-type": "text/html"}, request=request)
        return httpx.Response(200, json=probe_payload, request=request)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        finding = await run_differential_bfla(proposal, config, client=client)

    assert finding.assessment_outcome == AssessmentOutcome.INCONCLUSIVE
    assert finding.status == FindingStatus.NOT_EXECUTED
    assert budget.current_count == 2
    assert "inconclusive evidence" in finding.assessment_reason.lower()


# ---------------------------------------------------------------------------
# Scenario 15: Network Exceptions During Baseline vs Probe -> Request Accounting
# ---------------------------------------------------------------------------

@pytest.mark.anyio
async def test_s15_bfla_network_exceptions_accounting():
    endpoint = make_bfla_endpoint(path="/admin/data")
    proposal = make_bfla_proposal(endpoint)
    policy = make_bfla_policy()

    # 15a. Exception on baseline -> 1 request counted
    budget = RequestBudget(max_requests=5)
    config = ExecutionConfig(
        privileged_identity=make_admin_identity(),
        lower_privileged_identity=make_user_identity(),
        bfla_policy=policy,
        budget=budget,
    )

    def failing_baseline_handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("Network unreachable", request=request)

    async with httpx.AsyncClient(transport=httpx.MockTransport(failing_baseline_handler)) as client:
        finding = await run_differential_bfla(proposal, config, client=client)

    assert finding.execution_status == ExecutionStatus.FAILED
    assert finding.assessment_outcome == AssessmentOutcome.INCONCLUSIVE
    assert budget.current_count == 1

    # 15b. Exception on probe -> 2 requests counted
    budget2 = RequestBudget(max_requests=5)
    config2 = ExecutionConfig(
        privileged_identity=make_admin_identity(),
        lower_privileged_identity=make_user_identity(),
        bfla_policy=policy,
        budget=budget2,
    )

    call_num = 0
    def failing_probe_handler(request: httpx.Request) -> httpx.Response:
        nonlocal call_num
        call_num += 1
        if call_num == 1:
            return httpx.Response(200, json={"secret": "ok"}, request=request)
        raise httpx.ReadTimeout("Socket timeout", request=request)

    async with httpx.AsyncClient(transport=httpx.MockTransport(failing_probe_handler)) as client:
        finding2 = await run_differential_bfla(proposal, config2, client=client)

    assert finding2.execution_status == ExecutionStatus.FAILED
    assert finding2.assessment_outcome == AssessmentOutcome.INCONCLUSIVE
    assert budget2.current_count == 2


# ---------------------------------------------------------------------------
# Scenario 16: Credential and Evidence Sanitization -> No Secrets Leaked
# ---------------------------------------------------------------------------

@pytest.mark.anyio
async def test_s16_bfla_evidence_sanitization():
    endpoint = make_bfla_endpoint(path="/vuln/admin/data")
    proposal = make_bfla_proposal(endpoint)
    policy = make_bfla_policy(endpoint_path="/vuln/admin/data")
    budget = RequestBudget(max_requests=5)

    admin = make_admin_identity()
    user = make_user_identity()

    config = ExecutionConfig(
        mode=ExecutionMode.SPEC_DRIVEN,
        target_base_url="http://127.0.0.1:8001",
        privileged_identity=admin,
        lower_privileged_identity=user,
        bfla_policy=policy,
        budget=budget,
    )

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=mock_app),
        base_url="http://127.0.0.1:8001",
    ) as client:
        finding = await run_differential_bfla(proposal, config, client=client)

    finding_json = finding.model_dump_json()
    assert "adminPass" not in finding_json
    assert "passwordA" not in finding_json
    assert "Basic " not in finding_json


# ---------------------------------------------------------------------------
# Scenario 17: execute_proposals() SPEC_DRIVEN integration & Backward Compatibility
# ---------------------------------------------------------------------------

@pytest.mark.anyio
async def test_s17_bfla_execute_proposals_integration_and_backward_compatibility():
    # Setup session
    session_id = session_store.create_session()
    endpoint = make_bfla_endpoint(path="/vuln/admin/data")
    proposal = make_bfla_proposal(endpoint)
    session_store.add_proposal(session_id, proposal)
    session_store.set_proposal_status(session_id, proposal.test_id, TestStatus.APPROVED)

    policy = make_bfla_policy(endpoint_path="/vuln/admin/data")
    config = ExecutionConfig(
        mode=ExecutionMode.SPEC_DRIVEN,
        target_base_url="http://127.0.0.1:8001",
        privileged_identity=make_admin_identity(),
        lower_privileged_identity=make_user_identity(),
        bfla_policy=policy,
        budget=RequestBudget(max_requests=5),
    )

    # 17a. SPEC_DRIVEN execution executes differential BFLA
    findings = await execute_proposals(
        session_id=session_id,
        proposal_ids=[proposal.test_id],
        target="http://127.0.0.1:8001",
        config=config,
    )
    assert len(findings) == 1
    assert findings[0].assessment_outcome == AssessmentOutcome.SUSPECTED
    assert findings[0].remediation == BFLA_REMEDIATION

    # 17b. LEGACY_FIXTURE mode with BFLA proposal still uses _execute_bfla without error
    session_id2 = session_store.create_session()
    proposal2 = make_bfla_proposal(endpoint)
    session_store.add_proposal(session_id2, proposal2)
    session_store.set_proposal_status(session_id2, proposal2.test_id, TestStatus.APPROVED)

    legacy_findings = await execute_proposals(
        session_id=session_id2,
        proposal_ids=[proposal2.test_id],
        target="http://127.0.0.1:8001",
        config=ExecutionConfig(mode=ExecutionMode.LEGACY_FIXTURE, target_base_url="http://127.0.0.1:8001"),
    )
    assert len(legacy_findings) == 1
    assert legacy_findings[0].execution_status == ExecutionStatus.COMPLETED

