"""Stage 6.2.3.1 — BFLA Accuracy Remediation Tests.

Verifies fixes for the six findings identified in Stage 6.2.3 audit:
 1. Baseline comparison: Privileged baseline response used in probe evaluation.
    Meaningful protected-content overlap required for SUSPECTED; unrelated JSON yields INCONCLUSIVE.
 2. Empty responses: HTTP 204, raw_text: "", empty objects/arrays produce INCONCLUSIVE, not SUSPECTED.
 3. Role collision: Lower-privileged identity possessing permitted or required role is rejected (NOT_EXECUTED).
 4. Identity separation: Distinct identity IDs sharing effective credentials (username/password, tokens, API keys) rejected.
 5. Privileged role validation: Privileged identity must possess required_role or permitted_roles.
 6. Dispatcher diagnostics: Missing BFLA policy through execute_proposals() yields clear diagnostic NOT_EXECUTED.
"""

import json
import pytest
import httpx

from app.models import (
    AssessmentOutcome,
    BFLAPolicyMapping,
    EndpointModel,
    ExecutionConfig,
    ExecutionMode,
    ExecutionStatus,
    FindingStatus,
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
    extract_substantive_overlap,
    is_generic_or_login_response,
    run_differential_bfla,
)
from app.security.execution_engine import execute_proposals


# ---------------------------------------------------------------------------
# Test Helpers
# ---------------------------------------------------------------------------

def make_endpoint(path: str = "/admin/data", method: str = "get") -> EndpointModel:
    return EndpointModel.model_validate({
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
    })


def make_proposal(endpoint: EndpointModel) -> ProposedTest:
    return ProposedTest(
        test_id="bfla-remed-test-01",
        endpoint=endpoint,
        test_type="BFLA",
        description="BFLA test",
        severity="Critical",
        status=TestStatus.APPROVED,
    )


def make_policy(
    endpoint_path: str = "/admin/data",
    required_role: str = "admin",
    permitted_roles=None,
    forbidden_roles=None,
) -> BFLAPolicyMapping:
    return BFLAPolicyMapping(
        endpoint_path=endpoint_path,
        endpoint_method="GET",
        required_role=required_role,
        permitted_roles=permitted_roles if permitted_roles is not None else ["admin"],
        forbidden_roles=forbidden_roles if forbidden_roles is not None else ["user", "guest"],
    )


# ---------------------------------------------------------------------------
# FIX 1: Baseline Comparison — Unrelated JSON vs Matching Protected Data
# ---------------------------------------------------------------------------

@pytest.mark.anyio
async def test_remed1_unrelated_json_probe_inconclusive():
    """Probe returning HTTP 200 with unrelated schema/content must yield INCONCLUSIVE."""
    endpoint = make_endpoint()
    proposal = make_proposal(endpoint)
    policy = make_policy()
    budget = RequestBudget(max_requests=5)

    config = ExecutionConfig(
        privileged_identity=TestIdentity(identity_id="admin_1", username="admin", password="pA", roles=["admin"]),
        lower_privileged_identity=TestIdentity(identity_id="user_1", username="user", password="pB", roles=["user"]),
        bfla_policy=policy,
        budget=budget,
    )

    req_count = 0
    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal req_count
        req_count += 1
        if req_count == 1:
            # Privileged baseline: returns secret admin metrics
            return httpx.Response(200, json={"admin_key": "sec123", "revenue": 50000}, request=request)
        # Probe: returns completely unrelated public announcement JSON
        return httpx.Response(200, json={"announcements": ["Maintenance on Sunday"], "version": "1.0"}, request=request)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        finding = await run_differential_bfla(proposal, config, client=client)

    assert finding.assessment_outcome == AssessmentOutcome.INCONCLUSIVE
    assert finding.status == FindingStatus.NOT_EXECUTED
    assert budget.current_count == 2
    assert "substantive overlap" in finding.assessment_reason.lower()


@pytest.mark.anyio
async def test_remed1_matching_protected_data_suspected():
    """Probe returning HTTP 200 with substantive protected fields matching baseline must yield SUSPECTED."""
    endpoint = make_endpoint()
    proposal = make_proposal(endpoint)
    policy = make_policy()
    budget = RequestBudget(max_requests=5)

    config = ExecutionConfig(
        privileged_identity=TestIdentity(identity_id="admin_1", username="admin", password="pA", roles=["admin"]),
        lower_privileged_identity=TestIdentity(identity_id="user_1", username="user", password="pB", roles=["user"]),
        bfla_policy=policy,
        budget=budget,
    )

    req_count = 0
    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal req_count
        req_count += 1
        return httpx.Response(200, json={"admin_report": "sec123", "revenue": 50000}, request=request)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        finding = await run_differential_bfla(proposal, config, client=client)

    assert finding.assessment_outcome == AssessmentOutcome.SUSPECTED
    assert finding.status == FindingStatus.SUSPECTED
    assert budget.current_count == 2
    assert "admin_report" in finding.assessment_reason


# ---------------------------------------------------------------------------
# FIX 2: Empty Responses — HTTP 204 and Empty Representations -> INCONCLUSIVE
# ---------------------------------------------------------------------------

@pytest.mark.anyio
async def test_remed2_http_204_no_content_inconclusive():
    """Probe returning HTTP 204 No Content must yield INCONCLUSIVE."""
    endpoint = make_endpoint()
    proposal = make_proposal(endpoint)
    policy = make_policy()
    budget = RequestBudget(max_requests=5)

    config = ExecutionConfig(
        privileged_identity=TestIdentity(identity_id="admin_1", username="admin", password="pA", roles=["admin"]),
        lower_privileged_identity=TestIdentity(identity_id="user_1", username="user", password="pB", roles=["user"]),
        bfla_policy=policy,
        budget=budget,
    )

    req_count = 0
    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal req_count
        req_count += 1
        if req_count == 1:
            return httpx.Response(200, json={"secret": "admindata"}, request=request)
        return httpx.Response(204, request=request)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        finding = await run_differential_bfla(proposal, config, client=client)

    assert finding.assessment_outcome == AssessmentOutcome.INCONCLUSIVE
    assert finding.status == FindingStatus.NOT_EXECUTED
    assert budget.current_count == 2
    assert "204 no content" in finding.assessment_reason.lower()


@pytest.mark.anyio
@pytest.mark.parametrize("empty_payload", [
    "",
    "   ",
    {},
    [],
    {"items": []},
    {"raw_text": ""},
    {"data": {}},
])
async def test_remed2_empty_representations_inconclusive(empty_payload):
    """Empty response bodies or structures must yield INCONCLUSIVE, never SUSPECTED."""
    assert is_generic_or_login_response(empty_payload) is True


# ---------------------------------------------------------------------------
# FIX 3: Role Collision — Lower Identity with Permitted Role Rejected
# ---------------------------------------------------------------------------

@pytest.mark.anyio
async def test_remed3_multi_role_identity_with_permitted_role_rejected():
    """Lower identity holding both permitted and forbidden roles must be rejected before execution."""
    endpoint = make_endpoint()
    proposal = make_proposal(endpoint)
    policy = make_policy(required_role="admin", permitted_roles=["admin", "superadmin"], forbidden_roles=["user"])
    budget = RequestBudget(max_requests=5)

    # Lower identity has "user" (forbidden) but also "admin" (permitted)
    dual_role_user = TestIdentity(
        identity_id="dual_user",
        username="u1",
        password="p1",
        roles=["admin", "user"],
    )

    config = ExecutionConfig(
        privileged_identity=TestIdentity(identity_id="admin_1", username="admin", password="pA", roles=["admin"]),
        lower_privileged_identity=dual_role_user,
        bfla_policy=policy,
        budget=budget,
    )

    finding = await run_differential_bfla(proposal, config)
    assert finding.status == FindingStatus.NOT_EXECUTED
    assert finding.assessment_outcome == AssessmentOutcome.INCONCLUSIVE
    assert budget.current_count == 0  # Zero requests sent
    assert "authorized role" in finding.assessment_reason.lower()


# ---------------------------------------------------------------------------
# FIX 4: Identity Separation — Shared Effective Credentials Rejected
# ---------------------------------------------------------------------------

@pytest.mark.anyio
async def test_remed4_shared_username_password_rejected():
    """Identities sharing identical username and password must be rejected before sending requests."""
    endpoint = make_endpoint()
    proposal = make_proposal(endpoint)
    policy = make_policy()
    budget = RequestBudget(max_requests=5)

    # Distinct identity_id but identical credentials
    priv = TestIdentity(identity_id="priv_id", username="admin", password="sharedPassword", roles=["admin"])
    lower = TestIdentity(identity_id="lower_id", username="admin", password="sharedPassword", roles=["user"])

    config = ExecutionConfig(
        privileged_identity=priv,
        lower_privileged_identity=lower,
        bfla_policy=policy,
        budget=budget,
    )

    finding = await run_differential_bfla(proposal, config)
    assert finding.status == FindingStatus.NOT_EXECUTED
    assert budget.current_count == 0  # Zero requests sent
    assert "effective credentials" in finding.assessment_reason.lower()


@pytest.mark.anyio
async def test_remed4_shared_bearer_token_rejected():
    """Identities sharing identical bearer tokens must be rejected before sending requests."""
    endpoint = make_endpoint()
    proposal = make_proposal(endpoint)
    policy = make_policy()
    budget = RequestBudget(max_requests=5)

    priv = TestIdentity(identity_id="priv_id", token="shared_secret_jwt", roles=["admin"])
    lower = TestIdentity(identity_id="lower_id", token="shared_secret_jwt", roles=["user"])

    config = ExecutionConfig(
        privileged_identity=priv,
        lower_privileged_identity=lower,
        bfla_policy=policy,
        budget=budget,
    )

    finding = await run_differential_bfla(proposal, config)
    assert finding.status == FindingStatus.NOT_EXECUTED
    assert budget.current_count == 0
    assert "effective credentials" in finding.assessment_reason.lower()


# ---------------------------------------------------------------------------
# FIX 5: Privileged Role Validation — Privileged Identity Missing Required Role
# ---------------------------------------------------------------------------

@pytest.mark.anyio
async def test_remed5_missing_privileged_role_rejected():
    """Privileged identity lacking required_role and permitted_roles must be rejected before execution."""
    endpoint = make_endpoint()
    proposal = make_proposal(endpoint)
    policy = make_policy(required_role="admin", permitted_roles=["admin"])
    budget = RequestBudget(max_requests=5)

    # Privileged identity has role "guest" which is not admin
    unqualified_priv = TestIdentity(
        identity_id="fake_admin",
        username="guest",
        password="pG",
        roles=["guest"],
    )
    lower = TestIdentity(identity_id="lower_id", username="user", password="pU", roles=["user"])

    config = ExecutionConfig(
        privileged_identity=unqualified_priv,
        lower_privileged_identity=lower,
        bfla_policy=policy,
        budget=budget,
    )

    finding = await run_differential_bfla(proposal, config)
    assert finding.status == FindingStatus.NOT_EXECUTED
    assert budget.current_count == 0
    assert "does not hold required role" in finding.assessment_reason.lower()


# ---------------------------------------------------------------------------
# FIX 6: Dispatcher Diagnostics — Missing BFLA Policy via execute_proposals()
# ---------------------------------------------------------------------------

@pytest.mark.anyio
async def test_remed6_dispatcher_diagnostics_missing_policy():
    """Executing BFLA in SPEC_DRIVEN mode without bfla_policy returns clear diagnostic NOT_EXECUTED."""
    sid = session_store.create_session()
    endpoint = make_endpoint()
    proposal = make_proposal(endpoint)
    session_store.add_proposal(sid, proposal)
    session_store.set_proposal_status(sid, proposal.test_id, TestStatus.APPROVED)

    config = ExecutionConfig(
        mode=ExecutionMode.SPEC_DRIVEN,
        target_base_url="http://127.0.0.1:8001",
        bfla_policy=None,  # Missing policy mapping
    )

    findings = await execute_proposals(
        session_id=sid,
        proposal_ids=[proposal.test_id],
        target="http://127.0.0.1:8001",
        config=config,
    )

    assert len(findings) == 1
    f = findings[0]
    assert f.status == FindingStatus.NOT_EXECUTED
    assert f.execution_status == ExecutionStatus.NOT_EXECUTED
    assert "missing required bfla_policy" in f.notes.lower()
    assert "explicit bfla policy mapping is required" in f.notes.lower()

