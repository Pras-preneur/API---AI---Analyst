"""Tests for Stage 6.2.3.3 - Final BFLA Accuracy Remediation.

Covers the four findings from the Stage 6.2.3.2 security audit:
1. SEC-6.2.3.2-01: Redacted Marker Collision
   - Ensure [REDACTED] and REDACTED_MARKER can never count as substantive overlap.
   - Ensure different secrets that sanitize to the same marker do not cause SUSPECTED.
   - Ensure substantive non-secret overlap is still recognized.
2. SEC-6.2.3.2-02: Effective Credential Collision
   - Cross-field collisions (token vs api_key).
   - Scheme-guided apiKey checks (query, cookie, header).
   - Basic and Bearer Authorization headers.
   - Distinguishes authentication credentials from arbitrary query parameters and cookies.
3. SEC-6.2.3.2-03: Mixed-Case Role Normalization
   - Trimming and case-insensitive comparison across required, permitted, forbidden roles.
   - Proper handling of duplicate and empty role strings.
4. SEC-6.2.3.2-04: Public Metadata Filtering
   - Metadata keys (version, api_version, format, kind, type, schema, method, env, environment)
     are excluded from substantive overlap comparison.
"""

import httpx
import pytest

from app.models import (
    AssessmentOutcome,
    BFLAPolicyMapping,
    EndpointModel,
    ExecutionConfig,
    ExecutionMode,
    ExecutionStatus,
    Finding,
    FindingStatus,
    ProposedTest,
    RequestBudget,
    TestIdentity,
    TestStatus,
)
from app.parser.openapi_parser import (
    ResolvedSecurityRequirement,
    SecuritySchemeModel,
)
from app.security.bfla_engine import (
    check_identity_credential_collision,
    check_request_credential_collision,
    extract_substantive_overlap,
    normalize_role,
    normalize_roles,
    run_differential_bfla,
)
from app.security.request_builder import PreparedRequest
from app.security.sanitization import REDACTED_MARKER


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_endpoint(
    path: str = "/admin/data",
    method: str = "get",
    security_reqs=None,
) -> EndpointModel:
    if security_reqs is None:
        security_reqs = [
            ResolvedSecurityRequirement(
                scheme_name="basicAuth",
                scheme=SecuritySchemeModel(type="http", scheme="basic"),
            )
        ]
    return EndpointModel.model_validate({
        "path": path,
        "method": method,
        "responses": {
            "200": {"description": "OK"},
            "403": {"description": "Forbidden"},
        },
        "effective_security": security_reqs,
    })


def make_proposal(endpoint: EndpointModel) -> ProposedTest:
    return ProposedTest(
        test_id="bfla-remed-3-test",
        endpoint=endpoint,
        test_type="BFLA",
        description="BFLA Stage 6.2.3.3 test",
        severity="High",
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
        forbidden_roles=forbidden_roles if forbidden_roles is not None else ["user"],
    )


# ---------------------------------------------------------------------------
# 1. SEC-6.2.3.2-01: Redacted Marker Collision
# ---------------------------------------------------------------------------

def test_extract_substantive_overlap_redacted_markers_ignored():
    """Redacted markers must never be counted as substantive overlap."""
    # Dict with only redacted marker
    baseline = {"secret": "[REDACTED]", "api_key": REDACTED_MARKER}
    probe = {"secret": "[REDACTED]", "api_key": REDACTED_MARKER}
    has_match, fields = extract_substantive_overlap(baseline, probe)
    assert not has_match
    assert fields == []

    # List with redacted markers
    baseline_list = ["[REDACTED]", REDACTED_MARKER]
    probe_list = ["[REDACTED]", REDACTED_MARKER]
    has_match, fields = extract_substantive_overlap(baseline_list, probe_list)
    assert not has_match
    assert fields == []

    # Primitive redacted string
    has_match, fields = extract_substantive_overlap("[REDACTED]", "[REDACTED]")
    assert not has_match
    assert fields == []


def test_extract_substantive_overlap_preserves_genuine_protected_fields():
    """Redacted fields are ignored while genuine non-secret fields still match."""
    baseline = {"secret": "[REDACTED]", "report_code": "ALPHA_99", "confidential_count": 42}
    probe = {"secret": "[REDACTED]", "report_code": "ALPHA_99", "confidential_count": 42}
    has_match, fields = extract_substantive_overlap(baseline, probe)
    assert has_match
    assert len(fields) == 2
    assert "report_code='ALPHA_99'" in fields
    assert "confidential_count=42" in fields
    assert not any("secret" in f for f in fields)


@pytest.mark.anyio
async def test_different_secrets_sanitizing_to_same_marker_yields_inconclusive():
    """Different secrets sanitizing to [REDACTED] must not trigger SUSPECTED."""
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
            # Privileged baseline receives admin secret
            return httpx.Response(200, json={"secret": "ADMIN_SUPER_SECRET_111"}, request=request)
        # Probe receives distinct user secret
        return httpx.Response(200, json={"secret": "USER_DIFFERENT_SECRET_222"}, request=request)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        finding = await run_differential_bfla(proposal, config, client=client)

    assert finding.assessment_outcome == AssessmentOutcome.INCONCLUSIVE
    assert finding.status == FindingStatus.NOT_EXECUTED
    assert budget.current_count == 2


@pytest.mark.anyio
async def test_substantive_protected_data_alongside_redacted_secrets_yields_suspected():
    """When genuine substantive overlap exists alongside redacted secrets, SUSPECTED is assigned."""
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
        return httpx.Response(200, json={"secret": "SECRET_VAL", "admin_report": "Q4_FINANCIALS"}, request=request)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        finding = await run_differential_bfla(proposal, config, client=client)

    assert finding.assessment_outcome == AssessmentOutcome.SUSPECTED
    assert finding.status == FindingStatus.SUSPECTED
    assert "admin_report" in finding.assessment_reason
    assert "secret" not in finding.assessment_reason


# ---------------------------------------------------------------------------
# 2. SEC-6.2.3.2-02: Effective Credential Collision
# ---------------------------------------------------------------------------

def test_credential_collision_cross_field_token_and_api_key():
    """Token matching API-key across fields must be detected as collision."""
    priv = TestIdentity(identity_id="p1", token="shared_secret_value", roles=["admin"])
    lower = TestIdentity(identity_id="l1", api_key="shared_secret_value", roles=["user"])

    collision = check_identity_credential_collision(priv, lower)
    assert collision is not None
    assert "bearer token or API key" in collision


@pytest.mark.anyio
async def test_credential_collision_cross_field_rejected_before_requests():
    """Identities with cross-field credential collision must fail pre-execution with 0 requests."""
    endpoint = make_endpoint()
    proposal = make_proposal(endpoint)
    policy = make_policy()
    budget = RequestBudget(max_requests=5)

    config = ExecutionConfig(
        privileged_identity=TestIdentity(identity_id="p1", token="cross_token_123", roles=["admin"]),
        lower_privileged_identity=TestIdentity(identity_id="l1", api_key="cross_token_123", roles=["user"]),
        bfla_policy=policy,
        budget=budget,
    )

    finding = await run_differential_bfla(proposal, config)
    assert finding.status == FindingStatus.NOT_EXECUTED
    assert finding.assessment_outcome == AssessmentOutcome.INCONCLUSIVE
    assert budget.current_count == 0
    assert "share effective credentials" in finding.assessment_reason


def test_request_credential_collision_query_apikey():
    """Prepared requests with identical API-key query parameters must be detected."""
    sec_req = ResolvedSecurityRequirement(
        scheme_name="apiKeyQuery",
        scheme=SecuritySchemeModel(type="apiKey", name="api_token", in_location="query"),
    )
    endpoint = make_endpoint(security_reqs=[sec_req])

    req_base = PreparedRequest(
        method="GET",
        url="http://127.0.0.1/admin/data",
        headers={},
        params={"api_token": "same_key_val"},
    )
    req_probe = PreparedRequest(
        method="GET",
        url="http://127.0.0.1/admin/data",
        headers={},
        params={"api_token": "same_key_val"},
    )

    collision = check_request_credential_collision(endpoint, req_base, req_probe)
    assert collision is not None
    assert "api_token" in collision


def test_request_credential_collision_cookie_apikey():
    """Prepared requests with identical API-key cookies must be detected."""
    sec_req = ResolvedSecurityRequirement(
        scheme_name="cookieAuth",
        scheme=SecuritySchemeModel(type="apiKey", name="session_id", in_location="cookie"),
    )
    endpoint = make_endpoint(security_reqs=[sec_req])

    req_base = PreparedRequest(
        method="GET",
        url="http://127.0.0.1/admin/data",
        headers={},
        params={},
        cookies={"session_id": "sess_abc"},
    )
    req_probe = PreparedRequest(
        method="GET",
        url="http://127.0.0.1/admin/data",
        headers={},
        params={},
        cookies={"session_id": "sess_abc"},
    )

    collision = check_request_credential_collision(endpoint, req_base, req_probe)
    assert collision is not None
    assert "session_id" in collision


def test_request_credential_collision_header_apikey():
    """Prepared requests with identical API-key headers must be detected."""
    sec_req = ResolvedSecurityRequirement(
        scheme_name="apiKeyHeader",
        scheme=SecuritySchemeModel(type="apiKey", name="X-API-Key", in_location="header"),
    )
    endpoint = make_endpoint(security_reqs=[sec_req])

    req_base = PreparedRequest(
        method="GET",
        url="http://127.0.0.1/admin/data",
        headers={"x-api-key": "secret_hdr_val"},
        params={},
    )
    req_probe = PreparedRequest(
        method="GET",
        url="http://127.0.0.1/admin/data",
        headers={"X-API-Key": "secret_hdr_val"},
        params={},
    )

    collision = check_request_credential_collision(endpoint, req_base, req_probe)
    assert collision is not None
    assert "X-API-Key" in collision or "x-api-key" in collision.lower()


def test_request_non_credential_parameters_not_flagged_as_collision():
    """Identical non-credential query parameters or headers must not trigger false positive collision."""
    endpoint = make_endpoint()
    req_base = PreparedRequest(
        method="GET",
        url="http://127.0.0.1/admin/data",
        headers={"authorization": "Basic YWRtaW46cEE="},
        params={"format": "json", "limit": "10"},
        cookies={"theme": "dark"},
    )
    req_probe = PreparedRequest(
        method="GET",
        url="http://127.0.0.1/admin/data",
        headers={"authorization": "Basic dXNlcjpwQg=="},
        params={"format": "json", "limit": "10"},
        cookies={"theme": "dark"},
    )

    collision = check_request_credential_collision(endpoint, req_base, req_probe)
    assert collision is None


# ---------------------------------------------------------------------------
# 3. SEC-6.2.3.2-03: Mixed-Case Role Normalization
# ---------------------------------------------------------------------------

def test_normalize_role_helpers():
    """Test role trimming, lowercasing, and empty string handling."""
    assert normalize_role(" Admin ") == "admin"
    assert normalize_role("USER") == "user"
    assert normalize_role("") is None
    assert normalize_role("   ") is None
    assert normalize_role(None) is None

    assert normalize_roles([" Admin ", "ADMIN", "admin", ""]) == {"admin"}
    assert normalize_roles(None) == set()
    assert normalize_roles(" SuperAdmin ") == {"superadmin"}


@pytest.mark.anyio
async def test_mixed_case_role_permitted_rejection():
    """Lower-privileged identity with mixed-case permitted role must be rejected."""
    endpoint = make_endpoint()
    proposal = make_proposal(endpoint)
    policy = make_policy(permitted_roles=["admin", "auditor"], forbidden_roles=["user"])
    budget = RequestBudget(max_requests=5)

    # Lower identity has " Auditor " which normalizes to "auditor" in permitted_roles
    config = ExecutionConfig(
        privileged_identity=TestIdentity(identity_id="admin_1", username="admin", password="pA", roles=["admin"]),
        lower_privileged_identity=TestIdentity(identity_id="user_1", username="user", password="pB", roles=[" Auditor "]),
        bfla_policy=policy,
        budget=budget,
    )

    finding = await run_differential_bfla(proposal, config)
    assert finding.status == FindingStatus.NOT_EXECUTED
    assert finding.assessment_outcome == AssessmentOutcome.INCONCLUSIVE
    assert budget.current_count == 0
    assert "possesses authorized role(s)" in finding.assessment_reason


@pytest.mark.anyio
async def test_mixed_case_role_privileged_acceptance():
    """Privileged identity with mixed-case role must be accepted for baseline."""
    endpoint = make_endpoint()
    proposal = make_proposal(endpoint)
    policy = make_policy(required_role="admin", forbidden_roles=["user"])
    budget = RequestBudget(max_requests=5)

    # Privileged identity has " ADMIN "
    config = ExecutionConfig(
        privileged_identity=TestIdentity(identity_id="admin_1", username="admin", password="pA", roles=[" ADMIN "]),
        lower_privileged_identity=TestIdentity(identity_id="user_1", username="user", password="pB", roles=["user"]),
        bfla_policy=policy,
        budget=budget,
    )

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"admin_metric": 100}, request=request)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        finding = await run_differential_bfla(proposal, config, client=client)

    assert finding.assessment_outcome == AssessmentOutcome.SUSPECTED
    assert budget.current_count == 2


@pytest.mark.anyio
async def test_duplicate_and_empty_roles_handled_safely():
    """Empty and duplicate roles must be cleanly discarded without crashing or false matching."""
    endpoint = make_endpoint()
    proposal = make_proposal(endpoint)
    policy = make_policy(required_role="admin", forbidden_roles=["user"])
    budget = RequestBudget(max_requests=5)

    # Lower identity has empty strings and duplicate " USER "
    config = ExecutionConfig(
        privileged_identity=TestIdentity(identity_id="admin_1", username="admin", password="pA", roles=["admin"]),
        lower_privileged_identity=TestIdentity(identity_id="user_1", username="user", password="pB", roles=["", "   ", " USER ", "user"]),
        bfla_policy=policy,
        budget=budget,
    )

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"admin_metric": 100}, request=request)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        finding = await run_differential_bfla(proposal, config, client=client)

    assert finding.assessment_outcome == AssessmentOutcome.SUSPECTED
    assert budget.current_count == 2


# ---------------------------------------------------------------------------
# 4. SEC-6.2.3.2-04: Public Metadata Filtering
# ---------------------------------------------------------------------------

def test_extract_substantive_overlap_ignores_metadata_keys():
    """Generic metadata keys must not count as substantive overlap."""
    metadata_keys = [
        "version", "api_version", "format", "kind", "type",
        "schema", "method", "env", "environment",
    ]
    baseline = {k: "v1" for k in metadata_keys}
    baseline["extra_priv"] = "priv_only"

    probe = {k: "v1" for k in metadata_keys}
    probe["extra_lower"] = "lower_only"

    has_match, fields = extract_substantive_overlap(baseline, probe)
    assert not has_match
    assert fields == []


@pytest.mark.anyio
async def test_public_metadata_only_match_yields_inconclusive():
    """Responses matching only on version, type, kind, env etc. must yield INCONCLUSIVE."""
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
            return httpx.Response(
                200,
                json={"version": "2.4.0", "kind": "APIResponse", "type": "report", "env": "prod", "priv_data": 999},
                request=request,
            )
        return httpx.Response(
            200,
            json={"version": "2.4.0", "kind": "APIResponse", "type": "report", "env": "prod", "user_data": 111},
            request=request,
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        finding = await run_differential_bfla(proposal, config, client=client)

    assert finding.assessment_outcome == AssessmentOutcome.INCONCLUSIVE
    assert finding.status == FindingStatus.NOT_EXECUTED
    assert budget.current_count == 2

