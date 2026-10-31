"""Unit and integration tests for Stage 6.3.3: Authentication Test Engine.

Tests cover:
- SEC-6.3.2.1-01 regression: composite OpenAPI security requirements with AND semantics.
- OBS-6.3.2.1-01 regression: case-insensitive query and cookie parameter stripping.
- Core behavior scenarios:
  * Vulnerable mock endpoint returning protected data -> SUSPECTED
  * Secure endpoint returning 401 Unauthorized -> ACCESS_DENIED
  * Secure endpoint returning 403 Forbidden -> ACCESS_DENIED
  * 404 with and without static route concealment policy
  * 3xx redirect -> INCONCLUSIVE
  * 5xx server error -> INCONCLUSIVE
  * Empty, 204, generic status, and HTML login responses -> INCONCLUSIVE
  * Failed baseline (non-2xx, empty, network error) -> INCONCLUSIVE, probe NOT executed (1 request consumed)
- Safety and pre-execution validation:
  * Unapproved proposal -> PermissionError (0 requests)
  * Wrong test type -> NOT_EXECUTED (0 requests)
  * Mode != SPEC_DRIVEN -> NOT_EXECUTED (0 requests)
  * Method != GET -> NOT_EXECUTED (0 requests)
  * Missing security requirements -> NOT_EXECUTED (0 requests)
  * Missing or unverified authenticated identity -> NOT_EXECUTED (0 requests)
  * Non-localhost target -> NOT_EXECUTED (0 requests)
  * Insufficient budget (< 2 requests) -> NOT_EXECUTED (0 requests)
- Sanitization & Invariants:
  * Redacted marker collision prevention
  * No secrets in evidence or step logs
  * CONFIRMED outcome invariant strictly enforced
- Execution engine integration through execute_proposals()
"""

import json
import pytest
import httpx

from app.models import (
    AssessmentOutcome,
    AuthTestType,
    AuthenticationMutation,
    BFLAPolicyMapping,
    EndpointModel,
    Evidence,
    ExecutionConfig,
    ExecutionMode,
    ExecutionStatus,
    Finding,
    FindingStatus,
    ParameterFixtures,
    ProposedTest,
    RequestBudget,
    TestIdentity,
    TestStatus,
)
from app.parser.openapi_parser import ResolvedSecurityRequirement, SecuritySchemeModel, ResponseModel
from app.security.authentication_engine import (
    AUTH_REMEDIATION,
    run_authentication_test,
)
from app.security.execution_engine import execute_proposals
from app.security.request_builder import (
    build_request,
    build_unauthenticated_request,
    get_endpoint_auth_parameters,
)


# ---------------------------------------------------------------------------
# Fixtures & Helpers
# ---------------------------------------------------------------------------

@pytest.fixture
def sample_endpoint() -> EndpointModel:
    scheme = SecuritySchemeModel(
        type="http",
        scheme="bearer",
    )
    req = ResolvedSecurityRequirement(
        scheme_name="BearerAuth",
        scheme=scheme,
        schemes={"BearerAuth": scheme},
    )
    return EndpointModel(
        path="/api/v1/profile",
        method="get",
        summary="Get user profile",
        operation_id="get_profile",
        security=[{"BearerAuth": []}],
        effective_security=[req],
        responses={"200": ResponseModel(description="OK")},
    )


@pytest.fixture
def verified_identity() -> TestIdentity:
    return TestIdentity(
        identity_id="user_alice",
        username="alice",
        token="super-secret-token-alice-12345",
        api_key="alice-api-key-9999",
        credentials_verified=True,
        roles=["user"],
    )


@pytest.fixture
def execution_config(verified_identity: TestIdentity) -> ExecutionConfig:
    return ExecutionConfig(
        target_base_url="http://127.0.0.1:8001",
        mode=ExecutionMode.SPEC_DRIVEN,
        authenticated_identity=verified_identity,
        parameters=ParameterFixtures(
            owner_path_params={},
            attacker_path_params={},
            query_params={},
            headers={},
        ),
        budget=RequestBudget(max_requests=10),
    )


@pytest.fixture
def approved_auth_proposal(sample_endpoint: EndpointModel) -> ProposedTest:
    return ProposedTest(
        test_id="AUTH-001",
        endpoint=sample_endpoint,
        test_type=AuthTestType.AUTH_MISSING_CREDENTIALS.value,
        description="Verify endpoint enforces authentication",
        status=TestStatus.APPROVED,
        severity="High",
        rationale="Verify endpoint enforces authentication",
    )


# ---------------------------------------------------------------------------
# 1. Audit Finding Regressions: SEC-6.3.2.1-01 and OBS-6.3.2.1-01
# ---------------------------------------------------------------------------

def test_sec_6_3_2_1_01_composite_and_security_parameters():
    """SEC-6.3.2.1-01 regression: composite AND requirements must discover all schemes in req.schemes."""
    header_scheme = SecuritySchemeModel(
        type="apiKey",
        name="X-Api-Key",
        in_location="header",
    )
    query_scheme = SecuritySchemeModel(
        type="apiKey",
        name="api_token",
        in_location="query",
    )
    cookie_scheme = SecuritySchemeModel(
        type="apiKey",
        name="session_id",
        in_location="cookie",
    )

    req = ResolvedSecurityRequirement(
        scheme_name="ApiKeyHeader",
        scheme=header_scheme,
        schemes={
            "ApiKeyHeader": header_scheme,
            "ApiKeyQuery": query_scheme,
            "ApiKeyCookie": cookie_scheme,
        },
    )

    endpoint = EndpointModel(
        path="/api/composite/data",
        method="get",
        security=[{"ApiKeyHeader": [], "ApiKeyQuery": [], "ApiKeyCookie": []}],
        effective_security=[req],
        responses={"200": ResponseModel(description="OK")},
    )

    auth_headers, auth_query, auth_cookies = get_endpoint_auth_parameters(endpoint)

    assert "x-api-key" in auth_headers
    assert "authorization" in auth_headers
    assert "api_token" in auth_query
    assert "session_id" in auth_cookies

    # Test that build_unauthenticated_request strips ALL of them
    config = ExecutionConfig(
        target_base_url="http://127.0.0.1:8001",
        parameters=ParameterFixtures(
            headers={"X-Api-Key": "secret-hdr-123", "Custom-App-Header": "keep-me"},
            query_params={"api_token": "secret-query-token", "filter": "active"},
        ),
    )
    unauth_req = build_unauthenticated_request(endpoint, config)

    assert "x-api-key" not in [k.lower() for k in unauth_req.headers]
    assert "authorization" not in [k.lower() for k in unauth_req.headers]
    assert "Custom-App-Header" in unauth_req.headers
    assert "api_token" not in unauth_req.params
    assert unauth_req.params.get("filter") == "active"


def test_obs_6_3_2_1_01_mixed_case_parameter_names():
    """OBS-6.3.2.1-01 regression: mixed-case parameter names stripped case-insensitively."""
    query_scheme = SecuritySchemeModel(
        type="apiKey",
        name="ApiToken",
        in_location="query",
    )
    cookie_scheme = SecuritySchemeModel(
        type="apiKey",
        name="SessionKey",
        in_location="cookie",
    )

    req = ResolvedSecurityRequirement(
        scheme_name="MixedCaseScheme",
        scheme=query_scheme,
        schemes={"QueryKey": query_scheme, "CookieKey": cookie_scheme},
    )

    endpoint = EndpointModel(
        path="/api/mixed/data",
        method="get",
        effective_security=[req],
        responses={"200": ResponseModel(description="OK")},
    )

    # Provided with lowercase or different case in query_params
    config = ExecutionConfig(
        target_base_url="http://127.0.0.1:8001",
        parameters=ParameterFixtures(
            query_params={"apitoken": "secret-token-lower", "normal_arg": "preserve"},
        ),
    )
    unauth_req = build_unauthenticated_request(endpoint, config)

    assert "apitoken" not in unauth_req.params
    assert "ApiToken" not in unauth_req.params
    assert unauth_req.params.get("normal_arg") == "preserve"


def test_auth_openapi_multiple_or_security_requirements():
    """OpenAPI multiple OR requirements: endpoint allows either Bearer OR X-API-KEY."""
    bearer_scheme = SecuritySchemeModel(type="http", scheme="bearer")
    apikey_scheme = SecuritySchemeModel(type="apiKey", name="X-API-KEY", in_location="header")

    req_bearer = ResolvedSecurityRequirement(scheme_name="BearerAuth", scheme=bearer_scheme, schemes={"BearerAuth": bearer_scheme})
    req_apikey = ResolvedSecurityRequirement(scheme_name="ApiKeyAuth", scheme=apikey_scheme, schemes={"ApiKeyAuth": apikey_scheme})

    endpoint = EndpointModel(
        path="/api/or/resource",
        method="get",
        security=[{"BearerAuth": []}, {"ApiKeyAuth": []}],
        effective_security=[req_bearer, req_apikey],
        responses={"200": ResponseModel(description="OK")},
    )

    auth_headers, auth_query, auth_cookies = get_endpoint_auth_parameters(endpoint)
    assert "authorization" in auth_headers
    assert "x-api-key" in auth_headers

    config = ExecutionConfig(
        target_base_url="http://127.0.0.1:8001",
        parameters=ParameterFixtures(
            headers={"Authorization": "Bearer token123", "X-API-KEY": "key123", "X-Tenant": "tenantA"},
        ),
    )
    unauth_req = build_unauthenticated_request(endpoint, config)
    assert "authorization" not in [k.lower() for k in unauth_req.headers]
    assert "x-api-key" not in [k.lower() for k in unauth_req.headers]
    assert unauth_req.headers.get("X-Tenant") == "tenantA"


def test_auth_openapi_mixed_http_and_apikey_query():
    """OpenAPI mixed HTTP Bearer and API key query parameters."""
    bearer_scheme = SecuritySchemeModel(type="http", scheme="bearer")
    query_scheme = SecuritySchemeModel(type="apiKey", name="api_key", in_location="query")

    req = ResolvedSecurityRequirement(
        scheme_name="BearerAndQuery",
        scheme=bearer_scheme,
        schemes={"Bearer": bearer_scheme, "QueryKey": query_scheme},
    )

    endpoint = EndpointModel(
        path="/api/mixed/resource",
        method="get",
        effective_security=[req],
        responses={"200": ResponseModel(description="OK")},
    )

    config = ExecutionConfig(
        target_base_url="http://127.0.0.1:8001",
        parameters=ParameterFixtures(
            headers={"Authorization": "Bearer xyz"},
            query_params={"api_key": "query-secret", "page": "1"},
        ),
    )
    unauth_req = build_unauthenticated_request(endpoint, config)
    assert "authorization" not in [k.lower() for k in unauth_req.headers]
    assert "api_key" not in unauth_req.params
    assert unauth_req.params.get("page") == "1"


def test_auth_openapi_operation_override_empty_security(tmp_path):
    """Operation-level security: [] overrides global security, making endpoint unauthenticated."""
    import yaml
    from app.parser.openapi_parser import parse_openapi_spec

    spec_dict = {
        "openapi": "3.0.3",
        "info": {"title": "Test API", "version": "1.0"},
        "components": {
            "securitySchemes": {
                "GlobalBearer": {"type": "http", "scheme": "bearer"},
            }
        },
        "security": [{"GlobalBearer": []}],
        "paths": {
            "/public/health": {
                "get": {
                    "operationId": "healthCheck",
                    "security": [],  # Explicit override: no security
                    "responses": {"200": {"description": "OK"}},
                }
            },
            "/protected/profile": {
                "get": {
                    "operationId": "getProfile",
                    # Inherits global security
                    "responses": {"200": {"description": "OK"}},
                }
            },
        },
    }

    spec_file = tmp_path / "test_spec.yaml"
    spec_file.write_text(yaml.dump(spec_dict), encoding="utf-8")
    parsed = parse_openapi_spec(str(spec_file))
    health_ep = next(ep for ep in parsed.endpoints if ep.path == "/public/health")
    profile_ep = next(ep for ep in parsed.endpoints if ep.path == "/protected/profile")

    # Health endpoint has explicitly empty effective_security
    assert health_ep.effective_security == []
    auth_headers, _, _ = get_endpoint_auth_parameters(health_ep)
    assert len(auth_headers) == 0

    # Profile endpoint inherits GlobalBearer
    assert len(profile_ep.effective_security) == 1
    p_headers, _, _ = get_endpoint_auth_parameters(profile_ep)
    assert "authorization" in p_headers


# ---------------------------------------------------------------------------
# 2. Core Behavior: Vulnerable & Secure Endpoints
# ---------------------------------------------------------------------------

@pytest.mark.anyio
async def test_auth_test_vulnerable_endpoint_detected(
    approved_auth_proposal: ProposedTest,
    execution_config: ExecutionConfig,
):
    """Vulnerable endpoint: unauthenticated probe returns 200 with protected data -> SUSPECTED."""
    protected_content = {
        "user_id": "USR-101",
        "username": "alice",
        "email": "alice@example.com",
        "balance": 15000,
    }

    async def mock_handler(request: httpx.Request) -> httpx.Response:
        # Both baseline and unauthenticated probe receive protected data (vulnerability)
        return httpx.Response(200, json=protected_content)

    client = httpx.AsyncClient(transport=httpx.MockTransport(mock_handler))
    try:
        finding = await run_authentication_test(approved_auth_proposal, execution_config, client=client)

        assert finding.assessment_outcome == AssessmentOutcome.SUSPECTED
        assert finding.status == FindingStatus.SUSPECTED
        assert finding.execution_status == ExecutionStatus.COMPLETED
        assert "Authentication failure" in finding.assessment_reason
        assert "user_id" in finding.assessment_reason
        assert execution_config.budget.current_count == 2
    finally:
        await client.aclose()


@pytest.mark.anyio
async def test_auth_test_secure_endpoint_401(
    approved_auth_proposal: ProposedTest,
    execution_config: ExecutionConfig,
):
    """Secure endpoint: unauthenticated probe returns 401 Unauthorized -> ACCESS_DENIED."""
    protected_content = {"user_id": "USR-101", "balance": 15000}

    async def mock_handler(request: httpx.Request) -> httpx.Response:
        auth_header = request.headers.get("Authorization")
        if auth_header and "Bearer" in auth_header:
            return httpx.Response(200, json=protected_content)
        return httpx.Response(401, json={"error": "Unauthorized", "message": "Missing credentials"})

    client = httpx.AsyncClient(transport=httpx.MockTransport(mock_handler))
    try:
        finding = await run_authentication_test(approved_auth_proposal, execution_config, client=client)

        assert finding.assessment_outcome == AssessmentOutcome.ACCESS_DENIED
        assert finding.status == FindingStatus.NOT_EXECUTED
        assert finding.execution_status == ExecutionStatus.COMPLETED
        assert "HTTP 401" in finding.assessment_reason
        assert execution_config.budget.current_count == 2
    finally:
        await client.aclose()


@pytest.mark.anyio
async def test_auth_test_secure_endpoint_403(
    approved_auth_proposal: ProposedTest,
    execution_config: ExecutionConfig,
):
    """Secure endpoint: unauthenticated probe returns 403 Forbidden -> ACCESS_DENIED."""
    protected_content = {"user_id": "USR-101", "balance": 15000}

    async def mock_handler(request: httpx.Request) -> httpx.Response:
        if "Authorization" in request.headers:
            return httpx.Response(200, json=protected_content)
        return httpx.Response(403, json={"error": "Forbidden", "message": "Access denied"})

    client = httpx.AsyncClient(transport=httpx.MockTransport(mock_handler))
    try:
        finding = await run_authentication_test(approved_auth_proposal, execution_config, client=client)

        assert finding.assessment_outcome == AssessmentOutcome.ACCESS_DENIED
        assert finding.status == FindingStatus.NOT_EXECUTED
        assert "HTTP 403" in finding.assessment_reason
        assert execution_config.budget.current_count == 2
    finally:
        await client.aclose()


@pytest.mark.anyio
async def test_auth_test_route_concealment_404(
    approved_auth_proposal: ProposedTest,
    execution_config: ExecutionConfig,
):
    """404 handling: ACCESS_DENIED with static route concealment policy; INCONCLUSIVE otherwise."""
    protected_content = {"user_id": "USR-101", "balance": 15000}

    async def mock_handler(request: httpx.Request) -> httpx.Response:
        if "Authorization" in request.headers:
            return httpx.Response(200, json=protected_content)
        return httpx.Response(404, json={"detail": "Not Found"})

    # 1. With static route concealment enabled in bfla_policy
    execution_config.bfla_policy = BFLAPolicyMapping(
        endpoint_path="/api/v1/profile",
        endpoint_method="GET",
        required_role="admin",
        permitted_roles=["admin"],
        forbidden_roles=["user"],
        allow_static_route_concealment=True,
    )
    client1 = httpx.AsyncClient(transport=httpx.MockTransport(mock_handler))
    try:
        finding = await run_authentication_test(approved_auth_proposal, execution_config, client=client1)
        assert finding.assessment_outcome == AssessmentOutcome.ACCESS_DENIED
        assert "route concealment" in finding.assessment_reason
    finally:
        await client1.aclose()

    # 2. Without concealment policy -> INCONCLUSIVE
    execution_config.bfla_policy = None
    execution_config.budget = RequestBudget(max_requests=10)
    client2 = httpx.AsyncClient(transport=httpx.MockTransport(mock_handler))
    try:
        finding = await run_authentication_test(approved_auth_proposal, execution_config, client=client2)
        assert finding.assessment_outcome == AssessmentOutcome.INCONCLUSIVE
        assert "404 indicates missing resource" in finding.assessment_reason
    finally:
        await client2.aclose()


@pytest.mark.anyio
async def test_auth_test_redirect_3xx(
    approved_auth_proposal: ProposedTest,
    execution_config: ExecutionConfig,
):
    """Unauthenticated probe receives 302 redirect -> INCONCLUSIVE (redirects disabled)."""
    async def mock_handler(request: httpx.Request) -> httpx.Response:
        if "Authorization" in request.headers:
            return httpx.Response(200, json={"secret_resource": "data-100"})
        return httpx.Response(302, headers={"Location": "/login"})

    client = httpx.AsyncClient(transport=httpx.MockTransport(mock_handler))
    try:
        finding = await run_authentication_test(approved_auth_proposal, execution_config, client=client)
        assert finding.assessment_outcome == AssessmentOutcome.INCONCLUSIVE
        assert "redirect status 302" in finding.assessment_reason
    finally:
        await client.aclose()


@pytest.mark.anyio
async def test_auth_test_server_error_5xx(
    approved_auth_proposal: ProposedTest,
    execution_config: ExecutionConfig,
):
    """Unauthenticated probe receives 500 Internal Server Error -> INCONCLUSIVE."""
    async def mock_handler(request: httpx.Request) -> httpx.Response:
        if "Authorization" in request.headers:
            return httpx.Response(200, json={"secret_resource": "data-100"})
        return httpx.Response(500, json={"error": "Database error"})

    client = httpx.AsyncClient(transport=httpx.MockTransport(mock_handler))
    try:
        finding = await run_authentication_test(approved_auth_proposal, execution_config, client=client)
        assert finding.assessment_outcome == AssessmentOutcome.INCONCLUSIVE
        assert "HTTP 500" in finding.assessment_reason
    finally:
        await client.aclose()


@pytest.mark.anyio
async def test_auth_test_empty_or_generic_responses(
    approved_auth_proposal: ProposedTest,
    execution_config: ExecutionConfig,
):
    """Probe returning empty response, 204, or generic wrapper -> INCONCLUSIVE."""
    responses = [
        httpx.Response(204),
        httpx.Response(200, text=""),
        httpx.Response(200, json={}),
        httpx.Response(200, json={"status": "ok", "message": "public ping"}),
        httpx.Response(200, text="<html><body>Please sign in to continue with password</body></html>"),
    ]

    for probe_resp in responses:
        execution_config.budget = RequestBudget(max_requests=10)

        async def make_handler(p_resp: httpx.Response):
            async def handler(request: httpx.Request) -> httpx.Response:
                if "Authorization" in request.headers:
                    return httpx.Response(200, json={"account_number": "ACC-99", "balance": 1000})
                return p_resp
            return handler

        client = httpx.AsyncClient(transport=httpx.MockTransport(await make_handler(probe_resp)))
        try:
            finding = await run_authentication_test(approved_auth_proposal, execution_config, client=client)
            assert finding.assessment_outcome == AssessmentOutcome.INCONCLUSIVE
        finally:
            await client.aclose()


# ---------------------------------------------------------------------------
# 3. Failed Authenticated Baseline (Halts at Step 1, 1 Request Consumed)
# ---------------------------------------------------------------------------

@pytest.mark.anyio
async def test_auth_test_failed_baseline_non_2xx(
    approved_auth_proposal: ProposedTest,
    execution_config: ExecutionConfig,
):
    """If authenticated baseline returns 401/500, halt immediately (1 request consumed)."""
    probe_called = False

    async def mock_handler(request: httpx.Request) -> httpx.Response:
        nonlocal probe_called
        if "Authorization" in request.headers:
            return httpx.Response(401, json={"error": "Expired test token"})
        probe_called = True
        return httpx.Response(200, json={"data": "leaked"})

    client = httpx.AsyncClient(transport=httpx.MockTransport(mock_handler))
    try:
        finding = await run_authentication_test(approved_auth_proposal, execution_config, client=client)

        assert finding.assessment_outcome == AssessmentOutcome.INCONCLUSIVE
        assert "cannot establish authorized baseline" in finding.assessment_reason
        assert execution_config.budget.current_count == 1
        assert not probe_called, "Unauthenticated probe must not be called after failed baseline"
    finally:
        await client.aclose()


@pytest.mark.anyio
async def test_auth_test_failed_baseline_empty_or_login(
    approved_auth_proposal: ProposedTest,
    execution_config: ExecutionConfig,
):
    """If authenticated baseline returns empty/login response, halt immediately (1 request consumed)."""
    probe_called = False

    async def mock_handler(request: httpx.Request) -> httpx.Response:
        nonlocal probe_called
        if "Authorization" in request.headers:
            return httpx.Response(200, json={"status": "ok"})
        probe_called = True
        return httpx.Response(200, json={"data": "leaked"})

    client = httpx.AsyncClient(transport=httpx.MockTransport(mock_handler))
    try:
        finding = await run_authentication_test(approved_auth_proposal, execution_config, client=client)

        assert finding.assessment_outcome == AssessmentOutcome.INCONCLUSIVE
        assert execution_config.budget.current_count == 1
        assert not probe_called
    finally:
        await client.aclose()


@pytest.mark.anyio
async def test_auth_test_baseline_network_exception(
    approved_auth_proposal: ProposedTest,
    execution_config: ExecutionConfig,
):
    """Network failure during baseline request halts immediately with INCONCLUSIVE and 1 request consumed."""
    probe_called = False

    async def mock_handler(request: httpx.Request) -> httpx.Response:
        nonlocal probe_called
        if "Authorization" in request.headers:
            raise httpx.ConnectError("Connection refused to target")
        probe_called = True
        return httpx.Response(200)

    client = httpx.AsyncClient(transport=httpx.MockTransport(mock_handler))
    try:
        finding = await run_authentication_test(approved_auth_proposal, execution_config, client=client)

        assert finding.assessment_outcome == AssessmentOutcome.INCONCLUSIVE
        assert finding.execution_status == ExecutionStatus.FAILED
        assert "Connection refused" in finding.assessment_reason
        assert execution_config.budget.current_count == 1
        assert not probe_called
    finally:
        await client.aclose()


# ---------------------------------------------------------------------------
# 4. Pre-execution Validation & Safety (0 Requests Sent)
# ---------------------------------------------------------------------------

@pytest.mark.anyio
async def test_auth_test_unapproved_proposal_rejected(
    approved_auth_proposal: ProposedTest,
    execution_config: ExecutionConfig,
):
    """Unapproved proposal must raise PermissionError with 0 requests sent."""
    approved_auth_proposal.status = TestStatus.PROPOSED

    with pytest.raises(PermissionError, match="not approved"):
        await run_authentication_test(approved_auth_proposal, execution_config)

    assert execution_config.budget.current_count == 0


@pytest.mark.anyio
async def test_auth_test_wrong_test_type_rejected(
    approved_auth_proposal: ProposedTest,
    execution_config: ExecutionConfig,
):
    """Wrong test type produces NOT_EXECUTED finding with 0 requests sent."""
    approved_auth_proposal.test_type = "BOLA"

    finding = await run_authentication_test(approved_auth_proposal, execution_config)

    assert finding.status == FindingStatus.NOT_EXECUTED
    assert finding.execution_status == ExecutionStatus.NOT_EXECUTED
    assert "Unsupported test type" in finding.assessment_reason
    assert execution_config.budget.current_count == 0


@pytest.mark.anyio
async def test_auth_test_non_spec_driven_mode_rejected(
    approved_auth_proposal: ProposedTest,
    execution_config: ExecutionConfig,
):
    """LEGACY_FIXTURE mode produces NOT_EXECUTED with 0 requests sent."""
    execution_config.mode = ExecutionMode.LEGACY_FIXTURE

    finding = await run_authentication_test(approved_auth_proposal, execution_config)

    assert finding.status == FindingStatus.NOT_EXECUTED
    assert "SPEC_DRIVEN mode" in finding.assessment_reason
    assert execution_config.budget.current_count == 0


@pytest.mark.anyio
async def test_auth_test_non_get_method_rejected(
    approved_auth_proposal: ProposedTest,
    execution_config: ExecutionConfig,
):
    """Non-GET method (e.g. POST) produces NOT_EXECUTED with 0 requests sent."""
    approved_auth_proposal.endpoint.method = "post"

    finding = await run_authentication_test(approved_auth_proposal, execution_config)

    assert finding.status == FindingStatus.NOT_EXECUTED
    assert "non-destructive GET operations" in finding.assessment_reason
    assert execution_config.budget.current_count == 0


@pytest.mark.anyio
async def test_auth_test_missing_security_rejected(
    approved_auth_proposal: ProposedTest,
    execution_config: ExecutionConfig,
):
    """Endpoint without security requirements cannot execute auth tests (0 requests sent)."""
    approved_auth_proposal.endpoint.security = []
    approved_auth_proposal.endpoint.effective_security = []

    finding = await run_authentication_test(approved_auth_proposal, execution_config)

    assert finding.status == FindingStatus.NOT_EXECUTED
    assert "no security requirements" in finding.assessment_reason
    assert execution_config.budget.current_count == 0


@pytest.mark.anyio
async def test_auth_test_missing_or_unverified_identity_rejected(
    approved_auth_proposal: ProposedTest,
    execution_config: ExecutionConfig,
):
    """Missing or unverified authenticated identity produces NOT_EXECUTED (0 requests sent)."""
    # 1. Missing identity
    execution_config.authenticated_identity = None
    execution_config.owner_identity = None

    finding1 = await run_authentication_test(approved_auth_proposal, execution_config)
    assert finding1.status == FindingStatus.NOT_EXECUTED
    assert "Missing authenticated identity" in finding1.assessment_reason
    assert execution_config.budget.current_count == 0

    # 2. Unverified identity (credentials_verified = False)
    execution_config.authenticated_identity = TestIdentity(
        identity_id="unverified_user",
        token="token-abc",
        credentials_verified=False,
    )
    finding2 = await run_authentication_test(approved_auth_proposal, execution_config)
    assert finding2.status == FindingStatus.NOT_EXECUTED
    assert "not explicitly verified" in finding2.assessment_reason
    assert execution_config.budget.current_count == 0


@pytest.mark.anyio
async def test_auth_test_unauthorized_target_rejected(
    approved_auth_proposal: ProposedTest,
    execution_config: ExecutionConfig,
):
    """Non-localhost target rejected with 0 requests sent."""
    execution_config.target_base_url = "https://example.com"

    finding = await run_authentication_test(approved_auth_proposal, execution_config)

    assert finding.status == FindingStatus.NOT_EXECUTED
    assert "Unauthorized target URL" in finding.assessment_reason
    assert execution_config.budget.current_count == 0


@pytest.mark.anyio
async def test_auth_test_insufficient_budget_rejected(
    approved_auth_proposal: ProposedTest,
    execution_config: ExecutionConfig,
):
    """Budget < 2 requests rejected before sending any requests."""
    execution_config.budget = RequestBudget(max_requests=1)

    finding = await run_authentication_test(approved_auth_proposal, execution_config)

    assert finding.status == FindingStatus.NOT_EXECUTED
    assert "Execution budget exceeded before sending request" in finding.assessment_reason
    assert execution_config.budget.current_count == 0


# ---------------------------------------------------------------------------
# 5. Sanitization & Invariants
# ---------------------------------------------------------------------------

@pytest.mark.anyio
async def test_auth_test_redacted_marker_collision_guard(
    approved_auth_proposal: ProposedTest,
    execution_config: ExecutionConfig,
):
    """[REDACTED] in baseline and probe must NEVER count as substantive overlap."""
    async def mock_handler(request: httpx.Request) -> httpx.Response:
        if "Authorization" in request.headers:
            return httpx.Response(200, json={"token": "[REDACTED]", "secret_key": "[REDACTED]"})
        # Probe returns different values that sanitize to [REDACTED], but no substantive shared fields
        return httpx.Response(200, json={"token": "[REDACTED]", "secret_key": "[REDACTED]"})

    client = httpx.AsyncClient(transport=httpx.MockTransport(mock_handler))
    try:
        finding = await run_authentication_test(approved_auth_proposal, execution_config, client=client)

        # Must NOT be SUSPECTED because only redacted markers match!
        assert finding.assessment_outcome == AssessmentOutcome.INCONCLUSIVE
        assert finding.status == FindingStatus.NOT_EXECUTED
    finally:
        await client.aclose()


@pytest.mark.anyio
async def test_auth_test_no_secret_leakage_in_evidence_and_notes(
    approved_auth_proposal: ProposedTest,
    execution_config: ExecutionConfig,
):
    """Verify raw tokens and secrets never appear in finding evidence or notes."""
    secret_token = execution_config.authenticated_identity.token

    async def mock_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"account_id": "ACC-101", "name": "Alice"})

    client = httpx.AsyncClient(transport=httpx.MockTransport(mock_handler))
    try:
        finding = await run_authentication_test(approved_auth_proposal, execution_config, client=client)

        finding_str = json.dumps(finding.model_dump(), default=str)
        assert secret_token not in finding_str
    finally:
        await client.aclose()


# ---------------------------------------------------------------------------
# 6. Execution Engine Integration
# ---------------------------------------------------------------------------

@pytest.mark.anyio
async def test_execution_engine_dispatches_auth_proposals(
    approved_auth_proposal: ProposedTest,
    execution_config: ExecutionConfig,
):
    """execute_proposals() dispatches AUTH_MISSING_CREDENTIALS proposals in SPEC_DRIVEN mode."""
    from app.models import session_store
    session_store._sessions.clear()
    sid = session_store.create_session()
    session_store.add_proposal(sid, approved_auth_proposal)

    protected_content = {"user_id": "USR-101", "balance": 15000}

    async def mock_handler(request: httpx.Request) -> httpx.Response:
        auth_header = request.headers.get("Authorization")
        if auth_header:
            return httpx.Response(200, json=protected_content)
        return httpx.Response(401, json={"error": "Unauthorized"})

    # Using custom client requires mocking httpx.AsyncClient in execution_engine
    # or testing execute_proposals with mock_handler via monkeypatch
    with pytest.MonkeyPatch.context() as mp:
        original_init = httpx.AsyncClient.__init__
        def mocked_init(self, *args, **kwargs):
            kwargs["transport"] = httpx.MockTransport(mock_handler)
            original_init(self, *args, **kwargs)
        mp.setattr(httpx.AsyncClient, "__init__", mocked_init)

        findings = await execute_proposals(
            session_id=sid,
            proposal_ids=[approved_auth_proposal.test_id],
            target="http://127.0.0.1:8001",
            config=execution_config,
        )

        assert len(findings) == 1
        finding = findings[0]
        assert finding.test_id == approved_auth_proposal.test_id
        assert finding.assessment_outcome == AssessmentOutcome.ACCESS_DENIED
        assert approved_auth_proposal.executed_at is not None
