"""Unit tests for Stage 3: Dynamic Request Construction and Authentication Layer.

Verifies:
- Method resolution and path parameter substitution
- Strict target allowlist enforcement (local mock only)
- Path traversal prevention
- HTTP Bearer authentication resolution
- HTTP Basic authentication resolution (base64)
- API key authentication in header, query, and cookie
- Explicit unauthenticated endpoint handling
- Clear, sanitized configuration errors on missing/invalid credentials
- Strict redirect policy (follow_redirects=False)
- Credential sanitization for evidence metadata
- Request budget enforcement in SPEC_DRIVEN execution
"""

import asyncio
import base64
import json
import pytest

from app.models import (
    EndpointModel,
    ExecutionConfig,
    ExecutionMode,
    ExecutionStatus,
    FindingStatus,
    ParameterFixtures,
    ProposedTest,
    RequestBudget,
    TestIdentity,
    TestStatus,
    session_store,
)
from app.parser.openapi_parser import (
    ResolvedSecurityRequirement,
    SecuritySchemeModel,
)
from app.security.request_builder import (
    PreparedRequest,
    build_request,
    build_target_url,
    resolve_authentication,
)
from app.security.execution_engine import execute_proposals


def test_build_target_url_simple_and_substitution():
    """Target URL must be constructed from base URL and path template with parameter substitution."""
    url = build_target_url(
        base_url="http://127.0.0.1:8001",
        path_template="/users/{user_id}",
        path_params={"user_id": "alice"},
    )
    assert url == "http://127.0.0.1:8001/users/alice"

    # Multi-parameter template with trailing slash on base URL
    url2 = build_target_url(
        base_url="http://localhost:8001/",
        path_template="/orgs/{org_id}/teams/{team_id}",
        path_params={"org_id": "alpha", "team_id": "security"},
    )
    assert url2 == "http://localhost:8001/orgs/alpha/teams/security"


def test_build_target_url_missing_parameter_raises_value_error():
    """Missing required path parameter fixture must raise a clear ValueError."""
    with pytest.raises(ValueError, match="Missing required path parameter fixture 'user_id'"):
        build_target_url(
            base_url="http://127.0.0.1:8001",
            path_template="/users/{user_id}",
            path_params={},
        )


@pytest.mark.parametrize(
    "traversal_val",
    [
        "../admin",
        "..\\admin",
        "sub/user",
        "sub\\user",
        "%2e%2e%2fadmin",
        "%2e%2e/admin",
        "%5cadmin",
        "alice\x00extra",
        "",
    ],
)
def test_build_target_url_path_traversal_rejection(traversal_val):
    """Path parameters must reject traversal sequences, slashes, and null bytes."""
    with pytest.raises(ValueError, match="Path parameter.*(empty|illegal traversal)"):
        build_target_url(
            base_url="http://127.0.0.1:8001",
            path_template="/users/{user_id}",
            path_params={"user_id": traversal_val},
        )


def test_build_target_url_disallowed_target_raises_permission_error():
    """Constructing URLs for targets outside the localhost allowlist must raise PermissionError."""
    with pytest.raises(PermissionError, match="Unauthorized target URL"):
        build_target_url(
            base_url="http://example.com",
            path_template="/users/{user_id}",
            path_params={"user_id": "alice"},
        )

    with pytest.raises(PermissionError, match="Unauthorized target URL"):
        build_target_url(
            base_url="http://localhost:8888",
            path_template="/users/{user_id}",
            path_params={"user_id": "alice"},
        )


def test_resolve_authentication_http_bearer():
    """HTTP Bearer security schemes must resolve to an Authorization: Bearer <token> header."""
    bearer_scheme = SecuritySchemeModel(type="http", scheme="bearer", bearerFormat="JWT")
    endpoint = EndpointModel(
        path="/secure/profile",
        method="get",
        responses={"200": {"description": "ok"}},
        effective_security=[
            ResolvedSecurityRequirement(
                scheme_name="BearerAuth",
                scheme=bearer_scheme,
            )
        ],
    )
    identity = TestIdentity(identity_id="alice_user", token="jwt.test.token123")

    headers, params, cookies = resolve_authentication(endpoint, identity)
    assert headers["Authorization"] == "Bearer jwt.test.token123"
    assert params == {}
    assert cookies == {}


def test_resolve_authentication_http_basic():
    """HTTP Basic security schemes must resolve to an Authorization: Basic <base64> header."""
    basic_scheme = SecuritySchemeModel(type="http", scheme="basic")
    endpoint = EndpointModel(
        path="/admin/settings",
        method="get",
        responses={"200": {"description": "ok"}},
        effective_security=[
            ResolvedSecurityRequirement(
                scheme_name="BasicAuth",
                scheme=basic_scheme,
            )
        ],
    )
    identity = TestIdentity(identity_id="admin_user", username="admin", password="SecretPassword!")

    headers, params, cookies = resolve_authentication(endpoint, identity)
    expected_b64 = base64.b64encode(b"admin:SecretPassword!").decode("ascii")
    assert headers["Authorization"] == f"Basic {expected_b64}"


def test_resolve_authentication_api_key_locations():
    """API key schemes must resolve to header, query, or cookie locations as specified."""
    # Header location
    hdr_scheme = SecuritySchemeModel(type="apiKey", in_location="header", name="X-API-KEY")
    ep_hdr = EndpointModel(
        path="/api/data",
        method="get",
        responses={"200": {"description": "ok"}},
        effective_security=[ResolvedSecurityRequirement(scheme_name="HdrKey", scheme=hdr_scheme)],
    )
    id1 = TestIdentity(identity_id="id1", api_key="secret-api-key-1")
    h1, p1, c1 = resolve_authentication(ep_hdr, id1)
    assert h1["X-API-KEY"] == "secret-api-key-1"

    # Query location
    query_scheme = SecuritySchemeModel(type="apiKey", in_location="query", name="api_token")
    ep_query = EndpointModel(
        path="/api/data",
        method="get",
        responses={"200": {"description": "ok"}},
        effective_security=[ResolvedSecurityRequirement(scheme_name="QueryKey", scheme=query_scheme)],
    )
    h2, p2, c2 = resolve_authentication(ep_query, id1)
    assert p2["api_token"] == "secret-api-key-1"

    # Cookie location
    cookie_scheme = SecuritySchemeModel(type="apiKey", in_location="cookie", name="session_id")
    ep_cookie = EndpointModel(
        path="/api/data",
        method="get",
        responses={"200": {"description": "ok"}},
        effective_security=[ResolvedSecurityRequirement(scheme_name="CookieKey", scheme=cookie_scheme)],
    )
    h3, p3, c3 = resolve_authentication(ep_cookie, id1)
    assert c3["session_id"] == "secret-api-key-1"


def test_resolve_authentication_unauthenticated():
    """Explicitly unauthenticated endpoints (security: []) must not require credentials."""
    unauth_ep = EndpointModel(
        path="/public/status",
        method="get",
        responses={"200": {"description": "ok"}},
        effective_security=[],
    )
    headers, params, cookies = resolve_authentication(unauth_ep, identity=None)
    assert headers == {}
    assert params == {}
    assert cookies == {}

    # Endpoint with no security declared
    no_sec_ep = EndpointModel(
        path="/public/ping",
        method="get",
        responses={"200": {"description": "ok"}},
        effective_security=None,
    )
    h, p, c = resolve_authentication(no_sec_ep, identity=None)
    assert h == {}


def test_resolve_authentication_missing_credentials_raises_clear_error():
    """Missing or insufficient credentials must raise a clear sanitized configuration error."""
    bearer_scheme = SecuritySchemeModel(type="http", scheme="bearer")
    ep = EndpointModel(
        path="/users/{user_id}",
        method="get",
        responses={"200": {"description": "ok"}},
        effective_security=[ResolvedSecurityRequirement(scheme_name="BearerAuth", scheme=bearer_scheme)],
    )

    # Missing identity completely
    with pytest.raises(ValueError, match="requires authentication.*no test identity was provided"):
        resolve_authentication(ep, identity=None)

    # Identity missing token
    id_no_token = TestIdentity(identity_id="bob", username="bob")
    with pytest.raises(ValueError, match="Authentication failed for identity 'bob'"):
        resolve_authentication(ep, id_no_token)


def test_build_request_full_workflow():
    """build_request must assemble method, URL, auth, parameters, headers, and safety policies."""
    bearer_scheme = SecuritySchemeModel(type="http", scheme="bearer")
    ep = EndpointModel(
        path="/users/{user_id}/orders",
        method="get",
        responses={"200": {"description": "ok"}},
        effective_security=[ResolvedSecurityRequirement(scheme_name="BearerAuth", scheme=bearer_scheme)],
    )
    owner = TestIdentity(identity_id="owner_alice", token="alice-secret-token")
    cfg = ExecutionConfig(
        mode=ExecutionMode.SPEC_DRIVEN,
        target_base_url="http://127.0.0.1:8001",
        owner_identity=owner,
        parameters=ParameterFixtures(
            owner_path_params={"user_id": "alice"},
            query_params={"status": "active"},
            headers={"Accept": "application/json"},
        ),
        timeout_seconds=7.5,
    )

    req = build_request(ep, cfg)
    assert isinstance(req, PreparedRequest)
    assert req.method == "GET"
    assert req.url == "http://127.0.0.1:8001/users/alice/orders"
    assert req.headers["Authorization"] == "Bearer alice-secret-token"
    assert req.headers["Accept"] == "application/json"
    assert req.params["status"] == "active"
    assert req.timeout_seconds == 7.5
    assert req.follow_redirects is False


def test_prepared_request_evidence_sanitization():
    """to_evidence_dict must redact credentials and never leak secrets in evidence."""
    req = PreparedRequest(
        method="GET",
        url="http://127.0.0.1:8001/users/alice",
        headers={
            "Authorization": "Bearer super-secret-jwt-token",
            "X-API-KEY": "secret-api-key-999",
            "Cookie": "session=secret-session-abc",
            "Accept": "application/json",
        },
        params={"user": "alice", "auth_token": "leak-attempt"},
    )
    evidence_dict = req.to_evidence_dict()

    # Headers sanitized
    assert "Authorization" not in evidence_dict["headers"]
    assert evidence_dict["headers"]["X-API-KEY"] == "[REDACTED]"
    assert evidence_dict["headers"]["Cookie"] == "[REDACTED]"
    assert evidence_dict["headers"]["Accept"] == "application/json"

    # Params sanitized
    assert evidence_dict["params"]["auth_token"] == "[REDACTED]"
    assert evidence_dict["params"]["user"] == "alice"

    # Raw secrets must not be in string representation
    serialized = json.dumps(evidence_dict)
    assert "super-secret-jwt-token" not in serialized
    assert "secret-api-key-999" not in serialized
    assert "secret-session-abc" not in serialized
    assert "leak-attempt" not in serialized


def test_spec_driven_execution_budget_enforcement():
    """In SPEC_DRIVEN mode, when the budget is exhausted, test must be marked NOT_EXECUTED."""
    sid = session_store.create_session()
    ep = EndpointModel(
        path="/public/ping",
        method="get",
        responses={"200": {"description": "ok"}},
        effective_security=[],
    )
    prop = ProposedTest(
        endpoint=ep,
        test_type="BOLA",
        description="Spec-driven test",
        severity="Medium",
        status=TestStatus.APPROVED,
    )
    session_store.add_proposal(sid, prop)

    # Budget with 0 remaining
    exhausted_budget = RequestBudget(max_requests=1, current_count=1)
    cfg = ExecutionConfig(
        mode=ExecutionMode.SPEC_DRIVEN,
        target_base_url="http://127.0.0.1:8001",
        budget=exhausted_budget,
    )

    findings = asyncio.run(execute_proposals(
        session_id=sid,
        proposal_ids=[prop.test_id],
        target="http://127.0.0.1:8001",
        config=cfg,
    ))

    assert len(findings) == 1
    f = findings[0]
    assert f.status == FindingStatus.NOT_EXECUTED
    assert f.execution_status == ExecutionStatus.NOT_EXECUTED
    assert "budget exceeded" in f.notes.lower()


def test_spec_driven_configuration_error_recorded_as_not_executed():
    """In SPEC_DRIVEN mode, missing path fixtures must be captured as a NOT_EXECUTED finding."""
    sid = session_store.create_session()
    ep = EndpointModel(
        path="/users/{user_id}",
        method="get",
        responses={"200": {"description": "ok"}},
        effective_security=[],
    )
    prop = ProposedTest(
        endpoint=ep,
        test_type="BOLA",
        description="Spec-driven test missing fixture",
        severity="High",
        status=TestStatus.APPROVED,
    )
    session_store.add_proposal(sid, prop)

    # Config with empty path params
    cfg = ExecutionConfig(
        mode=ExecutionMode.SPEC_DRIVEN,
        target_base_url="http://127.0.0.1:8001",
        parameters=ParameterFixtures(owner_path_params={}),
    )

    findings = asyncio.run(execute_proposals(
        session_id=sid,
        proposal_ids=[prop.test_id],
        target="http://127.0.0.1:8001",
        config=cfg,
    ))

    assert len(findings) == 1
    f = findings[0]
    assert f.status == FindingStatus.NOT_EXECUTED
    assert f.execution_status == ExecutionStatus.NOT_EXECUTED
    assert "missing required path parameter" in f.notes.lower()
    f = findings[0]
    assert f.status == FindingStatus.NOT_EXECUTED
    assert f.execution_status == ExecutionStatus.NOT_EXECUTED
    assert "missing required path parameter" in f.notes.lower()
