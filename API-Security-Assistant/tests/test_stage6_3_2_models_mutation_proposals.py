"""Tests for Stage 6.3.2 - Authentication Models, Request Mutation & Proposal Generation.

Verifies:
1. Model additions: AuthTestType, AuthenticationMutation, and ExecutionConfig extensions.
2. Proposal generation:
   - Secured endpoint proposal generation for AUTH_MISSING_CREDENTIALS.
   - Public endpoint exclusion (effective_security=None).
   - Explicit operation-level security: [] exclusion.
   - Global security inheritance from OpenAPI specifications.
   - Deterministic and non-duplicate proposals.
3. Request mutation:
   - Deliberate authentication omission for AUTH_MISSING_CREDENTIALS.
   - Stripping of Bearer and Basic Authorization headers.
   - Stripping of API-key headers (case-insensitive).
   - Stripping of API-key query parameters.
   - Stripping of API-key cookies.
   - Preservation of unrelated application headers, query parameters, and cookies.
   - Localhost allowlist and path traversal safety controls preserved.
   - Backward compatibility for existing build_request and generate_proposals callers.
"""

from pathlib import Path
import pytest

from app.models import (
    AuthTestType,
    AuthenticationMutation,
    EndpointModel,
    ExecutionConfig,
    ExecutionMode,
    ParameterFixtures,
    ProposedTest,
    RequestBudget,
    TestIdentity,
    TestStatus,
)
from app.parser.openapi_parser import (
    ResolvedSecurityRequirement,
    SecuritySchemeModel,
    parse_openapi_spec,
)
from app.security.proposal_engine import (
    generate_auth_proposals,
    generate_proposals,
)
from app.security.request_builder import (
    build_request,
    build_unauthenticated_request,
    get_endpoint_auth_parameters,
)


# ---------------------------------------------------------------------------
# Test Helpers
# ---------------------------------------------------------------------------

def make_secured_endpoint(
    path: str = "/api/data",
    method: str = "get",
    security_reqs=None,
) -> EndpointModel:
    if security_reqs is None:
        security_reqs = [
            ResolvedSecurityRequirement(
                scheme_name="bearerAuth",
                scheme=SecuritySchemeModel(type="http", scheme="bearer"),
            )
        ]
    return EndpointModel.model_validate({
        "path": path,
        "method": method,
        "responses": {"200": {"description": "OK"}, "401": {"description": "Unauthorized"}},
        "effective_security": security_reqs,
    })


def make_public_endpoint(path: str = "/api/public", method: str = "get") -> EndpointModel:
    return EndpointModel.model_validate({
        "path": path,
        "method": method,
        "responses": {"200": {"description": "OK"}},
        "effective_security": None,
    })


def make_unsecured_override_endpoint(path: str = "/api/override", method: str = "get") -> EndpointModel:
    return EndpointModel.model_validate({
        "path": path,
        "method": method,
        "responses": {"200": {"description": "OK"}},
        "security": [],
        "effective_security": [],
    })


# ---------------------------------------------------------------------------
# 1. Models & Configuration
# ---------------------------------------------------------------------------

def test_models_auth_test_type_and_mutation_enums():
    """Verify enum constants and typed representations for authentication testing."""
    assert AuthTestType.AUTH_MISSING_CREDENTIALS.value == "AUTH_MISSING_CREDENTIALS"
    assert AuthenticationMutation.NONE.value == "NONE"
    assert AuthenticationMutation.MISSING_CREDENTIALS.value == "MISSING_CREDENTIALS"


def test_models_execution_config_authenticated_identity_and_mutation():
    """Verify ExecutionConfig backward-compatibility and new authentication fields."""
    # Default initialization
    config = ExecutionConfig()
    assert config.authenticated_identity is None
    assert config.auth_mutation == AuthenticationMutation.NONE

    # Configured with authenticated_identity and mutation
    ident = TestIdentity(identity_id="tester", token="secret_token_123")
    config_custom = ExecutionConfig(
        authenticated_identity=ident,
        auth_mutation=AuthenticationMutation.MISSING_CREDENTIALS,
    )
    assert config_custom.authenticated_identity.identity_id == "tester"
    assert config_custom.auth_mutation == AuthenticationMutation.MISSING_CREDENTIALS

    # Existing validators remain active
    with pytest.raises(ValueError, match="not authorized"):
        ExecutionConfig(target_base_url="http://malicious.external.com")


# ---------------------------------------------------------------------------
# 2. Proposal Generation
# ---------------------------------------------------------------------------

def test_proposals_secured_endpoint_generates_auth_missing_credentials():
    """Endpoints declaring effective security must generate AUTH_MISSING_CREDENTIALS."""
    ep = make_secured_endpoint(path="/secure/resource", method="GET")
    proposals = generate_auth_proposals([ep])

    assert len(proposals) == 1
    prop = proposals[0]
    assert isinstance(prop, ProposedTest)
    assert prop.test_type == AuthTestType.AUTH_MISSING_CREDENTIALS.value
    assert prop.endpoint.path == "/secure/resource"
    assert prop.status == TestStatus.PROPOSED
    assert "strictly rejected" in prop.description


def test_proposals_public_endpoint_excluded():
    """Public endpoints with effective_security=None must NOT generate AUTH_MISSING_CREDENTIALS."""
    ep = make_public_endpoint()
    proposals = generate_auth_proposals([ep])
    assert proposals == []


def test_proposals_explicit_security_empty_list_excluded():
    """Endpoints explicitly defining security: [] must NOT generate AUTH_MISSING_CREDENTIALS."""
    ep = make_unsecured_override_endpoint()
    proposals = generate_auth_proposals([ep])
    assert proposals == []


def test_proposals_global_security_inheritance():
    """Endpoints inheriting global security in OpenAPI spec must generate proposals."""
    yaml_content = """
openapi: 3.0.0
info:
  title: Test API
  version: "1.0"
components:
  securitySchemes:
    ApiKeyAuth:
      type: apiKey
      name: X-API-KEY
      in: header
security:
  - ApiKeyAuth: []
paths:
  /inherited-secure:
    get:
      summary: Inherits global auth
      responses:
        "200":
          description: OK
  /explicit-public:
    get:
      summary: Overrides with no auth
      security: []
      responses:
        "200":
          description: OK
"""
    import tempfile
    with tempfile.NamedTemporaryFile(suffix=".yaml", mode="w", delete=False, encoding="utf-8") as f:
        f.write(yaml_content)
        temp_path = f.name

    try:
        parsed_spec = parse_openapi_spec(temp_path)
        endpoints = parsed_spec.endpoints

        proposals = generate_auth_proposals(endpoints)
        assert len(proposals) == 1
        assert proposals[0].endpoint.path == "/inherited-secure"
        assert proposals[0].test_type == "AUTH_MISSING_CREDENTIALS"
    finally:
        Path(temp_path).unlink(missing_ok=True)


def test_proposals_no_duplicate_auth_proposals():
    """Duplicate endpoints in inventory must not create duplicate AUTH proposals."""
    ep = make_secured_endpoint(path="/secure/resource", method="GET")
    proposals = generate_auth_proposals([ep, ep])
    assert len(proposals) == 1


def test_generate_proposals_backward_compatibility():
    """generate_proposals with default include_auth_tests=False must preserve legacy proposals."""
    ep = make_secured_endpoint(path="/users/{id}", method="GET")
    # Default: does not include AUTH_MISSING_CREDENTIALS to protect existing legacy counts
    legacy_props = generate_proposals([ep])
    assert all(p.test_type != "AUTH_MISSING_CREDENTIALS" for p in legacy_props)
    assert any(p.test_type == "BOLA" for p in legacy_props)

    # Explicit opt-in: includes AUTH_MISSING_CREDENTIALS
    all_props = generate_proposals([ep], include_auth_tests=True)
    types = {p.test_type for p in all_props}
    assert "BOLA" in types
    assert "AUTH_MISSING_CREDENTIALS" in types


# ---------------------------------------------------------------------------
# 3. Request Mutation: Deliberate Authentication Omission
# ---------------------------------------------------------------------------

def test_request_builder_mutation_bearer_removal():
    """Bearer Authorization header must be stripped under MISSING_CREDENTIALS mutation."""
    ep = make_secured_endpoint()
    identity = TestIdentity(identity_id="tester", token="test_bearer_token")
    config = ExecutionConfig(
        parameters=ParameterFixtures(
            headers={"Accept": "application/json", "X-Client-ID": "web-app"}
        )
    )

    # 1. Normal request has Bearer header
    normal_req = build_request(ep, config, identity=identity, auth_mutation=AuthenticationMutation.NONE)
    assert normal_req.headers.get("Authorization") == "Bearer test_bearer_token"
    assert normal_req.headers.get("Accept") == "application/json"

    # 2. Mutated unauthenticated request strips Bearer header, preserves app headers
    unauth_req = build_unauthenticated_request(ep, config)
    assert "Authorization" not in unauth_req.headers
    assert "authorization" not in unauth_req.headers
    assert unauth_req.headers.get("Accept") == "application/json"
    assert unauth_req.headers.get("X-Client-ID") == "web-app"


def test_request_builder_mutation_basic_removal():
    """Basic Authorization header must be stripped under MISSING_CREDENTIALS mutation."""
    sec_req = ResolvedSecurityRequirement(
        scheme_name="basicAuth",
        scheme=SecuritySchemeModel(type="http", scheme="basic"),
    )
    ep = make_secured_endpoint(security_reqs=[sec_req])
    identity = TestIdentity(identity_id="tester", username="admin", password="password123")
    config = ExecutionConfig()

    # Normal request
    normal_req = build_request(ep, config, identity=identity)
    assert "Basic " in normal_req.headers.get("Authorization", "")

    # Mutated request
    unauth_req = build_request(ep, config, identity=identity, auth_mutation=AuthenticationMutation.MISSING_CREDENTIALS)
    assert "Authorization" not in unauth_req.headers
    assert "authorization" not in unauth_req.headers


def test_request_builder_mutation_apikey_header_removal():
    """API-key header must be stripped case-insensitively under MISSING_CREDENTIALS mutation."""
    sec_req = ResolvedSecurityRequirement(
        scheme_name="apiKeyHeader",
        scheme=SecuritySchemeModel(type="apiKey", name="X-API-KEY", in_location="header"),
    )
    ep = make_secured_endpoint(security_reqs=[sec_req])
    identity = TestIdentity(identity_id="tester", api_key="secret_api_key_val")
    config = ExecutionConfig(
        parameters=ParameterFixtures(headers={"x-api-key": "should_be_stripped", "Accept": "application/json"})
    )

    unauth_req = build_unauthenticated_request(ep, config)
    assert "X-API-KEY" not in unauth_req.headers
    assert "x-api-key" not in unauth_req.headers
    assert unauth_req.headers.get("Accept") == "application/json"


def test_request_builder_mutation_apikey_query_removal():
    """API-key query parameter must be stripped under MISSING_CREDENTIALS mutation."""
    sec_req = ResolvedSecurityRequirement(
        scheme_name="apiKeyQuery",
        scheme=SecuritySchemeModel(type="apiKey", name="api_token", in_location="query"),
    )
    ep = make_secured_endpoint(security_reqs=[sec_req])
    identity = TestIdentity(identity_id="tester", api_key="secret_token_val")
    config = ExecutionConfig(
        parameters=ParameterFixtures(query_params={"api_token": "should_be_stripped", "format": "json", "limit": 20})
    )

    # Normal request contains query param
    normal_req = build_request(ep, config, identity=identity)
    assert normal_req.params.get("api_token") == "secret_token_val"
    assert normal_req.params.get("format") == "json"

    # Mutated request strips api_token, preserves format and limit
    unauth_req = build_unauthenticated_request(ep, config)
    assert "api_token" not in unauth_req.params
    assert unauth_req.params.get("format") == "json"
    assert unauth_req.params.get("limit") == 20


def test_request_builder_mutation_apikey_cookie_removal():
    """API-key cookie must be stripped under MISSING_CREDENTIALS mutation."""
    sec_req = ResolvedSecurityRequirement(
        scheme_name="cookieAuth",
        scheme=SecuritySchemeModel(type="apiKey", name="auth_session", in_location="cookie"),
    )
    ep = make_secured_endpoint(security_reqs=[sec_req])
    identity = TestIdentity(identity_id="tester", api_key="sess_secret_val", cookies={"theme": "dark"})
    config = ExecutionConfig()

    normal_req = build_request(ep, config, identity=identity)
    assert normal_req.cookies.get("auth_session") == "sess_secret_val"

    unauth_req = build_unauthenticated_request(ep, config)
    assert "auth_session" not in unauth_req.cookies


def test_request_builder_mutation_unrelated_material_preserved():
    """All unrelated headers, params, and cookies must be preserved during mutation."""
    sec_req = ResolvedSecurityRequirement(
        scheme_name="bearerAuth",
        scheme=SecuritySchemeModel(type="http", scheme="bearer"),
    )
    ep = make_secured_endpoint(security_reqs=[sec_req])
    config = ExecutionConfig(
        parameters=ParameterFixtures(
            headers={"X-App-Env": "test", "Accept": "*/*"},
            query_params={"page": 1, "sort": "asc"},
        )
    )

    unauth_req = build_unauthenticated_request(ep, config)
    assert "Authorization" not in unauth_req.headers
    assert unauth_req.headers.get("X-App-Env") == "test"
    assert unauth_req.headers.get("Accept") == "*/*"
    assert unauth_req.params.get("page") == 1
    assert unauth_req.params.get("sort") == "asc"


def test_request_builder_safety_localhost_and_traversal_enforced():
    """build_unauthenticated_request must enforce localhost allowlist and traversal checks."""
    ep = make_secured_endpoint(path="/users/{user_id}")
    config = ExecutionConfig()

    # Traversal in path param fixture rejected
    with pytest.raises(ValueError, match="illegal traversal"):
        build_unauthenticated_request(ep, config, path_param_override={"user_id": "../../etc/passwd"})

