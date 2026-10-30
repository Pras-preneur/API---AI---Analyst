import json
import os
from pathlib import Path
import pytest

from app.parser.openapi_parser import (
    parse_openapi,
    parse_openapi_spec,
    EndpointModel,
    ParameterModel,
    SecuritySchemeModel,
    ResolvedSecurityRequirement,
    ParsedOpenAPISpec,
)

# Helper to get the sample spec path
SAMPLE_SPEC = Path(__file__).parents[1] / "sample_specs" / "demo_api.yaml"

def test_parse_yaml_success():
    endpoints = parse_openapi(str(SAMPLE_SPEC))
    paths_methods = {(e.path, e.method) for e in endpoints}
    expected = {
        ("/users", "get"),
        ("/users", "post"),
        ("/users/{user_id}", "get"),
        ("/users/{user_id}", "delete"),
        ("/profile", "patch"),
    }
    assert paths_methods == expected
    get_users = next(e for e in endpoints if e.path == "/users" and e.method == "get")
    assert get_users.operation_id == "listUsers"
    assert any(p.name == "limit" and p.location == "query" for p in get_users.parameters)
    # Security inheritance (global bearer)
    assert get_users.security == [{"BearerAuth": []}]

def test_parse_json_success(tmp_path):
    # Convert the YAML sample to JSON
    with open(SAMPLE_SPEC, "r", encoding="utf-8") as f:
        yaml_content = f.read()
    import yaml
    data = yaml.safe_load(yaml_content)
    json_file = tmp_path / "demo_api.json"
    json_file.write_text(json.dumps(data), encoding="utf-8")
    endpoints = parse_openapi(str(json_file))
    assert any(e.path == "/profile" and e.method == "patch" for e in endpoints)

def test_missing_file():
    with pytest.raises(FileNotFoundError):
        parse_openapi("nonexistent.yaml")

def test_unsupported_extension(tmp_path):
    txt_file = tmp_path / "spec.txt"
    txt_file.write_text("just text", encoding="utf-8")
    with pytest.raises(ValueError, match="Unsupported file type"):
        parse_openapi(str(txt_file))

def test_malformed_yaml(tmp_path):
    bad_yaml = tmp_path / "bad.yaml"
    bad_yaml.write_text("key: [unclosed", encoding="utf-8")
    with pytest.raises(Exception):
        parse_openapi(str(bad_yaml))

def test_malformed_json(tmp_path):
    bad_json = tmp_path / "bad.json"
    bad_json.write_text("{invalid json}", encoding="utf-8")
    with pytest.raises(Exception):
        parse_openapi(str(bad_json))

def test_unsupported_openapi_version(tmp_path):
    spec = {"openapi": "2.0", "paths": {}}
    file = tmp_path / "spec.yaml"
    import yaml
    file.write_text(yaml.safe_dump(spec), encoding="utf-8")
    with pytest.raises(ValueError, match="Only OpenAPI 3.x specifications are supported"):
        parse_openapi(str(file))

def test_unresolved_local_ref(tmp_path):
    spec = {
        "openapi": "3.0.0",
        "paths": {
            "/test": {
                "get": {
                    "parameters": [{"$ref": "#/components/parameters/MissingParam"}],
                    "responses": {"200": {"description": "ok"}}
                }
            }
        },
        "components": {"parameters": {"SomeOther": {"name": "x", "in": "query", "schema": {"type": "string"}}}}
    }
    file = tmp_path / "spec.yaml"
    import yaml
    file.write_text(yaml.safe_dump(spec), encoding="utf-8")
    with pytest.raises(ValueError, match="Unresolved local reference"):
        parse_openapi(str(file))

def test_file_size_limit(tmp_path, monkeypatch):
    large_file = tmp_path / "large.yaml"
    large_content = "openapi: 3.0.0\npaths: {}\n" + "#" * (5 * 1024 * 1024)
    large_file.write_text(large_content, encoding="utf-8")
    with pytest.raises(ValueError, match="Specification file exceeds maximum allowed size"):
        parse_openapi(str(large_file))

def test_security_override_and_empty(tmp_path):
    spec = {
        "openapi": "3.0.0",
        "components": {"securitySchemes": {"ApiKey": {"type": "apiKey", "in": "header", "name": "X-API"}}},
        "security": [{"ApiKey": []}],
        "paths": {
            "/secure": {
                "get": {
                    "responses": {"200": {"description": "ok"}}
                },
                "post": {
                    "security": [],
                    "responses": {"200": {"description": "ok"}}
                }
            }
        }
    }
    file = tmp_path / "spec.yaml"
    import yaml
    file.write_text(yaml.safe_dump(spec), encoding="utf-8")
    endpoints = parse_openapi(str(file))
    get_ep = next(e for e in endpoints if e.method == "get")
    post_ep = next(e for e in endpoints if e.method == "post")
    assert get_ep.security == [{"ApiKey": []}]
    assert post_ep.security == []


def test_parameter_path_level_override(tmp_path):
    spec = {
        "openapi": "3.0.0",
        "paths": {
            "/users/{id}": {
                "parameters": [
                    {"name": "id", "in": "path", "required": True, "description": "path-level"}
                ],
                "get": {
                    "parameters": [
                        {"name": "id", "in": "path", "required": True, "description": "op-level"}
                    ],
                    "responses": {"200": {"description": "ok"}}
                }
            }
        }
    }
    file = tmp_path / "override.yaml"
    import yaml
    file.write_text(yaml.safe_dump(spec), encoding="utf-8")
    endpoints = parse_openapi(str(file))
    assert len(endpoints) == 1
    params = endpoints[0].parameters
    assert len(params) == 1
    assert params[0].description == "op-level"


def test_component_response_and_request_body_ref(tmp_path):
    spec = {
        "openapi": "3.0.0",
        "components": {
            "requestBodies": {
                "UserBody": {
                    "required": True,
                    "content": {
                        "application/json": {
                            "schema": {"type": "object", "properties": {"name": {"type": "string"}}}
                        }
                    }
                }
            },
            "responses": {
                "UserResponse": {
                    "description": "User created successfully"
                }
            }
        },
        "paths": {
            "/users": {
                "post": {
                    "requestBody": {"$ref": "#/components/requestBodies/UserBody"},
                    "responses": {
                        "201": {"$ref": "#/components/responses/UserResponse"}
                    }
                }
            }
        }
    }
    file = tmp_path / "components_ref.yaml"
    import yaml
    file.write_text(yaml.safe_dump(spec), encoding="utf-8")
    endpoints = parse_openapi(str(file))
    assert len(endpoints) == 1
    ep = endpoints[0]
    assert ep.request_body is not None
    assert "application/json" in ep.request_body.content
    assert "201" in ep.responses
    assert ep.responses["201"].description == "User created successfully"


def test_parse_security_schemes_all_types(tmp_path):
    spec = {
        "openapi": "3.0.0",
        "components": {
            "securitySchemes": {
                "BearerJwt": {
                    "type": "http",
                    "scheme": "bearer",
                    "bearerFormat": "JWT",
                    "description": "JWT Bearer token",
                },
                "BasicAuth": {
                    "type": "http",
                    "scheme": "basic",
                },
                "ApiKeyHeader": {
                    "type": "apiKey",
                    "in": "header",
                    "name": "X-API-KEY",
                },
                "ApiKeyQuery": {
                    "type": "apiKey",
                    "in": "query",
                    "name": "api_key",
                },
                "ApiKeyCookie": {
                    "type": "apiKey",
                    "in": "cookie",
                    "name": "session_id",
                },
            }
        },
        "paths": {
            "/test": {
                "get": {
                    "responses": {"200": {"description": "ok"}}
                }
            }
        },
    }
    spec_file = tmp_path / "schemes.yaml"
    import yaml
    spec_file.write_text(yaml.safe_dump(spec), encoding="utf-8")

    parsed = parse_openapi_spec(str(spec_file))
    assert isinstance(parsed, ParsedOpenAPISpec)
    assert len(parsed.security_schemes) == 5

    bearer = parsed.security_schemes["BearerJwt"]
    assert bearer.type == "http"
    assert bearer.scheme == "bearer"
    assert bearer.bearer_format == "JWT"

    basic = parsed.security_schemes["BasicAuth"]
    assert basic.type == "http"
    assert basic.scheme == "basic"

    header_key = parsed.security_schemes["ApiKeyHeader"]
    assert header_key.type == "apikey"
    assert header_key.in_location == "header"
    assert header_key.location == "header"
    assert header_key.name == "X-API-KEY"

    query_key = parsed.security_schemes["ApiKeyQuery"]
    assert query_key.type == "apikey"
    assert query_key.in_location == "query"
    assert query_key.name == "api_key"

    cookie_key = parsed.security_schemes["ApiKeyCookie"]
    assert cookie_key.type == "apikey"
    assert cookie_key.in_location == "cookie"
    assert cookie_key.name == "session_id"


def test_effective_security_resolution_and_inheritance(tmp_path):
    spec = {
        "openapi": "3.0.0",
        "components": {
            "securitySchemes": {
                "BearerAuth": {"type": "http", "scheme": "bearer"},
                "ApiKeyAuth": {"type": "apiKey", "in": "header", "name": "X-Token"},
            }
        },
        "security": [{"BearerAuth": []}],
        "paths": {
            "/inherited": {
                "get": {"responses": {"200": {"description": "ok"}}}
            },
            "/overridden": {
                "get": {
                    "security": [{"ApiKeyAuth": []}],
                    "responses": {"200": {"description": "ok"}},
                }
            },
            "/unauthenticated": {
                "get": {
                    "security": [],
                    "responses": {"200": {"description": "ok"}},
                }
            },
        },
    }
    spec_file = tmp_path / "resolution.yaml"
    import yaml
    spec_file.write_text(yaml.safe_dump(spec), encoding="utf-8")

    endpoints = parse_openapi(str(spec_file))
    by_path = {e.path: e for e in endpoints}

    # /inherited inherits global BearerAuth
    inherited = by_path["/inherited"]
    assert inherited.security == [{"BearerAuth": []}]
    assert inherited.effective_security is not None
    assert len(inherited.effective_security) == 1
    assert inherited.effective_security == inherited.resolved_security
    res_req = inherited.effective_security[0]
    assert res_req.scheme_name == "BearerAuth"
    assert res_req.type == "http"
    assert res_req.http_scheme == "bearer"

    # /overridden overrides with ApiKeyAuth
    overridden = by_path["/overridden"]
    assert overridden.security == [{"ApiKeyAuth": []}]
    assert overridden.effective_security is not None
    assert len(overridden.effective_security) == 1
    res_req2 = overridden.effective_security[0]
    assert res_req2.scheme_name == "ApiKeyAuth"
    assert res_req2.type == "apikey"
    assert res_req2.in_location == "header"
    assert res_req2.parameter_name == "X-Token"

    # /unauthenticated explicitly declares security: []
    unauth = by_path["/unauthenticated"]
    assert unauth.security == []
    assert unauth.effective_security == []
    assert unauth.resolved_security == []

    # Check spec-level retention on endpoints
    assert inherited.global_security == [{"BearerAuth": []}]
    assert inherited.security_schemes is not None
    assert "BearerAuth" in inherited.security_schemes
    assert "ApiKeyAuth" in inherited.security_schemes


def test_unresolved_security_scheme_raises_value_error(tmp_path):
    spec = {
        "openapi": "3.0.0",
        "components": {"securitySchemes": {}},
        "security": [{"NonExistentAuth": []}],
        "paths": {
            "/test": {
                "get": {"responses": {"200": {"description": "ok"}}}
            }
        },
    }
    spec_file = tmp_path / "missing_scheme.yaml"
    import yaml
    spec_file.write_text(yaml.safe_dump(spec), encoding="utf-8")

    with pytest.raises(ValueError, match="not defined in components.securitySchemes"):
        parse_openapi(str(spec_file))


def test_operation_unresolved_security_scheme_raises_value_error(tmp_path):
    spec = {
        "openapi": "3.0.0",
        "components": {"securitySchemes": {"ValidAuth": {"type": "http", "scheme": "bearer"}}},
        "paths": {
            "/test": {
                "get": {
                    "security": [{"InvalidAuth": []}],
                    "responses": {"200": {"description": "ok"}}
                }
            }
        },
    }
    spec_file = tmp_path / "op_missing_scheme.yaml"
    import yaml
    spec_file.write_text(yaml.safe_dump(spec), encoding="utf-8")

    with pytest.raises(ValueError, match="not defined in components.securitySchemes"):
        parse_openapi(str(spec_file))


def test_spec_without_any_security(tmp_path):
    spec = {
        "openapi": "3.0.0",
        "paths": {
            "/public": {
                "get": {"responses": {"200": {"description": "ok"}}}
            }
        },
    }
    spec_file = tmp_path / "no_security.yaml"
    import yaml
    spec_file.write_text(yaml.safe_dump(spec), encoding="utf-8")

    endpoints = parse_openapi(str(spec_file))
    assert len(endpoints) == 1
    assert endpoints[0].security is None
    assert endpoints[0].effective_security is None
    assert endpoints[0].resolved_security is None
    assert endpoints[0].security_schemes == {}
    assert endpoints[0].global_security is None


def test_multiple_security_requirements_and_oauth_scopes(tmp_path):
    spec = {
        "openapi": "3.0.0",
        "components": {
            "securitySchemes": {
                "OAuth2": {
                    "type": "oauth2",
                    "description": "OAuth2 auth",
                },
                "ApiKey": {
                    "type": "apiKey",
                    "in": "header",
                    "name": "X-API-KEY",
                },
            }
        },
        "paths": {
            "/multi-options": {
                "get": {
                    "security": [
                        {"OAuth2": ["read:users", "write:users"]},
                        {"ApiKey": []},
                    ],
                    "responses": {"200": {"description": "ok"}},
                }
            },
            "/compound": {
                "post": {
                    "security": [
                        {"OAuth2": ["admin"], "ApiKey": []}
                    ],
                    "responses": {"200": {"description": "ok"}},
                }
            },
        },
    }
    spec_file = tmp_path / "oauth_multi.yaml"
    import yaml
    spec_file.write_text(yaml.safe_dump(spec), encoding="utf-8")

    endpoints = parse_openapi(str(spec_file))
    by_path = {e.path: e for e in endpoints}

    # /multi-options has 2 alternatives
    multi_ep = by_path["/multi-options"]
    assert multi_ep.effective_security is not None
    assert len(multi_ep.effective_security) == 2

    # First alternative: OAuth2 with scopes
    alt1 = multi_ep.effective_security[0]
    assert alt1.scheme_name == "OAuth2"
    assert alt1.scopes == ["read:users", "write:users"]
    assert alt1.type == "oauth2"

    # Second alternative: ApiKey with empty scopes
    alt2 = multi_ep.effective_security[1]
    assert alt2.scheme_name == "ApiKey"
    assert alt2.scopes == []
    assert alt2.in_location == "header"

    # /compound has 1 requirement with 2 combined schemes
    compound_ep = by_path["/compound"]
    assert compound_ep.effective_security is not None
    assert len(compound_ep.effective_security) == 1
    req = compound_ep.effective_security[0]
    assert "OAuth2" in req.schemes
    assert "ApiKey" in req.schemes
    assert req.scopes_by_scheme["OAuth2"] == ["admin"]
    assert req.scopes_by_scheme["ApiKey"] == []




