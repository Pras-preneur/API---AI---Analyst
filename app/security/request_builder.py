"""Dynamic request construction and authentication layer for specification-driven execution.

Constructs secure, validated HTTP requests based on OpenAPI endpoint definitions,
parameter fixtures, and test identities. Enforces safety policies:
- Strict target allowlist validation (local mock targets only)
- Path parameter substitution and traversal prevention
- Explicit authentication resolution (HTTP Bearer, HTTP Basic, API key, unauthenticated)
- Configuration error reporting without silent fallback
- Strict redirect prevention (follow_redirects=False)
- Credential sanitization for evidence and logs
"""

import base64
import re
import urllib.parse
from typing import Any, Dict, List, Optional, Set, Tuple

from pydantic import BaseModel, ConfigDict, Field

from ..config import ALLOWED_TARGETS, DEFAULT_REQUEST_TIMEOUT
from ..models import (
    AuthenticationMutation,
    EndpointModel,
    ExecutionConfig,
    ExecutionMode,
    ParameterFixtures,
    RequestBudget,
    TestIdentity,
)
from ..parser.openapi_parser import ResolvedSecurityRequirement
from .sanitization import sanitize_url


class PreparedRequest(BaseModel):
    """An immutable, validated representation of an HTTP request to be executed."""
    model_config = ConfigDict(populate_by_name=True)

    method: str
    url: str
    headers: Dict[str, str] = Field(default_factory=dict)
    params: Dict[str, Any] = Field(default_factory=dict)
    cookies: Dict[str, str] = Field(default_factory=dict)
    timeout_seconds: float = Field(default=DEFAULT_REQUEST_TIMEOUT)
    follow_redirects: bool = Field(default=False)

    def get_sanitized_headers(self) -> Dict[str, str]:
        """Return headers with credentials and sensitive authorization tokens redacted."""
        safe = {}
        for k, v in self.headers.items():
            k_lower = k.lower()
            if k_lower in {"authorization", "proxy-authorization"}:
                continue
            elif any(s in k_lower for s in ["auth", "token", "key", "secret", "cookie", "session"]):
                safe[k] = "[REDACTED]"
            else:
                safe[k] = v
        return safe

    def get_sanitized_params(self) -> Dict[str, Any]:
        """Return query params with sensitive tokens redacted."""
        safe = {}
        for k, v in self.params.items():
            k_lower = k.lower()
            if any(s in k_lower for s in ["auth", "token", "key", "secret", "password"]):
                safe[k] = "[REDACTED]"
            else:
                safe[k] = v
        return safe

    def to_evidence_dict(self) -> Dict[str, Any]:
        """Return sanitized request metadata safe for inclusion in Evidence models."""
        return {
            "method": self.method,
            "url": sanitize_url(self.url),
            "headers": self.get_sanitized_headers(),
            "params": self.get_sanitized_params(),
        }


def build_target_url(
    base_url: str,
    path_template: str,
    path_params: Dict[str, Any],
) -> str:
    """Construct and validate target URL from base URL and path template with parameter substitution.

    Raises:
        PermissionError: If target base URL is not in ALLOWED_TARGETS.
        ValueError: If required path parameters are missing, or contain traversal/injection sequences.
    """
    normalized_base = base_url.rstrip("/")
    if normalized_base not in ALLOWED_TARGETS:
        raise PermissionError(
            f"Unauthorized target URL: '{base_url}'. Only authorized local mock targets are allowed: {sorted(list(ALLOWED_TARGETS))}"
        )

    # Find all path parameters in the template: {param_name}
    template_params = re.findall(r"\{([^}]+)\}", path_template)
    resolved_path = path_template

    # Traversal and illegal patterns
    traversal_patterns = ["..", "/", "\\", "\x00", "%2e", "%2f", "%5c", "%00"]

    for param_name in template_params:
        if param_name not in path_params:
            raise ValueError(
                f"Missing required path parameter fixture '{param_name}' for endpoint '{path_template}'"
            )
        val = path_params[param_name]
        if val is None or val == "":
            raise ValueError(
                f"Path parameter fixture '{param_name}' cannot be empty or null for endpoint '{path_template}'"
            )
        val_str = str(val).strip()
        val_str_lower = val_str.lower()
        for pattern in traversal_patterns:
            if pattern in val_str_lower:
                raise ValueError(
                    f"Path parameter '{param_name}' contains illegal traversal sequence or separator: '{pattern}'"
                )

        # Safely quote parameter value (URL encoding non-alphanumeric if any, safe empty)
        encoded_val = urllib.parse.quote(val_str, safe="")
        resolved_path = resolved_path.replace(f"{{{param_name}}}", encoded_val)

    # Ensure resolved_path starts with '/'
    if not resolved_path.startswith("/"):
        resolved_path = "/" + resolved_path

    full_url = f"{normalized_base}{resolved_path}"

    # Final safety check: ensure the URL starts with the normalized base and contains no path traversal
    parsed = urllib.parse.urlparse(full_url)
    target_origin = f"{parsed.scheme}://{parsed.netloc}"
    if target_origin not in ALLOWED_TARGETS:
        raise PermissionError(f"Constructed URL origin '{target_origin}' is not authorized.")
    if "/../" in parsed.path or parsed.path.endswith("/.."):
        raise ValueError("Constructed path contains traversal sequence /../")

    return full_url


def resolve_authentication(
    endpoint: EndpointModel,
    identity: Optional[TestIdentity],
) -> Tuple[Dict[str, str], Dict[str, Any], Dict[str, str]]:
    """Resolve authentication headers, query parameters, and cookies according to OpenAPI security requirements.

    Returns:
        (headers, query_params, cookies)

    Raises:
        ValueError: If security requirement cannot be satisfied by the provided identity.
    """
    headers: Dict[str, str] = {}
    params: Dict[str, Any] = {}
    cookies: Dict[str, str] = {}

    # Check effective_security first, fallback to security
    effective_reqs: Optional[List[ResolvedSecurityRequirement]] = endpoint.effective_security

    # If effective_security is None and raw security is present:
    if effective_reqs is None and endpoint.security is not None:
        if len(endpoint.security) == 0:
            return headers, params, cookies

    # If explicitly unauthenticated (empty list):
    if effective_reqs is not None and len(effective_reqs) == 0:
        return headers, params, cookies

    # If no security defined (None):
    if effective_reqs is None and (endpoint.security is None or len(endpoint.security) == 0):
        return headers, params, cookies

    # Here, security requirements are defined. Identity is required.
    if identity is None:
        req_names = [r.scheme_name for r in effective_reqs] if effective_reqs else ["defined"]
        raise ValueError(
            f"Endpoint '{endpoint.path}' requires authentication ({req_names}), but no test identity was provided."
        )

    # Attempt to satisfy at least one security requirement alternative (logical OR in OpenAPI)
    errors: List[str] = []
    satisfied = False

    if effective_reqs:
        for req in effective_reqs:
            req_headers: Dict[str, str] = {}
            req_params: Dict[str, Any] = {}
            req_cookies: Dict[str, str] = {}

            schemes_to_process = list(req.schemes.items()) if req.schemes else ([(req.scheme_name, req.scheme)] if req.scheme else [])
            req_satisfied = True
            for s_name, scheme in schemes_to_process:
                scheme_type = ((scheme.type if scheme else None) or req.type or "").lower()
                http_scheme = ((scheme.scheme if scheme else None) or req.http_scheme or "").lower()
                in_loc = ((scheme.in_location if scheme else None) or req.in_location or "").lower()
                param_name = (scheme.name if scheme else None) or req.parameter_name or s_name

                if scheme_type == "http" and http_scheme == "bearer":
                    token = identity.token or identity.api_key
                    if not token:
                        errors.append(f"Scheme '{s_name}' (HTTP Bearer) requires token or api_key")
                        req_satisfied = False
                        break
                    req_headers["Authorization"] = f"Bearer {token}"
                elif scheme_type == "http" and http_scheme == "basic":
                    if not identity.username or not identity.password:
                        errors.append(f"Scheme '{s_name}' (HTTP Basic) requires username and password")
                        req_satisfied = False
                        break
                    creds = f"{identity.username}:{identity.password}"
                    encoded = base64.b64encode(creds.encode("utf-8")).decode("ascii")
                    req_headers["Authorization"] = f"Basic {encoded}"
                elif scheme_type in {"apikey", "api_key"}:
                    key_val = identity.api_key or identity.token
                    if not key_val:
                        errors.append(f"Scheme '{s_name}' (API Key) requires api_key or token")
                        req_satisfied = False
                        break
                    name = param_name or s_name or "api_key"
                    if in_loc == "header":
                        req_headers[name] = key_val
                    elif in_loc == "query":
                        req_params[name] = key_val
                    elif in_loc == "cookie":
                        req_cookies[name] = key_val
                    else:
                        errors.append(f"Scheme '{s_name}' has unsupported apiKey location '{in_loc}'")
                        req_satisfied = False
                        break
                else:
                    errors.append(f"Scheme '{s_name}' has unsupported type '{scheme_type}'")
                    req_satisfied = False
                    break

            if req_satisfied and schemes_to_process:
                headers.update(req_headers)
                params.update(req_params)
                cookies.update(req_cookies)
                satisfied = True
                break

    elif endpoint.security:
        # Fallback for manual EndpointModel with raw security dicts e.g. [{"BearerAuth": []}]
        for req_dict in endpoint.security:
            req_headers = {}
            for s_name in req_dict:
                s_lower = s_name.lower()
                if "bearer" in s_lower:
                    token = identity.token or identity.api_key
                    if token:
                        req_headers["Authorization"] = f"Bearer {token}"
                        satisfied = True
                elif "basic" in s_lower:
                    if identity.username and identity.password:
                        creds = f"{identity.username}:{identity.password}"
                        encoded = base64.b64encode(creds.encode("utf-8")).decode("ascii")
                        req_headers["Authorization"] = f"Basic {encoded}"
                        satisfied = True
                elif "api" in s_lower or "key" in s_lower:
                    key_val = identity.api_key or identity.token
                    if key_val:
                        req_headers["X-API-KEY"] = key_val
                        satisfied = True
            if satisfied:
                headers.update(req_headers)
                break

    if not satisfied:
        detail = "; ".join(errors) if errors else "Missing valid credentials matching security requirements"
        raise ValueError(
            f"Authentication failed for identity '{identity.identity_id}' on '{endpoint.path}': {detail}"
        )

    # Attach any explicit custom identity headers and cookies
    if identity.headers:
        headers.update(identity.headers)
    if identity.cookies:
        cookies.update(identity.cookies)

    return headers, params, cookies


def get_endpoint_auth_parameters(endpoint: EndpointModel) -> Tuple[Set[str], Set[str], Set[str]]:
    """Extract header names, query parameter names, and cookie names associated with endpoint security schemes.

    Returns:
        (auth_header_names_lower, auth_query_param_names, auth_cookie_names)
    """
    auth_headers: Set[str] = set()
    auth_query: Set[str] = set()
    auth_cookies: Set[str] = set()

    effective_reqs = endpoint.effective_security
    if effective_reqs:
        for req in effective_reqs:
            schemes_to_inspect = list(req.schemes.items()) if req.schemes else ([(req.scheme_name, req.scheme)] if req.scheme else [])
            for s_name, scheme in schemes_to_inspect:
                scheme_type = ((scheme.type if scheme else None) or req.type or "").lower()
                in_loc = ((scheme.in_location if scheme else None) or req.in_location or "").lower()
                param_name = (scheme.name if scheme else None) or req.parameter_name or s_name

                if scheme_type == "http":
                    auth_headers.add("authorization")
                elif scheme_type in {"apikey", "api_key"} and param_name:
                    if in_loc == "header":
                        auth_headers.add(param_name.lower())
                    elif in_loc == "query":
                        auth_query.add(param_name)
                    elif in_loc == "cookie":
                        auth_cookies.add(param_name)

    elif endpoint.security:
        for req_dict in endpoint.security:
            for s_name in req_dict:
                s_lower = s_name.lower()
                if "bearer" in s_lower or "basic" in s_lower:
                    auth_headers.add("authorization")
                elif "api" in s_lower or "key" in s_lower:
                    auth_headers.add("x-api-key")
                    auth_headers.add("authorization")

    # In HTTP specifications, Authorization is the canonical HTTP auth header
    if auth_headers:
        auth_headers.add("authorization")

    return auth_headers, auth_query, auth_cookies


def build_request(
    endpoint: EndpointModel,
    config: ExecutionConfig,
    identity: Optional[TestIdentity] = None,
    path_param_override: Optional[Dict[str, Any]] = None,
    auth_mutation: Optional[AuthenticationMutation] = None,
) -> PreparedRequest:
    """Build a fully validated PreparedRequest for an endpoint and execution configuration.

    Args:
        endpoint: Target OpenAPI endpoint definition.
        config: Execution configuration containing target base URL, parameter fixtures, limits.
        identity: Identity to authenticate as (defaults to config.authenticated_identity or config.owner_identity).
        path_param_override: Optional path parameters overriding default owner_path_params.
        auth_mutation: Optional explicit mutation mode (defaults to config.auth_mutation or NONE).

    Returns:
        PreparedRequest ready for execution.

    Raises:
        PermissionError: If target URL is not in authorized localhost allowlist.
        ValueError: If path parameters are missing, invalid, or traversal is detected.
        ValueError: If required authentication cannot be satisfied.
    """
    # 1. Target URL validation & construction
    base_url = config.target_base_url
    if path_param_override is not None:
        path_params = path_param_override
    else:
        path_params = config.parameters.owner_path_params

    full_url = build_target_url(base_url, endpoint.path, path_params)

    # 2. Method resolution
    method = endpoint.method.upper()

    # Determine effective mutation mode
    mutation = auth_mutation if auth_mutation is not None else getattr(config, "auth_mutation", AuthenticationMutation.NONE)

    # 3. Authentication resolution
    if mutation == AuthenticationMutation.MISSING_CREDENTIALS:
        # Deliberate unauthenticated probe: do not resolve or inject authenticating credentials
        auth_headers, auth_params, auth_cookies = {}, {}, {}
    else:
        chosen_identity = identity if identity is not None else (config.authenticated_identity or config.owner_identity)
        auth_headers, auth_params, auth_cookies = resolve_authentication(endpoint, chosen_identity)

    # 4. Merge query parameters and headers from config.parameters
    final_headers: Dict[str, str] = {}
    if config.parameters.headers:
        final_headers.update(config.parameters.headers)
    final_headers.update(auth_headers)

    final_params: Dict[str, Any] = {}
    if config.parameters.query_params:
        final_params.update(config.parameters.query_params)
    final_params.update(auth_params)

    final_cookies: Dict[str, str] = {}
    final_cookies.update(auth_cookies)

    # 4b. Enforce deliberate credential omission for MISSING_CREDENTIALS mutation
    if mutation == AuthenticationMutation.MISSING_CREDENTIALS:
        sec_headers, sec_params, sec_cookies = get_endpoint_auth_parameters(endpoint)
        sec_params_lower = {p.lower() for p in sec_params}
        sec_cookies_lower = {c.lower() for c in sec_cookies}

        # Strip Authorization header and any scheme-defined apiKey headers
        final_headers = {
            k: v for k, v in final_headers.items()
            if k.lower() not in sec_headers and k.lower() != "authorization"
        }

        # Strip any scheme-defined apiKey query parameters (case-insensitive)
        final_params = {
            k: v for k, v in final_params.items()
            if k.lower() not in sec_params_lower
        }

        # Strip any scheme-defined apiKey cookies (case-insensitive)
        final_cookies = {
            k: v for k, v in final_cookies.items()
            if k.lower() not in sec_cookies_lower
        }

    # 5. Build prepared request with strict safety guarantees
    return PreparedRequest(
        method=method,
        url=full_url,
        headers=final_headers,
        params=final_params,
        cookies=final_cookies,
        timeout_seconds=config.timeout_seconds,
        follow_redirects=False,
    )


def build_unauthenticated_request(
    endpoint: EndpointModel,
    config: ExecutionConfig,
    path_param_override: Optional[Dict[str, Any]] = None,
) -> PreparedRequest:
    """Build a deliberate unauthenticated request with all authentication material stripped.

    Removes Authorization headers, API-key headers, API-key query parameters, and API-key
    cookies associated with the endpoint's security schemes, while strictly preserving
    all non-authentication application parameters, headers, and cookies.
    """
    return build_request(
        endpoint=endpoint,
        config=config,
        identity=None,
        path_param_override=path_param_override,
        auth_mutation=AuthenticationMutation.MISSING_CREDENTIALS,
    )
