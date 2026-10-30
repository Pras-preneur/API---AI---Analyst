"""Isolated differential BFLA testing engine for specification-driven security assessments.

Executes a controlled two-step differential authorization assessment sequence:
1. Privileged baseline: access the privileged operation using privileged credentials.
   Must return 2xx (200, 201, 204). Non-2xx halts without sending probe.
2. Lower-privileged probe: attempt to execute the privileged operation using lower-privileged credentials.

Strict Invariants:
- Non-destructive operations only (GET only in Stage 6.2.2).
- Zero requests sent if pre-execution validation fails (approval, policy, budget, identities).
- Requires an explicit human-defined BFLAPolicyMapping.
- Requires lower-privileged identity's role to be explicitly listed as forbidden.
- Requires distinct privileged and lower-privileged identities.
- Budget preflight requires at least 2 requests before sending any.
- Every attempted request is recorded against budget even if it fails.
- Never automatically assigns AssessmentOutcome.CONFIRMED (maximum outcome is SUSPECTED).
- Complete sanitization: no credentials, tokens, or raw secrets in evidence, notes, or step logs.
"""

import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

import httpx

from ..models import (
    AssessmentOutcome,
    EndpointModel,
    Evidence,
    ExecutionConfig,
    ExecutionStatus,
    Finding,
    FindingStatus,
    ProposedTest,
    TestIdentity,
    TestStatus,
)
from .sanitization import (
    REDACTED_MARKER,
    sanitize_data,
    sanitize_error_message,
    sanitize_url,
)
from .request_builder import PreparedRequest, build_request


# ---------------------------------------------------------------------------
# Module Constants
# ---------------------------------------------------------------------------

BFLA_REMEDIATION = (
    "Enforce function-level access control on every privileged operation. "
    "Verify that the authenticated principal has the required role and permissions "
    "before executing the requested action or returning sensitive administrative data."
)

GENERIC_STATUS_KEYS: Set[str] = {
    "status",
    "msg",
    "message",
    "error",
    "code",
    "detail",
    "timestamp",
    "time",
    "success",
    "ok",
}


# ---------------------------------------------------------------------------
# Helper Functions
# ---------------------------------------------------------------------------

def _utc_now() -> str:
    """Return ISO 8601 UTC timestamp string."""
    return datetime.now(timezone.utc).isoformat()


def is_identity_verified(identity: Optional[TestIdentity]) -> bool:
    """Check whether the identity has been flagged as having verified credentials."""
    if identity is None:
        return False
    return getattr(identity, "credentials_verified", False) is True


def _sanitize_response_data(resp: httpx.Response) -> Dict[str, Any]:
    """Parse and sanitize response data safely, redacting credentials and tokens."""
    try:
        data = resp.json()
        if isinstance(data, dict):
            return sanitize_data(data)
        elif isinstance(data, list):
            return {"items": [sanitize_data(item) if isinstance(item, dict) else item for item in data]}
        else:
            return {"value": data}
    except Exception:
        text = resp.text
        if len(text) > 500:
            text = text[:500] + "... [TRUNCATED]"
        return {"raw_text": sanitize_data(text)}


def _build_step_log(
    identity_id: str,
    req: PreparedRequest,
    resp: httpx.Response,
    data: Dict[str, Any],
) -> Dict[str, Any]:
    """Build a sanitized audit step record without credentials or secrets."""
    return {
        "timestamp": _utc_now(),
        "identity": identity_id,
        "url": sanitize_url(req.url),
        "method": req.method,
        "status_code": resp.status_code,
        "body_present": bool(resp.content),
        "content_type": resp.headers.get("content-type", "unknown"),
    }


def is_generic_or_login_response(data: Any) -> bool:
    """Check if response data is empty, a generic envelope/wrapper, or a login redirect/page."""
    if data is None or data == {} or data == [] or data == "":
        return True
    if isinstance(data, str) and not data.strip():
        return True

    # Empty dictionary or dictionary with only empty values
    if isinstance(data, dict):
        if "raw_text" in data and len(data) == 1:
            raw = data["raw_text"]
            if raw is None or not str(raw).strip():
                return True
        if "items" in data and len(data) == 1 and not data["items"]:
            return True
        if "value" in data and len(data) == 1 and data["value"] in (None, ""):
            return True
        if all(v in (None, "", [], {}) for v in data.values()):
            return True

    data_str = json.dumps(data) if isinstance(data, (dict, list)) else str(data)
    data_str_lower = data_str.lower()

    # HTML page or login form detection
    if any(token in data_str_lower for token in ["<!doctype html", "<html", "<form", "action=\"/login\"", "action='/login'"]):
        return True
    if "login" in data_str_lower and ("password" in data_str_lower or "sign in" in data_str_lower or "authenticate" in data_str_lower):
        return True

    # Generic wrapper or envelope with no real payload
    if isinstance(data, dict):
        keys = set(data.keys())
        if keys.issubset(GENERIC_STATUS_KEYS):
            for val in data.values():
                if isinstance(val, (dict, list)) and val:
                    return False
            return True

    return False


def normalize_role(role: Any) -> Optional[str]:
    """Safely trim and lowercase a role string, returning None if empty."""
    if role is None:
        return None
    val = str(role).strip().lower()
    return val if val else None


def normalize_roles(roles: Any) -> Set[str]:
    """Return a de-duplicated set of normalized, non-empty role strings."""
    if roles is None:
        return set()
    if isinstance(roles, str):
        roles = [roles]
    normalized: Set[str] = set()
    for r in roles:
        norm = normalize_role(r)
        if norm:
            normalized.add(norm)
    return normalized


def extract_substantive_overlap(baseline_data: Any, probe_data: Any) -> Tuple[bool, List[str]]:
    """Determine whether probe response contains substantive protected data from baseline response."""
    if is_generic_or_login_response(baseline_data) or is_generic_or_login_response(probe_data):
        return False, []

    ignored_keys = GENERIC_STATUS_KEYS | {
        "timestamp", "time", "date", "created_at", "updated_at",
        "request_id", "trace_id", "correlation_id", "nonce",
        "role", "status", "active", "tier", "country",
        "version", "api_version", "format", "kind", "type",
        "schema", "method", "env", "environment",
    }

    matching_fields: List[str] = []

    # Case 1: Both are dictionaries
    if isinstance(baseline_data, dict) and isinstance(probe_data, dict):
        for key in baseline_data:
            if key in ignored_keys:
                continue
            if key in probe_data:
                b_val = baseline_data[key]
                p_val = probe_data[key]

                # Distinguish boolean from integer
                if isinstance(b_val, bool) != isinstance(p_val, bool):
                    continue

                # Guard against REDACTED marker collisions:
                # Two different secrets sanitize to "[REDACTED]", which must NEVER count as substantive overlap.
                if b_val == REDACTED_MARKER or p_val == REDACTED_MARKER or "[REDACTED]" in str(b_val):
                    continue

                if b_val == p_val and b_val not in (None, "", [], {}):
                    matching_fields.append(f"{key}={b_val!r}")
                elif isinstance(b_val, dict) and isinstance(p_val, dict):
                    sub_match, sub_fields = extract_substantive_overlap(b_val, p_val)
                    if sub_match:
                        matching_fields.extend([f"{key}.{sf}" for sf in sub_fields])
                elif isinstance(b_val, list) and isinstance(p_val, list) and b_val and p_val:
                    b_elem_set = [
                        elem for elem in b_val
                        if not is_generic_or_login_response(elem)
                        and elem != REDACTED_MARKER
                        and elem != "[REDACTED]"
                    ]
                    p_elem_set = [
                        elem for elem in p_val
                        if not is_generic_or_login_response(elem)
                        and elem != REDACTED_MARKER
                        and elem != "[REDACTED]"
                    ]
                    common_elems = [e for e in p_elem_set if e in b_elem_set]
                    if common_elems:
                        matching_fields.append(f"{key}[{len(common_elems)} items match]")

        return len(matching_fields) > 0, matching_fields

    # Case 2: Both are lists
    if isinstance(baseline_data, list) and isinstance(probe_data, list):
        if not baseline_data or not probe_data:
            return False, []
        common = [
            item for item in probe_data
            if item in baseline_data
            and not is_generic_or_login_response(item)
            and item != REDACTED_MARKER
            and item != "[REDACTED]"
        ]
        if common:
            return True, [f"items[{len(common)} matches]"]
        return False, []

    # Case 3: Primitive / text values
    if (
        baseline_data == probe_data
        and not is_generic_or_login_response(probe_data)
        and probe_data != REDACTED_MARKER
        and probe_data != "[REDACTED]"
    ):
        return True, ["exact_value_match"]

    return False, []


def check_identity_credential_collision(
    priv_id: TestIdentity,
    lower_id: TestIdentity,
) -> Optional[str]:
    """Verify that privileged and lower identities do not share credentials at model level."""
    # 1. Username + Password collision
    if priv_id.username and lower_id.username and priv_id.username.strip() == lower_id.username.strip():
        if priv_id.password and lower_id.password and priv_id.password == lower_id.password:
            return "Identities share identical username and password"

    # 2. Token and API-key cross-field collision
    priv_tokens = {v.strip() for v in [priv_id.token, priv_id.api_key] if v and str(v).strip()}
    lower_tokens = {v.strip() for v in [lower_id.token, lower_id.api_key] if v and str(v).strip()}
    shared_tokens = priv_tokens & lower_tokens
    if shared_tokens:
        return "Identities share identical bearer token or API key value"

    # 3. Shared sensitive headers
    for k, v in priv_id.headers.items():
        if any(sec in k.lower() for sec in ["auth", "token", "key", "secret", "session", "credential"]):
            for lk, lv in lower_id.headers.items():
                if v and v == lv and any(sec in lk.lower() for sec in ["auth", "token", "key", "secret", "session", "credential"]):
                    return f"Identities share identical sensitive header '{k}'"

    # 4. Shared sensitive cookies
    for c, v in priv_id.cookies.items():
        if any(sec in c.lower() for sec in ["session", "token", "auth", "secret"]):
            for lc, lv in lower_id.cookies.items():
                if v and v == lv and any(sec in lc.lower() for sec in ["session", "token", "auth", "secret"]):
                    return f"Identities share identical sensitive cookie '{c}'"

    return None


def check_request_credential_collision(
    endpoint: EndpointModel,
    baseline_req: PreparedRequest,
    probe_req: PreparedRequest,
) -> Optional[str]:
    """Verify that prepared requests do not emit identical effective authentication credentials.

    Inspects authentication material guided by the OpenAPI security scheme:
    - Authorization headers for HTTP schemes (Basic, Bearer)
    - Target header for apiKey in header
    - Target query parameter for apiKey in query
    - Target cookie for apiKey in cookie
    """
    # 1. Authorization header comparison
    b_auth = baseline_req.headers.get("authorization") or baseline_req.headers.get("Authorization")
    p_auth = probe_req.headers.get("authorization") or probe_req.headers.get("Authorization")
    if b_auth and p_auth and b_auth == p_auth:
        return "Identities generate identical Authorization request headers"

    # 2. Scheme-guided parameter/cookie/header inspection
    effective_reqs = endpoint.effective_security
    if effective_reqs:
        for req in effective_reqs:
            scheme = req.scheme
            scheme_type = (req.type or (scheme.type if scheme else None) or "").lower()
            in_loc = (req.in_location or (scheme.in_location if scheme else None) or "").lower()
            param_name = req.parameter_name or (scheme.name if scheme else None) or req.scheme_name

            if scheme_type in {"apikey", "api_key"} and param_name:
                if in_loc == "query":
                    b_val = baseline_req.params.get(param_name)
                    p_val = probe_req.params.get(param_name)
                    if b_val and p_val and b_val == p_val:
                        return f"Prepared requests contain identical API-key query parameter '{param_name}'"
                elif in_loc == "cookie":
                    b_val = baseline_req.cookies.get(param_name)
                    p_val = probe_req.cookies.get(param_name)
                    if b_val and p_val and b_val == p_val:
                        return f"Prepared requests contain identical API-key cookie '{param_name}'"
                elif in_loc == "header":
                    b_val = None
                    p_val = None
                    for hk, hv in baseline_req.headers.items():
                        if hk.lower() == param_name.lower():
                            b_val = hv
                            break
                    for hk, hv in probe_req.headers.items():
                        if hk.lower() == param_name.lower():
                            p_val = hv
                            break
                    if b_val and p_val and b_val == p_val:
                        return f"Prepared requests contain identical API-key header '{param_name}'"

    # 3. Fallback for raw security requirements or sensitive auth parameters
    for qk, qv in baseline_req.params.items():
        if any(sec == qk.lower() or f"{sec}_" in qk.lower() or f"_{sec}" in qk.lower() for sec in ["api_key", "apikey", "token", "auth", "secret"]):
            if qv and qv == probe_req.params.get(qk):
                return f"Prepared requests contain identical authentication query parameter '{qk}'"

    for ck, cv in baseline_req.cookies.items():
        if any(sec in ck.lower() for sec in ["session", "token", "auth", "secret", "api_key"]):
            if cv and cv == probe_req.cookies.get(ck):
                return f"Prepared requests contain identical authentication cookie '{ck}'"

    for hk, hv in baseline_req.headers.items():
        if any(sec in hk.lower() for sec in ["api-key", "apikey", "token", "secret", "session"]):
            for phk, phv in probe_req.headers.items():
                if hk.lower() == phk.lower() and hv and hv == phv:
                    return f"Prepared requests contain identical authentication header '{hk}'"

    return None


def _create_not_executed_finding(
    proposal: ProposedTest,
    reason: str,
    *,
    error: Optional[str] = None,
    execution_status: ExecutionStatus = ExecutionStatus.NOT_EXECUTED,
) -> Finding:
    """Create a standardized NOT_EXECUTED finding for pre-execution failures."""
    return Finding(
        test_id=proposal.test_id,
        endpoint=proposal.endpoint,
        evidence=Evidence(request={}, response={}, notes=reason),
        severity=proposal.severity,
        status=FindingStatus.NOT_EXECUTED,
        execution_status=execution_status,
        assessment_outcome=AssessmentOutcome.INCONCLUSIVE,
        assessment_reason=reason,
        remediation=BFLA_REMEDIATION,
        is_human_reviewed=False,
        notes=json.dumps({"reason": reason, "error": error} if error else {"reason": reason}),
    )


# ---------------------------------------------------------------------------
# Core Differential BFLA Runner
# ---------------------------------------------------------------------------

async def run_differential_bfla(
    proposal: ProposedTest,
    config: ExecutionConfig,
    client: Optional[httpx.AsyncClient] = None,
) -> Finding:
    """Execute a specification-driven differential BFLA security test.

    Sequence:
    1. Pre-execution validations (approval, test_type, GET method, policy, identities, budget).
       If any check fails, 0 requests are sent and a NOT_EXECUTED finding is returned.
    2. Privileged Baseline: executes 1 request with privileged identity.
       If baseline non-2xx, halts sequence without executing probe.
    3. Lower-Privileged Probe: executes 1 request with lower-privileged identity.
    4. Conservative Outcome Evaluation:
       - 403: ACCESS_DENIED
       - 401 with verified credentials: ACCESS_DENIED; unverified: INCONCLUSIVE
       - 404 with route concealment policy: ACCESS_DENIED; otherwise: INCONCLUSIVE
       - 3xx/5xx: INCONCLUSIVE
       - 2xx: checks for substantive privileged data. Generic/login -> INCONCLUSIVE; substantive -> SUSPECTED.
    """
    # 1. Approval check (explicit human approval required)
    if proposal.status != TestStatus.APPROVED:
        raise PermissionError(
            f"Proposal '{proposal.test_id}' is not approved (status: {proposal.status}). "
            "Security tests can only execute with explicit human approval."
        )

    # 2. Test type check
    if proposal.test_type != "BFLA":
        return _create_not_executed_finding(
            proposal,
            f"Unsupported test type '{proposal.test_type}' for BFLA engine; expected 'BFLA'",
        )

    # 3. Non-destructive method check: strictly GET in Stage 6.2.2
    if proposal.endpoint.method.upper() != "GET":
        return _create_not_executed_finding(
            proposal,
            f"BFLA testing in Stage 6.2.2 strictly supports non-destructive GET operations; "
            f"method '{proposal.endpoint.method}' is not supported.",
        )

    # 4. Explicit Policy Mapping check
    if config.bfla_policy is None:
        return _create_not_executed_finding(
            proposal,
            "Missing required bfla_policy in execution configuration; explicit BFLA policy mapping is required. "
            "(Only BOLA is currently supported in SPEC_DRIVEN mode without explicit policy mapping.)",
        )

    policy_path = config.bfla_policy.endpoint_path.rstrip("/").lower()
    proposal_path = proposal.endpoint.path.rstrip("/").lower()
    if policy_path != proposal_path:
        return _create_not_executed_finding(
            proposal,
            f"BFLA policy endpoint path '{config.bfla_policy.endpoint_path}' does not match proposal path '{proposal.endpoint.path}'",
        )

    if config.bfla_policy.endpoint_method.upper() != proposal.endpoint.method.upper():
        return _create_not_executed_finding(
            proposal,
            f"BFLA policy method '{config.bfla_policy.endpoint_method}' does not match proposal method '{proposal.endpoint.method}'",
        )

    # 5. Identity Validations
    if config.privileged_identity is None:
        return _create_not_executed_finding(
            proposal,
            "Missing required privileged_identity in execution configuration",
        )
    if config.lower_privileged_identity is None:
        return _create_not_executed_finding(
            proposal,
            "Missing required lower_privileged_identity in execution configuration",
        )
    if config.privileged_identity.identity_id == config.lower_privileged_identity.identity_id:
        return _create_not_executed_finding(
            proposal,
            f"Privileged identity and lower-privileged identity must be distinct; both have ID '{config.privileged_identity.identity_id}'",
        )

    # Normalize roles for robust comparison
    req_role_norm = normalize_role(config.bfla_policy.required_role)
    permitted_roles_norm = normalize_roles(config.bfla_policy.permitted_roles)
    if req_role_norm:
        permitted_roles_norm.add(req_role_norm)

    forbidden_roles_norm = normalize_roles(config.bfla_policy.forbidden_roles)
    priv_roles_norm = normalize_roles(config.privileged_identity.roles)
    lower_roles_norm = normalize_roles(config.lower_privileged_identity.roles)

    # Privileged identity must possess the required role or at least one permitted role
    has_privileged_role = bool(priv_roles_norm & permitted_roles_norm)
    if not has_privileged_role:
        return _create_not_executed_finding(
            proposal,
            f"Privileged identity '{config.privileged_identity.identity_id}' with roles {config.privileged_identity.roles} "
            f"does not hold required role '{config.bfla_policy.required_role}' or permitted role(s) {config.bfla_policy.permitted_roles}; "
            "cannot establish authorized privileged baseline.",
        )

    # Lower-privileged identity must NOT have any permitted role or the required role
    has_permitted_role = bool(lower_roles_norm & permitted_roles_norm)
    if has_permitted_role:
        return _create_not_executed_finding(
            proposal,
            f"Lower-privileged identity '{config.lower_privileged_identity.identity_id}' possesses authorized role(s) "
            f"({config.lower_privileged_identity.roles} overlaps with permitted {config.bfla_policy.permitted_roles} or required '{config.bfla_policy.required_role}'); "
            "cannot evaluate BFLA with an identity holding permitted roles.",
        )

    # Lower-privileged identity's role must be explicitly listed in forbidden_roles
    has_forbidden_role = bool(lower_roles_norm & forbidden_roles_norm)
    if not has_forbidden_role:
        return _create_not_executed_finding(
            proposal,
            f"Lower-privileged identity '{config.lower_privileged_identity.identity_id}' does not have a role "
            f"explicitly listed in forbidden_roles ({config.bfla_policy.forbidden_roles})",
        )

    # 6. Request Budget Preflight Check (Sequence requires exactly 2 requests)
    planned_requests = 2
    if not config.budget.can_request(planned_requests):
        return _create_not_executed_finding(
            proposal,
            f"Execution budget exceeded before sending request: BFLA sequence requires {planned_requests} request(s), "
            f"but only {config.budget.remaining} remaining",
        )

    # 6b. Validate identity credentials do not share identical secrets
    ident_cred_collision = check_identity_credential_collision(
        config.privileged_identity,
        config.lower_privileged_identity,
    )
    if ident_cred_collision:
        return _create_not_executed_finding(
            proposal,
            f"Privileged identity and lower-privileged identity share effective credentials ({ident_cred_collision}); "
            "cannot perform differential authorization assessment with identical credentials.",
        )

    # 7. Request Construction (Dry Run)
    try:
        baseline_req = build_request(
            proposal.endpoint,
            config,
            identity=config.privileged_identity,
            path_param_override=config.parameters.owner_path_params if config.parameters else None,
        )
        probe_req = build_request(
            proposal.endpoint,
            config,
            identity=config.lower_privileged_identity,
            path_param_override=config.parameters.owner_path_params if config.parameters else None,
        )
    except (ValueError, PermissionError) as exc:
        safe_err = sanitize_error_message(str(exc))
        return _create_not_executed_finding(
            proposal,
            f"Request construction failed: {safe_err}",
            error=safe_err,
        )

    # 7b. Validate that requests do not emit identical Authorization headers
    req_cred_collision = check_request_credential_collision(
        proposal.endpoint,
        baseline_req,
        probe_req,
    )
    if req_cred_collision:
        return _create_not_executed_finding(
            proposal,
            f"Privileged identity and lower-privileged identity share effective credentials ({req_cred_collision}); "
            "cannot perform differential authorization assessment with identical credentials.",
        )

    # 8. Execute Controlled Differential Sequence
    step_logs: Dict[str, Any] = {}
    should_close_client = False
    http_client = client
    if http_client is None:
        http_client = httpx.AsyncClient(
            timeout=config.timeout_seconds,
            follow_redirects=False,
        )
        should_close_client = True

    try:
        # Step 1: Privileged Baseline (1 request consumed)
        config.budget.record_request(1)
        try:
            baseline_resp = await http_client.request(
                method=baseline_req.method,
                url=baseline_req.url,
                headers=baseline_req.headers,
                params=baseline_req.params,
                cookies=baseline_req.cookies or None,
            )
            baseline_data = _sanitize_response_data(baseline_resp)
            step_logs["privileged_baseline"] = _build_step_log(
                config.privileged_identity.identity_id,
                baseline_req,
                baseline_resp,
                baseline_data,
            )
        except Exception as exc:
            safe_err = sanitize_error_message(str(exc))
            return Finding(
                test_id=proposal.test_id,
                endpoint=proposal.endpoint,
                evidence=Evidence(
                    request=baseline_req.to_evidence_dict(),
                    response={},
                    notes=f"Privileged baseline request failed: {safe_err}",
                ),
                severity=proposal.severity,
                status=FindingStatus.NOT_EXECUTED,
                execution_status=ExecutionStatus.FAILED,
                assessment_outcome=AssessmentOutcome.INCONCLUSIVE,
                assessment_reason=f"Privileged baseline request failed: {safe_err}",
                remediation=BFLA_REMEDIATION,
                is_human_reviewed=False,
                notes=json.dumps({"error": safe_err, "steps": sanitize_data(step_logs)}),
            )

        # Baseline must succeed (2xx) to validate authorized access
        if baseline_resp.status_code not in {200, 201, 204}:
            baseline_reason = (
                f"Privileged baseline returned status {baseline_resp.status_code}; "
                "cannot establish authorized baseline for function-level differential testing"
            )
            return Finding(
                test_id=proposal.test_id,
                endpoint=proposal.endpoint,
                evidence=Evidence(
                    request=baseline_req.to_evidence_dict(),
                    response=baseline_data,
                    notes=f"Privileged baseline returned non-2xx status code {baseline_resp.status_code}",
                ),
                severity=proposal.severity,
                status=FindingStatus.NOT_EXECUTED,
                execution_status=ExecutionStatus.COMPLETED,
                assessment_outcome=AssessmentOutcome.INCONCLUSIVE,
                assessment_reason=baseline_reason,
                remediation=BFLA_REMEDIATION,
                is_human_reviewed=False,
                notes=json.dumps({
                    "reason": baseline_reason,
                    "steps": sanitize_data(step_logs),
                }),
            )

        # Step 2: Lower-Privileged Probe (1 request consumed)
        config.budget.record_request(1)
        try:
            probe_resp = await http_client.request(
                method=probe_req.method,
                url=probe_req.url,
                headers=probe_req.headers,
                params=probe_req.params,
                cookies=probe_req.cookies or None,
            )
            probe_data = _sanitize_response_data(probe_resp)
            step_logs["lower_privileged_probe"] = _build_step_log(
                config.lower_privileged_identity.identity_id,
                probe_req,
                probe_resp,
                probe_data,
            )
        except Exception as exc:
            safe_err = sanitize_error_message(str(exc))
            return Finding(
                test_id=proposal.test_id,
                endpoint=proposal.endpoint,
                evidence=Evidence(
                    request=probe_req.to_evidence_dict(),
                    response={},
                    notes=f"Lower-privileged probe request failed: {safe_err}",
                ),
                severity=proposal.severity,
                status=FindingStatus.NOT_EXECUTED,
                execution_status=ExecutionStatus.FAILED,
                assessment_outcome=AssessmentOutcome.INCONCLUSIVE,
                assessment_reason=f"Lower-privileged probe request failed: {safe_err}",
                remediation=BFLA_REMEDIATION,
                is_human_reviewed=False,
                notes=json.dumps({"error": safe_err, "steps": sanitize_data(step_logs)}),
            )

        # 9. Conservative Outcome Classification
        probe_status = probe_resp.status_code
        is_static_route = "{" not in proposal.endpoint.path

        if probe_status == 403:
            outcome = AssessmentOutcome.ACCESS_DENIED
            status = FindingStatus.NOT_EXECUTED
            reason = (
                f"Lower-privileged probe received HTTP 403 Forbidden; "
                f"function-level access control enforced for operation '{proposal.endpoint.method.upper()} {proposal.endpoint.path}'."
            )
        elif probe_status == 401:
            if is_identity_verified(config.lower_privileged_identity):
                outcome = AssessmentOutcome.ACCESS_DENIED
                status = FindingStatus.NOT_EXECUTED
                reason = (
                    f"Lower-privileged probe received HTTP 401 with verified lower-privileged credentials; "
                    "access denied to unauthorized role."
                )
            else:
                outcome = AssessmentOutcome.INCONCLUSIVE
                status = FindingStatus.NOT_EXECUTED
                reason = (
                    f"Lower-privileged probe received HTTP 401 with unverified credentials. "
                    "Cannot determine whether access was denied due to function-level authorization or invalid authentication."
                )
        elif probe_status == 404:
            if config.bfla_policy.allow_static_route_concealment and is_static_route:
                outcome = AssessmentOutcome.ACCESS_DENIED
                status = FindingStatus.NOT_EXECUTED
                reason = (
                    f"Lower-privileged probe received HTTP 404 on static route under route concealment policy; "
                    "endpoint concealed from unauthorized role."
                )
            else:
                outcome = AssessmentOutcome.INCONCLUSIVE
                status = FindingStatus.NOT_EXECUTED
                reason = (
                    f"Lower-privileged probe received HTTP 404. Without route concealment policy or on dynamic routes, "
                    "404 indicates missing resource or unmapped endpoint, yielding inconclusive assessment."
                )
        elif 300 <= probe_status <= 399:
            outcome = AssessmentOutcome.INCONCLUSIVE
            status = FindingStatus.NOT_EXECUTED
            reason = (
                f"Lower-privileged probe received redirect status {probe_status}; "
                "redirects are disabled to prevent SSRF and execution ambiguity."
            )
        elif 500 <= probe_status <= 599:
            outcome = AssessmentOutcome.INCONCLUSIVE
            status = FindingStatus.NOT_EXECUTED
            reason = (
                f"Lower-privileged probe received HTTP {probe_status} (server error). "
                "Cannot determine function-level authorization behavior from a server failure."
            )
        elif probe_status == 204:
            outcome = AssessmentOutcome.INCONCLUSIVE
            status = FindingStatus.NOT_EXECUTED
            reason = (
                "Lower-privileged probe received HTTP 204 No Content; "
                "no substantive privileged data returned."
            )
        elif probe_status in {200, 201}:
            if is_generic_or_login_response(probe_data):
                outcome = AssessmentOutcome.INCONCLUSIVE
                status = FindingStatus.NOT_EXECUTED
                reason = (
                    f"Lower-privileged probe received status {probe_status}, but the response was empty, "
                    "a generic status wrapper, or a login page; inconclusive evidence of function execution."
                )
            else:
                has_overlap, matched_fields = extract_substantive_overlap(baseline_data, probe_data)
                if has_overlap:
                    outcome = AssessmentOutcome.SUSPECTED
                    status = FindingStatus.SUSPECTED
                    reason = (
                        f"Function-level authorization failure: lower-privileged identity '{config.lower_privileged_identity.identity_id}' "
                        f"with forbidden role(s) {config.lower_privileged_identity.roles} successfully executed privileged operation "
                        f"'{proposal.endpoint.method.upper()} {proposal.endpoint.path}' and retrieved substantive privileged data "
                        f"matching privileged baseline: {', '.join(matched_fields[:5])}."
                    )
                else:
                    outcome = AssessmentOutcome.INCONCLUSIVE
                    status = FindingStatus.NOT_EXECUTED
                    reason = (
                        f"Lower-privileged probe received status {probe_status}, but response content did not contain "
                        "meaningful substantive overlap with privileged baseline data; inconclusive assessment."
                    )
        else:
            outcome = AssessmentOutcome.INCONCLUSIVE
            status = FindingStatus.NOT_EXECUTED
            reason = (
                f"Lower-privileged probe received unexpected HTTP status {probe_status}; "
                "inconclusive assessment."
            )

        return Finding(
            test_id=proposal.test_id,
            endpoint=proposal.endpoint,
            evidence=Evidence(
                request=probe_req.to_evidence_dict(),
                response=probe_data,
                notes=f"Privileged baseline returned {baseline_resp.status_code}; lower-privileged probe returned {probe_resp.status_code}",
            ),
            severity=proposal.severity,
            status=status,
            execution_status=ExecutionStatus.COMPLETED,
            assessment_outcome=outcome,
            assessment_reason=reason,
            remediation=BFLA_REMEDIATION,
            is_human_reviewed=False,
            notes=json.dumps({
                "steps": sanitize_data(step_logs),
                "privileged_status": baseline_resp.status_code,
                "probe_status": probe_resp.status_code,
                "policy": {
                    "endpoint_path": config.bfla_policy.endpoint_path,
                    "endpoint_method": config.bfla_policy.endpoint_method,
                    "required_role": config.bfla_policy.required_role,
                    "forbidden_roles": config.bfla_policy.forbidden_roles,
                    "lower_identity_roles": config.lower_privileged_identity.roles,
                },
            }),
        )

    finally:
        if should_close_client:
            await http_client.aclose()
