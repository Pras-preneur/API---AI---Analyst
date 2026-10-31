"""Isolated authentication test engine for specification-driven security assessments.

Executes a controlled two-step authentication verification sequence:
1. Authenticated baseline: access the protected operation using authenticated credentials.
   Must return 2xx (200, 201) with meaningful protected content.
   Non-2xx, empty, or generic login wrapper halts sequence without sending probe (1 request consumed).
2. Unauthenticated probe: attempt to access the protected operation with all authentication
   material deliberately omitted (MISSING_CREDENTIALS mutation).

Strict Invariants:
- Non-destructive operations only (GET only in this stage).
- Zero requests sent if pre-execution validation fails (approval, scheme, budget, identity).
- Explicit human approval required (proposal.status == TestStatus.APPROVED).
- Authenticated identity must be provided and explicitly verified (credentials_verified=True).
- Budget preflight requires at least 2 requests before sending any.
- Every attempted request is recorded against budget even if it fails.
- Never automatically assigns AssessmentOutcome.CONFIRMED (maximum outcome is SUSPECTED).
- Conservative classification:
    * 401 / 403: ACCESS_DENIED
    * 404: ACCESS_DENIED only if route concealment policy is enabled on static route; otherwise INCONCLUSIVE
    * 3xx / 5xx: INCONCLUSIVE
    * Empty / generic / login wrapper: INCONCLUSIVE
    * 2xx with substantive overlap against authenticated baseline: SUSPECTED
    * 2xx without substantive overlap: INCONCLUSIVE
- Redaction markers ([REDACTED], configured marker) never count as substantive overlap.
- Complete sanitization: no credentials, tokens, or raw secrets in evidence, notes, or step logs.
- Authorized localhost mock targets only.
"""

import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

import httpx

from ..models import (
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
    ProposedTest,
    TestIdentity,
    TestStatus,
    validate_assessment_outcome,
)
from .bfla_engine import (
    GENERIC_STATUS_KEYS,
    _build_step_log,
    _sanitize_response_data,
    _utc_now,
    extract_substantive_overlap,
    is_generic_or_login_response,
    is_identity_verified,
)
from .request_builder import (
    ALLOWED_TARGETS,
    PreparedRequest,
    build_request,
    build_unauthenticated_request,
)
from .sanitization import (
    REDACTED_MARKER,
    sanitize_data,
    sanitize_error_message,
    sanitize_url,
)

# ---------------------------------------------------------------------------
# Module Constants
# ---------------------------------------------------------------------------

AUTH_REMEDIATION = (
    "Enforce strict authentication on every protected endpoint. "
    "Verify credentials before executing business logic or returning sensitive resource data."
)


# ---------------------------------------------------------------------------
# Internal Helpers
# ---------------------------------------------------------------------------

def _create_not_executed_finding(
    proposal: ProposedTest,
    reason: str,
    error: Optional[str] = None,
) -> Finding:
    """Construct a finding for pre-execution validation failure (0 requests sent)."""
    notes_dict: Dict[str, Any] = {"reason": reason}
    if error:
        notes_dict["error"] = error
    return Finding(
        test_id=proposal.test_id,
        endpoint=proposal.endpoint,
        evidence=Evidence(
            request={},
            response={},
            notes=reason,
        ),
        severity=proposal.severity,
        status=FindingStatus.NOT_EXECUTED,
        execution_status=ExecutionStatus.NOT_EXECUTED,
        assessment_outcome=AssessmentOutcome.INCONCLUSIVE,
        assessment_reason=reason,
        remediation=AUTH_REMEDIATION,
        is_human_reviewed=False,
        notes=json.dumps(notes_dict),
    )


# ---------------------------------------------------------------------------
# Main Authentication Test Runner
# ---------------------------------------------------------------------------

async def run_authentication_test(
    proposal: ProposedTest,
    config: ExecutionConfig,
    client: Optional[httpx.AsyncClient] = None,
) -> Finding:
    """Execute a controlled authentication test verifying credential requirement on protected endpoints.

    Pre-execution Validation Sequence (0 requests sent on failure):
    1. Human approval check: proposal.status must be APPROVED (raises PermissionError otherwise).
    2. Test type check: must be AUTH_MISSING_CREDENTIALS.
    3. Execution mode check: config.mode must be SPEC_DRIVEN.
    4. Non-destructive method check: strictly GET in this stage.
    5. Security requirement check: endpoint must have effective security requirements defined.
    6. Authenticated identity check: authenticated_identity (or owner_identity) must be provided and verified.
    7. Allowlist check: target base URL must be in ALLOWED_TARGETS.
    8. Budget preflight: requires at least 2 requests before sending any.
    9. Request construction dry-run: builds both prepared requests safely.

    Execution Sequence:
    1. Step 1: Authenticated Baseline (1 request consumed).
       - Halts immediately with INCONCLUSIVE if baseline request fails or returns non-2xx / empty / login wrapper.
    2. Step 2: Unauthenticated Probe (1 request consumed).
       - Deliberately strips all authenticating headers, query params, and cookies.
    3. Classification:
       - 401 / 403 -> ACCESS_DENIED
       - 404 -> ACCESS_DENIED if route concealment allowed on static route, else INCONCLUSIVE
       - 3xx / 5xx -> INCONCLUSIVE
       - Empty / generic wrapper / login -> INCONCLUSIVE
       - 2xx with substantive overlap against baseline -> SUSPECTED
       - 2xx without substantive overlap -> INCONCLUSIVE
    """
    # 1. Approval check (explicit human approval required)
    if proposal.status != TestStatus.APPROVED:
        raise PermissionError(
            f"Proposal '{proposal.test_id}' is not approved (status: {proposal.status}). "
            "Security tests can only execute with explicit human approval."
        )

    # 2. Test type check
    supported_types = {AuthTestType.AUTH_MISSING_CREDENTIALS.value, "AUTH_MISSING_CREDENTIALS"}
    if proposal.test_type not in supported_types:
        return _create_not_executed_finding(
            proposal,
            f"Unsupported test type '{proposal.test_type}' for authentication engine; expected '{AuthTestType.AUTH_MISSING_CREDENTIALS.value}'",
        )

    # 3. Mode check: SPEC_DRIVEN required
    if config.mode != ExecutionMode.SPEC_DRIVEN:
        return _create_not_executed_finding(
            proposal,
            f"Authentication engine requires SPEC_DRIVEN mode; current mode is '{config.mode}'",
        )

    # 4. Non-destructive method check: strictly GET in this stage
    if proposal.endpoint.method.upper() != "GET":
        return _create_not_executed_finding(
            proposal,
            f"Authentication test engine strictly supports non-destructive GET operations in this stage; method '{proposal.endpoint.method}' is not supported.",
        )

    # 5. Security requirement check: must have defined security schemes
    effective_reqs = proposal.endpoint.effective_security
    raw_security = proposal.endpoint.security
    has_effective_sec = (effective_reqs is not None and len(effective_reqs) > 0) or (
        raw_security is not None and len(raw_security) > 0
    )
    if not has_effective_sec:
        return _create_not_executed_finding(
            proposal,
            f"Endpoint '{proposal.endpoint.method.upper()} {proposal.endpoint.path}' has no security requirements defined; cannot execute missing-credentials authentication test on an unsecured endpoint.",
        )

    # 6. Baseline identity check: must be configured and explicitly verified
    baseline_identity: Optional[TestIdentity] = config.authenticated_identity or config.owner_identity
    if baseline_identity is None:
        return _create_not_executed_finding(
            proposal,
            "Missing authenticated identity in execution configuration; cannot execute authentication test without an authenticated baseline identity.",
        )
    if not is_identity_verified(baseline_identity):
        return _create_not_executed_finding(
            proposal,
            f"Authenticated baseline identity '{baseline_identity.identity_id}' credentials are not explicitly verified (credentials_verified=False); cannot establish trustworthy baseline.",
        )

    # 7. Target Allowlist Check
    normalized_base = config.target_base_url.rstrip("/")
    if normalized_base not in ALLOWED_TARGETS:
        return _create_not_executed_finding(
            proposal,
            f"Unauthorized target URL: '{config.target_base_url}'. Only authorized local mock targets are allowed: {sorted(list(ALLOWED_TARGETS))}",
        )

    # 8. Request Budget Preflight Check (Sequence requires 2 requests: baseline + probe)
    planned_requests = 2
    if not config.budget.can_request(planned_requests):
        return _create_not_executed_finding(
            proposal,
            f"Execution budget exceeded before sending request: Authentication test sequence requires {planned_requests} request(s), but only {config.budget.remaining} remaining",
        )

    # 9. Request Construction (Dry Run)
    try:
        baseline_req = build_request(
            endpoint=proposal.endpoint,
            config=config,
            identity=baseline_identity,
            path_param_override=config.parameters.owner_path_params if config.parameters else None,
            auth_mutation=AuthenticationMutation.NONE,
        )
        probe_req = build_unauthenticated_request(
            endpoint=proposal.endpoint,
            config=config,
            path_param_override=config.parameters.owner_path_params if config.parameters else None,
        )
    except (ValueError, PermissionError) as exc:
        safe_err = sanitize_error_message(str(exc))
        return _create_not_executed_finding(
            proposal,
            f"Request construction failed: {safe_err}",
            error=safe_err,
        )

    # 10. Execute Controlled Differential Authentication Sequence
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
        # Step 1: Authenticated Baseline (1 request consumed)
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
            step_logs["authenticated_baseline"] = _build_step_log(
                baseline_identity.identity_id,
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
                    notes=f"Authenticated baseline request failed: {safe_err}",
                ),
                severity=proposal.severity,
                status=FindingStatus.NOT_EXECUTED,
                execution_status=ExecutionStatus.FAILED,
                assessment_outcome=AssessmentOutcome.INCONCLUSIVE,
                assessment_reason=f"Authenticated baseline request failed: {safe_err}",
                remediation=AUTH_REMEDIATION,
                is_human_reviewed=False,
                notes=json.dumps({"error": safe_err, "steps": sanitize_data(step_logs), "requests_consumed": 1}),
            )

        # Baseline must succeed (200 or 201) and establish meaningful access
        if baseline_resp.status_code not in {200, 201} or is_generic_or_login_response(baseline_data):
            baseline_reason = (
                f"Authenticated baseline returned status {baseline_resp.status_code} "
                f"with {'generic/empty/login' if is_generic_or_login_response(baseline_data) else 'non-2xx'} response; "
                "cannot establish authorized baseline for authentication differential testing."
            )
            return Finding(
                test_id=proposal.test_id,
                endpoint=proposal.endpoint,
                evidence=Evidence(
                    request=baseline_req.to_evidence_dict(),
                    response=baseline_data,
                    notes=baseline_reason,
                ),
                severity=proposal.severity,
                status=FindingStatus.NOT_EXECUTED,
                execution_status=ExecutionStatus.COMPLETED,
                assessment_outcome=AssessmentOutcome.INCONCLUSIVE,
                assessment_reason=baseline_reason,
                remediation=AUTH_REMEDIATION,
                is_human_reviewed=False,
                notes=json.dumps({
                    "reason": baseline_reason,
                    "steps": sanitize_data(step_logs),
                    "authenticated_baseline_status": baseline_resp.status_code,
                    "requests_consumed": 1,
                }),
            )

        # Step 2: Unauthenticated Probe (1 request consumed)
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
            step_logs["unauthenticated_probe"] = _build_step_log(
                "unauthenticated",
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
                    notes=f"Unauthenticated probe request failed: {safe_err}",
                ),
                severity=proposal.severity,
                status=FindingStatus.NOT_EXECUTED,
                execution_status=ExecutionStatus.FAILED,
                assessment_outcome=AssessmentOutcome.INCONCLUSIVE,
                assessment_reason=f"Unauthenticated probe request failed: {safe_err}",
                remediation=AUTH_REMEDIATION,
                is_human_reviewed=False,
                notes=json.dumps({"error": safe_err, "steps": sanitize_data(step_logs), "requests_consumed": 2}),
            )

        # 11. Conservative Outcome Classification
        probe_status = probe_resp.status_code
        is_static_route = "{" not in proposal.endpoint.path
        allow_concealment = getattr(config.bfla_policy, "allow_static_route_concealment", False) if config.bfla_policy else False

        if probe_status in {401, 403}:
            outcome = AssessmentOutcome.ACCESS_DENIED
            status = FindingStatus.NOT_EXECUTED
            reason = (
                f"Unauthenticated probe received HTTP {probe_status}; "
                f"authentication enforced for protected operation '{proposal.endpoint.method.upper()} {proposal.endpoint.path}'."
            )
        elif probe_status == 404:
            if allow_concealment and is_static_route:
                outcome = AssessmentOutcome.ACCESS_DENIED
                status = FindingStatus.NOT_EXECUTED
                reason = (
                    f"Unauthenticated probe received HTTP 404 on static route under route concealment policy; "
                    "endpoint concealed from unauthenticated requests."
                )
            else:
                outcome = AssessmentOutcome.INCONCLUSIVE
                status = FindingStatus.NOT_EXECUTED
                reason = (
                    f"Unauthenticated probe received HTTP 404. Without route concealment policy or on dynamic routes, "
                    "404 indicates missing resource or unmapped endpoint, yielding inconclusive assessment."
                )
        elif 300 <= probe_status <= 399:
            outcome = AssessmentOutcome.INCONCLUSIVE
            status = FindingStatus.NOT_EXECUTED
            reason = (
                f"Unauthenticated probe received redirect status {probe_status}; "
                "redirects are disabled to prevent SSRF and authentication bypass masking."
            )
        elif 500 <= probe_status <= 599:
            outcome = AssessmentOutcome.INCONCLUSIVE
            status = FindingStatus.NOT_EXECUTED
            reason = (
                f"Unauthenticated probe received HTTP {probe_status} (server error). "
                "Cannot determine authentication enforcement from a server failure."
            )
        elif probe_status == 204:
            outcome = AssessmentOutcome.INCONCLUSIVE
            status = FindingStatus.NOT_EXECUTED
            reason = (
                "Unauthenticated probe received HTTP 204 No Content; "
                "no substantive protected data returned."
            )
        elif probe_status in {200, 201}:
            if is_generic_or_login_response(probe_data):
                outcome = AssessmentOutcome.INCONCLUSIVE
                status = FindingStatus.NOT_EXECUTED
                reason = (
                    f"Unauthenticated probe received status {probe_status}, but response was empty, "
                    "a generic status wrapper, or a login page; inconclusive evidence of access to protected resource."
                )
            else:
                has_overlap, matched_fields = extract_substantive_overlap(baseline_data, probe_data)
                if has_overlap:
                    outcome = AssessmentOutcome.SUSPECTED
                    status = FindingStatus.SUSPECTED
                    reason = (
                        f"Authentication failure: unauthenticated request to protected endpoint "
                        f"'{proposal.endpoint.method.upper()} {proposal.endpoint.path}' succeeded with HTTP {probe_status} "
                        f"and returned substantive protected resource data matching authenticated baseline: {', '.join(matched_fields[:5])}."
                    )
                else:
                    outcome = AssessmentOutcome.INCONCLUSIVE
                    status = FindingStatus.NOT_EXECUTED
                    reason = (
                        f"Unauthenticated probe received status {probe_status}, but response content did not contain "
                        "meaningful substantive overlap with authenticated baseline data; inconclusive assessment."
                    )
        else:
            outcome = AssessmentOutcome.INCONCLUSIVE
            status = FindingStatus.NOT_EXECUTED
            reason = (
                f"Unauthenticated probe received unexpected HTTP status {probe_status}; "
                "inconclusive assessment."
            )

        # Enforce that CONFIRMED cannot be assigned automatically
        validate_assessment_outcome(outcome, is_human_review=False)

        return Finding(
            test_id=proposal.test_id,
            endpoint=proposal.endpoint,
            evidence=Evidence(
                request=probe_req.to_evidence_dict(),
                response=probe_data,
                notes=f"Authenticated baseline returned {baseline_resp.status_code}; unauthenticated probe returned {probe_resp.status_code}",
            ),
            severity=proposal.severity,
            status=status,
            execution_status=ExecutionStatus.COMPLETED,
            assessment_outcome=outcome,
            assessment_reason=reason,
            remediation=AUTH_REMEDIATION,
            is_human_reviewed=False,
            notes=json.dumps({
                "steps": sanitize_data(step_logs),
                "authenticated_baseline_status": baseline_resp.status_code,
                "probe_status": probe_resp.status_code,
                "mutation": AuthenticationMutation.MISSING_CREDENTIALS.value,
                "requests_consumed": 2,
            }),
        )

    finally:
        if should_close_client:
            await http_client.aclose()

