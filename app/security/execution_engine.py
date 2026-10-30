"""Execution engine for approved security‑test proposals.

The engine runs only against the local mock API (http://127.0.0.1:8001 or http://localhost:8001).
It validates that proposals are APPROVED, belong to the same session, and that the target URL is allowed.
Supports both LEGACY_FIXTURE execution (for existing tests) and SPEC_DRIVEN execution (using dynamic
OpenAPI request construction).
"""

import json
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional

import httpx

from ..models import (
    AssessmentOutcome,
    AuthTestType,
    Evidence,
    ExecutionConfig,
    ExecutionMode,
    ExecutionStatus,
    Finding,
    FindingStatus,
    ProposedTest,
    TestStatus,
    session_store,
)
from ..parser.openapi_parser import EndpointModel
from ..config import ALLOWED_TARGETS, MAX_REQUESTS_PER_EXECUTION, DEFAULT_REQUEST_TIMEOUT
from .sanitization import (
    sanitize_request as _sanitize_req_util,
    sanitize_response as _sanitize_resp_util,
    sanitize_error_message,
)
from .request_builder import build_request, PreparedRequest
from .differential_engine import run_differential_bola
from .bfla_engine import run_differential_bfla
from .authentication_engine import run_authentication_test

REQUEST_TIMEOUT = DEFAULT_REQUEST_TIMEOUT


# ---------------------------------------------------------------------------
# Helper utilities (delegating to centralized sanitization)
# ---------------------------------------------------------------------------
def _sanitize_request(method: str, url: str, headers: Dict[str, Any]) -> Dict[str, Any]:
    """Return sanitized request metadata with credentials and sensitive headers removed."""
    return _sanitize_req_util(method=method, url=url, headers=headers)


def _sanitize_response(resp: httpx.Response) -> Dict[str, Any]:
    """Return a sanitized representation of the response with tokens and PII scrubbed."""
    return _sanitize_resp_util(resp)

# ---------------------------------------------------------------------------
# Legacy Executor implementations per test type
# ---------------------------------------------------------------------------
async def _execute_bola(base_url: str, proposal: ProposedTest) -> Finding:
    """BOLA / IDOR test against the legacy vulnerable endpoint."""
    target = f"{base_url}/vuln/users/user_b"
    auth = httpx.BasicAuth("user_a", "passwordA")
    async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT, follow_redirects=False) as client:
        resp = await client.get(target, auth=auth)
    evidence = Evidence(
        request=_sanitize_request("GET", target, dict(resp.request.headers)),
        response=_sanitize_response(resp),
    )
    is_vuln = (
        resp.status_code == 200
        and isinstance(evidence.response["body"], dict)
        and evidence.response["body"].get("username") == "user_b"
    )
    confidence = 1.0 if is_vuln else 0.0
    finding = Finding(
        test_id=proposal.test_id,
        endpoint=proposal.endpoint,
        evidence=evidence,
        severity=proposal.severity,
        status=FindingStatus.SUSPECTED if is_vuln else FindingStatus.NOT_EXECUTED,
        execution_status=ExecutionStatus.COMPLETED,
        assessment_outcome=AssessmentOutcome.SUSPECTED if is_vuln else AssessmentOutcome.INCONCLUSIVE,
        assessment_reason="Legacy BOLA mock fixture returned username 'user_b' with HTTP 200" if is_vuln else "Mock fixture did not return expected user data",
        remediation="Enforce object-level authorization on every request. Verify that the authenticated principal owns or has explicit access to the requested resource before returning any data.",
        notes=json.dumps({"confidence": confidence}),
    )
    return finding


async def _execute_bfla(base_url: str, proposal: ProposedTest) -> Finding:
    """BFLA test – access admin data without proper privilege."""
    target = f"{base_url}/vuln/admin/data"
    auth = httpx.BasicAuth("user_a", "passwordA")
    async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT, follow_redirects=False) as client:
        resp = await client.get(target, auth=auth)
    evidence = Evidence(
        request=_sanitize_request("GET", target, dict(resp.request.headers)),
        response=_sanitize_response(resp),
    )
    is_vuln = resp.status_code == 200
    confidence = 1.0 if is_vuln else 0.0
    finding = Finding(
        test_id=proposal.test_id,
        endpoint=proposal.endpoint,
        evidence=evidence,
        severity=proposal.severity,
        status=FindingStatus.SUSPECTED if is_vuln else FindingStatus.NOT_EXECUTED,
        execution_status=ExecutionStatus.COMPLETED,
        assessment_outcome=AssessmentOutcome.SUSPECTED if is_vuln else AssessmentOutcome.ACCESS_DENIED,
        assessment_reason="Admin endpoint returned HTTP 200 without administrative authorization" if is_vuln else "Admin endpoint returned non-200 status",
        remediation="Apply function-level access controls using server-side role or permission checks. Never rely on client-supplied claims alone.",
        notes=json.dumps({"confidence": confidence}),
    )
    return finding


async def _execute_excessive_data(base_url: str, proposal: ProposedTest) -> Finding:
    """Excessive data exposure – call the endpoint that returns all users."""
    target = f"{base_url}/vuln/expose-all"
    async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT, follow_redirects=False) as client:
        resp = await client.get(target)
    evidence = Evidence(
        request=_sanitize_request("GET", target, dict(resp.request.headers)),
        response=_sanitize_response(resp),
    )
    body = evidence.response["body"]
    is_vuln = isinstance(body, dict) and len(body.get("users", [])) > 2
    confidence = 1.0 if is_vuln else 0.0
    finding = Finding(
        test_id=proposal.test_id,
        endpoint=proposal.endpoint,
        evidence=evidence,
        severity=proposal.severity,
        status=FindingStatus.SUSPECTED if is_vuln else FindingStatus.NOT_EXECUTED,
        execution_status=ExecutionStatus.COMPLETED,
        assessment_outcome=AssessmentOutcome.SUSPECTED if is_vuln else AssessmentOutcome.INCONCLUSIVE,
        assessment_reason="Endpoint returned full user collection exceeding caller's authorized scope" if is_vuln else "Endpoint did not return excessive user collection",
        remediation="Return only authorized fields using response DTOs or schemas to filter sensitive attributes.",
        notes=json.dumps({"confidence": confidence}),
    )
    return finding


async def _execute_missing_auth(base_url: str, proposal: ProposedTest) -> Finding:
    """Missing authentication – request a protected endpoint without auth."""
    target = f"{base_url}/admin/data"
    async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT, follow_redirects=False) as client:
        resp = await client.get(target)
    evidence = Evidence(
        request=_sanitize_request("GET", target, dict(resp.request.headers)),
        response=_sanitize_response(resp),
    )
    is_vuln = resp.status_code == 200
    confidence = 1.0 if is_vuln else 0.0
    finding = Finding(
        test_id=proposal.test_id,
        endpoint=proposal.endpoint,
        evidence=evidence,
        severity=proposal.severity,
        status=FindingStatus.SUSPECTED if is_vuln else FindingStatus.NOT_EXECUTED,
        execution_status=ExecutionStatus.COMPLETED,
        assessment_outcome=AssessmentOutcome.SUSPECTED if is_vuln else AssessmentOutcome.ACCESS_DENIED,
        assessment_reason="Unauthenticated request succeeded with HTTP 200 on protected endpoint" if is_vuln else "Protected endpoint denied unauthenticated access",
        remediation="Require authentication on all non-public endpoints. Validate tokens server-side on every request.",
        notes=json.dumps({"confidence": confidence}),
    )
    return finding


async def _execute_mass_assignment(base_url: str, proposal: ProposedTest) -> Finding:
    """Mass‑assignment – PATCH the profile with an innocuous field."""
    target = f"{base_url}/profile"
    auth = httpx.BasicAuth("user_a", "passwordA")
    payload = {"bio": "injected"}
    async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT, follow_redirects=False) as client:
        resp = await client.patch(target, json=payload, auth=auth)
    evidence = Evidence(
        request=_sanitize_request("PATCH", target, dict(resp.request.headers)),
        response=_sanitize_response(resp),
    )
    is_vuln = resp.status_code == 200
    confidence = 1.0 if is_vuln else 0.0
    finding = Finding(
        test_id=proposal.test_id,
        endpoint=proposal.endpoint,
        evidence=evidence,
        severity=proposal.severity,
        status=FindingStatus.SUSPECTED if is_vuln else FindingStatus.NOT_EXECUTED,
        execution_status=ExecutionStatus.COMPLETED,
        assessment_outcome=AssessmentOutcome.SUSPECTED if is_vuln else AssessmentOutcome.INCONCLUSIVE,
        assessment_reason="Object profile was updated with client-supplied fields without input allowlisting" if is_vuln else "Profile update returned non-200 status",
        remediation="Bind only explicitly allowed fields from incoming payloads using strict allowlists.",
        notes=json.dumps({"confidence": confidence}),
    )
    return finding


# Mapping from test_type string to executor coroutine
EXECUTOR_MAP = {
    "BOLA": _execute_bola,
    "BFLA": _execute_bfla,
    "ExcessiveData": _execute_excessive_data,
    "MissingAuth": _execute_missing_auth,
    "MassAssignment": _execute_mass_assignment,
}


async def execute_proposals(
    session_id: str,
    proposal_ids: List[str],
    target: str,
    config: Optional[ExecutionConfig] = None,
) -> List[Finding]:
    """Execute a list of approved proposal IDs for the given session.

    Supports both LEGACY_FIXTURE mode (using hardcoded mock routes) and
    SPEC_DRIVEN mode (using dynamic request construction and authentication).

    Returns the list of created ``Finding`` objects. Raises ``ValueError`` or
    ``KeyError``/``PermissionError`` for validation failures – callers (FastAPI
    endpoint) should translate those to appropriate HTTP responses.
    """
    # Basic request validation
    if not proposal_ids:
        raise ValueError("Empty proposal list")
    if target not in ALLOWED_TARGETS:
        raise PermissionError("Unauthorized target URL")
    if config is not None and config.target_base_url not in ALLOWED_TARGETS:
        raise PermissionError("Unauthorized target URL")
    if len(proposal_ids) > MAX_REQUESTS_PER_EXECUTION:
        raise ValueError("Too many proposals in a single execution request")

    if config is None:
        config = ExecutionConfig(mode=ExecutionMode.LEGACY_FIXTURE, target_base_url=target)

    # Retrieve session – will raise KeyError if unknown
    session = session_store.get_session(session_id)

    # ---------------------------------------------------------------------
    # Phase 1: Validate *all* proposals before any HTTP request is made.
    # ---------------------------------------------------------------------
    proposals_to_execute: List[ProposedTest] = []
    for pid in proposal_ids:
        proposal = session.proposals.get(pid)
        if proposal is None:
            # Does the proposal belong to another session?
            exists_elsewhere = any(
                pid in other_session.proposals
                for sid, other_session in session_store._sessions.items()
                if sid != session_id
            )
            if exists_elsewhere:
                raise PermissionError(
                    f"Proposal {pid} does not belong to session {session_id}"
                )
            raise KeyError(f"Proposal {pid} not found in session {session_id}")
        if proposal.status != TestStatus.APPROVED:
            raise PermissionError(f"Proposal {pid} is not approved")
        if proposal.executed_at is not None:
            raise PermissionError(f"Proposal {pid} has already been executed")
        proposals_to_execute.append(proposal)

    # ---------------------------------------------------------------------
    # Phase 2: Execute validated proposals according to configured mode.
    # ---------------------------------------------------------------------
    findings: List[Finding] = []

    if config.mode == ExecutionMode.LEGACY_FIXTURE:
        for proposal in proposals_to_execute:
            executor = EXECUTOR_MAP.get(proposal.test_type)
            if executor is None:
                # Unsupported test type – record as NOT_EXECUTED
                finding = Finding(
                    test_id=proposal.test_id,
                    endpoint=proposal.endpoint,
                    evidence=Evidence(request={}, response={}),
                    severity=proposal.severity,
                    status=FindingStatus.NOT_EXECUTED,
                    execution_status=ExecutionStatus.NOT_EXECUTED,
                    notes=json.dumps({"reason": "Unsupported test type"}),
                )
                session_store.add_finding(session_id, finding)
                findings.append(finding)
                continue
            try:
                finding = await executor(target, proposal)
            except Exception as exc:
                # Execution error – store empty evidence and sanitized error note
                safe_err = sanitize_error_message(str(exc))
                finding = Finding(
                    test_id=proposal.test_id,
                    endpoint=proposal.endpoint,
                    evidence=Evidence(request={}, response={}, notes=f"Execution failed: {safe_err}"),
                    severity=proposal.severity,
                    status=FindingStatus.NOT_EXECUTED,
                    execution_status=ExecutionStatus.FAILED,
                    assessment_outcome=AssessmentOutcome.INCONCLUSIVE,
                    assessment_reason=f"Execution failed: {safe_err}",
                    notes=json.dumps({"error": safe_err}),
                )
            # Record the finding and mark the proposal as executed
            session_store.add_finding(session_id, finding)
            proposal.executed_at = datetime.now(timezone.utc)
            findings.append(finding)

    elif config.mode == ExecutionMode.SPEC_DRIVEN:
        for proposal in proposals_to_execute:
            if proposal.test_type == "BOLA":
                finding = await run_differential_bola(proposal, config)
            elif proposal.test_type == "BFLA":
                finding = await run_differential_bfla(proposal, config)
            elif proposal.test_type in {AuthTestType.AUTH_MISSING_CREDENTIALS.value, "AUTH_MISSING_CREDENTIALS"}:
                finding = await run_authentication_test(proposal, config)
            else:
                # Unsupported in SPEC_DRIVEN mode
                finding = Finding(
                    test_id=proposal.test_id,
                    endpoint=proposal.endpoint,
                    evidence=Evidence(request={}, response={}),
                    severity=proposal.severity,
                    status=FindingStatus.NOT_EXECUTED,
                    execution_status=ExecutionStatus.NOT_EXECUTED,
                    assessment_outcome=AssessmentOutcome.INCONCLUSIVE,
                    notes=json.dumps({"reason": f"Test type '{proposal.test_type}' is not supported in SPEC_DRIVEN mode."}),
                )
            session_store.add_finding(session_id, finding)
            proposal.executed_at = datetime.now(timezone.utc)
            findings.append(finding)

    return findings
