"""Report generation engine for the API Security Testing Assistant.

Produces a structured, evidence-backed security assessment report from the
findings already stored for a given session.

Design constraints
------------------
- No HTTP requests are made during report generation.
- No findings are fabricated; only data already in the session is used.
- NOT_EXECUTED findings are listed separately and never marked as confirmed.
- All evidence included in the report has already been sanitized by the
  execution engine (no passwords, tokens, API keys, or authorization headers).
- Reports are held in memory and are NOT persisted across application restarts.

Test-category resolution
------------------------
``Finding.test_id`` is the same UUID that was assigned to the originating
``ProposedTest``.  When the session still holds the proposal, the engine
looks it up via ``session.proposals[finding.test_id]`` and copies the
``test_type`` string verbatim.  If the proposal has been removed or the
finding was inserted without a matching proposal (e.g. in tests), the
category falls back to ``"Unmatched"`` — an explicit, documented sentinel
that consumers can filter on.  The engine never invents a category.
"""

from typing import Dict, List, Optional

from ..models import (
    AssessmentOutcome,
    ExecutionStatus,
    Finding,
    FindingDetail,
    FindingStatus,
    ProposedTest,
    Report,
    Session,
    SeverityCounts,
    TestStatus,
)
from .sanitization import sanitize_data

# ---------------------------------------------------------------------------
# Remediation advice per test category
# ---------------------------------------------------------------------------
_REMEDIATION: Dict[str, str] = {
    "BOLA": (
        "Enforce object-level authorization on every request. Verify that the "
        "authenticated principal owns or has explicit access to the requested "
        "resource before returning any data."
    ),
    "BFLA": (
        "Apply function-level access controls using a server-side role or "
        "permission check. Never rely on client-supplied role claims alone."
    ),
    "ExcessiveData": (
        "Return only the fields the caller is authorized to see. Use response "
        "schemas or dedicated DTOs to filter out sensitive attributes before "
        "serializing the response."
    ),
    "MissingAuth": (
        "Require authentication for every endpoint that accesses or modifies "
        "non-public resources. Validate tokens server-side on every request."
    ),
    "AUTH_MISSING_CREDENTIALS": (
        "Enforce strict authentication on every protected endpoint. Reject unauthenticated "
        "requests with HTTP 401 Unauthorized before processing business logic or returning resource data."
    ),
    "MassAssignment": (
        "Bind only explicitly allowed fields from the incoming payload. Use an "
        "allowlist (whitelist) rather than mapping the entire request body to "
        "the domain object."
    ),
}

_DEFAULT_REMEDIATION = (
    "Review the affected endpoint for authorization, input validation, and "
    "data-exposure issues according to the OWASP API Security Top 10."
)

# Sentinel value used when a category cannot be recovered from the session.
# Documented here so callers can treat it as a known fallback, not a real category.
_CATEGORY_FALLBACK = "Unresolved (proposal unavailable)"

# ---------------------------------------------------------------------------
# Observed-behaviour descriptions per status
# ---------------------------------------------------------------------------
_BEHAVIOR_BY_STATUS: Dict[str, str] = {
    FindingStatus.SUSPECTED: (
        "The test produced a response that is consistent with the presence of "
        "a vulnerability, but confirmation requires manual review of the "
        "sanitized evidence."
    ),
    FindingStatus.CONFIRMED: (
        "The test response conclusively demonstrates the vulnerability. "
        "Immediate remediation is recommended."
    ),
    FindingStatus.FALSE_POSITIVE: (
        "The initial indicator was investigated and determined not to represent "
        "a real vulnerability in the target."
    ),
    FindingStatus.NOT_EXECUTED: (
        "This test was not executed. No HTTP request was sent and no evidence "
        "was collected."
    ),
}


def _severity_bucket(severity: str) -> str:
    """Normalise severity string to a canonical bucket name."""
    return severity.strip().lower()


def _build_severity_counts(findings: List[Finding]) -> SeverityCounts:
    counts = SeverityCounts()
    for f in findings:
        bucket = _severity_bucket(f.severity)
        if bucket == "critical":
            counts.critical += 1
        elif bucket == "high":
            counts.high += 1
        elif bucket == "medium":
            counts.medium += 1
        elif bucket == "low":
            counts.low += 1
        else:
            counts.unknown += 1
    return counts


def _evidence_summary(finding: Finding) -> dict:
    """Return a minimal, already-sanitized summary of the finding's evidence.

    The execution engine has already redacted credentials; this function
    further limits what appears in the report to avoid unnecessary data.
    """
    resp = finding.evidence.response or {}
    sanitized_resp = sanitize_data(resp)
    req = finding.evidence.request or {}
    sanitized_req = sanitize_data(req)

    summary = {
        "status_code": sanitized_resp.get("status_code"),
        # Include the body only when it is a non-empty dict (JSON response).
        # Raw text bodies may be large; we omit them from the report summary.
        "response_body_present": bool(sanitized_resp.get("body")),
    }
    if sanitized_req.get("headers"):
        summary["sanitized_request_headers"] = sanitized_req.get("headers")
    return summary


def _resolve_category(
    finding: Finding,
    proposals: Dict[str, ProposedTest],
) -> str:
    """Recover the test category for *finding* using the session's proposal index.

    Resolution order:
    1. Look up the matching ``ProposedTest`` by ``finding.test_id`` and return
       its ``test_type`` directly — this is the authoritative source.
    2. If no proposal is found, return ``_CATEGORY_FALLBACK`` ("Unresolved (proposal unavailable)").
       The caller should not treat this as a real vulnerability category.
    """
    proposal = proposals.get(finding.test_id)
    if proposal is not None:
        return proposal.test_type
    return _CATEGORY_FALLBACK


def _build_finding_detail(
    finding: Finding,
    proposals: Dict[str, ProposedTest],
) -> FindingDetail:
    """Convert a ``Finding`` into a ``FindingDetail`` for the report.

    *proposals* is the session's ``{test_id: ProposedTest}`` mapping and is
    used to recover the test category and category-specific remediation text.
    """
    category = _resolve_category(finding, proposals)
    remediation = finding.remediation or _REMEDIATION.get(category, _DEFAULT_REMEDIATION)

    limitations_list = []
    if category == _CATEGORY_FALLBACK:
        limitations_list.append(
            "The originating test proposal was not found in the session. "
            "The test category could not be determined reliably."
        )
    if finding.is_human_reviewed and finding.assessment_outcome == AssessmentOutcome.CONFIRMED:
        limitations_list.append(f"Vulnerability confirmed via human review by {finding.reviewer_id or 'analyst'}.")
    elif finding.is_human_reviewed and finding.assessment_outcome == AssessmentOutcome.FALSE_POSITIVE:
        limitations_list.append(f"Investigated and determined to be a false positive by {finding.reviewer_id or 'analyst'}.")
    elif finding.status == FindingStatus.SUSPECTED or finding.assessment_outcome == AssessmentOutcome.SUSPECTED:
        limitations_list.append(
            "The finding status is SUSPECTED. Manual review of the evidence "
            "is required before treating this as a confirmed vulnerability."
        )
    elif finding.status == FindingStatus.NOT_EXECUTED or finding.execution_status == ExecutionStatus.NOT_EXECUTED:
        limitations_list.append("No evidence was collected because the test was not executed.")

    # Resolve status and outcome values cleanly with veracity guard
    status_str = finding.status.value if hasattr(finding.status, "value") else str(finding.status)
    outcome_str = finding.assessment_outcome.value if finding.assessment_outcome else None

    # Veracity Guard: CONFIRMED strictly requires human review
    if (status_str.upper() == "CONFIRMED" or (outcome_str and outcome_str.upper() == "CONFIRMED")) and not finding.is_human_reviewed:
        status_str = FindingStatus.SUSPECTED.value
        outcome_str = AssessmentOutcome.SUSPECTED.value
        limitations_list.append(
            "Veracity Guard: This finding was recorded as confirmed without an explicit human review record. "
            "It has been strictly constrained to SUSPECTED in accordance with verification policy."
        )

    limitations = " ".join(limitations_list) if limitations_list else None

    has_retest = bool(
        finding.requires_re_review
        or any(
            (getattr(r, "retest_run", False) if not isinstance(r, dict) else r.get("retest_run", False))
            for r in (finding.review_history or [])
        )
    )
    remediation_status = (
        "Retest Executed (Updated network evidence collected)"
        if has_retest
        else "Unverified Recommendation (Pending retest execution)"
    )

    return FindingDetail(
        finding_id=finding.finding_id,
        title=f"{finding.severity} severity finding on {finding.endpoint.path}",
        test_category=category,
        endpoint_path=finding.endpoint.path,
        endpoint_method=finding.endpoint.method,
        severity=finding.severity,
        status=status_str,
        evidence_summary=_evidence_summary(finding),
        observed_behavior=_BEHAVIOR_BY_STATUS.get(
            finding.status, "No behavioral description available."
        ),
        recommended_remediation=remediation,
        remediation_status=remediation_status,
        limitations=limitations,
        execution_status=finding.execution_status.value if finding.execution_status else None,
        assessment_outcome=outcome_str,
        assessment_reason=finding.assessment_reason or finding.notes,
        is_human_reviewed=finding.is_human_reviewed,
        reviewer_id=finding.reviewer_id,
        reviewed_at=finding.reviewed_at,
        reviewer_notes=finding.reviewer_notes,
        requires_re_review=finding.requires_re_review,
        review_history=[r.model_dump() if hasattr(r, "model_dump") else (r.dict() if hasattr(r, "dict") else r) for r in finding.review_history],
    )


def _build_assessment_summary(
    executed: List[Finding],
    failed: List[Finding],
    not_executed: List[Finding],
    target: str,
    pending_review: int = 0,
) -> str:
    total = len(executed) + len(failed) + len(not_executed)
    if total == 0:
        return (
            f"No security tests were executed against {target}. "
            "Approve and execute proposals before generating a report."
        )
    parts = [
        f"Assessment completed against target {target}. "
        f"{len(executed)} test(s) produced findings; "
        f"{len(failed)} test(s) failed during execution; "
        f"{len(not_executed)} test(s) were not executed."
    ]
    suspected = sum(1 for f in executed if f.status == FindingStatus.SUSPECTED or f.assessment_outcome == AssessmentOutcome.SUSPECTED)
    confirmed = sum(1 for f in executed if f.status == FindingStatus.CONFIRMED or f.assessment_outcome == AssessmentOutcome.CONFIRMED)
    if confirmed:
        parts.append(f"{confirmed} finding(s) are CONFIRMED and require immediate attention.")
    if suspected:
        parts.append(f"{suspected} finding(s) are SUSPECTED and require manual review.")
    if pending_review:
        parts.append(f"{pending_review} finding(s) currently await human review.")
    parts.append(
        "All evidence has been sanitized; no credentials or secrets are included in this report."
    )
    return " ".join(parts)


def generate_report(session: Session, target_base_url: str) -> Report:
    """Generate a ``Report`` from the findings already stored in *session*.

    This function:
    - Does **not** perform any HTTP requests.
    - Does **not** fabricate findings.
    - Accurately distinguishes completed, failed, and unexecuted tests.
    - Marks suspected findings clearly as requiring manual review.
    - Computes verified execution statistics.
    - Resolves test categories from the session's proposal index (``Finding.test_id``
      == ``ProposedTest.test_id``).  Falls back to ``"Unresolved (proposal unavailable)"`` when the
      proposal is absent; never guesses or invents a category.
    """
    all_findings = list(session.findings.values())

    failed = [
        f for f in all_findings
        if f.execution_status == ExecutionStatus.FAILED
    ]
    not_executed = [
        f for f in all_findings
        if f.execution_status == ExecutionStatus.NOT_EXECUTED
        or (f.execution_status is None and f.status == FindingStatus.NOT_EXECUTED)
    ]
    executed = [
        f for f in all_findings
        if f not in not_executed and f not in failed
    ]

    severity_counts = _build_severity_counts(executed)
    finding_details = [
        _build_finding_detail(f, session.proposals) for f in executed
    ]
    not_executed_ids = [f.finding_id for f in not_executed]
    failed_ids = [f.finding_id for f in failed]

    # Proposals breakdown
    proposed_tests = sum(
        1 for p in session.proposals.values() if p.status == TestStatus.PROPOSED
    )
    approved_tests = sum(
        1 for p in session.proposals.values() if p.status == TestStatus.APPROVED
    )
    rejected_tests = sum(
        1 for p in session.proposals.values() if p.status == TestStatus.REJECTED
    )

    # Unsupported tests: recorded as NOT_EXECUTED with "unsupported" in notes or matching known unsupported test types
    unsupported_tests = sum(
        1 for f in not_executed
        if "unsupported" in (f.notes or "").lower()
        or (session.proposals.get(f.test_id) and session.proposals.get(f.test_id).test_type in ["MassAssignment", "ExcessiveData"])
    )

    # Veracity-checked outcome counts
    confirmed_findings = sum(
        1 for f in all_findings
        if (f.assessment_outcome == AssessmentOutcome.CONFIRMED or f.status == FindingStatus.CONFIRMED)
        and f.is_human_reviewed
    )
    suspected_findings = sum(
        1 for f in all_findings
        if (f.assessment_outcome == AssessmentOutcome.SUSPECTED or (f.status == FindingStatus.SUSPECTED and f.assessment_outcome is None))
        or ((f.assessment_outcome == AssessmentOutcome.CONFIRMED or f.status == FindingStatus.CONFIRMED) and not f.is_human_reviewed)
    )
    false_positive_findings = sum(
        1 for f in all_findings
        if (f.assessment_outcome == AssessmentOutcome.FALSE_POSITIVE or f.status == FindingStatus.FALSE_POSITIVE)
        and f.is_human_reviewed
    )
    access_denied_findings = sum(
        1 for f in all_findings
        if f.assessment_outcome == AssessmentOutcome.ACCESS_DENIED
    )
    inconclusive_findings = sum(
        1 for f in all_findings
        if f.assessment_outcome == AssessmentOutcome.INCONCLUSIVE
    )

    # Compute execution and review statistics
    pending_review = sum(
        1 for f in all_findings
        if (f.assessment_outcome == AssessmentOutcome.SUSPECTED or f.status == FindingStatus.SUSPECTED or f.requires_re_review)
        and not f.is_human_reviewed
    )

    execution_statistics = {
        "total_proposals": len(session.proposals),
        "proposed_tests": proposed_tests,
        "approved_tests": approved_tests,
        "rejected_tests": rejected_tests,
        "total_findings": len(all_findings),
        "executed_tests": len(executed),
        "completed_tests": sum(1 for f in all_findings if f.execution_status == ExecutionStatus.COMPLETED or (f.execution_status is None and f.status != FindingStatus.NOT_EXECUTED)),
        "failed_tests": len(failed),
        "unsupported_tests": unsupported_tests,
        "not_executed_tests": len(not_executed),
        "suspected_findings": suspected_findings,
        "confirmed_findings": confirmed_findings,
        "false_positive_findings": false_positive_findings,
        "access_denied_findings": access_denied_findings,
        "inconclusive_findings": inconclusive_findings,
        "pending_review": pending_review,
    }

    summary = _build_assessment_summary(
        executed=executed,
        failed=failed,
        not_executed=not_executed,
        target=target_base_url,
        pending_review=pending_review,
    )

    endpoints_cataloged = [
        {"method": ep.method, "path": ep.path}
        for ep in (session.endpoints or [])
    ]

    retested_findings = [
        f for f in all_findings
        if f.requires_re_review
        or any(
            (getattr(r, "retest_run", False) if not isinstance(r, dict) else r.get("retest_run", False))
            for r in (f.review_history or [])
        )
    ]
    retested_count = len(retested_findings)

    if retested_count == 0:
        retesting_guidance = (
            "Initial Assessment Run — No retest execution has been conducted in this session. "
            "All suggested remediations are unverified advisory recommendations. "
            "To verify a fix, deploy the patch and re-execute the approved test proposals."
        )
    else:
        retesting_guidance = (
            f"Retest Assessment Run — {retested_count} finding(s) have undergone repeat network execution. "
            "Fresh execution evidence invalidates prior review decisions and requires operator re-review."
        )

    methodology = (
        "Automated differential security probes with human-in-the-loop verification. "
        "Tests detect Broken Object Level Authorization (BOLA), Broken Function Level "
        "Authorization (BFLA), and Missing Credentials. Scanners never mark findings CONFIRMED autonomously."
    )

    return Report(
        session_id=session.session_id,
        target_base_url=target_base_url,
        assessment_summary=summary,
        severity_counts=severity_counts,
        finding_details=finding_details,
        not_executed_tests=not_executed_ids,
        failed_tests=failed_ids,
        execution_statistics=execution_statistics,
        pending_review_count=pending_review,
        endpoints_cataloged=endpoints_cataloged,
        retesting_guidance=retesting_guidance,
        methodology=methodology,
    )
