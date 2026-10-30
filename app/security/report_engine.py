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
    return {
        "status_code": sanitized_resp.get("status_code"),
        # Include the body only when it is a non-empty dict (JSON response).
        # Raw text bodies may be large; we omit them from the report summary.
        "response_body_present": bool(sanitized_resp.get("body")),
    }


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

    limitations = " ".join(limitations_list) if limitations_list else None

    # Resolve status value cleanly
    status_str = finding.status.value if hasattr(finding.status, "value") else str(finding.status)

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
        limitations=limitations,
        execution_status=finding.execution_status.value if finding.execution_status else None,
        assessment_outcome=finding.assessment_outcome.value if finding.assessment_outcome else None,
        assessment_reason=finding.assessment_reason or finding.notes,
        is_human_reviewed=finding.is_human_reviewed,
        reviewer_id=finding.reviewer_id,
        reviewed_at=finding.reviewed_at,
        reviewer_notes=finding.reviewer_notes,
        requires_re_review=finding.requires_re_review,
        review_history=[r.dict() if hasattr(r, "dict") else r for r in finding.review_history],
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

    # Compute execution and review statistics
    pending_review = sum(
        1 for f in all_findings
        if (f.assessment_outcome == AssessmentOutcome.SUSPECTED or f.status == FindingStatus.SUSPECTED or f.requires_re_review)
        and not f.is_human_reviewed
    )

    execution_statistics = {
        "total_proposals": len(session.proposals),
        "total_findings": len(all_findings),
        "executed_tests": len(executed),
        "completed_tests": sum(1 for f in all_findings if f.execution_status == ExecutionStatus.COMPLETED or (f.execution_status is None and f.status != FindingStatus.NOT_EXECUTED)),
        "failed_tests": len(failed),
        "not_executed_tests": len(not_executed),
        "suspected_findings": sum(1 for f in all_findings if f.assessment_outcome == AssessmentOutcome.SUSPECTED or (f.status == FindingStatus.SUSPECTED and f.assessment_outcome is None)),
        "confirmed_findings": sum(1 for f in all_findings if f.assessment_outcome == AssessmentOutcome.CONFIRMED or f.status == FindingStatus.CONFIRMED),
        "false_positive_findings": sum(1 for f in all_findings if f.assessment_outcome == AssessmentOutcome.FALSE_POSITIVE or f.status == FindingStatus.FALSE_POSITIVE),
        "pending_review": pending_review,
    }

    summary = _build_assessment_summary(
        executed=executed,
        failed=failed,
        not_executed=not_executed,
        target=target_base_url,
        pending_review=pending_review,
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
    )
