"""Evidence integrity validator for security findings and human review.

Enforces strict verification of HTTP response evidence before a finding can be
marked CONFIRMED by human review. Ensures that evidence represents genuine,
completed execution responses and rejects arbitrary metadata, malformed data,
or findings inconsistent with vulnerability confirmation.
"""

import json
import re
from typing import Any, Dict, Optional, Tuple, Union

from fastapi import HTTPException

from ..models import AssessmentOutcome, ExecutionStatus, Finding

# Valid HTTP status code bounds
MIN_HTTP_STATUS = 100
MAX_HTTP_STATUS = 599

# HTTP status codes that legitimately have empty response bodies
EMPTY_BODY_ALLOWED_STATUSES = {204, 205, 304}

# Status codes that represent access denial and cannot confirm a vulnerability
ACCESS_DENIED_STATUS_CODES = {401, 403}

# Regex pattern to extract HTTP status code from evidence notes
_STATUS_CODE_NOTE_PATTERN = re.compile(
    r"(?:probe returned|baseline returned|HTTP)\s+(?:status\s+)?(\d{3})",
    re.IGNORECASE,
)


def extract_http_status_code(finding: Finding) -> Optional[int]:
    """Extract and parse the primary probe HTTP status code from a finding.

    Checks multiple sanctioned evidence locations:
    1. Direct `status_code` attribute in `finding.evidence.response`.
    2. Explicit `probe_status` in `finding.notes` JSON metadata.
    3. Step log status codes in `finding.notes["steps"]`.
    4. Text notes in `finding.evidence.notes`.

    Returns:
        Integer status code if found and parseable, None otherwise.
    """
    if not finding.evidence:
        return None

    resp = finding.evidence.response
    if isinstance(resp, dict) and "status_code" in resp:
        try:
            return int(resp["status_code"])
        except (ValueError, TypeError):
            return None

    # Check finding.notes JSON
    if finding.notes and isinstance(finding.notes, str):
        try:
            notes_meta = json.loads(finding.notes)
            if isinstance(notes_meta, dict):
                # Check probe_status
                if "probe_status" in notes_meta:
                    return int(notes_meta["probe_status"])

                # Check execution step logs
                steps = notes_meta.get("steps")
                if isinstance(steps, dict):
                    for step_key in ("lower_privileged_probe", "unauthenticated_probe", "cross_tenant_probe", "probe"):
                        step_data = steps.get(step_key)
                        if isinstance(step_data, dict) and "status_code" in step_data:
                            return int(step_data["status_code"])
        except (ValueError, TypeError, json.JSONDecodeError):
            pass

    # Check evidence.notes text
    if finding.evidence.notes and isinstance(finding.evidence.notes, str):
        match = _STATUS_CODE_NOTE_PATTERN.search(finding.evidence.notes)
        if match:
            try:
                return int(match.group(1))
            except (ValueError, TypeError):
                pass

    return None


def validate_human_review_evidence(finding: Finding) -> int:
    """Validate that finding evidence satisfies all integrity constraints for confirmation.

    Raises:
        HTTPException(status_code=400) if evidence is missing, invalid, or inconsistent.

    Returns:
        The validated integer HTTP status code.
    """
    # 1. Execution status check: only COMPLETED executions can be confirmed
    if finding.execution_status != ExecutionStatus.COMPLETED:
        raise HTTPException(
            status_code=400,
            detail=(
                f"Cannot confirm finding with execution status '{finding.execution_status}'. "
                f"Only COMPLETED executions can be confirmed as vulnerabilities."
            ),
        )

    # 2. Automated outcome consistency checks
    if finding.assessment_outcome == AssessmentOutcome.INCONCLUSIVE:
        raise HTTPException(
            status_code=400,
            detail="Cannot confirm finding when automated assessment outcome is INCONCLUSIVE (insufficient evidence).",
        )

    if finding.assessment_outcome == AssessmentOutcome.ACCESS_DENIED:
        raise HTTPException(
            status_code=400,
            detail="Cannot confirm finding when access was denied (endpoint enforced authorization boundary).",
        )

    # 3. Evidence presence check
    if not finding.evidence or not isinstance(finding.evidence.response, dict):
        raise HTTPException(
            status_code=400,
            detail="Cannot confirm finding without valid HTTP response evidence.",
        )

    resp = finding.evidence.response

    # 4. Extract and validate HTTP status code
    status_code = extract_http_status_code(finding)
    if status_code is None:
        raise HTTPException(
            status_code=400,
            detail="Cannot confirm finding without valid HTTP response evidence: missing or unverifiable HTTP status code.",
        )

    if not (MIN_HTTP_STATUS <= status_code <= MAX_HTTP_STATUS):
        raise HTTPException(
            status_code=400,
            detail=f"Cannot confirm finding without valid HTTP response evidence: invalid HTTP status code {status_code}.",
        )

    # 5. Access denial response status check (cannot confirm a 401 or 403 as a vulnerability)
    if status_code in ACCESS_DENIED_STATUS_CODES:
        raise HTTPException(
            status_code=400,
            detail=f"Cannot confirm finding when access was denied (endpoint enforced authorization boundary, HTTP {status_code}).",
        )

    # 6. Response body and execution step verification
    # Legitimate empty responses: 204 No Content, 205, 304
    is_empty_allowed = status_code in EMPTY_BODY_ALLOWED_STATUSES

    # Check whether response data is present
    has_body_key = "body" in resp
    has_content = bool(resp) and (not has_body_key or resp.get("body") is not None)

    # If completely empty dict and not an allowed empty status code
    if not resp and not is_empty_allowed:
        raise HTTPException(
            status_code=400,
            detail="Cannot confirm finding without valid HTTP response evidence.",
        )

    # If resp is just arbitrary metadata without status_code in resp and without step logs
    if "status_code" not in resp:
        has_step_log = False
        if finding.notes and isinstance(finding.notes, str):
            try:
                meta = json.loads(finding.notes)
                if isinstance(meta, dict) and isinstance(meta.get("steps"), dict):
                    has_step_log = True
            except Exception:
                pass

        if not has_step_log and not finding.evidence.notes:
            raise HTTPException(
                status_code=400,
                detail="Cannot confirm finding without valid HTTP response evidence: arbitrary metadata is not valid evidence.",
            )

    return status_code
