"""FastAPI entry point for API Security Assistant.

Provides a health check and an endpoint to parse a local OpenAPI specification file.
"""

import json
import yaml
from datetime import datetime, timezone
from fastapi.responses import JSONResponse
from pathlib import Path

from .config import MAX_SPEC_SIZE
from .models import (
    session_store,
    ProposedTest,
    TestStatus,
    FindingStatus,
    AssessmentOutcome,
    ExecutionStatus,
    HumanReviewOutcome,
    ReviewRecord,
    FindingReviewRequest,
    validate_assessment_outcome,
)

from .parser.openapi_parser import EndpointModel, parse_openapi
from .security.proposal_engine import generate_proposals
from .security.evidence_validator import validate_human_review_evidence



from fastapi import FastAPI, File, UploadFile, HTTPException, Header, Request, Response
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(title="API Security Assistant")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ],
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type", "X-Session-ID", "Accept", "Authorization"],
    expose_headers=["X-Session-ID", "Content-Disposition"],
)


@app.get("/health")
async def health() -> dict:
    return {"status": "ok"}


@app.post("/tests/propose")
async def propose_tests(
    request: Request,
    x_session_id: str = Header(..., alias="X-Session-ID"),
    include_auth: bool = False,
):
    """Generate security‑test proposals for a given OpenAPI endpoint inventory.

    Payload: Optional JSON array of endpoint objects matching :class:`EndpointModel` schema.
    If the payload is omitted or empty, the session's stored endpoint inventory is used.
    Header ``X-Session-ID`` identifies the session to store proposals.
    """
    # Validate session existence
    try:
        session = session_store.get_session(x_session_id)
    except KeyError:
        raise HTTPException(status_code=404, detail="Session not found")

    body = await request.body()
    data = None
    if body and body.strip():
        try:
            data = json.loads(body)
        except Exception as exc:
            raise HTTPException(status_code=400, detail=f"Invalid JSON payload: {exc}")

    if data is not None:
        if not isinstance(data, list) or len(data) == 0:
            raise HTTPException(status_code=400, detail="Endpoint inventory must be a non‑empty list")
        if len(data) > 1000:
            raise HTTPException(status_code=413, detail="Endpoint inventory too large")

        # Parse into EndpointModel objects (validation will raise)
        try:
            endpoints = [EndpointModel.model_validate(item) for item in data]
        except Exception as exc:
            raise HTTPException(status_code=400, detail=f"Invalid endpoint data: {exc}")
        session.set_endpoints(endpoints)
    else:
        endpoints = session.get_endpoints()
        if not endpoints:
            raise HTTPException(
                status_code=400,
                detail="Endpoint inventory must be a non-empty list or previously uploaded to this session",
            )

    proposals = generate_proposals(endpoints, include_auth_tests=include_auth)
    # Store proposals in the session
    for proposal in proposals:
        session_store.add_proposal(x_session_id, proposal)

    return [p.dict() for p in proposals]

@app.post("/tests/{test_id}/approve")
async def approve_test(test_id: str, x_session_id: str = Header(..., alias="X-Session-ID")):
    """Approve a proposed test. Transition PROPOSED → APPROVED.
    Records UTC timestamp in `approved_at`.
    """
    try:
        session = session_store.get_session(x_session_id)
    except KeyError:
        raise HTTPException(status_code=404, detail="Session not found")
    try:
        proposal: ProposedTest = session_store.get_proposal(x_session_id, test_id)
    except KeyError:
        raise HTTPException(status_code=404, detail="Proposal not found")
    if proposal.status != TestStatus.PROPOSED:
        raise HTTPException(status_code=400, detail="Only PROPOSED proposals can be approved")
    proposal.status = TestStatus.APPROVED
    proposal.approved_at = datetime.now(timezone.utc)
    return proposal.dict()

@app.get("/tests/{test_id}")
async def get_test(test_id: str, x_session_id: str = Header(..., alias="X-Session-ID")):
    """Retrieve a specific test proposal by ID within a session.
    Returns 404 if session or proposal not found.
    """
    try:
        session = session_store.get_session(x_session_id)
    except KeyError:
        raise HTTPException(status_code=404, detail="Session not found")
    try:
        proposal: ProposedTest = session_store.get_proposal(x_session_id, test_id)
    except KeyError:
        raise HTTPException(status_code=404, detail="Proposal not found")
    return proposal.dict()
@app.post("/tests/{test_id}/reject")
async def reject_test(test_id: str, x_session_id: str = Header(..., alias="X-Session-ID")):
    """Reject a proposed test. Transition PROPOSED → REJECTED.
    Records UTC timestamp in `rejected_at`.
    """
    try:
        session = session_store.get_session(x_session_id)
    except KeyError:
        raise HTTPException(status_code=404, detail="Session not found")
    try:
        proposal: ProposedTest = session_store.get_proposal(x_session_id, test_id)
    except KeyError:
        raise HTTPException(status_code=404, detail="Proposal not found")
    if proposal.status != TestStatus.PROPOSED:
        raise HTTPException(status_code=400, detail="Only PROPOSED proposals can be rejected")
    proposal.status = TestStatus.REJECTED
    proposal.rejected_at = datetime.now(timezone.utc)
    return proposal.dict()


@app.post("/parse-openapi")
async def parse_openapi_endpoint(file: UploadFile = File(...)):
    # Validate size (UploadFile may not have size attribute; read into memory with limit)
    contents = await file.read()
    if len(contents) > MAX_SPEC_SIZE:
        raise HTTPException(status_code=413, detail="Specification file too large (max 5 MB).")
    # Validate extension
    if not file.filename.lower().endswith((".json", ".yaml", ".yml")):
        raise HTTPException(status_code=400, detail="Unsupported file type. Use .json, .yaml, or .yml.")
    # Save to a secure temporary file on the local filesystem
    import tempfile
    with tempfile.NamedTemporaryFile(delete=False, suffix=Path(file.filename).suffix) as tmp:
        tmp.write(contents)
        temp_path = Path(tmp.name)
    try:
        # Parse using the existing OpenAPI parser; any validation errors raise ValueError
        endpoints = parse_openapi(str(temp_path))
        # Convert Pydantic models to plain dicts for a JSON‑serialisable response
        data = [e.dict() for e in endpoints]

        # Create a session for this API assessment and store the parsed inventory
        session_id = session_store.create_session()
        session_store.set_endpoints(session_id, endpoints)

        # Preserve the existing JSON array response for backward compatibility
        return JSONResponse(
            content=data,
            headers={"X-Session-ID": session_id}
        )
    except (ValueError, yaml.YAMLError, json.JSONDecodeError) as exc:
        # Surface parser validation problems as a 400 Bad Request
        raise HTTPException(status_code=400, detail=str(exc))
    finally:
        # Ensure the temporary file is removed regardless of success or failure
        if temp_path.exists():
            temp_path.unlink()


# ---------------------------------------------------------------------------
# Execution Engine Endpoints
# ---------------------------------------------------------------------------

from pydantic import BaseModel, Field
from .models import ExecuteRequest
from .security.execution_engine import execute_proposals

@app.post("/tests/execute")
async def execute_tests(request: ExecuteRequest, x_session_id: str = Header(..., alias="X-Session-ID")):
    """Execute approved test proposals for a session.

    Performs validation via ``execute_proposals`` and returns the created findings.
    """
    try:
        # Ensure session exists
        session_store.get_session(x_session_id)
    except KeyError:
        raise HTTPException(status_code=404, detail="Session not found")
    try:
        findings = await execute_proposals(
            x_session_id,
            request.proposal_ids,
            request.target,
            config=request.config,
        )
    except ValueError as ve:
        raise HTTPException(status_code=400, detail=str(ve))
    except PermissionError as pe:
        raise HTTPException(status_code=403, detail=str(pe))
    except KeyError:
        raise HTTPException(status_code=500, detail="Internal server error: unknown proposal ID")
    return [f.dict() for f in findings]

@app.get("/findings")
async def list_findings(x_session_id: str = Header(..., alias="X-Session-ID")):
    """Return all findings stored for the given session."""
    try:
        session = session_store.get_session(x_session_id)
    except KeyError:
        raise HTTPException(status_code=404, detail="Session not found")
    return [f.dict() for f in session.findings.values()]


@app.get("/findings/{finding_id}")
async def get_finding(
    finding_id: str,
    x_session_id: str = Header(..., alias="X-Session-ID"),
):
    """Retrieve a specific security finding by ID within the session."""
    try:
        session = session_store.get_session(x_session_id)
    except KeyError:
        raise HTTPException(status_code=404, detail="Session not found")
    try:
        finding = session.get_finding(finding_id)
    except KeyError:
        raise HTTPException(status_code=404, detail="Finding not found")
    return finding.dict()


@app.post("/findings/{finding_id}/review")
async def review_finding(
    finding_id: str,
    review: FindingReviewRequest,
    x_session_id: str = Header(..., alias="X-Session-ID"),
):
    """Human review workflow for confirming or dismissing a security finding.

    Strictly separates test execution from vulnerability confirmation:
    - Only explicit human review can mark a finding as CONFIRMED or FALSE_POSITIVE.
    - Automated algorithms, test runs, and differential comparisons CANNOT confirm vulnerabilities.
    - Unexecuted, failed, or inconclusive tests cannot be confirmed.
    - Full reviewer metadata and append-only review history are preserved.
    - NOTE: `reviewer_id` is a client-asserted audit identifier. The current backend
      does not authenticate reviewer identity.
    """
    try:
        session = session_store.get_session(x_session_id)
    except KeyError:
        raise HTTPException(status_code=404, detail="Session not found")
    try:
        finding = session.get_finding(finding_id)
    except KeyError:
        raise HTTPException(status_code=404, detail="Finding not found")

    # Validate execution status, evidence integrity, and outcome consistency
    if review.outcome == HumanReviewOutcome.CONFIRMED:
        validate_human_review_evidence(finding)

    # Validate human review constraints
    try:
        validate_assessment_outcome(
            AssessmentOutcome(review.outcome.value),
            is_human_review=True,
            reviewer_notes=review.reviewer_notes,
        )
    except ValueError as ve:
        raise HTTPException(status_code=400, detail=str(ve))

    # Append to immutable review history
    record = ReviewRecord(
        reviewer_id=review.reviewer_id,
        decision=review.outcome,
        notes=review.reviewer_notes,
        previous_outcome=finding.assessment_outcome.value if finding.assessment_outcome else None,
    )
    finding.review_history.append(record)

    # Apply human review decision
    finding.is_human_reviewed = True
    finding.reviewed_at = record.reviewed_at
    finding.reviewer_id = review.reviewer_id
    finding.reviewer_notes = review.reviewer_notes
    finding.requires_re_review = False

    if review.outcome == HumanReviewOutcome.CONFIRMED:
        finding.assessment_outcome = AssessmentOutcome.CONFIRMED
        finding.status = FindingStatus.CONFIRMED
    elif review.outcome == HumanReviewOutcome.FALSE_POSITIVE:
        finding.assessment_outcome = AssessmentOutcome.FALSE_POSITIVE
        finding.status = FindingStatus.FALSE_POSITIVE

    return finding.dict()


# ---------------------------------------------------------------------------
# Report Endpoints (Phase 2C)
# NOTE: Reports are stored in memory only and are lost on application restart.
# ---------------------------------------------------------------------------

from pydantic import BaseModel as _BaseModel

class ReportRequest(_BaseModel):
    target: str = Field(..., description="Base URL of the target that was tested")


from .security.report_engine import generate_report as _generate_report


@app.post("/reports")
async def create_report(
    request: ReportRequest,
    x_session_id: str = Header(..., alias="X-Session-ID"),
):
    """Generate a security assessment report from findings stored for this session.

    No HTTP requests are made during report generation.
    Reports are stored in memory and are not durable across application restarts.
    """
    try:
        session = session_store.get_session(x_session_id)
    except KeyError:
        raise HTTPException(status_code=404, detail="Session not found")

    report = _generate_report(session, request.target)
    session_store.add_report(x_session_id, report)
    return report.dict()


@app.get("/reports/{report_id}")
async def get_report(
    report_id: str,
    x_session_id: str = Header(..., alias="X-Session-ID"),
):
    """Retrieve a previously generated report belonging to the current session."""
    try:
        session = session_store.get_session(x_session_id)
    except KeyError:
        raise HTTPException(status_code=404, detail="Session not found")
    try:
        report = session.get_report(report_id)
    except KeyError:
        raise HTTPException(status_code=404, detail="Report not found")
    return report.dict()


from .security.pdf_export import generate_pdf_report as _generate_pdf_report
from .security.json_export import export_report_to_json as _export_report_to_json


@app.get("/reports/{report_id}/pdf")
async def get_report_pdf(
    report_id: str,
    x_session_id: str = Header(..., alias="X-Session-ID"),
):
    """Export an in-memory assessment report as a styled, paginated PDF document."""
    try:
        session = session_store.get_session(x_session_id)
    except KeyError:
        raise HTTPException(status_code=404, detail="Session not found")
    try:
        report = session.get_report(report_id)
    except KeyError:
        raise HTTPException(status_code=404, detail="Report not found")

    pdf_bytes = _generate_pdf_report(report)
    filename = f"report-{report_id}.pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Cache-Control": "no-cache, no-store, must-revalidate",
        },
    )


@app.get("/reports/{report_id}/json")
async def get_report_json(
    report_id: str,
    x_session_id: str = Header(..., alias="X-Session-ID"),
):
    """Export an in-memory assessment report as a structured, sanitized JSON document."""
    try:
        session = session_store.get_session(x_session_id)
    except KeyError:
        raise HTTPException(status_code=404, detail="Session not found")
    try:
        report = session.get_report(report_id)
    except KeyError:
        raise HTTPException(status_code=404, detail="Report not found")

    json_str = _export_report_to_json(report)
    filename = f"report-{report_id}.json"
    return Response(
        content=json_str,
        media_type="application/json",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Cache-Control": "no-cache, no-store, must-revalidate",
        },
    )

