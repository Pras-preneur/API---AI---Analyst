"""AI/ML Service Adapter bridging main backend Finding models with ML/SLM reasoning."""

import re
import json
from typing import Dict, Any, Optional

from app.models import Finding, AssessmentOutcome, session_store
from app.security.sanitization import sanitize_string
from app.ai.schemas import (
    SecurityFindingInput,
    FindingAnalysisOutput,
    ChatMessageRequest,
    SLMStructuredResponse,
)
from app.ai.analyst.chatbot import analyze_finding
from app.ai.slm.engine import slm_engine
from app.ai.slm.report_generator import report_generator


def sanitize_text_evidence(text: str) -> str:
    """Redact tokens, bearer strings, and credentials from textual evidence."""
    if not text:
        return ""
    # Redact Authorization headers or Bearer tokens
    redacted = re.sub(r"(Bearer\s+)[A-Za-z0-9_\-\.]{8,}", r"\1[REDACTED_TOKEN]", text, flags=re.IGNORECASE)
    # Redact passwords, secrets, api keys
    redacted = re.sub(r'("(?:password|secret|api_key|token|auth)"\s*:\s*)"[^"]+"', r'\1"[REDACTED]"', redacted, flags=re.IGNORECASE)
    return sanitize_string(redacted)


def finding_to_ml_features(finding: Finding) -> Dict[str, str]:
    """Map real backend Finding object into categorical features for Random Forest classifier."""
    endpoint = getattr(finding, "endpoint", None)
    if endpoint is not None:
        path = str(getattr(endpoint, "path", "")).lower()
        method = str(getattr(endpoint, "method", "GET")).upper()
    else:
        path = str(getattr(finding, "endpoint_path", "")).lower()
        method = str(getattr(finding, "endpoint_method", "GET")).upper()

    context_text = f"{getattr(finding, 'test_id', '')} {getattr(finding, 'test_category', '')} {getattr(finding, 'assessment_reason', '')} {getattr(finding, 'remediation', '')} {path}".lower()

    if "bola" in context_text or "idor" in context_text:
        finding_type = "bola"
    elif "bfla" in context_text or "function" in context_text or "admin" in path:
        finding_type = "bfla"
    elif "mass" in context_text or "assignment" in context_text or "property" in context_text:
        finding_type = "mass_assignment"
    elif "disclosure" in context_text or "leak" in context_text or "env" in path or "metrics" in path:
        finding_type = "information_disclosure"
    elif "auth" in context_text:
        finding_type = "bola"
    else:
        finding_type = "other"

    if finding.is_human_reviewed and finding.assessment_outcome == AssessmentOutcome.CONFIRMED:
        evidence_confidence = "high"
    elif finding.assessment_outcome in [AssessmentOutcome.SUSPECTED, getattr(AssessmentOutcome, "SUSPECTED_VULNERABILITY", AssessmentOutcome.SUSPECTED)]:
        evidence_confidence = "high"
    else:
        evidence_confidence = "medium"

    if any(k in path for k in ["internal", "admin", "debug", "private", "actuator"]):
        exposure = "internal"
    else:
        exposure = "internet_facing"

    if any(k in path for k in ["statement", "account", "user", "billing", "payment", "card", "credential", "auth"]):
        data_sensitivity = "sensitive"
    elif any(k in path for k in ["tenant", "org", "company", "export"]):
        data_sensitivity = "business"
    elif "public" in path:
        data_sensitivity = "public"
    else:
        data_sensitivity = "business"

    auth_required = "true" if ("auth" in context_text or "admin" in path or (endpoint and getattr(endpoint, "auth_required", False))) else "false"

    sev = str(getattr(finding, "severity", "medium")).upper()
    if sev in ["CRITICAL", "P1"]:
        exploitability = "high"
    elif sev in ["HIGH", "P2"]:
        exploitability = "medium"
    else:
        exploitability = "low"

    return {
        "finding_type": finding_type,
        "evidence_confidence": evidence_confidence,
        "exposure": exposure,
        "data_sensitivity": data_sensitivity,
        "auth_required": auth_required,
        "exploitability": exploitability,
    }


def finding_to_security_input(finding: Finding) -> SecurityFindingInput:
    """Convert a backend Finding model to a sanitized SecurityFindingInput schema."""
    features = finding_to_ml_features(finding)

    endpoint = getattr(finding, "endpoint", None)
    if endpoint is not None:
        path = str(getattr(endpoint, "path", "/api/endpoint"))
        method = str(getattr(endpoint, "method", "GET")).upper()
    else:
        path = str(getattr(finding, "endpoint_path", "/api/endpoint"))
        method = str(getattr(finding, "endpoint_method", "GET")).upper()

    fid = getattr(finding, "finding_id", getattr(finding, "id", "finding-unknown"))

    evidence_str = ""
    evidence = getattr(finding, "evidence", None)
    if evidence is not None:
        summary_parts = []
        resp = getattr(evidence, "response", {})
        if isinstance(resp, dict):
            status = resp.get("status_code") or resp.get("status")
            if status:
                summary_parts.append(f"HTTP Status: {status}")
            body = resp.get("body")
            if body:
                summary_parts.append(sanitize_text_evidence(str(body)[:300]))

        if getattr(evidence, "notes", None):
            summary_parts.append(sanitize_text_evidence(str(evidence.notes)[:200]))

        evidence_str = " | ".join(summary_parts) or "Evidence recorded by differential scanner."

    verdict_str = finding.assessment_outcome.value if finding.assessment_outcome else finding.status.value

    valid_methods = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"]
    chosen_method = method if method in valid_methods else "GET"

    return SecurityFindingInput(
        finding_id=fid,
        scanner_verdict=f"Scanner Verdict: {verdict_str}",
        finding_type=features["finding_type"],
        evidence_confidence=features["evidence_confidence"],
        exposure=features["exposure"],
        data_sensitivity=features["data_sensitivity"],
        auth_required=features["auth_required"],
        exploitability=features["exploitability"],
        endpoint=path,
        http_method=chosen_method,
        evidence=evidence_str,
        description=finding.assessment_reason or f"Automated differential security finding on {path}",
    )


def analyze_security_finding_service(finding_input: SecurityFindingInput) -> FindingAnalysisOutput:
    """Analyze finding via ML priority classifier and SLM reasoning engine."""
    raw_res = analyze_finding(finding_input.model_dump())
    return FindingAnalysisOutput.model_validate(raw_res)


def process_chat_service(request: ChatMessageRequest, session_id: Optional[str] = None) -> SLMStructuredResponse:
    """Process user prompt using ZYNORA SLM Engine with live session intelligence."""
    ctx = dict(request.context or {})
    sid = session_id or ctx.get("sessionId") or ctx.get("session_id")
    live_session_data = None

    if sid:
        with session_store._lock:
            if sid in session_store._sessions:
                s = session_store._sessions[sid]
                endpoints = s.get_endpoints()
                proposals = list(s.proposals.values())
                findings = list(s.findings.values())
                reports = list(s.reports.values())

                live_session_data = {
                    "session_id": sid,
                    "endpoints": [
                        {
                            "method": ep.method,
                            "path": ep.path,
                            "summary": ep.summary or "",
                            "tags": ep.tags or [],
                        }
                        for ep in endpoints
                    ],
                    "proposals": [
                        {
                            "test_id": p.test_id,
                            "method": p.endpoint.method,
                            "path": p.endpoint.path,
                            "test_type": p.test_type,
                            "severity": p.severity,
                            "status": p.status.value,
                            "description": p.description,
                            "executed_at": p.executed_at.isoformat() if p.executed_at else None,
                        }
                        for p in proposals
                    ],
                    "findings": [
                        {
                            "finding_id": f.finding_id,
                            "test_id": f.test_id,
                            "method": f.endpoint.method if f.endpoint else "",
                            "path": f.endpoint.path if f.endpoint else "",
                            "vulnerability_type": getattr(f, "vulnerability_type", getattr(f, "test_category", "Security Finding")),
                            "severity": f.severity,
                            "status": f.status.value,
                            "assessment_outcome": f.assessment_outcome.value if f.assessment_outcome else f.status.value,
                            "assessment_reason": f.assessment_reason or "",
                            "evidence": f.evidence.model_dump() if f.evidence else {},
                            "is_human_reviewed": f.is_human_reviewed,
                            "reviewer_notes": f.reviewer_notes or "",
                        }
                        for f in findings
                    ],
                    "reports": [
                        {
                            "report_id": r.report_id,
                            "title": r.title,
                            "created_at": r.created_at.isoformat() if hasattr(r, "created_at") and r.created_at else None,
                        }
                        for r in reports
                    ]
                }

    ctx["session_id"] = sid
    if live_session_data is not None:
        ctx["live_session"] = live_session_data

    res = slm_engine.process_chat(request.message, ctx)
    return SLMStructuredResponse.model_validate(res)


def generate_document_service(
    report_type: str,
    spec_title: str = "API Security Assessment",
    endpoints_count: int = 5,
    findings: Optional[list] = None,
    context: Optional[dict] = None
) -> dict:
    """Generate multi-format publication report document."""
    return report_generator.generate_report(
        report_type=report_type,
        spec_title=spec_title,
        endpoints_count=endpoints_count,
        findings=findings,
        context=context,
    )
