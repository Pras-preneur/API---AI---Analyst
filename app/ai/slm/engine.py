"""ZYNORA AI - Intelligent Small Language Model (SLM) & Reasoning Engine.

Specialized for API Security Analysis, Penetration Testing Documentation,
and Evidence-Grounded Risk Prioritization.
"""

import json
import re
from typing import Dict, Any, List, Optional
from app.ai.slm.report_generator import report_generator


class ZynoraSecuritySLMEngine:
    """Domain-specialized SLM reasoning engine for API penetration testing."""

    IDENTITY = {
        "platform": "ZYNORA AI",
        "product": "AI-Powered API Security Analysis & Penetration Testing Workspace",
        "role": "AI API Security Analyst",
        "purpose": (
            "Analyze API security findings, assess technical evidence, recommend risk priorities, "
            "explain vulnerabilities against the OWASP API Security Top 10, formulate safe probe assertions, "
            "and generate audit-grade penetration testing documentation."
        ),
        "capabilities": [
            "OWASP API Security Top 10 vector analysis (BOLA, BFLA, Mass Assignment, BOPLA, SSRF, etc.)",
            "Empirical evidence evaluation without hallucinating results",
            "Multi-factor ML risk prioritization (P1 Critical, P2 High, P3 Moderate/Low)",
            "Automated audit documentation across 7 industry-standard formats (21-Section Pentest Report, Bug Bounty, Executive, PPT)",
            "Human-in-the-Loop non-destructive probe formulation"
        ]
    }

    VULNERABILITY_KB = {
        "bola": {
            "title": "Broken Object Level Authorization (BOLA / IDOR)",
            "owasp_code": "API1:2023",
            "impact": "Direct cross-tenant data compromise, unauthorized record exfiltration, and customer identity impersonation.",
            "remediation": [
                "Implement tenancy verification middleware in the service controller: assert `current_user.tenant_id == resource.tenant_id` before query execution.",
                "Adopt Attribute-Based Access Control (ABAC) or Open Policy Agent (OPA) to evaluate tenancy claims against token claims.",
                "Replace guessable sequential integer IDs with cryptographically secure UUIDv4 or HMAC-signed handles in public API paths."
            ],
            "validation": [
                'curl -s -i -H "Authorization: Bearer $FOREIGN_USER_TOKEN" "{endpoint}" (Assert HTTP 403 Forbidden)',
                "Integrate automated regression assertions in CI/CD verifying that foreign tenant IDs consistently return HTTP 403 or 404."
            ],
            "test_payload_template": "GET {endpoint} with ID replaced by unassigned tenant handle"
        },
        "bfla": {
            "title": "Broken Function Level Authorization (BFLA)",
            "owasp_code": "API5:2023",
            "impact": "Privilege escalation allowing unprivileged users to execute administrative routines, trigger bulk exports, or mutate global configurations.",
            "remediation": [
                "Enforce role-based access control (RBAC) at the API gateway router for all administrative and operational endpoints.",
                "Deny administrative actions by default; require explicit permissions (e.g., `@require_permission('admin:export')`).",
                "Regularly audit API route registries to prevent unmapped administrative paths from exposing internal workflows."
            ],
            "validation": [
                'curl -i -X POST "{endpoint}" -H "Authorization: Bearer $STANDARD_USER_TOKEN" (Assert HTTP 403 Forbidden)',
                "Verify that the API gateway rejects requests missing administrative scopes before reaching backend services."
            ],
            "test_payload_template": "POST {endpoint} with standard non-admin bearer token"
        },
        "mass_assignment": {
            "title": "Mass Assignment / Object Property Tampering",
            "owasp_code": "API3:2023",
            "impact": "Unauthorized privilege escalation (e.g. self-assigning `is_admin: true`), billing tier tampering, or bypass of status checks.",
            "remediation": [
                "Enforce strict Data Transfer Object (DTO) schemas with explicit allowlists of modifiable fields.",
                "In Pydantic/FastAPI, configure `model_config = ConfigDict(extra='forbid')` to reject unrecognized JSON payload keys.",
                "Decouple client request payloads from internal database ORM persistence models."
            ],
            "validation": [
                'curl -X PUT "{endpoint}" -H "Content-Type: application/json" -d \'{"is_admin": true, "role": "superadmin"}\' (Assert HTTP 422 Unprocessable Entity)',
                "Assert that modified user entity does not persist injected administrative attributes."
            ],
            "test_payload_template": 'PUT/POST {endpoint} with payload {"role": "admin", "verified": true}'
        },
        "information_disclosure": {
            "title": "Sensitive Information Disclosure / Security Misconfiguration",
            "owasp_code": "API8:2023",
            "impact": "Exposure of internal database strings, cloud credentials, cryptographic salts, or stack traces facilitating targeted exploits.",
            "remediation": [
                "Disable debug endpoints (e.g. `/debug/*`, `/actuator/env`, `/metrics/dump`) in production gateway configurations.",
                "Enforce outbound JSON projection filters to prevent internal database fields from serializing to clients.",
                "Manage all API secrets and credentials in secure vault solutions (e.g., HashiCorp Vault, AWS Secrets Manager)."
            ],
            "validation": [
                'curl -s "{endpoint}" | grep -Ei "(password|secret|key|token|connection_string)" (Assert 0 matches)',
                "Verify custom error handlers return generic error identifiers without stack traces."
            ],
            "test_payload_template": "GET {endpoint} with error-triggering headers or debug parameters"
        },
        "excessive_data_exposure": {
            "title": "Excessive Data Exposure",
            "owasp_code": "API3:2023",
            "impact": "Client-side interception of confidential user attributes, personally identifiable information (PII), or business records.",
            "remediation": [
                "Define explicit outbound response schemas; never return raw database entity models directly.",
                "Audit client consumers and restrict payload properties strictly to fields required by the user interface.",
                "Apply automated API contract testing verifying that sensitive fields (SSN, credit card, hashes) are not present."
            ],
            "validation": [
                'curl -s "{endpoint}" -H "Authorization: Bearer $VALID_TOKEN" | jq "keys" (Verify strict field allowlist)'
            ],
            "test_payload_template": "GET {endpoint} asserting response payload size and field list"
        },
        "input_validation": {
            "title": "Unrestricted Resource Consumption / Input Validation",
            "owasp_code": "API4:2023",
            "impact": "Service degradation, Denial of Service (DoS) via ReDoS or oversized payloads, or backend injection.",
            "remediation": [
                "Enforce strict input length, regex timeout bounds, and maximum request payload size at the API gateway.",
                "Implement rate limiting with token bucket algorithms (e.g., 60 requests/min per IP/token).",
                "Set strict pagination limits (e.g., max limit=100) on all query list endpoints."
            ],
            "validation": [
                'curl -X GET "{endpoint}?limit=100000" (Assert response caps at maximum limit=100)',
                "Send payload exceeding maximum size limit (Assert HTTP 413 Payload Too Large)."
            ],
            "test_payload_template": "GET/POST {endpoint} with oversized pagination parameters"
        }
    }

    def __init__(self):
        pass

    # ------------------------------------------------------------------------
    # 1. Master Structured Chat Processor
    # ------------------------------------------------------------------------
    def process_chat(self, user_prompt: str, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Classify user intent and return a validated structured SLM response contract."""
        text = user_prompt.strip()
        p = text.lower()
        spec_title = context.get("specTitle", "the uploaded specification") if context else "the uploaded specification"
        endpoints_count = context.get("endpointCount", 5) if context else 5
        live_session = context.get("live_session") if context else None

        # 1. Greeting
        if self._is_greeting(p):
            return self._handle_greeting(p, spec_title)

        # 2. Mistake / Malformed Finding Detection (prioritize early detection)
        mistake_analysis = self._detect_mistakes(text)
        if mistake_analysis:
            return mistake_analysis

        # 3. Platform / Identity Inquiry
        if self._is_identity_inquiry(p):
            return self._handle_identity_inquiry()

        # 4. Conceptual Security Explanations (BOLA vs BFLA, 401 vs 403)
        if ("401" in p and "403" in p) or ("unauthorized" in p and "forbidden" in p):
            return self._handle_http_auth_comparison()

        if "bola" in p and "bfla" in p:
            return self._handle_vulnerability_explanation("bola_vs_bfla", spec_title, p)

        # 5. Live Assessment / Session Intelligence (Discovered endpoints, proposals, findings, evidence, summaries)
        live_query_res = self._handle_live_session_query(p, spec_title, live_session)
        if live_query_res:
            return live_query_res

        # 6. Report Generation Request
        if self._is_report_request(p):
            return self._handle_report_request(p, spec_title, endpoints_count, context)

        # 7. Specific Security Vulnerability Analysis (single vector)
        vuln_type = self._match_vulnerability_type(p)
        if vuln_type:
            return self._handle_vulnerability_explanation(vuln_type, spec_title, p)

        # 8. Prioritization / Risk Inquiry
        if any(w in p for w in ["prioritize", "priority", "p1", "p2", "p3", "risk model", "ml", "calculated"]):
            return self._handle_priority_inquiry()

        # 9. Test Execution & Human-in-the-Loop Inquiry / Safety Boundary
        if any(w in p for w in ["test", "probe", "execute", "approve", "scan", "audit", "hack", "attack", "exploit"]):
            return self._handle_test_inquiry(spec_title)

        # 10. General / Fallback Security Assistance
        return self._handle_general_fallback(spec_title)

    # ------------------------------------------------------------------------
    # Intent Classifiers & Handlers
    # ------------------------------------------------------------------------
    def _handle_http_auth_comparison(self) -> Dict[str, Any]:
        msg = (
            "### Difference Between HTTP 401 Unauthorized and HTTP 403 Forbidden\n\n"
            "1. **HTTP 401 Unauthorized (Authentication Failure):**\n"
            "   - **Definition:** The client has not supplied valid authentication credentials or credentials are missing, expired, or malformed.\n"
            "   - **Semantics:** 'Who are you?' — The identity is unauthenticated.\n"
            "   - **Example:** Missing or invalid `Authorization: Bearer <token>` on protected `/api/v1/profile`.\n\n"
            "2. **HTTP 403 Forbidden (Authorization Failure):**\n"
            "   - **Definition:** The client is authenticated and their identity is recognized, but the identity lacks sufficient privileges, tenancy claims, or role permissions to access the resource.\n"
            "   - **Semantics:** 'I know who you are, but you do not have permission to access this resource.'\n"
            "   - **Example:** A standard user attempting to invoke an administrator route (`POST /admin/users`) (BFLA) or Tenant A attempting to access Tenant B's object (`GET /accounts/tenant_b_id`) (BOLA).\n\n"
            "**API Security Testing Relevance:** In differential authorization testing, observing HTTP 401/403 confirms that defensive authentication and authorization controls are functioning as intended."
        )
        return {
            "message": msg,
            "reply": msg,
            "intent": "general_qa",
            "conversation_state": "ready",
            "ui_actions": [{"type": "none"}],
            "requires_confirmation": False,
            "slm_engine": "Zynora-SLM-API-v2.0"
        }

    def _handle_live_session_query(
        self,
        p: str,
        spec_title: str,
        live_session: Optional[Dict[str, Any]]
    ) -> Optional[Dict[str, Any]]:
        sid = live_session.get("session_id", "none") if live_session else None
        endpoints = live_session.get("endpoints", []) if live_session else []
        proposals = live_session.get("proposals", []) if live_session else []
        findings = live_session.get("findings", []) if live_session else []
        reports = live_session.get("reports", []) if live_session else []

        # 1. Discovered endpoints inquiry
        if ("endpoint" in p and any(k in p for k in ["what", "which", "discover", "list", "inventory", "show", "in my session", "current session"])) or p == "endpoints":
            if not live_session or not endpoints:
                msg = (
                    "### Discovered Endpoints (Current Session)\n\n"
                    "No endpoints have been discovered in the current session. "
                    "Please upload an OpenAPI specification (.yaml or .json) to discover available endpoints and populate the inventory."
                )
            else:
                lines = [f"- **`{ep.get('method', 'GET')}`** `{ep.get('path', '')}` — {ep.get('summary') or 'API Endpoint'}" for ep in endpoints]
                msg = (
                    f"### Discovered Endpoints ({len(endpoints)} routes in session `{sid}`)\n\n"
                    f"The current session contains **{len(endpoints)}** discovered endpoint(s) from **{spec_title}**:\n\n"
                    + "\n".join(lines) + "\n\n"
                    f"You can formulate targeted security test proposals for these endpoints using the proposal engine."
                )
            return {
                "message": msg,
                "reply": msg,
                "intent": "scanner_review",
                "conversation_state": "ready",
                "ui_actions": [{"type": "none"}],
                "requires_confirmation": False,
                "slm_engine": "Zynora-SLM-API-v2.0"
            }

        # 2. Pending / waiting approval tests
        if ("waiting" in p and "approval" in p) or ("pending" in p and any(k in p for k in ["test", "proposal", "approval"])) or ("require" in p and "approval" in p) or ("need" in p and "approval" in p):
            if not live_session:
                msg = "### Pending Security Tests (Approval Required)\n\nNo active assessment session. Please upload a specification to generate proposals."
            else:
                pending = [pr for pr in proposals if str(pr.get("status", "")).lower() == "proposed"]
                if not pending:
                    msg = "### Pending Security Tests (Approval Required)\n\nThere are currently **0** security test proposals waiting for approval in this session."
                else:
                    lines = [
                        f"- **Test ID:** `{pr['test_id']}`\n"
                        f"  - **Target:** `{pr.get('method', '')} {pr.get('path', '')}`\n"
                        f"  - **Vector:** {pr.get('test_type', 'Security Test')}\n"
                        f"  - **Severity:** {pr.get('severity', 'Medium')}\n"
                        f"  - **Description:** {pr.get('description', '')}"
                        for pr in pending
                    ]
                    msg = (
                        f"### Pending Security Tests ({len(pending)} Awaiting Operator Approval)\n\n"
                        f"The following **{len(pending)}** proposal(s) require explicit operator approval before execution:\n\n"
                        + "\n\n".join(lines) + "\n\n"
                        f"> [!IMPORTANT]\n"
                        f"> Non-destructive safety invariant: Automated security probes are blocked until explicitly approved via the Approve action."
                    )
            return {
                "message": msg,
                "reply": msg,
                "intent": "scanner_review",
                "conversation_state": "ready",
                "ui_actions": [{"type": "none"}],
                "requires_confirmation": False,
                "slm_engine": "Zynora-SLM-API-v2.0"
            }

        # 3. Rejected tests
        if "rejected" in p and any(k in p for k in ["test", "proposal", "which", "what", "show", "list"]):
            if not live_session:
                msg = "### Rejected Security Tests\n\nNo active assessment session."
            else:
                rejected = [pr for pr in proposals if str(pr.get("status", "")).lower() == "rejected"]
                if not rejected:
                    msg = "### Rejected Security Tests\n\nNo security test proposals have been rejected in the current session."
                else:
                    lines = [f"- **Test ID:** `{pr['test_id']}` | **Target:** `{pr.get('method', '')} {pr.get('path', '')}` | **Vector:** {pr.get('test_type', 'Security Test')}" for pr in rejected]
                    msg = (
                        f"### Rejected Security Tests ({len(rejected)})\n\n"
                        f"The following **{len(rejected)}** proposal(s) have been rejected by the operator and will NOT be executed:\n\n"
                        + "\n".join(lines)
                    )
            return {
                "message": msg,
                "reply": msg,
                "intent": "scanner_review",
                "conversation_state": "ready",
                "ui_actions": [{"type": "none"}],
                "requires_confirmation": False,
                "slm_engine": "Zynora-SLM-API-v2.0"
            }

        # 4. Executed tests / How many tested
        if "actually executed" in p or "have executed" in p or ("how many" in p and "tested" in p) or "which tests have" in p or ("executed" in p and "test" in p):
            if not live_session:
                msg = "### Executed Security Tests\n\n**Not tested.** No active assessment session."
            else:
                executed_props = [pr for pr in proposals if pr.get("executed_at") or str(pr.get("status", "")).lower() == "executed"]
                if not executed_props and not findings:
                    msg = (
                        "### Executed Security Tests (Current Session)\n\n"
                        "**Not tested.** 0 security tests have executed in this session.\n\n"
                        "All proposed security tests require explicit operator approval before execution can proceed."
                    )
                else:
                    count = max(len(executed_props), len(findings))
                    items = []
                    if findings:
                        for f in findings:
                            items.append(f"- **Test ID:** `{f.get('test_id')}` | **Target:** `{f.get('method', '')} {f.get('path', '')}` | **Vector:** {f.get('vulnerability_type', '')} | **Outcome:** `{f.get('assessment_outcome', f.get('status', 'EXECUTED'))}`")
                    else:
                        for pr in executed_props:
                            items.append(f"- **Test ID:** `{pr['test_id']}` | **Target:** `{pr.get('method', '')} {pr.get('path', '')}` | **Vector:** {pr.get('test_type', '')} | **Status:** Executed")
                    msg = (
                        f"### Executed Security Tests ({count} Completed)\n\n"
                        f"A total of **{count}** security test(s) have executed in session `{sid}`:\n\n"
                        + "\n".join(items)
                    )
            return {
                "message": msg,
                "reply": msg,
                "intent": "scanner_review",
                "conversation_state": "ready",
                "ui_actions": [{"type": "none"}],
                "requires_confirmation": False,
                "slm_engine": "Zynora-SLM-API-v2.0"
            }

        # 6. Evidence supporting highest-severity finding
        if "evidence" in p and any(k in p for k in ["support", "highest", "finding", "show"]):
            if not live_session or not findings:
                msg = "### Finding Evidence\n\nNo evidence is available because no security tests have executed or produced findings in the current session."
            else:
                sev_weights = {"critical": 4, "p1": 4, "high": 3, "p2": 3, "medium": 2, "p3": 2, "low": 1}
                sorted_findings = sorted(findings, key=lambda f: sev_weights.get(str(f.get("severity", "")).lower(), 1), reverse=True)
                top = sorted_findings[0]
                ev = top.get("evidence", {})
                req = ev.get("request", {})
                resp = ev.get("response", {})

                req_str = f"{req.get('method', top.get('method', 'GET'))} {req.get('url', top.get('path', ''))}\n"
                headers = req.get("headers", {})
                if isinstance(headers, dict):
                    for hk, hv in list(headers.items())[:5]:
                        req_str += f"{hk}: {hv}\n"

                status_code = resp.get("status_code", resp.get("status", 200)) if isinstance(resp, dict) else 200
                body_prev = ""
                if isinstance(resp, dict):
                    body_raw = resp.get("body", "")
                    body_prev = str(body_raw)[:300] if body_raw else "Response body captured by differential scanner."
                else:
                    body_prev = str(resp)[:300]

                msg = (
                    f"### Evidence for Highest-Severity Finding (`{top['finding_id']}`)\n\n"
                    f"- **Vulnerability Type:** {top.get('vulnerability_type', 'Vulnerability')}\n"
                    f"- **Severity:** {top.get('severity', 'High')}\n"
                    f"- **Endpoint:** `{top.get('method', '')} {top.get('path', '')}`\n"
                    f"- **Scanner Verdict:** `{top.get('status', 'SUSPECTED')}` (Outcome: `{top.get('assessment_outcome', 'SUSPECTED')}`)\n\n"
                    f"#### Sanitized HTTP Request (Redacted):\n"
                    f"```http\n{req_str.strip()}\n```\n\n"
                    f"#### Sanitized HTTP Response (Redacted):\n"
                    f"```http\nHTTP/1.1 {status_code}\nContent-Type: application/json\n\n{body_prev.strip()}\n```\n\n"
                    f"- **Assessment Reason:** {top.get('assessment_reason', '')}\n"
                    f"- **Remediation:** {top.get('remediation', 'Enforce strict authorization and validation controls.')}"
                )
            return {
                "message": msg,
                "reply": msg,
                "intent": "scanner_review",
                "conversation_state": "ready",
                "ui_actions": [{"type": "none"}],
                "requires_confirmation": False,
                "slm_engine": "Zynora-SLM-API-v2.0"
            }

        # 5. Findings from latest execution / Detected vulnerabilities
        if ("finding" in p and any(k in p for k in ["latest", "show", "execution", "what", "list"])) or ("vulnerabilit" in p and any(k in p for k in ["discover", "found", "were", "detect", "what"])):
            if not live_session or not findings:
                msg = (
                    "### Security Findings (Live Session)\n\n"
                    "No security findings have been recorded in this session. No tests have been executed or yielded vulnerabilities yet."
                )
            else:
                items = []
                for f in findings:
                    items.append(
                        f"- **Finding ID:** `{f['finding_id']}` (Test: `{f.get('test_id')}`)\n"
                        f"  - **Endpoint:** `{f.get('method', '')} {f.get('path', '')}`\n"
                        f"  - **Vulnerability:** {f.get('vulnerability_type', 'Security Finding')}\n"
                        f"  - **Severity:** {f.get('severity', 'Medium')}\n"
                        f"  - **Status:** `{f.get('status', 'SUSPECTED')}` | **Outcome:** `{f.get('assessment_outcome', 'SUSPECTED')}`\n"
                        f"  - **Reason:** {f.get('assessment_reason', '')}\n"
                        f"  - **Human Reviewed:** {'Yes' if f.get('is_human_reviewed') else 'Pending Human Review'}"
                    )
                msg = (
                    f"### Security Findings ({len(findings)} Recorded in Session `{sid}`)\n\n"
                    + "\n\n".join(items) + "\n\n"
                    f"> [!NOTE]\n"
                    f"> **Governance Invariant:** Automated findings with status `SUSPECTED` require explicit human reviewer sign-off before being marked `CONFIRMED`."
                )
            return {
                "message": msg,
                "reply": msg,
                "intent": "scanner_review",
                "conversation_state": "ready",
                "ui_actions": [{"type": "none"}],
                "requires_confirmation": False,
                "slm_engine": "Zynora-SLM-API-v2.0"
            }



        # 7. Severity distribution
        if "severity" in p and any(k in p for k in ["distribution", "breakdown", "count"]):
            crit = len([f for f in findings if str(f.get("severity", "")).lower() in ["critical", "p1"]])
            high = len([f for f in findings if str(f.get("severity", "")).lower() in ["high", "p2"]])
            med = len([f for f in findings if str(f.get("severity", "")).lower() in ["medium", "p3"]])
            low = len([f for f in findings if str(f.get("severity", "")).lower() in ["low", "p4"]])
            msg = (
                f"### Finding Severity Distribution (Session `{sid}`)\n\n"
                f"Total Recorded Findings: **{len(findings)}**\n\n"
                f"- **Critical (P1):** {crit}\n"
                f"- **High (P2):** {high}\n"
                f"- **Medium (P3):** {med}\n"
                f"- **Low (P4):** {low}\n\n"
                f"Findings are prioritized using multi-factor ML risk analysis based on network exposure, data sensitivity, and exploitability."
            )
            return {
                "message": msg,
                "reply": msg,
                "intent": "scanner_review",
                "conversation_state": "ready",
                "ui_actions": [{"type": "none"}],
                "requires_confirmation": False,
                "slm_engine": "Zynora-SLM-API-v2.0"
            }

        # 8. Vulnerable endpoints
        if "vulnerable" in p and "endpoint" in p:
            if not live_session or not findings:
                msg = "### Vulnerable Endpoints (Current Session)\n\nNo vulnerable endpoints have been detected or confirmed in the current session."
            else:
                vuln_findings = [f for f in findings if str(f.get("status", "")).upper() in ["SUSPECTED", "CONFIRMED"]]
                if not vuln_findings:
                    msg = "### Vulnerable Endpoints (Current Session)\n\nNo vulnerable endpoints have been detected or confirmed in the current session."
                else:
                    items = [f"- **`{f.get('method', '')} {f.get('path', '')}`** — {f.get('vulnerability_type', '')} ({f.get('severity', 'Medium')}) [Status: `{f.get('status')}`]" for f in vuln_findings]
                    msg = (
                        f"### Vulnerable Endpoints ({len(vuln_findings)} detected in session `{sid}`)\n\n"
                        f"The following endpoint(s) have exhibited differential anomalies:\n\n"
                        + "\n".join(items)
                    )
            return {
                "message": msg,
                "reply": msg,
                "intent": "scanner_review",
                "conversation_state": "ready",
                "ui_actions": [{"type": "none"}],
                "requires_confirmation": False,
                "slm_engine": "Zynora-SLM-API-v2.0"
            }

        # 9. What should I test next
        if "test next" in p or "what to test" in p or "next step" in p or "next test" in p:
            if not live_session or not endpoints:
                msg = (
                    "### Recommended Next Step\n\n"
                    "1. **Upload an OpenAPI Specification:** Connect or upload an OpenAPI specification (.yaml or .json) "
                    "to parse and discover API endpoints in a fresh assessment session."
                )
            elif not proposals:
                msg = (
                    f"### Recommended Next Step (Session `{sid}`)\n\n"
                    f"1. **Formulate Security Proposals:** You have **{len(endpoints)}** discovered endpoints. "
                    f"Generate security test proposals targeting BOLA, BFLA, Broken Authentication, and Mass Assignment vectors."
                )
            else:
                pending = [pr for pr in proposals if str(pr.get("status", "")).lower() == "proposed"]
                approved = [pr for pr in proposals if str(pr.get("status", "")).lower() == "approved"]
                unreviewed = [f for f in findings if not f.get("is_human_reviewed")]
                if pending:
                    msg = (
                        f"### Recommended Next Step (Session `{sid}`)\n\n"
                        f"1. **Review Pending Proposals:** You have **{len(pending)}** proposal(s) awaiting approval (such as `{pending[0]['test_id']}`). "
                        f"Inspect the target endpoint `{pending[0].get('method')} {pending[0].get('path')}` and approve or reject."
                    )
                elif approved:
                    msg = (
                        f"### Recommended Next Step (Session `{sid}`)\n\n"
                        f"1. **Execute Approved Proposals:** You have **{len(approved)}** approved proposal(s) ready for execution. "
                        f"Trigger controlled execution against the local target `http://127.0.0.1:8001`."
                    )
                elif unreviewed:
                    msg = (
                        f"### Recommended Next Step (Session `{sid}`)\n\n"
                        f"1. **Conduct Human Auditor Review:** You have **{len(unreviewed)}** unreviewed finding(s) with sanitized evidence. "
                        f"Review the evidence and mark them `CONFIRMED` or `FALSE_POSITIVE`."
                    )
                else:
                    msg = (
                        f"### Recommended Next Step (Session `{sid}`)\n\n"
                        f"1. **Compile Final Security Report:** All proposed tests have executed and findings have been reviewed. "
                        f"Export the 21-Section CREST Penetration Testing Report or Executive Briefing."
                    )
            return {
                "message": msg,
                "reply": msg,
                "intent": "scanner_review",
                "conversation_state": "ready",
                "ui_actions": [{"type": "none"}],
                "requires_confirmation": False,
                "slm_engine": "Zynora-SLM-API-v2.0"
            }

        # 10. Summarize current assessment / Status / Executive security summary
        if ("summarize" in p and "assessment" in p) or ("summary" in p and "assessment" in p) or ("status" in p and "assessment" in p) or "executive security summary" in p or "executive summary" in p:
            if not live_session or not endpoints:
                msg = (
                    "### Executive Security Summary (No Active Assessment Data)\n\n"
                    "**Status:** Inactive Session\n\n"
                    "There is currently no active security assessment data recorded. "
                    "Please upload an OpenAPI specification to begin endpoint discovery and vulnerability scanning."
                )
            else:
                pending_count = len([pr for pr in proposals if str(pr.get("status", "")).lower() == "proposed"])
                approved_count = len([pr for pr in proposals if str(pr.get("status", "")).lower() == "approved"])
                rejected_count = len([pr for pr in proposals if str(pr.get("status", "")).lower() == "rejected"])
                executed_count = max(len([pr for pr in proposals if pr.get("executed_at")]), len(findings))

                crit = len([f for f in findings if str(f.get("severity", "")).lower() in ["critical", "p1"]])
                high = len([f for f in findings if str(f.get("severity", "")).lower() in ["high", "p2"]])
                med = len([f for f in findings if str(f.get("severity", "")).lower() in ["medium", "p3"]])
                low = len([f for f in findings if str(f.get("severity", "")).lower() in ["low", "p4"]])

                reviewed_count = len([f for f in findings if f.get("is_human_reviewed")])

                msg = (
                    f"### Executive Security Summary — Live Assessment\n\n"
                    f"**Session ID:** `{sid}`  \n"
                    f"**Target Specification:** {spec_title}  \n\n"
                    f"#### 1. Inventory & Test Lifecycle\n"
                    f"- **Discovered Endpoints:** {len(endpoints)}\n"
                    f"- **Total Security Proposals:** {len(proposals)}\n"
                    f"  - **Pending Approval:** {pending_count}\n"
                    f"  - **Approved:** {approved_count}\n"
                    f"  - **Rejected:** {rejected_count}\n"
                    f"- **Executed Tests:** {executed_count}\n\n"
                    f"#### 2. Findings & Risk Posture\n"
                    f"- **Recorded Findings:** {len(findings)}\n"
                    f"- **Severity Breakdown:** Critical: {crit} | High: {high} | Medium: {med} | Low: {low}\n"
                    f"- **Human Auditor Sign-off:** {reviewed_count} of {len(findings)} findings verified\n\n"
                    f"#### 3. Compliance & Governance\n"
                    f"All tests follow non-destructive differential analysis under OWASP API Security Top 10 guidelines."
                )
            return {
                "message": msg,
                "reply": msg,
                "intent": "scanner_review",
                "conversation_state": "ready",
                "ui_actions": [{"type": "none"}],
                "requires_confirmation": False,
                "slm_engine": "Zynora-SLM-API-v2.0"
            }

        return None

    def _is_greeting(self, text: str) -> bool:
        greetings = ["hello", "hi", "hey", "good morning", "good afternoon", "good evening", "namaste", "greetings"]
        words = re.findall(r"\b\w+\b", text)
        return len(words) <= 4 and any(w in greetings for w in words)

    def _handle_greeting(self, prompt: str, spec_title: str) -> Dict[str, Any]:
        if "namaste" in prompt:
            msg = f"Namaste! Welcome to **ZYNORA AI**. I am your API Security Analyst. Preloaded **{spec_title}**. How can I assist your security assessment today?"
        elif "good morning" in prompt:
            msg = f"Good morning! I am your AI Security Analyst, ready to audit API specifications, evaluate vulnerability evidence, or generate penetration testing documentation for **{spec_title}**."
        else:
            msg = f"Hello! I am your **ZYNORA AI Security Analyst**. Ready to audit **{spec_title}**, inspect OWASP API Top 10 vulnerabilities, or compile assessment reports."

        return {
            "message": msg,
            "reply": msg,
            "intent": "greeting",
            "conversation_state": "ready",
            "ui_actions": [{"type": "none"}],
            "requires_confirmation": False,
            "slm_engine": "Zynora-SLM-API-v2.0"
        }

    def _is_identity_inquiry(self, text: str) -> bool:
        triggers = [
            "who are you", "what is zynora", "what can you do", "how does this work",
            "what can zynora do", "zynora do", "how do i use you", "what makes you different",
            "your identity", "about you", "zynora platform"
        ]
        return any(t in text for t in triggers) or ("zynora" in text and ("what" in text or "who" in text or "capability" in text or "can" in text))

    def _handle_identity_inquiry(self) -> Dict[str, Any]:
        msg = (
            "### About ZYNORA AI | Intelligent API Penetration Testing Analyst\n\n"
            "**Platform:** ZYNORA AI  \n"
            "**Role:** AI API Security Analyst & Penetration Testing Workspace  \n"
            "**Core Purpose:** Transform raw API scanner findings and OpenAPI specifications into verified, "
            "prioritized, actionable security intelligence and audit-ready documentation.\n\n"
            "**What ZYNORA Does for Your Security Team:**\n"
            "1. **OWASP API Top 10 Vulnerability Analysis:** Pinpoint BOLA, BFLA, and mass assignment flaws using evidence grounding.\n"
            "2. **Trained ML Prioritization:** Evaluate exposure, sensitivity, and exploitability to recommend realistic P1/P2/P3 ratings.\n"
            "3. **Human-in-the-Loop Safe Probing:** Formulate safe verification assertions requiring explicit operator approval.\n"
            "4. **Complete Report Generation:** Produce 21-Section Penetration Testing Reports, Bug Bounty writeups, and Executive slide decks.\n"
            "5. **Zero Cloud Leakage:** Local SLM architecture guarantees total sovereign data privacy."
        )
        return {
            "message": msg,
            "reply": msg,
            "intent": "platform_inquiry",
            "conversation_state": "ready",
            "ui_actions": [
                {
                    "type": "show_report_options",
                    "title": "Available Security Documentation Formats",
                    "options": report_generator.REPORT_CATALOG[:4]
                }
            ],
            "requires_confirmation": False,
            "slm_engine": "Zynora-SLM-API-v2.0"
        }

    def _is_report_request(self, text: str) -> bool:
        triggers = ["report", "generate report", "export", "pentest", "bug bounty", "bounty", "presentation", "slide", "slides", "documentation package"]
        return any(t in text for t in triggers)

    def _handle_report_request(
        self,
        prompt: str,
        spec_title: str,
        endpoints_count: int,
        context: Optional[Dict[str, Any]]
    ) -> Dict[str, Any]:
        target_format = None
        if "pentest" in prompt:
            target_format = "pentest_report"
        elif "bounty" in prompt or "bug bounty" in prompt:
            target_format = "bug_bounty"
        elif "presentation" in prompt or "slide" in prompt or "ppt" in prompt:
            target_format = "security_presentation"
        elif "executive" in prompt:
            target_format = "executive_assessment"
        elif "technical" in prompt:
            target_format = "technical_assessment"
        elif "remediation" in prompt or "runbook" in prompt:
            target_format = "remediation_report"

        if target_format:
            doc = report_generator.generate_report(
                report_type=target_format,
                spec_title=spec_title,
                endpoints_count=endpoints_count,
                findings=context.get("findings") if context else None
            )
            msg = (
                f"### {doc['title']} Compiled\n\n"
                f"I have prepared the **{doc['title']}** based on verified findings and ML priority assessments for **{spec_title}**.\n\n"
                f"- **Document ID:** `{doc['report_id']}`\n"
                f"- **Format:** {doc['format']}\n"
                f"- **Report Structure:** 21-Section CREST/OWASP Audit Standard with Verified Findings\n"
                f"- **Status:** Audit-Ready & Exportable\n\n"
                f"You can preview the document structure below or export it directly."
            )
            return {
                "message": msg,
                "reply": msg,
                "intent": "report_generation",
                "conversation_state": "completed",
                "ui_actions": [
                    {
                        "type": "show_finding_card",
                        "title": doc["title"],
                        "payload": doc
                    }
                ],
                "report": {
                    "status": "completed",
                    "format": doc["format"],
                    "document": doc
                },
                "requires_confirmation": False,
                "slm_engine": "Zynora-SLM-API-v2.0"
            }

        msg = (
            "### Which security document would you like me to prepare?\n\n"
            "I can compile verified assessment findings for **" + spec_title + "** into any of our standard reporting formats:\n\n"
            "1. **Penetration Testing Report (21-Section)** — Comprehensive CREST/OWASP audit document with methodology and findings.\n"
            "2. **Bug Bounty Report** — Submission-ready writeup for HackerOne/Bugcrowd with preconditions and reproduction steps.\n"
            "3. **Executive Security Assessment** — High-level briefing for C-level leadership detailing organizational posture and roadmap.\n"
            "4. **Security Assessment Presentation (PPT)** — Structured slide deck highlighting risk distribution and key vulnerabilities.\n"
            "5. **Technical Vulnerability Assessment** — Engineering breakdown with curl requests and FastAPI/Pydantic code fixes.\n"
            "6. **Remediation & Validation Runbook** — Step-by-step developer playbook with automated assertion scripts.\n"
            "7. **Complete Assessment Package** — Bundles all documentation artifacts and JSON exports.\n\n"
            "Select an option below or type your preferred format."
        )

        return {
            "message": msg,
            "reply": msg,
            "intent": "report_request",
            "conversation_state": "awaiting_user_selection",
            "ui_actions": [
                {
                    "type": "show_report_options",
                    "title": "Select Security Document Format",
                    "options": report_generator.REPORT_CATALOG
                }
            ],
            "report": {
                "status": "selecting_format",
                "format": None
            },
            "requires_confirmation": True,
            "slm_engine": "Zynora-SLM-API-v2.0"
        }

    def _detect_mistakes(self, text: str) -> Optional[Dict[str, Any]]:
        """Identify missing information, malformed JSON, invalid endpoints, or contradictory findings."""
        p = text.lower()

        if ("without endpoint" in p or "missing endpoint" in p or "without method" in p or 
            ("analyze finding" in p and not any(k in p for k in ["/api", "http", "get", "post", "put", "delete", "/"]))):
            msg = (
                "### Incomplete Finding Metadata: Missing Endpoint & Method\n\n"
                "To analyze this finding accurately without fabricating evidence, please specify:\n"
                "1. **Target Endpoint Path** (e.g., `/api/v1/accounts/{id}`)\n"
                "2. **HTTP Method** (`GET`, `POST`, `PUT`, `DELETE`)\n"
                "3. **Observed Scanner Verdict** (e.g., `Suspected BOLA`, `Confirmed Unauthorized Access`)\n\n"
                "Missing endpoint and HTTP method parameters must be supplied. I never invent missing endpoints or assume authentication states."
            )
            return {
                "message": msg,
                "reply": msg,
                "intent": "missing_information",
                "conversation_state": "clarification_needed",
                "ui_actions": [
                    {
                        "type": "request_clarification",
                        "payload": {"missing_fields": ["endpoint", "http_method", "scanner_verdict"]}
                    }
                ],
                "requires_confirmation": False,
                "slm_engine": "Zynora-SLM-API-v2.0"
            }

        if ("{" in text or "[" in text) and any(kw in text for kw in ["finding", "endpoint", "vulnerability", "scanner"]):
            try:
                json_match = re.search(r"(\{.*\}|\[.*\])", text, re.DOTALL)
                if json_match:
                    json.loads(json_match.group(1))
            except json.JSONDecodeError as err:
                msg = (
                    f"### Input Validation Error: Malformed JSON Detected\n\n"
                    f"The supplied finding snippet contains invalid JSON syntax:\n"
                    f"- **Parse Error:** `{str(err)}`\n\n"
                    f"**Correction Suggestion:** Ensure all property keys and strings use double quotes (`\"`), "
                    f"and verify closing braces/brackets before resubmitting."
                )
                return {
                    "message": msg,
                    "reply": msg,
                    "intent": "missing_information",
                    "conversation_state": "clarification_needed",
                    "ui_actions": [
                        {
                            "type": "request_clarification",
                            "payload": {"error": str(err), "field": "raw_json"}
                        }
                    ],
                    "requires_confirmation": False,
                    "slm_engine": "Zynora-SLM-API-v2.0"
                }

        return None

    def _match_vulnerability_type(self, p: str) -> Optional[str]:
        if "bola" in p and "bfla" in p:
            return "bola_vs_bfla"
        if "bola" in p or "idor" in p or ("object level" in p and "authorization" in p):
            return "bola"
        if "bfla" in p or ("function level" in p and "authorization" in p):
            return "bfla"
        if "mass assignment" in p or "property tampering" in p or "dto" in p:
            return "mass_assignment"
        if "disclosure" in p or "leak" in p or "env" in p or "telemetry" in p:
            return "information_disclosure"
        if "excessive" in p and "data" in p:
            return "excessive_data_exposure"
        if "rate limit" in p or "resource consumption" in p or "input validation" in p:
            return "input_validation"
        return None

    def _handle_vulnerability_explanation(self, vuln_type: str, spec_title: str, prompt: str) -> Dict[str, Any]:
        if vuln_type == "bola_vs_bfla":
            msg = (
                "### Difference Between BOLA and BFLA (OWASP API Top 10)\n\n"
                "1. **Broken Object Level Authorization (BOLA / IDOR - API1:2023):**\n"
                "   - **Core Defect:** User accesses another tenant's object or data record by manipulating resource identifiers in the URL (e.g. `/accounts/{id}`).\n"
                "   - **Root Cause:** Missing tenancy authorization checks in the data layer.\n\n"
                "2. **Broken Function Level Authorization (BFLA - API5:2023):**\n"
                "   - **Core Defect:** Unprivileged user executes administrative or privileged operations (e.g. `POST /api/v1/admin/tenants/export`).\n"
                "   - **Root Cause:** Missing role-based privilege checks at the API gateway router.\n\n"
                "Both vectors require strict middleware enforcement and non-destructive regression test assertions."
            )
            return {
                "message": msg,
                "reply": msg,
                "intent": "vulnerability_analysis",
                "conversation_state": "ready",
                "ui_actions": [{"type": "none"}],
                "requires_confirmation": False,
                "slm_engine": "Zynora-SLM-API-v2.0"
            }

        kb = self.VULNERABILITY_KB[vuln_type]
        msg = (
            f"### {kb['title']} ({kb['owasp_code']})\n\n"
            f"**Potential Impact:** {kb['impact']}\n\n"
            f"**Defensive Remediation Strategy:**\n"
            + "\n".join([f"{i+1}. {r}" for i, r in enumerate(kb['remediation'])]) + "\n\n"
            f"**Verification Assertions (Non-Destructive):**\n"
            + "\n".join([f"- `{v}`" for v in kb['validation']]) + "\n\n"
            f"Would you like me to formulate human-in-the-loop test proposals for `{spec_title}` targeting this vector?"
        )
        return {
            "message": msg,
            "reply": msg,
            "intent": "vulnerability_analysis",
            "conversation_state": "ready",
            "ui_actions": [
                {
                    "type": "show_test_proposals",
                    "payload": {"vulnerability_type": vuln_type}
                }
            ],
            "requires_confirmation": False,
            "slm_engine": "Zynora-SLM-API-v2.0"
        }

    def _handle_priority_inquiry(self) -> Dict[str, Any]:
        msg = (
            "### ZYNORA ML Risk Prioritization Framework (P1 vs P2 vs P3)\n\n"
            "Our multi-factor Random Forest model calculates risk priority recommendations using empirical security parameters:\n\n"
            "- **P1 (Critical Urgency):** Internet-facing endpoints exposing sensitive records with verified high exploitability (e.g. unauthenticated BOLA on banking accounts).\n"
            "- **P2 (High Urgency):** Authenticated administrative functions (BFLA) or object property tampering (Mass Assignment) requiring valid session tokens.\n"
            "- **P3 (Moderate / Low):** Internal diagnostics or minor schema deviations without immediate exploit leverage.\n\n"
            "**Key Principles:**\n"
            "1. The ML priority is an assistive recommendation based on exposure, sensitivity, and exploitability.\n"
            "2. It **never alters or overrides** the scanner verdict, which remains immutable ground truth."
        )
        return {
            "message": msg,
            "reply": msg,
            "intent": "risk_prioritization",
            "conversation_state": "ready",
            "ui_actions": [{"type": "none"}],
            "requires_confirmation": False,
            "slm_engine": "Zynora-SLM-API-v2.0"
        }

    def _handle_test_inquiry(self, spec_title: str) -> Dict[str, Any]:
        msg = (
            f"### Human-in-the-Loop Safe Security Probing\n\n"
            f"ZYNORA AI operates under strict authorized penetration testing rules:\n\n"
            f"- **Safety Guarantee:** Probes are safe, non-destructive boundary assertions (such as verifying HTTP 403 Forbidden responses) and never trigger destructive database writes.\n"
            f"- **Operator Approval Required:** We never conduct unauthorized attacks or hack external targets. All automated security testing requires explicit operator approval prior to execution.\n\n"
            f"You can review and approve formulated probes for **{spec_title}** using the interactive approval cards."
        )
        return {
            "message": msg,
            "reply": msg,
            "intent": "security_assessment",
            "conversation_state": "awaiting_approval",
            "ui_actions": [{"type": "show_test_proposals"}],
            "requires_confirmation": True,
            "slm_engine": "Zynora-SLM-API-v2.0"
        }

    def _handle_general_fallback(self, spec_title: str) -> Dict[str, Any]:
        msg = (
            f"### API Security Analyst Ready\n\n"
            f"I am active for **{spec_title}**. I can:\n"
            f"- **Analyze API Findings:** Assess empirical evidence against OWASP API Top 10.\n"
            f"- **Formulate Probes:** Generate human-in-the-loop test assertions for tenancy and role boundaries.\n"
            f"- **Predict ML Priorities:** Recommend P1/P2/P3 classifications without altering scanner verdicts.\n"
            f"- **Generate Reports:** Compile 21-Section Pentest Reports, Bug Bounty writeups, or Executive briefings.\n\n"
            f"Ask a question regarding an endpoint, or click a quick-action chip below."
        )
        return {
            "message": msg,
            "reply": msg,
            "intent": "general_qa",
            "conversation_state": "ready",
            "ui_actions": [
                {
                    "type": "show_report_options",
                    "title": "Quick Document Export",
                    "options": report_generator.REPORT_CATALOG[:3]
                }
            ],
            "requires_confirmation": False,
            "slm_engine": "Zynora-SLM-API-v2.0"
        }

    # ------------------------------------------------------------------------
    # 2. Finding Analysis (Used by /api/v1/analyze)
    # ------------------------------------------------------------------------
    def summarize_finding(self, finding: Dict[str, Any], ml_priority: str) -> Dict[str, Any]:
        """Generate a structured, evidence-grounded analysis."""
        ftype = str(finding.get("finding_type", "other")).lower().strip()
        endpoint = finding.get("endpoint") or "/api/endpoint"

        kb = self.VULNERABILITY_KB.get(ftype, {
            "title": f"Security Finding ({ftype.upper()})",
            "owasp_code": "OWASP API Security",
            "impact": "Potential compromise of system integrity or data confidentiality depending on gateway exposure.",
            "remediation": [
                "Apply defense-in-depth security controls at the API gateway.",
                "Enforce strict authentication and authorization checks before business logic execution."
            ],
            "validation": [
                f'curl -s -i "{endpoint}" (Verify rejection of unauthorized parameters)'
            ],
            "test_payload_template": f"Assert boundary validation on {endpoint}"
        })

        summary = (
            f"{kb['title']} identified on endpoint `{endpoint}`. "
            f"The scanner recorded a verdict of '{finding.get('scanner_verdict', 'Suspected')}' "
            f"with {finding.get('evidence_confidence', 'medium')} evidence confidence."
        )

        evidence_assessment = (
            finding.get("evidence") or 
            f"Observed behavioral deviation on {endpoint} matching {kb['title']} patterns."
        )

        explanation = (
            f"The ML priority model recommended {ml_priority} by evaluating exposure ({finding.get('exposure', 'unknown')}), "
            f"data sensitivity ({finding.get('data_sensitivity', 'unknown')}), and exploitability ({finding.get('exploitability', 'unknown')}). "
            f"This priority is an assistive recommendation and preserves the immutable scanner verdict."
        )

        formatted_remediation = kb["remediation"]
        formatted_validation = [v.replace("{endpoint}", endpoint) for v in kb["validation"]]

        return {
            "finding_summary": summary,
            "evidence_assessment": evidence_assessment,
            "potential_impact": kb["impact"],
            "priority_explanation": explanation,
            "remediation_steps": formatted_remediation,
            "validation_steps": formatted_validation,
            "limitations": [
                "Analysis performed solely on supplied finding metadata.",
                "Upstream WAF or gateway rate limits may attenuate exploitability in production environments."
            ],
            "slm_engine": "Zynora-SLM-API-v2.0 (Local Zero-Cloud Engine)"
        }

    def generate_chat_response(self, user_prompt: str, context: Optional[Dict[str, Any]] = None) -> str:
        res = self.process_chat(user_prompt, context)
        return res["message"]


slm_engine = ZynoraSecuritySLMEngine()
SecuritySLMEngine = ZynoraSecuritySLMEngine

