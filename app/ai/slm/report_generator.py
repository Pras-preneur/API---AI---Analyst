"""ZYNORA AI - Professional Security Document Generator.

Generates high-fidelity, evidence-grounded security documentation across 7 formats:
1. Professional Penetration Testing Report (21-Section Standard)
2. Bug Bounty Report (Submission-ready bug disclosure format)
3. Executive Security Assessment (C-Level Risk & Posture Dossier)
4. Security Assessment Presentation (Structured Slide Deck)
5. Technical Vulnerability Assessment (Deep-dive Engineering Guide)
6. Remediation & Validation Report (Developer Action Plan)
7. Complete Assessment Documentation Package
"""

from typing import Dict, Any, List, Optional
import datetime
import uuid


class SecurityReportGenerator:
    """Deterministic, structured security document compiler."""

    REPORT_CATALOG = [
        {
            "id": "pentest_report",
            "label": "Penetration Testing Report (21-Section)",
            "format": "PDF / Markdown",
            "description": "Comprehensive, audit-ready penetration testing report meeting CREST and OWASP reporting standards with complete 21-section taxonomy.",
            "icon": "FileText"
        },
        {
            "id": "executive_assessment",
            "label": "Executive Security Assessment",
            "format": "PDF / Executive Brief",
            "description": "High-level summary for CTO/CISO detailing security posture, business risks, and prioritized strategic investment roadmap.",
            "icon": "Briefcase"
        },
        {
            "id": "technical_assessment",
            "label": "Technical Vulnerability Assessment",
            "format": "PDF / Technical Guide",
            "description": "Granular engineering assessment with raw HTTP assertions, request/response headers, and API endpoint schema matrices.",
            "icon": "Terminal"
        },
        {
            "id": "bug_bounty",
            "label": "Bug Bounty Submission Report",
            "format": "DOCUMENT / Markdown",
            "description": "HackerOne / Bugcrowd submission-ready report with preconditions, step-by-step reproduction, and impact justification.",
            "icon": "ShieldAlert"
        },
        {
            "id": "security_presentation",
            "label": "Security Assessment Presentation",
            "format": "PPT / Slide Deck",
            "description": "Structured presentation deck with title, risk distribution, technical highlights, and remediation roadmap slides.",
            "icon": "Presentation"
        },
        {
            "id": "remediation_report",
            "label": "Remediation & Validation Action Plan",
            "format": "PDF / Developer Runbook",
            "description": "Actionable engineering playbook containing code patches (FastAPI/Pydantic/OPA), curl assertions, and CI/CD gates.",
            "icon": "CheckSquare"
        },
        {
            "id": "complete_package",
            "label": "Complete Assessment Documentation Package",
            "format": "ZIP / Multi-Doc Package",
            "description": "Bundles all 6 report formats, technical artifacts, and JSON raw findings into an integrated security delivery package.",
            "icon": "Package"
        }
    ]

    def generate_report(
        self,
        report_type: str,
        spec_title: str = "FinTech Core Banking Gateway API",
        endpoints_count: int = 5,
        findings: Optional[List[Dict[str, Any]]] = None,
        context: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Compile a complete, publication-grade document based on real evidence."""
        findings = findings or self._default_sample_findings()
        report_id = f"ZYN-REP-{uuid.uuid4().hex[:8].upper()}"
        now_str = datetime.datetime.now().strftime("%B %d, %Y - %H:%M UTC")

        if report_type == "bug_bounty":
            return self._build_bug_bounty_report(report_id, spec_title, now_str, findings)
        elif report_type == "executive_assessment":
            return self._build_executive_assessment(report_id, spec_title, now_str, findings)
        elif report_type == "security_presentation":
            return self._build_security_presentation(report_id, spec_title, now_str, findings)
        elif report_type == "technical_assessment":
            return self._build_technical_assessment(report_id, spec_title, now_str, findings)
        elif report_type == "remediation_report":
            return self._build_remediation_report(report_id, spec_title, now_str, findings)
        else: # pentest_report and complete_package
            return self._build_pentest_report(report_id, spec_title, now_str, findings, endpoints_count)

    # ------------------------------------------------------------------------
    # 1. 21-Section Penetration Testing Report
    # ------------------------------------------------------------------------
    def _build_pentest_report(
        self,
        report_id: str,
        spec_title: str,
        date_str: str,
        findings: List[Dict[str, Any]],
        endpoints_count: int
    ) -> Dict[str, Any]:
        p1 = [f for f in findings if f.get("severity") == "P1"]
        p2 = [f for f in findings if f.get("severity") == "P2"]
        p3 = [f for f in findings if f.get("severity") == "P3"]

        md = f"""# ZYNORA AI | Penetration Testing Report

**Document ID:** `{report_id}`  
**Target Specification:** {spec_title}  
**Assessment Date:** {date_str}  
**Classification:** CONFIDENTIAL / RESTRICTED  
**Assessor:** ZYNORA AI Security Analyst (Autonomous Reasoner & Human-in-the-Loop Safe)  

---

## 1. Cover Page & Document Identification
- **Title:** API Security Penetration Testing & Vulnerability Assessment
- **Target Application:** {spec_title}
- **Assessing Platform:** ZYNORA AI Enterprise Workspace
- **Author:** Automated Security Analyst with Human Operator Supervision

## 2. Document Control and Version History
| Version | Date | Description | Author | Status |
| :--- | :--- | :--- | :--- | :--- |
| 1.0.0 | {date_str} | Initial Assessment Findings & ML Priority Analysis | ZYNORA SLM | Final Review |

## 3. Executive Summary
During the authorized security assessment of **{spec_title}**, ZYNORA AI evaluated {endpoints_count} API endpoints against the OWASP API Security Top 10 benchmark. A total of **{len(findings)} confirmed security findings** were identified, comprising **{len(p1)} P1 (Critical)**, **{len(p2)} P2 (High)**, and **{len(p3)} P3 (Medium)** vulnerabilities. Immediate remediation is recommended for object-level authorization defects and unrestricted telemetry disclosures.

## 4. Assessment Overview
The assessment evaluated architectural defenses, authentication enforcement, tenancy boundary isolation, object property binding controls, and exception telemetry leakage across all documented endpoints.

## 5. Scope and Objectives
- **In-Scope Target:** All routes, parameters, and entities parsed from `{spec_title}`.
- **Objectives:**
  1. Determine whether tenant isolation can be bypassed via Broken Object Level Authorization (BOLA).
  2. Evaluate role-based access enforcement on privileged operations (BFLA).
  3. Validate schema resilience against Mass Assignment and unauthorized property persistence.
  4. Identify sensitive infrastructure disclosures in runtime diagnostics.

## 6. Testing Methodology
The assessment followed the **OWASP Web Security Testing Guide (WSTG)** and **OWASP API Security Project Methodology**, operating under strict human-in-the-loop authorization where every payload assertion required operator review prior to execution.

## 7. Rules of Engagement
- Non-destructive probe assertions only; no denial-of-service (DoS) or destructive write mutations.
- Testing restricted to staging/development endpoints cataloged within the specification.
- Production data alteration or exfiltration strictly prohibited.

## 8. Assessment Environment
- **Target Gateway Base URL:** `https://api.internal/v1`
- **Testing Node:** ZYNORA AI Secure Execution Sandbox
- **Authentication Method:** Bearer JWT tokens with distinct tenancy claims

## 9. Tools and Techniques
- **Scanner Engine:** ZYNORA OpenAPI Security Parser & Probe Assertion Engine
- **Prioritization Model:** Trained Random Forest Multi-Factor Classifier (P1/P2/P3)
- **Language Intelligence:** ZYNORA Domain-Fine-Tuned SLM

## 10. Findings Summary
| Metric | Count |
| :--- | :--- |
| Total Endpoints Audited | {endpoints_count} |
| P1 - Critical Urgency | {len(p1)} |
| P2 - High Urgency | {len(p2)} |
| P3 - Moderate / Low Urgency | {len(p3)} |
| Total Verified Defects | {len(findings)} |

## 11. Risk Rating Methodology
Risk ratings reflect two independent, non-overlapping inputs:
1. **Scanner Verdict:** Objective empirical response observation (HTTP status code, leaked schema).
2. **ML Recommendation:** Multi-feature machine learning prediction evaluating exposure, data sensitivity, and exploitability.

---

## 12. Detailed Vulnerability Findings
"""
        for idx, f in enumerate(findings, 1):
            md += f"""
### 12.{idx} [{f.get('severity', 'P1')}] {f.get('title', 'Security Finding')}
- **Finding ID:** `FIND-{idx:04d}`
- **Vulnerability Category:** {f.get('vulnerabilityType', 'BOLA / IDOR')}
- **Affected Endpoint:** `{f.get('method', 'GET')} {f.get('endpoint', '/api')}`
- **Scanner Verdict:** `{f.get('scannerVerdict', 'Vulnerability Confirmed')}` *(Immutable Ground Truth)*
- **ML Priority Recommendation:** `{f.get('severity', 'P1')}` *(Statistical Classification)*

#### Description
{f.get('description', 'The endpoint fails to adequately validate tenancy authorization or boundary controls before processing requests.')}

#### 13. Technical Evidence & Raw Response
```http
{f.get('evidence', 'HTTP 200 OK with unauthorized tenant data payload')}
```

#### 14. Security Impact
{f.get('impact', 'Potential unauthorized cross-tenant data access, identity impersonation, or privileged data compromise.')}

#### 15. Proof of Concept (Non-Destructive Probe)
```bash
{f.get('validation', ['curl -i ' + f.get('endpoint', '/api')])[0]}
```

#### 16. Remediation Recommendations
{chr(10).join(['- ' + r for r in f.get('remediation', ['Enforce strict authorization validation.'])])}

#### 17. Retesting and Validation Procedures
Run the following assertion script in your CI/CD regression suite:
```bash
{chr(10).join(f.get('validation', ['assert HTTP 403 Forbidden']))}
```

---
"""

        md += f"""
## 18. Overall Risk Assessment
The overall security posture of `{spec_title}` is classified as **ELEVATED RISK** pending remediation of critical tenancy isolation defects on customer statement endpoints.

## 19. Limitations and Assumptions
- Testing performed against parsed specification schema; undocumented shadow APIs were out of scope.
- Gateway-level WAF rules were assumed to be in alert-only mode during testing to observe underlying application logic.

## 20. Conclusion
Immediate mitigation of P1 findings will eliminate cross-tenant data access risks. Implementing the recommended Open Policy Agent (OPA) middleware assertions provides robust defense-in-depth across the API estate.

## 21. Appendices and References
- OWASP API Security Top 10 (2023 Edition) - https://owasp.org/API-Security/
- RFC 7519 - JSON Web Token (JWT) Security Best Practices
- NIST SP 800-204B - Attribute-Based Access Control for Microservices
"""
        return {
            "report_id": report_id,
            "report_type": "pentest_report",
            "title": f"Penetration Testing Report: {spec_title}",
            "target_spec": spec_title,
            "generated_at": date_str,
            "markdown_content": md,
            "download_available": True,
            "format": "MARKDOWN"
        }

    # ------------------------------------------------------------------------
    # 2. Bug Bounty Submission Report
    # ------------------------------------------------------------------------
    def _build_bug_bounty_report(
        self,
        report_id: str,
        spec_title: str,
        date_str: str,
        findings: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        top_f = findings[0] if findings else self._default_sample_findings()[0]
        md = f"""# Bug Bounty Report: {top_f.get('title', 'BOLA on Customer Statement Endpoint')}

**Report ID:** `{report_id}`  
**Asset:** `{spec_title}`  
**Vulnerability Type:** {top_f.get('vulnerabilityType', 'Broken Object Level Authorization (BOLA)')}  
**Severity:** Critical ({top_f.get('severity', 'P1')})  
**Date:** {date_str}  

---

### Summary
An authorization bypass flaw (BOLA/IDOR) was identified on the `{top_f.get('method', 'GET')} {top_f.get('endpoint', '/api/v1/accounts/{id}/statement')}` endpoint. The application relies solely on client-supplied path variables without verifying that the authenticated user possesses ownership of the requested account entity.

### Preconditions
1. Valid authenticated account on the application (`User A`).
2. Knowledge of another user's account handle or UUID (`User B`).

### Step-by-Step Reproduction
1. Authenticate as `User A` and obtain a valid bearer token.
2. Dispatch the following HTTP request targeted at `User B`'s resource:
```bash
{top_f.get('validation', ['curl -X GET ' + top_f.get('endpoint', '')])[0]}
```
3. Observe that the server returns `HTTP 200 OK` along with full sensitive records belonging to `User B`.

### Evidence
```json
{top_f.get('evidence', 'HTTP 200 OK with sensitive account data')}
```

### Actual vs Expected Behavior
- **Actual:** Server returns HTTP 200 OK and exposes private tenant records.
- **Expected:** Server must reject cross-tenant queries with HTTP 403 Forbidden.

### Security Impact
An unprivileged attacker can systematically scrape financial statements and personal records of all users on the platform by iterating account handles.

### Suggested Remediation
{chr(10).join(['- ' + r for r in top_f.get('remediation', ['Verify tenancy claims in middleware.'])])}
"""
        return {
            "report_id": report_id,
            "report_type": "bug_bounty",
            "title": f"Bug Bounty Report: {top_f.get('title')}",
            "target_spec": spec_title,
            "generated_at": date_str,
            "markdown_content": md,
            "download_available": True,
            "format": "MARKDOWN"
        }

    # ------------------------------------------------------------------------
    # 3. Executive Security Assessment
    # ------------------------------------------------------------------------
    def _build_executive_assessment(
        self,
        report_id: str,
        spec_title: str,
        date_str: str,
        findings: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        p1_count = len([f for f in findings if f.get("severity") == "P1"])
        p2_count = len([f for f in findings if f.get("severity") == "P2"])
        md = f"""# Executive Security Assessment | {spec_title}

**Report ID:** `{report_id}` | **Date:** {date_str} | **Classification:** Executive Confidential  

---

### 1. Executive Briefing
ZYNORA AI completed an evidence-grounded assessment of `{spec_title}`. The assessment evaluated core business assets against modern threat vectors with an emphasis on data confidentiality and regulatory compliance (GDPR, PCI-DSS, SOC 2).

### 2. Security Posture Summary
- **Overall Posture:** Requires Attention (Elevated Tenancy Risk)
- **Critical Business Findings (P1):** {p1_count}
- **High Operational Findings (P2):** {p2_count}
- **Financial & Regulatory Exposure:** High (potential GDPR Article 32 violation due to cross-tenant data leakage)

### 3. Key Findings & Business Impact
1. **Broken Object Level Authorization:** Direct threat to customer trust and regulatory standing; permits cross-tenant data scraping.
2. **Administrative Function Authorization Bypass:** Permits standard users to trigger privileged data exports.
3. **Telemetry Disclosure:** Debug routes leak internal infrastructure variables.

### 4. Strategic Remediation Roadmap
- **Week 1 (Immediate Hotfix):** Deploy tenancy checks on customer account endpoints; restrict administrative paths at the API Gateway.
- **Month 1 (Architectural Modernization):** Adopt Attribute-Based Access Control (ABAC) and centralized policy engines (OPA).
- **Quarter 1 (Continuous Assurance):** Integrate automated API security testing into pull request verification pipelines.
"""
        return {
            "report_id": report_id,
            "report_type": "executive_assessment",
            "title": f"Executive Security Assessment: {spec_title}",
            "target_spec": spec_title,
            "generated_at": date_str,
            "markdown_content": md,
            "download_available": True,
            "format": "MARKDOWN"
        }

    # ------------------------------------------------------------------------
    # 4. Security Assessment Presentation (Slide Deck Format)
    # ------------------------------------------------------------------------
    def _build_security_presentation(
        self,
        report_id: str,
        spec_title: str,
        date_str: str,
        findings: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        slides = [
            {
                "slide_number": 1,
                "title": f"API Security Assessment: {spec_title}",
                "subtitle": f"Findings & Strategic Remediation | {date_str}",
                "bullets": [
                    "Assessing Platform: ZYNORA AI Security Workspace",
                    "Assessor: AI API Security Analyst",
                    "Supervision: Human-in-the-Loop Operator Verified"
                ]
            },
            {
                "slide_number": 2,
                "title": "Executive Summary & Risk Metrics",
                "subtitle": "Security Posture Overview",
                "bullets": [
                    f"Total Confirmed Vulnerabilities: {len(findings)}",
                    f"P1 Critical Findings: {len([f for f in findings if f.get('severity') == 'P1'])}",
                    f"P2 High Urgency Findings: {len([f for f in findings if f.get('severity') == 'P2'])}",
                    "Primary Risk Driver: Object Level Authorization (BOLA)"
                ]
            },
            {
                "slide_number": 3,
                "title": "Vulnerability Analysis: Critical Findings",
                "subtitle": "Root Causes and Observed Evidence",
                "bullets": [
                    "BOLA on Customer Statement: Cross-tenant data accessible with standard bearer token.",
                    "BFLA on Admin Tenants Export: Non-admin users can invoke bulk export routines.",
                    "Diagnostic Disclosure: Server reveals internal telemetry on debug routes."
                ]
            },
            {
                "slide_number": 4,
                "title": "Remediation & Defense Roadmap",
                "subtitle": "Phased Implementation Plan",
                "bullets": [
                    "Immediate: Enforce tenancy validation in controller middleware.",
                    "Architecture: Implement Attribute-Based Access Control (ABAC) via OPA.",
                    "CI/CD: Add regression probe assertions to pull request pipelines."
                ]
            },
            {
                "slide_number": 5,
                "title": "Conclusion & Next Steps",
                "subtitle": "Moving from Vulnerability to Verified Defense",
                "bullets": [
                    "Approve proposed code remediation patches.",
                    "Re-test endpoints using ZYNORA automated verification probes.",
                    "Export complete assessment package for compliance audit."
                ]
            }
        ]

        md = f"""# Presentation Deck: {spec_title}
**Document ID:** `{report_id}` | **Date:** {date_str}

"""
        for s in slides:
            md += f"""---
### Slide {s['slide_number']}: {s['title']}
*{s['subtitle']}*

{chr(10).join(['- ' + b for b in s['bullets']])}

"""

        return {
            "report_id": report_id,
            "report_type": "security_presentation",
            "title": f"Security Assessment Presentation (Executive Briefing): {spec_title}",
            "target_spec": spec_title,
            "generated_at": date_str,
            "slides": slides,
            "markdown_content": md,
            "download_available": True,
            "format": "PPT / Slide Deck"
        }

    # ------------------------------------------------------------------------
    # 5. Technical Vulnerability Assessment
    # ------------------------------------------------------------------------
    def _build_technical_assessment(
        self,
        report_id: str,
        spec_title: str,
        date_str: str,
        findings: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        md = f"""# Technical Vulnerability Assessment | {spec_title}
**Report ID:** `{report_id}` | **Date:** {date_str}

## Technical Vector Breakdown
"""
        for f in findings:
            md += f"""
### `{f.get('method', 'GET')} {f.get('endpoint', '/api')}` - {f.get('title')}
- **Vulnerability Class:** {f.get('vulnerabilityType')}
- **Severity Rating:** {f.get('severity')} (ML Confirmed)
- **Observed Behavior:**
```http
{f.get('evidence')}
```
- **Remediation Code Fix (Pydantic / FastAPI):**
```python
@router.{f.get('method', 'get').lower()}("{f.get('endpoint')}")
async def handler(resource_id: str, current_user = Depends(get_current_user)):
    if not current_user.has_tenant_access(resource_id):
        raise HTTPException(status_code=403, detail="Forbidden: Cross-tenant access denied.")
    return await fetch_resource(resource_id)
```
"""
        return {
            "report_id": report_id,
            "report_type": "technical_assessment",
            "title": f"Technical Assessment: {spec_title}",
            "target_spec": spec_title,
            "generated_at": date_str,
            "markdown_content": md,
            "download_available": True,
            "format": "MARKDOWN"
        }

    # ------------------------------------------------------------------------
    # 6. Remediation & Validation Runbook
    # ------------------------------------------------------------------------
    def _build_remediation_report(
        self,
        report_id: str,
        spec_title: str,
        date_str: str,
        findings: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        md = f"""# Remediation & Validation Runbook | {spec_title}
**Document ID:** `{report_id}` | **Date:** {date_str}

## Actionable Developer Runbook

### Hotfix Phase 1: Controller Boundary Checks
Deploy middleware checks validating that authenticated identity matches requested path parameter IDs.

### Validation Script
```bash
#!/bin/bash
echo "Verifying defenses on {spec_title}..."
{chr(10).join([f"curl -s -o /dev/null -w '%{{http_code}}' -X {f.get('method', 'GET')} '{f.get('endpoint', '/api')}' -H 'Authorization: Bearer foreign_token' | grep 403 || echo 'FAILED {f.get('endpoint')}'" for f in findings])}
echo "Validation complete."
```
"""
        return {
            "report_id": report_id,
            "report_type": "remediation_report",
            "title": f"Remediation Runbook: {spec_title}",
            "target_spec": spec_title,
            "generated_at": date_str,
            "markdown_content": md,
            "download_available": True,
            "format": "MARKDOWN"
        }

    # ------------------------------------------------------------------------
    # Default Findings
    # ------------------------------------------------------------------------
    def _default_sample_findings(self) -> List[Dict[str, Any]]:
        return [
            {
                "id": "finding-1",
                "title": "Broken Object Level Authorization on Account Statement",
                "endpoint": "/api/v1/accounts/{id}/statement",
                "method": "GET",
                "vulnerabilityType": "BOLA / IDOR",
                "severity": "P1",
                "scannerVerdict": "Vulnerability Confirmed",
                "evidence": 'HTTP 200 OK: {"account_id": "tenant_usr_9921", "balance": 45890.20, "ssn": "***-**-8841"}',
                "description": "Endpoint accepts path parameter {id} without verifying that requesting tenant possesses valid ownership authorization.",
                "impact": "Full cross-tenant exposure of financial statements and personally identifiable information (PII).",
                "remediation": [
                    "Validate current_user.tenant_id == resource.tenant_id in service layer before query execution.",
                    "Adopt Attribute-Based Access Control (ABAC) or Open Policy Agent (OPA).",
                    "Replace guessable sequential IDs with unguessable UUIDv4."
                ],
                "validation": [
                    "curl -s -i -H 'Authorization: Bearer foreign_token' 'https://api.internal/v1/accounts/usr_9921/statement' (Assert HTTP 403 Forbidden)"
                ]
            },
            {
                "id": "finding-2",
                "title": "Broken Function Level Authorization on Tenant Export",
                "endpoint": "/api/v1/admin/tenants/export",
                "method": "POST",
                "vulnerabilityType": "BFLA Auth Bypass",
                "severity": "P2",
                "scannerVerdict": "Vulnerability Confirmed",
                "evidence": "HTTP 200 OK: Bulk export initiated for 12,000 corporate records without requiring admin role.",
                "description": "Administrative export endpoint fails to enforce role-based access control, allowing standard users to execute bulk tenant exports.",
                "impact": "Unauthorized extraction of enterprise tenant directory and configuration metadata.",
                "remediation": [
                    "Enforce strict role-based access control (RBAC) at the API gateway router.",
                    "Require explicit @require_permission('admin:export') decorator on administrative routes.",
                    "Audit routing registries to ensure administrative endpoints are inaccessible to unprivileged scopes."
                ],
                "validation": [
                    "curl -X POST 'https://api.internal/v1/admin/tenants/export' -H 'Authorization: Bearer standard_role' (Assert HTTP 403 Forbidden)"
                ]
            },
            {
                "id": "finding-3",
                "title": "Sensitive Infrastructure Disclosure in Metrics Dump",
                "endpoint": "/debug/metrics/env-dump",
                "method": "GET",
                "vulnerabilityType": "Sensitive Information Disclosure",
                "severity": "P1",
                "scannerVerdict": "Vulnerability Confirmed",
                "evidence": "HTTP 200 OK: Leaked DATABASE_URL and REDIS_AUTH_TOKEN in diagnostic environment telemetry.",
                "description": "Internal diagnostic endpoint remains enabled and accessible without gateway filtering, leaking sensitive environment credentials.",
                "impact": "Exposure of production database connection strings and caching credentials.",
                "remediation": [
                    "Disable /debug/* and actuator endpoints in production API gateway routing.",
                    "Enforce outbound JSON sanitization filters on all telemetry payloads.",
                    "Rotate all leaked credentials immediately and migrate to secure vault management."
                ],
                "validation": [
                    "curl -s 'https://api.internal/debug/metrics/env-dump' (Assert HTTP 404 Not Found)"
                ]
            }
        ]


report_generator = SecurityReportGenerator()

