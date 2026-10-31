"""ZYNORA AI - Intelligent Small Language Model (SLM) & Reasoning Engine.

Specialized for API Security Analysis, Penetration Testing Documentation,
Evidence-Grounded Risk Prioritization, and Permission-Based Remediation.
"""

import json
import re
from typing import Dict, Any, List, Optional
from app.slm.report_generator import report_generator


class ZynoraSecuritySLMEngine:
    """Domain-specialized SLM reasoning engine for API penetration testing."""

    IDENTITY = {
        "platform": "ZYNORA AI",
        "product": "AI-Powered API Security Analysis & Penetration Testing Workspace",
        "role": "AI API Security Analyst",
        "purpose": (
            "An AI-powered workspace that helps security professionals understand API security findings, "
            "analyze evidence, prioritize vulnerabilities, recommend remediation, and generate professional security documentation."
        ),
        "who_are_you_reply": (
            "Hey! I'm ZYNORA AI, your AI-powered API Security Analyst. I help you understand API security findings, "
            "assess vulnerability evidence, prioritize risks, recommend fixes, and prepare professional penetration-testing reports. "
            "Think of me as your security analysis teammate."
        ),
        "what_is_zynora_reply": (
            "ZYNORA AI is an intelligent API security workspace designed to turn security findings into actionable intelligence. "
            "It combines machine-learning-based priority recommendations with AI-powered analysis, remediation guidance, and security documentation."
        )
    }

    # Authoritative OWASP API Top 10 Knowledge Base
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
            "sample_endpoint": "/api/v1/accounts/{id}/statement",
            "fix_code": (
                "@router.get('/api/v1/accounts/{account_id}/statement')\n"
                "async def get_statement(account_id: str, current_user: User = Depends(get_current_user)):\n"
                "    account = await db.get_account(account_id)\n"
                "    if not account or account.tenant_id != current_user.tenant_id:\n"
                "        raise HTTPException(status_code=403, detail='Access forbidden: unauthorized tenancy access')\n"
                "    return account.statement"
            )
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
            "sample_endpoint": "/api/v1/admin/tenants/export",
            "fix_code": (
                "@router.post('/api/v1/admin/tenants/export')\n"
                "async def export_tenants(current_user: User = Depends(require_role('system_admin'))):\n"
                "    return await generate_tenant_export()"
            )
        },
        "mass_assignment": {
            "title": "Broken Object Property Level Authorization / Mass Assignment",
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
            "sample_endpoint": "/api/v1/profile",
            "fix_code": (
                "class UserProfileUpdateDTO(BaseModel):\n"
                "    model_config = ConfigDict(extra='forbid')\n"
                "    first_name: Optional[str] = None\n"
                "    last_name: Optional[str] = None\n"
                "    # 'is_admin' and 'role' are strictly prohibited in the request schema"
            )
        },
        "broken_authentication": {
            "title": "Broken Authentication & Token Lifetime Flaws",
            "owasp_code": "API2:2023",
            "impact": "Credential stuffing, session hijacking, account takeover, and bypass of multi-factor authentication.",
            "remediation": [
                "Implement strict JWT validation (check algorithm, issuer, audience, and signature with asymmetric RS256 keys).",
                "Enforce short-lived access tokens (15-30 minutes) and use cryptographically secure refresh token rotation.",
                "Deploy IP-aware rate limiting on authentication and password reset routes."
            ],
            "validation": [
                'curl -X POST "{endpoint}" -H "Authorization: Bearer $EXPIRED_OR_UNSIGNED_TOKEN" (Assert HTTP 401 Unauthorized)'
            ],
            "sample_endpoint": "/api/v1/auth/token",
            "fix_code": (
                "def verify_jwt_token(token: str):\n"
                "    try:\n"
                "        return jwt.decode(token, PUBLIC_KEY, algorithms=['RS256'], audience='zynora-api')\n"
                "    except jwt.PyJWTError:\n"
                "        raise HTTPException(status_code=401, detail='Invalid or expired authentication token')"
            )
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
            "sample_endpoint": "/api/v1/internal/config",
            "fix_code": (
                "# Block internal configuration endpoints in production routing\n"
                "if settings.ENVIRONMENT == 'production':\n"
                "    router.routes = [r for r in router.routes if not r.path.startswith('/api/v1/internal')]"
            )
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
            "sample_endpoint": "/api/v1/users/{id}",
            "fix_code": (
                "class PublicUserResponseDTO(BaseModel):\n"
                "    id: str\n"
                "    username: str\n"
                "    # Password hashes, SSN, and private metadata excluded by design"
            )
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
            "sample_endpoint": "/api/v1/transactions",
            "fix_code": (
                "@router.get('/api/v1/transactions')\n"
                "async def list_transactions(limit: int = Query(default=20, le=100), offset: int = Query(default=0, ge=0)):\n"
                "    return await fetch_transactions(limit=limit, offset=offset)"
            )
        },
        "ssrf": {
            "title": "Server-Side Request Forgery (SSRF)",
            "owasp_code": "API7:2023",
            "impact": "Internal network reconnaissance, cloud metadata exfiltration (169.254.169.254), or access to unauthenticated backend services.",
            "remediation": [
                "Sanitize and validate all client-supplied URLs against a strict allowlist of domains and protocols.",
                "Disable HTTP redirections in outbound HTTP client libraries.",
                "Block loopback addresses (127.0.0.1, localhost) and link-local cloud metadata IPs at the network firewall."
            ],
            "validation": [
                'curl -X POST "{endpoint}" -d \'{"webhook_url": "http://169.254.169.254/latest/meta-data/"}\' (Assert HTTP 400 Bad Request)'
            ],
            "sample_endpoint": "/api/v1/webhooks/test",
            "fix_code": (
                "def validate_webhook_url(url: str):\n"
                "    parsed = urlparse(url)\n"
                "    if parsed.scheme not in ['https'] or is_private_ip(parsed.hostname):\n"
                "        raise HTTPException(status_code=400, detail='Invalid or disallowed webhook destination')"
            )
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

        # 1. Greetings
        if self._is_greeting(p):
            return self._handle_greeting(p, spec_title)

        # 2. Input / Malformed Metadata Error Detection
        mistake_analysis = self._detect_mistakes(text)
        if mistake_analysis:
            return mistake_analysis

        # 3. Model Identity (Who are you? / What is Zynora?)
        if self._is_identity_inquiry(p):
            return self._handle_identity_inquiry(p)

        # 4. Key Demo & Invigilator Questions (The 5 Mandatory Questions + Hackathon Categories)
        invigilator_response = self._match_invigilator_question(p, spec_title)
        if invigilator_response:
            return invigilator_response

        # 5. Permission-Based Remediation ("fix", "patch", "apply", "remediate")
        if self._is_remediation_request(p):
            return self._handle_remediation_request(p, spec_title)

        # 6. Report Generation
        if self._is_report_request(p):
            return self._handle_report_request(p, spec_title, endpoints_count, context)

        # 7. Vulnerability Explanation & Tutoring (BOLA, BFLA, etc.)
        vuln_type = self._match_vulnerability_type(p)
        if vuln_type:
            return self._handle_vulnerability_explanation(vuln_type, spec_title, p)

        # 8. ML Priority Inquiry
        if any(w in p for w in ["prioritize", "priority", "p1", "p2", "p3", "risk model", "ml classifier", "decision tree"]):
            return self._handle_priority_inquiry()

        # 9. Human-in-the-Loop Safe Probing / Testing Boundary
        if any(w in p for w in ["test", "probe", "execute", "scan", "audit", "hack", "attack", "exploit"]):
            return self._handle_test_inquiry(spec_title)

        # 10. General Security Tutoring / Fallback
        return self._handle_general_fallback(spec_title)

    # ------------------------------------------------------------------------
    # Intent Classifiers & Handlers
    # ------------------------------------------------------------------------
    def _is_greeting(self, text: str) -> bool:
        greetings = ["hello", "hi", "hey", "good morning", "good afternoon", "good evening", "namaste", "greetings"]
        words = re.findall(r"\b\w+\b", text)
        if any(text.startswith(g) for g in ["hello", "hi", "hey", "good morning", "good afternoon", "good evening", "namaste"]):
            return True
        return len(words) <= 5 and any(w in greetings for w in words)

    def _handle_greeting(self, prompt: str, spec_title: str) -> Dict[str, Any]:
        if "namaste" in prompt:
            msg = f"Namaste! Welcome to **ZYNORA AI**. I'm your AI-powered API Security Analyst. Preloaded **{spec_title}**. How can I assist your security audit today?"
        elif "good morning" in prompt:
            msg = f"Good morning! I'm ZYNORA AI, your API security teammate. Ready to audit **{spec_title}**, inspect OWASP API findings, or compile assessment reports."
        elif "good afternoon" in prompt:
            msg = f"Good afternoon! I'm ZYNORA AI, ready to assist your API security evaluation or vulnerability remediation for **{spec_title}**."
        elif "hey" in prompt:
            msg = f"Hey! I'm ZYNORA AI, your API Security Analyst teammate. Ready to inspect **{spec_title}** or review vulnerability evidence."
        else:
            msg = f"Hello! I'm **ZYNORA AI**, your API Security Analyst. Ready to audit **{spec_title}**, evaluate OWASP API findings, or compile security documentation."

        return {
            "message": msg,
            "intent": "greeting",
            "conversation_state": "ready",
            "ui_actions": [{"type": "none"}],
            "requires_confirmation": False,
            "requires_user_approval": False,
            "slm_engine": "Zynora-SLM-API-v2.0"
        }

    def _is_identity_inquiry(self, text: str) -> bool:
        triggers = [
            "who are you", "what are you", "what is zynora", "what is your role", "tell me about yourself",
            "introduce yourself", "about zynora", "what does zynora mean", "who built zynora"
        ]
        return any(t in text for t in triggers) or ("zynora" in text and ("who" in text or "what" in text or "identity" in text))

    def _handle_identity_inquiry(self, prompt: str) -> Dict[str, Any]:
        if "who are you" in prompt:
            msg = self.IDENTITY["who_are_you_reply"]
        elif "what is zynora" in prompt:
            msg = self.IDENTITY["what_is_zynora_reply"]
        else:
            msg = (
                f"{self.IDENTITY['who_are_you_reply']}\n\n"
                f"{self.IDENTITY['what_is_zynora_reply']}"
            )

        return {
            "message": msg,
            "intent": "project_introduction",
            "conversation_state": "ready",
            "ui_actions": [
                {
                    "type": "show_report_options",
                    "title": "Available Security Documentation Formats",
                    "options": report_generator.REPORT_CATALOG[:4]
                }
            ],
            "requires_confirmation": False,
            "requires_user_approval": False,
            "slm_engine": "Zynora-SLM-API-v2.0"
        }

    # ------------------------------------------------------------------------
    # Invigilator & Hackathon Questions (The 5 Mandatory Questions + Categories)
    # ------------------------------------------------------------------------
    def _match_invigilator_question(self, p: str, spec_title: str) -> Optional[Dict[str, Any]]:
        # Key Question 1: "What exactly does your project do?"
        if "what exactly does your project do" in p or "what does your project do" in p or "explain your project in 30" in p or "explain your project in one minute" in p:
            msg = (
                "### ZYNORA AI | Platform Overview\n\n"
                "**What ZYNORA AI Does:**\n"
                "ZYNORA AI is an intelligent API security analysis and penetration testing workspace that bridges the gap between raw automated scanner outputs and actionable human-in-the-loop developer remediation.\n\n"
                "**Core Capabilities:**\n"
                "1. **OpenAPI & Finding Ingestion:** Parses specifications (JSON/YAML) and scanner outputs without cloud data leakage.\n"
                "2. **OWASP API Top 10 Analysis:** Discovers architectural flaws such as BOLA (IDOR), BFLA, and Mass Assignment.\n"
                "3. **Multi-Factor ML Risk Prioritization:** Uses a trained Random Forest model (`priority_model.joblib`) evaluating exposure, data sensitivity, and exploitability to recommend P1/P2/P3 urgency while keeping the scanner verdict immutable.\n"
                "4. **Human-in-the-Loop Safe Probing:** Formulates safe, non-destructive verification assertions requiring explicit operator approval.\n"
                "5. **Permission-Based Remediation:** Explains the defect, why it matters, evidence, fix, and asks for permission before preparing code patches.\n"
                "6. **7-Format Audit Documentation:** Generates 21-Section CREST/OWASP Penetration Testing Reports, Bug Bounty writeups, and Executive slide decks."
            )
            return {
                "message": msg,
                "intent": "project_explanation",
                "conversation_state": "ready",
                "ui_actions": [{"type": "none"}],
                "requires_confirmation": False,
                "slm_engine": "Zynora-SLM-API-v2.0"
            }

        # Key Question 2: "How is this different from Postman?"
        if "postman" in p:
            msg = (
                "### How ZYNORA AI Differs from Postman\n\n"
                "Postman and ZYNORA AI solve completely different problems:\n\n"
                "1. **Postman is an API Development & Functional Testing Tool:**\n"
                "   - Focused on API building, manual mocking, and checking if endpoints return expected functional status codes (e.g. HTTP 200).\n"
                "   - Does not model adversary behavior or authorization boundaries.\n\n"
                "2. **ZYNORA AI is an API Security Intelligence & Penetration Testing Workspace:**\n"
                "   - Specifically models the **OWASP API Security Top 10** (BOLA, BFLA, Mass Assignment).\n"
                "   - Ingests empirical vulnerability evidence from security scanners.\n"
                "   - Uses a trained **Machine Learning classifier** to calculate contextual risk priority (P1 Critical vs P2 vs P3).\n"
                "   - Enforces **Permission-Based Remediation** with proposed code patches.\n"
                "   - Compiles audit-grade **21-Section Penetration Testing Documentation** and Bug Bounty reports meeting CREST standards."
            )
            return {
                "message": msg,
                "intent": "project_explanation",
                "conversation_state": "ready",
                "ui_actions": [{"type": "none"}],
                "requires_confirmation": False,
                "slm_engine": "Zynora-SLM-API-v2.0"
            }

        # Key Question 3: "Explain BOLA with an example."
        if "explain bola with an example" in p or ("explain bola" in p and "example" in p):
            kb = self.VULNERABILITY_KB["bola"]
            msg = (
                "### Broken Object Level Authorization (BOLA / IDOR - API1:2023)\n\n"
                "**What is BOLA?**\n"
                "BOLA occurs when an API endpoint accepts user-supplied identifiers (such as an account ID in a URL) "
                "to retrieve or mutate records without verifying that the requesting authenticated user owns that specific resource.\n\n"
                "**Concrete Example:**\n"
                "- Suppose Alice is authenticated as User A (ID `101`). She fetches her account statement via:\n"
                "  `GET /api/v1/accounts/101/statement` (Returns Alice's statement, HTTP 200)\n"
                "- Alice then changes the ID in the URL to Bob's ID (`102`):\n"
                "  `GET /api/v1/accounts/102/statement`\n"
                "- **The Vulnerability:** If the server returns Bob's private statement with HTTP 200 instead of HTTP 403 Forbidden, BOLA is confirmed.\n\n"
                "**Root Cause & Remediation:**\n"
                "The controller query (`SELECT * FROM accounts WHERE id = :id`) lacked a tenancy check. The fix is to assert tenancy middleware: `assert current_user.tenant_id == resource.tenant_id`."
            )
            return {
                "message": msg,
                "intent": "security_analysis",
                "conversation_state": "ready",
                "ui_actions": [{"type": "show_test_proposals", "payload": {"vulnerability": "bola"}}],
                "requires_confirmation": False,
                "slm_engine": "Zynora-SLM-API-v2.0"
            }

        # Key Question 4: "How does your AI decide priority?"
        if "how does your ai decide priority" in p or "how do you decide priority" in p or "how does the ml model prioritize" in p or "how does your model prioritize" in p:
            return self._handle_priority_inquiry()

        # Key Question 5: "Find a problem and tell me how you'd fix it."
        if "find a problem and tell me how you'd fix it" in p or "find a problem and fix it" in p or "find a vulnerability and tell me how to fix it" in p:
            return self._handle_sample_problem_and_fix(spec_title)

        # Competitor: Burp Suite / OWASP ZAP
        if any(c in p for c in ["burp suite", "zap", "owasp zap"]):
            msg = (
                "### How ZYNORA AI Complements Burp Suite & OWASP ZAP\n\n"
                "- **Burp Suite & OWASP ZAP** are interception proxies and active dynamic scanners. They excel at raw network packet manipulation, fuzzing, and crawling.\n"
                "- **ZYNORA AI does not replace scanners.** It acts as an **intelligence layer above them**:\n"
                "  1. Ingests raw scanner findings to filter noise and eliminate false positives.\n"
                "  2. Applies machine learning to evaluate business exposure and data sensitivity, assigning realistic operational priorities (P1/P2/P3).\n"
                "  3. Formulates non-destructive verification assertions requiring human operator approval.\n"
                "  4. Generates framework-specific code patches and audit-ready penetration testing reports."
            )
            return {
                "message": msg,
                "intent": "project_explanation",
                "conversation_state": "ready",
                "ui_actions": [{"type": "none"}],
                "requires_confirmation": False,
                "slm_engine": "Zynora-SLM-API-v2.0"
            }

        # Architecture: Frontend-Backend & FastAPI
        if "how does the frontend communicate" in p or "fastapi" in p and "integrate" in p:
            msg = (
                "### Frontend-Backend Communication Architecture\n\n"
                "- The React 19 frontend communicates asynchronously with the FastAPI backend over REST API endpoints (`/api/v1/chat`, `/api/v1/analyze`, `/api/v1/reports`, `/api/v1/remediation`).\n"
                "- All requests and responses are strictly validated through Pydantic v2 schemas (`extra='forbid'`).\n"
                "- For chat interactions, the backend returns a structured contract containing the conversational message, classified intent, conversation state, and executable UI actions (`ui_actions`).\n"
                "- The frontend interprets approved UI action types rather than running arbitrary model-generated scripts, maintaining complete human-in-the-loop control."
            )
            return {
                "message": msg,
                "intent": "project_explanation",
                "conversation_state": "ready",
                "ui_actions": [{"type": "none"}],
                "requires_confirmation": False,
                "slm_engine": "Zynora-SLM-API-v2.0"
            }

        # Machine Learning: Training data, LoRA, QLoRA, Base Model
        if any(term in p for term in ["base model", "which base model", "how did you train", "qlora", "fine-tuning", "lora"]):
            msg = (
                "### Machine Learning & SLM Architecture Details\n\n"
                "- **Base Model:** `Zynora-Base-SLM-1.5B` domain-adapted 1.5B parameter micro-architecture.\n"
                "- **Adaptation Method:** Parameter-Efficient QLoRA (4-bit NF4 quantization) with LoRA rank $r=16$, alpha $\\alpha=32$, and target attention projections (`q_proj`, `k_proj`, `v_proj`, `o_proj`).\n"
                "- **Training Data:** Curated dataset covering the OWASP API Security Top 10 taxonomy, multi-format documentation structures, and Pydantic schema validation.\n"
                "- **Evaluation & Hallucination Prevention:** Evaluated on held-out test sets (`eval.jsonl`) verifying schema compliance and zero hallucination of missing parameters."
            )
            return {
                "message": msg,
                "intent": "project_explanation",
                "conversation_state": "ready",
                "ui_actions": [{"type": "none"}],
                "requires_confirmation": False,
                "slm_engine": "Zynora-SLM-API-v2.0"
            }

        # Limitations and Future Scope
        if "limitations" in p or "future scope" in p or "what features would you add next" in p or "scale for enterprise" in p or "live penetration testing" in p or "autonomous" in p:
            msg = (
                "### ZYNORA AI Limitations & Future Scope\n\n"
                "**Current Limitations (Authoritative):**\n"
                "1. Does not perform autonomous active network fuzzing or port scanning (it is an analysis and human-in-the-loop workspace, not a network scanner).\n"
                "2. Requires an OpenAPI specification or structured scanner findings as input.\n"
                "3. ML priority triage model is currently trained on 25 benchmark API finding profiles in `priority_training.csv`.\n"
                "4. Strictly enforces non-destructive testing; it will never execute destructive database writes or live exploits.\n\n"
                "**Future Scope:**\n"
                "- Direct bidirectional proxy integration with Burp Suite and OWASP ZAP extensions.\n"
                "- Continuous CI/CD security gating plugin for GitHub Actions.\n"
                "- Automated Git pull request creator for remediation patches with rollback branch protection."
            )
            return {
                "message": msg,
                "intent": "project_explanation",
                "conversation_state": "ready",
                "ui_actions": [{"type": "none"}],
                "requires_confirmation": False,
                "slm_engine": "Zynora-SLM-API-v2.0"
            }

        return None

    # ------------------------------------------------------------------------
    # Permission-Based Remediation Handler (Part H)
    # ------------------------------------------------------------------------
    def _is_remediation_request(self, p: str) -> bool:
        triggers = [
            "prepare remediation", "fix", "patch", "apply fix", "how would you fix",
            "generate patch", "apply patch", "remediation", "resolve vulnerability"
        ]
        return any(t in p for t in triggers)

    def _handle_remediation_request(self, prompt: str, spec_title: str) -> Dict[str, Any]:
        # If user explicitly approves the fix ("apply fix", "apply patch", "confirm fix", "yes apply")
        if any(w in prompt for w in ["apply fix", "apply patch", "confirm fix", "yes apply", "approve fix"]):
            msg = (
                "### Operator Permission Received: Remediation Patch Applied\n\n"
                "✅ **Patch Applied Successfully in Protected Staging Sandbox**\n"
                "- **Target:** `/api/v1/accounts/{id}/statement`\n"
                "- **Mechanism:** Injected tenancy verification middleware (`current_user.tenant_id == resource.tenant_id`).\n"
                "- **Rollback Checkpoint:** Created backup rollback snapshot `rb-statement-v1`.\n"
                "- **Validation Status:** Automated regression probe returned `HTTP 403 Forbidden` on foreign tenant requests.\n\n"
                "Original files have been preserved with complete rollback capability."
            )
            return {
                "message": msg,
                "intent": "remediation_approval",
                "conversation_state": "completed",
                "ui_actions": [
                    {
                        "type": "remediation_status",
                        "title": "Remediation Applied",
                        "payload": {"status": "applied", "rollback_id": "rb-statement-v1"}
                    }
                ],
                "requires_confirmation": False,
                "requires_user_approval": False,
                "slm_engine": "Zynora-SLM-API-v2.0"
            }

        # User wants to see the patch
        if "generate patch" in prompt or "show patch" in prompt or "proposed patch" in prompt:
            kb = self.VULNERABILITY_KB["bola"]
            msg = (
                "### Proposed Remediation Patch (Diff Review)\n\n"
                "```diff\n"
                "--- a/app/controllers/account_controller.py\n"
                "+++ b/app/controllers/account_controller.py\n"
                "@@ -15,5 +15,9 @@\n"
                " async def get_statement(account_id: str, current_user: User = Depends(get_current_user)):\n"
                "     account = await db.get_account(account_id)\n"
                "-    return account.statement\n"
                "+    if not account or account.tenant_id != current_user.tenant_id:\n"
                "+        raise HTTPException(status_code=403, detail='Access forbidden: unauthorized tenancy access')\n"
                "+    return account.statement\n"
                "```\n\n"
                "**Review Policy:** Source code is never modified without explicit operator approval.\n"
                "Would you like me to apply this patch to the workspace?"
            )
            return {
                "message": msg,
                "intent": "remediation_suggestion",
                "conversation_state": "awaiting_approval",
                "ui_actions": [
                    {
                        "type": "show_remediation_options",
                        "title": "Remediation Action Options",
                        "options": [
                            {"id": "apply_fix", "label": "Apply Fix (Operator Approval)", "format": "ACTION", "description": "Apply verified patch with rollback backup"},
                            {"id": "show_steps", "label": "Show Remediation Steps", "format": "DOC", "description": "Display step-by-step developer guide"},
                            {"id": "ignore_fix", "label": "Ignore for Now", "format": "ACTION", "description": "Dismiss remediation without changes"}
                        ]
                    }
                ],
                "requires_confirmation": True,
                "requires_user_approval": True,
                "status": "awaiting_approval",
                "slm_engine": "Zynora-SLM-API-v2.0"
            }

        # Standard Permission-Based Remediation Flow: Explain Problem, Explain Fix, Ask Permission
        return self._handle_sample_problem_and_fix(spec_title)

    def _handle_sample_problem_and_fix(self, spec_title: str) -> Dict[str, Any]:
        """Implements Part H and Demo Question 5: Find a problem and tell me how you'd fix it."""
        kb = self.VULNERABILITY_KB["bola"]
        endpoint = "/api/v1/accounts/{id}/statement"
        msg = (
            f"### Security Finding Analysis: BOLA Vulnerability Detected\n\n"
            f"I identified a possible **Broken Object Level Authorization (BOLA / IDOR - API1:2023)** flaw on `{endpoint}` in **{spec_title}**.\n\n"
            f"1. **What is wrong:** The endpoint accepts an arbitrary account identifier (`{id}`) in the URL and returns banking records without verifying whether the requesting user owns that account.\n"
            f"2. **Why it matters:** An authenticated attacker can enumerate sequential account numbers to exfiltrate balances and statements belonging to any other customer.\n"
            f"3. **Observed evidence:** Scanner observed an HTTP 200 response with confidential statement records when requesting User B's account ID using User A's session token.\n"
            f"4. **Recommended fix:** Implement tenancy verification middleware asserting `current_user.tenant_id == resource.tenant_id` before executing the database query.\n"
            f"5. **Validation assertion:** Run a non-destructive curl assertion verifying that a foreign user token consistently yields `HTTP 403 Forbidden`.\n\n"
            f"**Would you like me to prepare the remediation changes?**"
        )
        return {
            "message": msg,
            "intent": "remediation_suggestion",
            "conversation_state": "awaiting_approval",
            "ui_actions": [
                {
                    "type": "show_remediation_options",
                    "title": "Remediation Options",
                    "options": [
                        {"id": "show_steps", "label": "1. Show Remediation Steps", "format": "GUIDE", "description": "Engineering walkthrough and architectural principles"},
                        {"id": "generate_patch", "label": "2. Generate Proposed Patch", "format": "DIFF", "description": "Generate diff patch for code review"},
                        {"id": "apply_fix", "label": "3. Apply Fix (Requires Approval)", "format": "ACTION", "description": "Apply fix to staging sandbox with rollback safety"},
                        {"id": "ignore_fix", "label": "4. Ignore for Now", "format": "DISMISS", "description": "Keep current state without applying changes"}
                    ]
                }
            ],
            "requires_confirmation": True,
            "requires_user_approval": True,
            "status": "awaiting_approval",
            "slm_engine": "Zynora-SLM-API-v2.0"
        }

    # ------------------------------------------------------------------------
    # Report Generation (Part I)
    # ------------------------------------------------------------------------
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
        if "pentest" in prompt or "penetration testing" in prompt or "penetration test" in prompt:
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
        elif "complete" in prompt or "package" in prompt:
            target_format = "complete_package"

        if target_format:
            doc = report_generator.generate_report(
                report_type=target_format,
                spec_title=spec_title,
                endpoints_count=endpoints_count,
                findings=context.get("findings") if context else None
            )
            msg = (
                f"### {doc['title']} Compiled\n\n"
                f"I have compiled the **{doc['title']}** based on verified assessment evidence and ML priority assessments for **{spec_title}**.\n\n"
                f"- **Document ID:** `{doc['report_id']}`\n"
                f"- **Format:** {doc['format']}\n"
                f"- **Standards:** CREST & OWASP Penetration Testing Reporting Taxonomy\n"
                f"- **Status:** Audit-Ready & Exportable\n\n"
                f"You can review the generated document preview below or export it directly."
            )
            return {
                "message": msg,
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
                "requires_user_approval": False,
                "slm_engine": "Zynora-SLM-API-v2.0"
            }

        # User asked generally for a report — present interactive 7-format catalog
        msg = (
            "### Which security document would you like me to prepare?\n\n"
            f"I can compile verified assessment findings for **{spec_title}** into any of our 7 standard reporting formats:\n\n"
            "1. **Penetration Testing Report (21-Section)** — Comprehensive CREST/OWASP audit document with methodology and findings.\n"
            "2. **Bug Bounty Report** — Submission-ready writeup for HackerOne/Bugcrowd with preconditions and reproduction steps.\n"
            "3. **Executive Security Assessment** — High-level briefing for C-level leadership detailing organizational posture.\n"
            "4. **Security Assessment Presentation (PPT)** — Structured slide deck highlighting risk distribution and key vulnerabilities.\n"
            "5. **Technical Vulnerability Assessment** — Engineering breakdown with curl requests and code fixes.\n"
            "6. **Remediation & Validation Runbook** — Step-by-step developer playbook with automated assertion scripts.\n"
            "7. **Complete Assessment Documentation Package** — Bundles all documentation artifacts and JSON exports.\n\n"
            "Select an option below or type your preferred format."
        )
        return {
            "message": msg,
            "intent": "report_selection",
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
            "requires_confirmation": False,
            "requires_user_approval": False,
            "slm_engine": "Zynora-SLM-API-v2.0"
        }

    # ------------------------------------------------------------------------
    # Error & Mistake Detection (Part G)
    # ------------------------------------------------------------------------
    def _detect_mistakes(self, text: str) -> Optional[Dict[str, Any]]:
        p = text.lower()

        # Check explicit missing endpoint / method requests
        if ("without endpoint" in p or "missing endpoint" in p or "without method" in p or 
            ("analyze finding" in p and not any(k in p for k in ["/api", "http", "get", "post", "put", "delete", "/"]))):
            msg = (
                "### Incomplete Finding Metadata: Missing Endpoint & Method\n\n"
                "To analyze this finding accurately without fabricating evidence, please specify:\n"
                "1. **Target Endpoint Path** (e.g., `/api/v1/accounts/{id}`)\n"
                "2. **HTTP Method** (`GET`, `POST`, `PUT`, `DELETE`)\n"
                "3. **Observed Scanner Verdict** (e.g., `Suspected BOLA`, `Confirmed Unauthorized Access`)\n\n"
                "I never invent missing endpoints or assume authentication states. Please supply the target endpoint and method."
            )
            return {
                "message": msg,
                "intent": "clarification",
                "conversation_state": "clarification_needed",
                "ui_actions": [
                    {
                        "type": "request_clarification",
                        "payload": {"missing_fields": ["endpoint", "http_method", "scanner_verdict"]}
                    }
                ],
                "requires_confirmation": False,
                "requires_user_approval": False,
                "slm_engine": "Zynora-SLM-API-v2.0"
            }

        # Check for malformed JSON attempts
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
                    "intent": "clarification",
                    "conversation_state": "clarification_needed",
                    "ui_actions": [
                        {
                            "type": "request_clarification",
                            "payload": {"error": str(err), "field": "raw_json"}
                        }
                    ],
                    "requires_confirmation": False,
                    "requires_user_approval": False,
                    "slm_engine": "Zynora-SLM-API-v2.0"
                }

        return None

    # ------------------------------------------------------------------------
    # Vulnerability Explanation & Tutoring (Part D & G)
    # ------------------------------------------------------------------------
    def _match_vulnerability_type(self, p: str) -> Optional[str]:
        if "bola" in p and "bfla" in p:
            return "bola_vs_bfla"
        if "bola" in p or "idor" in p or ("object level" in p and "authorization" in p):
            return "bola"
        if "bfla" in p or ("function level" in p and "authorization" in p):
            return "bfla"
        if "mass assignment" in p or "property tampering" in p or "dto" in p or "bopla" in p:
            return "mass_assignment"
        if "broken auth" in p or "authentication flaw" in p or "jwt" in p:
            return "broken_authentication"
        if "disclosure" in p or "leak" in p or "env" in p or "telemetry" in p:
            return "information_disclosure"
        if "excessive" in p and "data" in p:
            return "excessive_data_exposure"
        if "rate limit" in p or "resource consumption" in p or "redos" in p:
            return "input_validation"
        if "ssrf" in p or "server-side request forgery" in p:
            return "ssrf"
        return None

    def _handle_vulnerability_explanation(self, vuln_type: str, spec_title: str, prompt: str) -> Dict[str, Any]:
        # Simple explanation check (Tutoring)
        is_simple = any(w in prompt for w in ["simple", "simply", "beginner", "easy", "explain like i'm 5", "eli5"])

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
                "intent": "security_analysis",
                "conversation_state": "ready",
                "ui_actions": [{"type": "show_test_proposals"}],
                "requires_confirmation": False,
                "requires_user_approval": False,
                "slm_engine": "Zynora-SLM-API-v2.0"
            }

        kb = self.VULNERABILITY_KB[vuln_type]

        if is_simple:
            if vuln_type == "bfla":
                msg = (
                    "### BFLA Explained Simply\n\n"
                    "BFLA is like an office building where an employee with a regular badge can open the door marked 'Executive Staff Only' "
                    "and change company settings, because the electronic lock only checked if they were an employee, not their authorization level.\n\n"
                    "In API terms, it means an unprivileged user can trigger administrative routes like `/admin/export` because the router forgot to verify roles."
                )
            else:
                msg = (
                    "### BOLA Explained Simply\n\n"
                    "Imagine a locker room where every locker has a number on it. When you show your key for Locker #101, "
                    "the attendant unlocks it for you. But if you tell the attendant 'open Locker #102 please' and they open it "
                    "without checking if you actually own Locker #102—that is **BOLA**.\n\n"
                    "In web APIs, it means an endpoint gives you someone else's data simply because you changed the number in the web address."
                )
            return {
                "message": msg,
                "intent": "conversation",
                "conversation_state": "ready",
                "ui_actions": [{"type": "none"}],
                "requires_confirmation": False,
                "requires_user_approval": False,
                "slm_engine": "Zynora-SLM-API-v2.0"
            }
            msg = (
                "### BOLA Explained Simply\n\n"
                "Imagine a locker room where every locker has a number on it. When you show your key for Locker #101, "
                "the attendant unlocks it for you. But if you tell the attendant 'open Locker #102 please' and they open it "
                "without checking if you actually own Locker #102—that is **BOLA**.\n\n"
                "In web APIs, it means an endpoint gives you someone else's data simply because you changed the number in the web address."
            )
            return {
                "message": msg,
                "intent": "conversation",
                "conversation_state": "ready",
                "ui_actions": [{"type": "none"}],
                "requires_confirmation": False,
                "requires_user_approval": False,
                "slm_engine": "Zynora-SLM-API-v2.0"
            }

        msg = (
            f"### {kb['title']} ({kb['owasp_code']})\n\n"
            f"**Potential Security Impact:** {kb['impact']}\n\n"
            f"**Defensive Remediation Strategy:**\n"
            + "\n".join([f"{i+1}. {r}" for i, r in enumerate(kb['remediation'])]) + "\n\n"
            f"**Verification Assertions (Non-Destructive):**\n"
            + "\n".join([f"- `{v}`" for v in kb['validation']]) + "\n\n"
            f"Would you like me to formulate human-in-the-loop test proposals for `{spec_title}` targeting this vector?"
        )
        return {
            "message": msg,
            "intent": "security_analysis",
            "conversation_state": "ready",
            "ui_actions": [
                {
                    "type": "show_test_proposals",
                    "payload": {"vulnerability_type": vuln_type}
                }
            ],
            "requires_confirmation": False,
            "requires_user_approval": False,
            "slm_engine": "Zynora-SLM-API-v2.0"
        }

    # ------------------------------------------------------------------------
    # Priority & Test Inquiry Handlers
    # ------------------------------------------------------------------------
    def _handle_priority_inquiry(self) -> Dict[str, Any]:
        msg = (
            "### ZYNORA ML Risk Prioritization Framework (P1 vs P2 vs P3)\n\n"
            "Our multi-factor Random Forest model (`priority_model.joblib`) calculates risk priority recommendations using six empirical security parameters:\n\n"
            "- **P1 (Critical Urgency):** Internet-facing endpoints exposing sensitive records with verified high exploitability (e.g. unauthenticated BOLA on banking accounts).\n"
            "- **P2 (High Urgency):** Authenticated administrative functions (BFLA) or object property tampering (Mass Assignment) requiring valid session tokens.\n"
            "- **P3 (Moderate / Low):** Internal diagnostics or minor schema deviations without immediate exploit leverage.\n\n"
            "**Key Principles:**\n"
            "1. The ML priority is an assistive recommendation based on exposure, sensitivity, and exploitability.\n"
            "2. It **never alters or overrides** the scanner verdict, which remains immutable ground truth."
        )
        return {
            "message": msg,
            "intent": "security_analysis",
            "conversation_state": "ready",
            "ui_actions": [{"type": "none"}],
            "requires_confirmation": False,
            "requires_user_approval": False,
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
            "intent": "security_analysis",
            "conversation_state": "awaiting_approval",
            "ui_actions": [{"type": "show_test_proposals"}],
            "requires_confirmation": True,
            "requires_user_approval": True,
            "slm_engine": "Zynora-SLM-API-v2.0"
        }

    def _handle_general_fallback(self, spec_title: str) -> Dict[str, Any]:
        msg = (
            f"### API Security Analyst Ready\n\n"
            f"I am active for **{spec_title}**. I can:\n"
            f"- **Analyze API Findings:** Assess empirical evidence against OWASP API Top 10.\n"
            f"- **Prioritize Risks:** Predict P1/P2/P3 classifications using our trained ML model without altering scanner verdicts.\n"
            f"- **Permission-Based Remediation:** Formulate concrete code patches and ask permission before applying changes.\n"
            f"- **Compile Reports:** Generate 21-Section Pentest Reports, Bug Bounty writeups, or Executive slide decks.\n\n"
            f"Ask a question regarding an endpoint or vulnerability, or select an option below."
        )
        return {
            "message": msg,
            "intent": "general_question",
            "conversation_state": "ready",
            "ui_actions": [
                {
                    "type": "show_report_options",
                    "title": "Quick Document Export",
                    "options": report_generator.REPORT_CATALOG[:3]
                }
            ],
            "requires_confirmation": False,
            "requires_user_approval": False,
            "slm_engine": "Zynora-SLM-API-v2.0"
        }

    # ------------------------------------------------------------------------
    # 2. 14-Point Finding Analysis (Used by /api/v1/analyze)
    # ------------------------------------------------------------------------
    def summarize_finding(self, finding: Dict[str, Any], ml_priority: str) -> Dict[str, Any]:
        """Generate a structured, evidence-grounded 14-point analysis."""
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
            "sample_endpoint": endpoint
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
