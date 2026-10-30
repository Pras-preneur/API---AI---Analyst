"""Pydantic schemas for AI/ML security finding analysis and conversational SLM.

Enforces strict request/response contracts for:
- Security finding ingestion & priority analysis
- ML priority prediction & explanation
- SLM conversational intelligence & structured UI actions
- Multi-format report generation (Pentest, Bug Bounty, Executive, Presentation)
"""

from typing import List, Dict, Any, Optional, Literal
from pydantic import BaseModel, Field, ConfigDict


# ============================================================================
# 1. Finding & Analysis Schemas
# ============================================================================

class SecurityFindingInput(BaseModel):
    model_config = ConfigDict(extra="ignore")

    finding_id: str = Field(..., min_length=1, description="Unique scanner finding identifier")
    scanner_verdict: str = Field(..., min_length=1, description="Immutable scanner ground truth verdict")
    finding_type: str = Field(..., description="Vulnerability type (e.g. bola, bfla, mass_assignment, information_disclosure)")
    evidence_confidence: Literal["low", "medium", "high", "confirmed"] = Field(..., description="Confidence of the observed evidence")
    exposure: Literal["internet_facing", "internal", "unknown"] = Field(..., description="Network exposure of the affected endpoint")
    data_sensitivity: Literal["public", "business", "personal", "sensitive", "unknown"] = Field(..., description="Sensitivity of data handled by the endpoint")
    auth_required: Literal["true", "false", "unknown"] = Field(..., description="Whether authentication is required")
    exploitability: Literal["low", "medium", "high", "unknown"] = Field(..., description="Ease of exploitation")

    endpoint: Optional[str] = Field(None, description="API endpoint path (e.g. /api/v1/accounts/{id})")
    http_method: Optional[Literal["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"]] = Field(None, description="HTTP verb")
    evidence: Optional[str] = Field(None, description="Observed evidence snippet or raw HTTP response")
    description: Optional[str] = Field(None, description="Detailed description of the finding")


class FindingAnalysisOutput(BaseModel):
    finding_id: str
    scanner_verdict: str
    priority: str
    priority_source: str = "ml_recommendation"
    priority_probabilities: Dict[str, float] = Field(default_factory=dict)
    finding_summary: str
    evidence_assessment: str
    potential_impact: str
    priority_explanation: str
    remediation_steps: List[str]
    validation_steps: List[str]
    limitations: List[str]
    scanner_verdict_changed: bool = False
    slm_engine: str = "Zynora-SLM-API-v2.0"
    is_model_recommendation: bool = True


# ============================================================================
# 2. Structured Response Contract & UI Actions
# ============================================================================

class ReportOption(BaseModel):
    id: str = Field(..., description="Unique report type ID (e.g. pentest_report, bug_bounty)")
    label: str = Field(..., description="Human-readable title")
    format: str = Field(..., description="Format: PDF, DOCUMENT, PPT, MARKDOWN")
    description: str = Field(..., description="Brief summary of document scope and audience")
    icon: Optional[str] = None


class UIAction(BaseModel):
    type: Literal[
        "show_report_options",
        "show_test_proposals",
        "show_finding_card",
        "request_clarification",
        "display_code_remediation",
        "display_presentation_slides",
        "none"
    ]
    title: Optional[str] = None
    options: Optional[List[ReportOption]] = None
    payload: Optional[Dict[str, Any]] = None


class ReportDocument(BaseModel):
    report_id: str
    report_type: Literal[
        "pentest_report",
        "executive_assessment",
        "technical_assessment",
        "bug_bounty",
        "security_presentation",
        "remediation_report",
        "complete_package"
    ]
    title: str
    target_spec: str
    generated_at: str
    sections: List[Dict[str, Any]] = Field(default_factory=list)
    slides: Optional[List[Dict[str, Any]]] = None
    markdown_content: str
    download_available: bool = True
    format: str = "MARKDOWN"


class ReportMeta(BaseModel):
    status: Literal["not_started", "selecting_format", "generating", "completed", "failed"]
    format: Optional[str] = None
    document: Optional[ReportDocument] = None


class ChatMessageRequest(BaseModel):
    message: str = Field(..., min_length=1, max_length=4000)
    context: Optional[Dict[str, Any]] = None


class ReportGenerationRequest(BaseModel):
    report_type: str
    spec_title: str = "API Security Assessment"
    endpoints_count: int = 0
    findings: Optional[List[Dict[str, Any]]] = None
    context: Optional[Dict[str, Any]] = None


class SLMStructuredResponse(BaseModel):
    """Structured response contract between ZYNORA SLM and frontend."""
    message: str = Field(..., description="Conversational explanation rendered in chat")
    reply: Optional[str] = Field(None, description="Alias for message for frontend compatibility")
    intent: Literal[
        "greeting",
        "platform_inquiry",
        "general_qa",
        "vulnerability_analysis",
        "finding_investigation",
        "scanner_review",
        "risk_prioritization",
        "report_request",
        "report_generation",
        "security_assessment",
        "cowork_task",
        "missing_information",
        "error_handling"
    ] = "general_qa"
    conversation_state: Literal[
        "ready",
        "awaiting_user_selection",
        "in_progress",
        "awaiting_approval",
        "completed",
        "clarification_needed"
    ] = "ready"
    ui_actions: List[UIAction] = Field(default_factory=list)
    report: Optional[ReportMeta] = None
    finding_analysis: Optional[FindingAnalysisOutput] = None
    requires_confirmation: bool = False
    slm_engine: str = "Zynora-SLM-API-v2.0"
