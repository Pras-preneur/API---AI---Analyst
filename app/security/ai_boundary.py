"""AI/ML Integration Boundary for API Security Testing Assistant.

This module defines the integration contract and data schemas for future
AI-assisted finding analysis.

SAFETY CONSTRAINTS:
1. The AI model is strictly read-only: it MUST NOT execute HTTP requests,
   interact with networks, or modify session or execution state.
2. Credentials and secrets are strictly excluded: only sanitized finding metadata
   and scrubbed evidence may be passed to the AI boundary.
3. The AI model CANNOT confirm vulnerabilities: assessment outcomes can only be
   transitioned to CONFIRMED via explicit human review.
4. AI outputs are advisory annotations only: they do not alter finding status,
   severity, or assessment outcome.
"""

import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict, Field, field_validator

from .sanitization import sanitize_data


class AIFindingAnalysisInput(BaseModel):
    """Sanitized input payload prepared for AI-assisted finding explanation.

    Contains only scrubbed metadata and non-sensitive evidence.
    """
    model_config = ConfigDict(populate_by_name=True)

    finding_id: str = Field(..., description="Unique identifier of the finding being analyzed")
    test_type: str = Field(..., description="Vulnerability category (e.g. 'BOLA', 'BFLA')")
    endpoint_path: str = Field(..., description="API endpoint path evaluated")
    endpoint_method: str = Field(..., description="HTTP method evaluated (e.g. 'GET', 'POST')")
    severity: str = Field(..., description="Reported finding severity (Low, Medium, High, Critical)")
    execution_status: str = Field(..., description="Execution status (e.g. 'COMPLETED', 'NOT_EXECUTED')")
    assessment_outcome: str = Field(..., description="Current assessment outcome (e.g. 'SUSPECTED')")
    sanitized_evidence: Dict[str, Any] = Field(
        default_factory=dict,
        description="Scrubbed request and response metadata without credentials or secrets",
    )
    observed_behavior: Optional[str] = Field(
        default=None,
        description="High-level description of behavior observed during testing",
    )

    @field_validator("sanitized_evidence")
    @classmethod
    def _validate_evidence_sanitized(cls, evidence: Dict[str, Any]) -> Dict[str, Any]:
        """Guarantee evidence passed into AI boundary is sanitized."""
        return sanitize_data(evidence)


class AIFindingAnalysisOutput(BaseModel):
    """Structured, advisory explanation produced by future AI finding analysis.

    NOTE: AI outputs are informational only. They do not automatically confirm
    vulnerabilities or alter the human-in-the-loop workflow.
    """
    model_config = ConfigDict(populate_by_name=True)

    analysis_id: str = Field(
        default_factory=lambda: str(uuid.uuid4()),
        description="Unique identifier for this AI analysis record",
    )
    finding_id: str = Field(..., description="Identifier of the finding analyzed")
    explanation: str = Field(..., description="Clear explanation of the observed behavior and security implications")
    evidence_references: List[str] = Field(
        default_factory=list,
        description="References to specific status codes, headers, or differential indicators that justify the explanation",
    )
    uncertainty_and_limitations: str = Field(
        ...,
        description="Explicit limitations, assumptions, or alternative explanations for the observation",
    )
    suggested_remediation: Optional[str] = Field(
        default=None,
        description="Actionable developer guidance for remediating the suspected issue",
    )
    confidence_score: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
        description="Model confidence estimate between 0.0 and 1.0",
    )
    is_advisory_only: bool = Field(
        default=True,
        description="Enforces that this analysis is strictly advisory and cannot alter execution or confirmation state",
    )
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC timestamp when the AI analysis was generated",
    )

    @field_validator("is_advisory_only")
    @classmethod
    def _enforce_advisory(cls, val: bool) -> bool:
        if not val:
            raise ValueError("AI analysis outputs must remain strictly advisory.")
        return val


@runtime_checkable
class AIFindingAnalyzer(Protocol):
    """Protocol defining the integration contract for any future AI analysis provider.

    Implementations must be stateless and read-only.
    """
    def analyze_finding(self, input_data: AIFindingAnalysisInput) -> AIFindingAnalysisOutput:
        """Analyze a sanitized finding and produce an advisory explanation."""
        ...


def prepare_ai_input_from_finding(
    finding_dict: Dict[str, Any],
    test_type: str = "BOLA",
    observed_behavior: Optional[str] = None,
) -> AIFindingAnalysisInput:
    """Helper to construct and validate an AIFindingAnalysisInput from finding data.

    Enforces that evidence is scrubbed before being packaged for the AI interface.
    """
    endpoint = finding_dict.get("endpoint") or {}
    evidence = finding_dict.get("evidence") or {}

    sanitized_evidence = sanitize_data(evidence)

    return AIFindingAnalysisInput(
        finding_id=finding_dict.get("finding_id", "unknown"),
        test_type=test_type,
        endpoint_path=endpoint.get("path", ""),
        endpoint_method=endpoint.get("method", "GET"),
        severity=finding_dict.get("severity", "Medium"),
        execution_status=str(finding_dict.get("execution_status") or "COMPLETED"),
        assessment_outcome=str(finding_dict.get("assessment_outcome") or "SUSPECTED"),
        sanitized_evidence=sanitized_evidence,
        observed_behavior=observed_behavior,
    )

