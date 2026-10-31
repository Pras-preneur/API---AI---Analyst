import threading
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, List, Dict, Optional

from pydantic import BaseModel, Field, ConfigDict, field_validator, model_validator, PrivateAttr

# Reuse existing parser models for endpoint representation
from .parser.openapi_parser import EndpointModel
from .config import ALLOWED_TARGETS, MAX_REQUESTS_PER_EXECUTION, DEFAULT_REQUEST_TIMEOUT


# ---------------------------------------------------------------------------
# Enums for execution and assessment states
# ---------------------------------------------------------------------------

class TestStatus(str, Enum):
    """Proposal lifecycle status."""
    __test__ = False
    PROPOSED = "Proposed"
    APPROVED = "Approved"
    REJECTED = "Rejected"
    EXECUTED = "Executed"


class FindingStatus(str, Enum):
    """Legacy finding status (retained for backward compatibility with reports)."""
    SUSPECTED = "Suspected"
    CONFIRMED = "Confirmed"
    FALSE_POSITIVE = "FalsePositive"
    NOT_EXECUTED = "NotExecuted"


class ExecutionMode(str, Enum):
    """Execution mode: specification-driven or legacy fixture-based."""
    SPEC_DRIVEN = "SPEC_DRIVEN"
    LEGACY_FIXTURE = "LEGACY_FIXTURE"


class ExecutionStatus(str, Enum):
    """Status of the test execution process itself (separate from assessment outcome)."""
    __test__ = False
    NOT_EXECUTED = "NOT_EXECUTED"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


class AssessmentOutcome(str, Enum):
    """Vulnerability assessment outcome of a security test.

    States distinguish between suspected vulnerabilities discovered automatically,
    inconclusive executions, verified access denials, and confirmed findings.

    NOTE: A CONFIRMED outcome can ONLY be assigned by explicit human review,
    never automatically by response status codes or automated differential comparisons.
    """
    SUSPECTED = "SUSPECTED"
    INCONCLUSIVE = "INCONCLUSIVE"
    ACCESS_DENIED = "ACCESS_DENIED"
    CONFIRMED = "CONFIRMED"
    FALSE_POSITIVE = "FALSE_POSITIVE"


class AuthTestType(str, Enum):
    """Supported authentication test types for specification-driven security testing."""
    AUTH_MISSING_CREDENTIALS = "AUTH_MISSING_CREDENTIALS"


class AuthenticationMutation(str, Enum):
    """Explicit authentication mutation modes for controlled security probing."""
    NONE = "NONE"                                # Normal authenticated request
    MISSING_CREDENTIALS = "MISSING_CREDENTIALS"  # Deliberately omit all authentication material


def validate_assessment_outcome(
    outcome: AssessmentOutcome,
    *,
    is_human_review: bool = False,
    reviewer_notes: Optional[str] = None,
) -> None:
    """Enforce that CONFIRMED outcome requires explicit human review and justification.

    Automated differential comparisons or HTTP status codes alone must NEVER
    assign CONFIRMED without human reviewer sign-off.
    """
    if outcome == AssessmentOutcome.CONFIRMED:
        if not is_human_review:
            raise ValueError(
                "Assessment outcome 'CONFIRMED' requires explicit human review and "
                "cannot be assigned automatically by automated differential comparisons or status codes."
            )
        if reviewer_notes is not None and len(reviewer_notes.strip()) < 5:
            raise ValueError(
                "Reviewer notes must contain at least 5 characters to confirm a finding."
            )


# ---------------------------------------------------------------------------
# Execution Configuration Models (Stage 2)
# ---------------------------------------------------------------------------

class TestIdentity(BaseModel):
    """Configurable test persona (e.g. resource owner or attacker) without hardcoded secrets."""
    __test__ = False
    model_config = ConfigDict(populate_by_name=True)

    identity_id: str = Field(..., description="Unique label for persona (e.g., 'owner', 'attacker')")
    username: Optional[str] = None
    password: Optional[str] = None
    token: Optional[str] = None
    api_key: Optional[str] = None
    headers: Dict[str, str] = Field(default_factory=dict, description="Custom auth headers (e.g. session tokens)")
    cookies: Dict[str, str] = Field(default_factory=dict, description="Authentication cookies")
    roles: List[str] = Field(default_factory=list, description="Roles assigned to this identity")
    credentials_verified: bool = Field(default=False, description="Flag indicating if the identity's credentials have been verified as valid for authentication")
    description: Optional[str] = None

    def get_redacted_summary(self) -> Dict[str, Any]:
        """Return safe identity representation with all credentials redacted."""
        redacted_headers = {}
        for k, v in self.headers.items():
            if any(s in k.lower() for s in ["auth", "token", "key", "secret", "cookie", "session"]):
                redacted_headers[k] = "[REDACTED]"
            else:
                redacted_headers[k] = v

        return {
            "identity_id": self.identity_id,
            "username": self.username,
            "has_password": bool(self.password),
            "has_token": bool(self.token),
            "has_api_key": bool(self.api_key),
            "roles": self.roles,
            "credentials_verified": self.credentials_verified,
            "headers": redacted_headers,
            "cookies": {k: "[REDACTED]" for k in self.cookies},
            "description": self.description,
        }


class ParameterFixtures(BaseModel):
    """Parameter fixtures for endpoint path substitution and supported query/header parameters."""
    model_config = ConfigDict(populate_by_name=True)

    owner_path_params: Dict[str, Any] = Field(
        default_factory=dict,
        description="Path parameter values for the resource owner, e.g. {'user_id': '101'}",
    )
    attacker_path_params: Dict[str, Any] = Field(
        default_factory=dict,
        description="Path parameter values for the attacker control test, e.g. {'user_id': '202'}",
    )
    query_params: Dict[str, Any] = Field(
        default_factory=dict,
        description="Query parameters to include in requests",
    )
    headers: Dict[str, str] = Field(
        default_factory=dict,
        description="Static request headers (non-credential)",
    )

    @field_validator("owner_path_params", "attacker_path_params")
    @classmethod
    def _validate_path_params(cls, params: Dict[str, Any]) -> Dict[str, Any]:
        """Validate path parameter values against path traversal, separators, and null bytes."""
        traversal_patterns = ["..", "/", "\\", "\x00", "%2e", "%2f", "%5c", "%00"]
        for key, val in params.items():
            if val is None or val == "":
                raise ValueError(f"Path parameter '{key}' cannot be null or empty")
            val_str = str(val).strip()
            val_str_lower = val_str.lower()
            for pattern in traversal_patterns:
                if pattern in val_str_lower:
                    raise ValueError(
                        f"Path parameter '{key}' contains illegal traversal sequence or separator: '{pattern}'"
                    )
        return params


class RequestBudget(BaseModel):
    """Bounded per-test execution budget enforcing request limits before sending."""
    max_requests: int = Field(
        default=5,
        ge=1,
        le=MAX_REQUESTS_PER_EXECUTION,
        description=f"Maximum requests permitted for this test (1-{MAX_REQUESTS_PER_EXECUTION})",
    )
    current_count: int = Field(default=0, ge=0, description="Requests consumed so far")

    def can_request(self, planned_count: int = 1) -> bool:
        """Check whether the planned number of requests can be made within budget."""
        return (self.current_count + planned_count) <= self.max_requests

    def record_request(self, count: int = 1) -> None:
        """Record consumed requests against budget; raises ValueError if exceeded."""
        if not self.can_request(count):
            raise ValueError(
                f"Execution budget exceeded: cannot make {count} request(s) "
                f"({self.current_count}/{self.max_requests} consumed)"
            )
        self.current_count += count

    @property
    def remaining(self) -> int:
        return max(0, self.max_requests - self.current_count)


class BFLAPolicyMapping(BaseModel):
    """Explicit human-defined authorization policy mapping for BFLA testing.

    BFLA testing MUST NOT infer policies from OpenAPI tags, names, or scopes.
    An explicit policy mapping is required before differential BFLA can execute.
    """
    model_config = ConfigDict(populate_by_name=True)

    endpoint_path: str = Field(..., description="Exact endpoint path to test, e.g. '/admin/data'")
    endpoint_method: str = Field(default="GET", description="HTTP method for the endpoint (Stage 6.2.2 strictly GET)")
    required_role: str = Field(..., description="Role required to access the endpoint, e.g. 'admin'")
    permitted_roles: List[str] = Field(default_factory=list, description="Roles authorized to access this function")
    forbidden_roles: List[str] = Field(default_factory=list, description="Roles explicitly forbidden from accessing this function")
    allow_static_route_concealment: bool = Field(default=False, description="Whether 404 responses for static endpoints should be interpreted as ACCESS_DENIED")
    notes: Optional[str] = Field(None, description="Optional security assessment or policy notes")


class ExecutionConfig(BaseModel):
    """Configuration for test execution, enforcing local targets, approval, and budget safeguards."""
    model_config = ConfigDict(populate_by_name=True)

    mode: ExecutionMode = Field(
        default=ExecutionMode.SPEC_DRIVEN,
        description="Execution mode: SPEC_DRIVEN uses uploaded specification; LEGACY_FIXTURE uses mock /vuln routes",
    )
    target_base_url: str = Field(
        default="http://127.0.0.1:8001",
        description="Base URL of target API; restricted to authorized local mock addresses",
    )
    owner_identity: Optional[TestIdentity] = None
    attacker_identity: Optional[TestIdentity] = None
    privileged_identity: Optional[TestIdentity] = None
    lower_privileged_identity: Optional[TestIdentity] = None
    authenticated_identity: Optional[TestIdentity] = Field(
        default=None,
        description="Configured identity possessing valid credentials for establishing an authenticated baseline",
    )
    auth_mutation: AuthenticationMutation = Field(
        default=AuthenticationMutation.NONE,
        description="Deliberate authentication mutation mode for authentication testing",
    )
    bfla_policy: Optional[BFLAPolicyMapping] = None
    parameters: ParameterFixtures = Field(default_factory=ParameterFixtures)
    budget: RequestBudget = Field(default_factory=RequestBudget)
    timeout_seconds: float = Field(default=DEFAULT_REQUEST_TIMEOUT, ge=0.5, le=30.0)
    follow_redirects: bool = Field(default=False)
    require_approval: bool = Field(default=True)

    @field_validator("target_base_url")
    @classmethod
    def _validate_target_url(cls, target: str) -> str:
        normalized = target.rstrip("/")
        if normalized not in ALLOWED_TARGETS:
            raise ValueError(
                f"Target URL '{target}' is not authorized. Must be one of: {sorted(list(ALLOWED_TARGETS))}"
            )
        return normalized

    @field_validator("require_approval")
    @classmethod
    def _validate_require_approval(cls, val: bool) -> bool:
        if not val:
            raise ValueError("Execution without explicit human approval is strictly prohibited by safety policy.")
        return val

    @field_validator("follow_redirects")
    @classmethod
    def _validate_follow_redirects(cls, val: bool) -> bool:
        if val:
            raise ValueError("follow_redirects must be False to prevent SSRF and redirect loops.")
        return val


class ExecuteRequest(BaseModel):
    """Payload for test execution endpoint."""
    model_config = ConfigDict(populate_by_name=True)

    proposal_ids: List[str] = Field(..., description="List of proposal IDs to execute")
    target: str = Field(..., description="Base URL of the target mock API")
    config: Optional[ExecutionConfig] = None


# ---------------------------------------------------------------------------
# Proposal and Finding models
# ---------------------------------------------------------------------------

class ProposedTest(BaseModel):
    """A security‑test suggestion generated from an endpoint inventory."""
    test_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    endpoint: EndpointModel
    test_type: str  # e.g. "BOLA", "BFLA", "ExcessiveData", etc.
    description: str
    severity: str  # Low / Medium / High / Critical
    status: TestStatus = TestStatus.PROPOSED
    # Optional human‑written notes
    notes: Optional[str] = None
    # Timestamps for human actions
    approved_at: Optional[datetime] = None
    rejected_at: Optional[datetime] = None
    # Execution timestamp – set when a proposal is successfully executed
    executed_at: Optional[datetime] = None


class Evidence(BaseModel):
    """Captured request/response data for a finding (credentials are redacted)."""
    request: Dict
    response: Dict
    notes: Optional[str] = None


class HumanReviewOutcome(str, Enum):
    """Permitted outcomes for an explicit human review decision."""
    CONFIRMED = "CONFIRMED"
    FALSE_POSITIVE = "FALSE_POSITIVE"


class ReviewRecord(BaseModel):
    """Immutable audit record representing a human review decision."""
    model_config = ConfigDict(populate_by_name=True)

    record_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    reviewed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    reviewer_id: str = Field(..., min_length=1, description="Client-asserted identifier of human reviewer (audit traceability only)")
    decision: HumanReviewOutcome = Field(..., description="Review outcome: CONFIRMED or FALSE_POSITIVE")
    notes: Optional[str] = Field(None, description="Review justification / notes")
    previous_outcome: Optional[str] = Field(None, description="Assessment outcome prior to this review")


class Finding(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    finding_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    test_id: str
    endpoint: EndpointModel
    evidence: Evidence
    severity: str
    status: FindingStatus = FindingStatus.SUSPECTED
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    # Optional field for notes, execution reasoning, confidence, or NOT_EXECUTED reason
    notes: Optional[str] = None
    # Stage 2 enhancements: explicit execution status and assessment outcome
    execution_status: Optional[ExecutionStatus] = None
    assessment_outcome: Optional[AssessmentOutcome] = None
    # Stage 5 enhancements: traceability, reason, remediation, and human review metadata
    assessment_reason: Optional[str] = None
    remediation: Optional[str] = None
    is_human_reviewed: bool = False
    reviewed_at: Optional[datetime] = None
    reviewer_id: Optional[str] = None
    reviewer_notes: Optional[str] = None
    # Audit trail of human reviews and re-execution invalidation flag
    review_history: List[ReviewRecord] = Field(default_factory=list, description="Append-only audit trail of human reviews")
    requires_re_review: bool = Field(default=False, description="Flag indicating whether re-execution requires re-review")

    @property
    def proposal_id(self) -> str:
        """Alias for test_id to provide explicit proposal-to-finding traceability."""
        return self.test_id

    @model_validator(mode="after")
    def _validate_finding_review(self) -> "Finding":
        """Enforce that CONFIRMED outcome requires explicit human review."""
        if self.assessment_outcome == AssessmentOutcome.CONFIRMED and not self.is_human_reviewed:
            raise ValueError(
                "Assessment outcome 'CONFIRMED' requires explicit human review and "
                "cannot be assigned automatically by differential comparisons or status codes."
            )
        return self


class FindingReviewRequest(BaseModel):
    """Request payload for human review of a security finding.

    NOTE ON REVIEWER IDENTITY:
    The `reviewer_id` field is a client-asserted audit identifier. The current backend
    does not feature an identity or authentication provider; therefore, this identifier
    is recorded for audit and traceability purposes only and is not cryptographically verified.
    """
    model_config = ConfigDict(populate_by_name=True)

    outcome: HumanReviewOutcome = Field(..., description="Review decision: strictly CONFIRMED or FALSE_POSITIVE")
    reviewer_id: str = Field(..., min_length=1, description="Client-asserted identifier of the human reviewer (audit traceability only)")
    reviewer_notes: Optional[str] = Field(None, description="Review justification / notes")


# ---------------------------------------------------------------------------
# Report models (Phase 2C)
# NOTE: Reports are stored in memory and are NOT durable across application
#       restarts. They are scoped to the session that generated them.
# ---------------------------------------------------------------------------

class FindingDetail(BaseModel):
    """Structured, human‑readable representation of a single finding for reports."""
    finding_id: str
    title: str
    test_category: str
    endpoint_path: Optional[str] = None
    endpoint_method: Optional[str] = None
    severity: str
    status: str
    # Sanitized evidence only – no secrets, no raw response bodies
    evidence_summary: Dict[str, Any] = Field(default_factory=dict)
    observed_behavior: str
    recommended_remediation: str
    limitations: Optional[str] = None
    # Stage 5 additions: detailed state and human review metadata
    execution_status: Optional[str] = None
    assessment_outcome: Optional[str] = None
    assessment_reason: Optional[str] = None
    is_human_reviewed: bool = False
    reviewer_id: Optional[str] = None
    reviewed_at: Optional[datetime] = None
    reviewer_notes: Optional[str] = None
    # Re-review required flag and serialized review history for reports
    requires_re_review: bool = False
    review_history: List[Dict[str, Any]] = Field(default_factory=list)
    remediation_status: Optional[str] = None


class SeverityCounts(BaseModel):
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    unknown: int = 0


class Report(BaseModel):
    """Full assessment report for a session.

    NOTE: In-memory only. Reports are lost when the application restarts.
    """
    report_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    session_id: str
    generated_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    target_base_url: str
    assessment_summary: str
    severity_counts: SeverityCounts
    finding_details: List[FindingDetail] = Field(default_factory=list)
    not_executed_tests: List[str] = Field(default_factory=list)
    failed_tests: List[str] = Field(default_factory=list)
    scope_and_limitations: str = (
        "This assessment was performed against a local mock target only. "
        "Results reflect behaviour of the mock API and may not represent "
        "production exposure. Reports are held in memory and are not "
        "persisted across application restarts."
    )
    # Stage 5 additions: execution statistics and review status counters
    execution_statistics: Dict[str, int] = Field(default_factory=dict)
    pending_review_count: int = 0
    endpoints_cataloged: List[Dict[str, str]] = Field(default_factory=list)
    retesting_guidance: Optional[str] = None
    methodology: Optional[str] = None


# Session model – holds proposals, findings, and reports per user workflow
class Session(BaseModel):
    _lock: threading.RLock = PrivateAttr(default_factory=threading.RLock)
    session_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    # Stored endpoint inventory for this assessment session
    endpoints: List[EndpointModel] = Field(default_factory=list)
    # Mapping of test_id -> ProposedTest
    proposals: Dict[str, ProposedTest] = Field(default_factory=dict)
    # Mapping of finding_id -> Finding
    findings: Dict[str, Finding] = Field(default_factory=dict)
    # Mapping of report_id -> Report
    reports: Dict[str, Report] = Field(default_factory=dict)

    def set_endpoints(self, endpoints: List[EndpointModel]) -> None:
        self.endpoints = endpoints

    def get_endpoints(self) -> List[EndpointModel]:
        return self.endpoints

    def add_proposal(self, proposal: ProposedTest) -> str:
        with self._lock:
            self.proposals[proposal.test_id] = proposal
        return proposal.test_id

    def get_proposal(self, test_id: str) -> ProposedTest:
        return self.proposals[test_id]

    def set_proposal_status(self, test_id: str, status: TestStatus) -> None:
        with self._lock:
            self.proposals[test_id].status = status

    def add_finding(self, finding: Finding) -> str:
        with self._lock:
            # Prevent duplicate findings when the same proposal is processed again:
            # update existing finding for the same test_id in place while preserving its finding_id.
            for existing_id, existing_finding in self.findings.items():
                if existing_finding.test_id == finding.test_id:
                    finding.finding_id = existing_finding.finding_id
                    finding.timestamp = existing_finding.timestamp
                    # Preserve prior review history
                    finding.review_history = list(existing_finding.review_history)
                    if existing_finding.is_human_reviewed:
                        # A prior human review existed. The new execution provides fresh evidence,
                        # so do not preserve a prior CONFIRMED or FALSE_POSITIVE decision as automatically
                        # valid for the new execution run. Mark finding as requiring re-review while
                        # maintaining the historical audit trail in review_history.
                        finding.requires_re_review = True
                        finding.is_human_reviewed = False
                        finding.reviewer_id = None
                        finding.reviewed_at = None
                        finding.reviewer_notes = None

                    self.findings[existing_id] = finding
                    return existing_id

            self.findings[finding.finding_id] = finding
            return finding.finding_id

    def get_finding(self, finding_id: str) -> Finding:
        return self.findings[finding_id]

    def get_finding_by_test_id(self, test_id: str) -> Optional[Finding]:
        for finding in self.findings.values():
            if finding.test_id == test_id:
                return finding
        return None

    def add_report(self, report: "Report") -> str:
        with self._lock:
            self.reports[report.report_id] = report
        return report.report_id

    def get_report(self, report_id: str) -> "Report":
        return self.reports[report_id]


# In‑memory store – a simple singleton that can be swapped later for a DB
class SessionStore:
    def __init__(self):
        self._sessions: Dict[str, Session] = {}
        self._lock = threading.RLock()

    def create_session(self) -> str:
        with self._lock:
            session = Session()
            self._sessions[session.session_id] = session
        return session.session_id

    def get_session(self, session_id: str) -> Session:
        return self._sessions[session_id]

    # Helper shortcuts
    def set_endpoints(self, session_id: str, endpoints: List[EndpointModel]) -> None:
        session = self.get_session(session_id)
        session.set_endpoints(endpoints)

    def get_endpoints(self, session_id: str) -> List[EndpointModel]:
        session = self.get_session(session_id)
        return session.get_endpoints()

    def add_proposal(self, session_id: str, proposal: ProposedTest) -> str:
        session = self.get_session(session_id)
        return session.add_proposal(proposal)

    def get_proposal(self, session_id: str, test_id: str) -> ProposedTest:
        session = self.get_session(session_id)
        return session.get_proposal(test_id)

    def set_proposal_status(self, session_id: str, test_id: str, status: TestStatus) -> None:
        session = self.get_session(session_id)
        session.set_proposal_status(test_id, status)

    def add_finding(self, session_id: str, finding: Finding) -> str:
        session = self.get_session(session_id)
        return session.add_finding(finding)

    def get_finding(self, session_id: str, finding_id: str) -> Finding:
        session = self.get_session(session_id)
        return session.get_finding(finding_id)

    def get_finding_by_test_id(self, session_id: str, test_id: str) -> Optional[Finding]:
        session = self.get_session(session_id)
        return session.get_finding_by_test_id(test_id)

    def add_report(self, session_id: str, report: Report) -> str:
        session = self.get_session(session_id)
        return session.add_report(report)

    def get_report(self, session_id: str, report_id: str) -> Report:
        session = self.get_session(session_id)
        return session.get_report(report_id)


# Export a module‑level singleton for easy import
session_store = SessionStore()
