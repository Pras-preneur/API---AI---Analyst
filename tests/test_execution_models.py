"""Unit tests for Stage 2: Execution Configuration Models and Safety Validations.

Verifies:
- ExecutionMode separation (SPEC_DRIVEN vs LEGACY_FIXTURE)
- ExecutionStatus separation from AssessmentOutcome
- AssessmentOutcome restrictions (CONFIRMED requires human sign-off)
- TestIdentity configuration and credential redaction
- ParameterFixtures validation and path-traversal prevention
- RequestBudget enforcement and bounded limits
- ExecutionConfig safety policies (target allowlist, mandatory approval, no redirects)
- Backward compatibility for Finding and ExecuteRequest
"""

import pytest
from pydantic import ValidationError

from app.models import (
    ExecutionMode,
    ExecutionStatus,
    AssessmentOutcome,
    validate_assessment_outcome,
    TestIdentity,
    ParameterFixtures,
    RequestBudget,
    ExecutionConfig,
    ExecuteRequest,
    Finding,
    FindingStatus,
    Evidence,
    EndpointModel,
)


def test_execution_mode_values_and_separation():
    """ExecutionMode must strictly separate SPEC_DRIVEN and LEGACY_FIXTURE."""
    assert ExecutionMode.SPEC_DRIVEN == "SPEC_DRIVEN"
    assert ExecutionMode.LEGACY_FIXTURE == "LEGACY_FIXTURE"
    assert ExecutionMode.SPEC_DRIVEN != ExecutionMode.LEGACY_FIXTURE

    # Ensure round-trip serialization
    assert ExecutionMode("SPEC_DRIVEN") is ExecutionMode.SPEC_DRIVEN
    assert ExecutionMode("LEGACY_FIXTURE") is ExecutionMode.LEGACY_FIXTURE
    with pytest.raises(ValueError):
        ExecutionMode("UNKNOWN_MODE")


def test_execution_status_separation_from_assessment_outcome():
    """Execution process status must be distinct from vulnerability assessment outcome."""
    assert ExecutionStatus.NOT_EXECUTED == "NOT_EXECUTED"
    assert ExecutionStatus.COMPLETED == "COMPLETED"
    assert ExecutionStatus.FAILED == "FAILED"

    assert AssessmentOutcome.SUSPECTED == "SUSPECTED"
    assert AssessmentOutcome.INCONCLUSIVE == "INCONCLUSIVE"
    assert AssessmentOutcome.ACCESS_DENIED == "ACCESS_DENIED"
    assert AssessmentOutcome.CONFIRMED == "CONFIRMED"
    assert AssessmentOutcome.FALSE_POSITIVE == "FALSE_POSITIVE"

    # Enums are completely distinct
    assert type(ExecutionStatus.COMPLETED) is not type(AssessmentOutcome.SUSPECTED)


def test_assessment_outcome_confirmed_requires_human_review():
    """CONFIRMED outcome cannot be assigned automatically by differential comparisons."""
    # Automated assessment assigning CONFIRMED must fail
    with pytest.raises(ValueError, match="CONFIRMED.*requires explicit human review"):
        validate_assessment_outcome(AssessmentOutcome.CONFIRMED, is_human_review=False)

    # Human reviewer signing off on CONFIRMED must succeed
    validate_assessment_outcome(
        AssessmentOutcome.CONFIRMED,
        is_human_review=True,
        reviewer_notes="Verified manual reproduction of BOLA vulnerability",
    )

    # Other outcomes can be assigned automatically by machine
    validate_assessment_outcome(AssessmentOutcome.SUSPECTED, is_human_review=False)
    validate_assessment_outcome(AssessmentOutcome.INCONCLUSIVE, is_human_review=False)
    validate_assessment_outcome(AssessmentOutcome.ACCESS_DENIED, is_human_review=False)


def test_test_identity_models_and_credential_redaction():
    """Test identities must support configurable credentials and sanitize secrets for evidence."""
    owner = TestIdentity(
        identity_id="owner",
        username="alice",
        password="AliceSecretPassword123!",
        token="jwt.secret.owner.token",
        roles=["user"],
    )
    assert owner.identity_id == "owner"
    assert owner.username == "alice"
    assert owner.password == "AliceSecretPassword123!"

    attacker = TestIdentity(
        identity_id="attacker",
        username="bob",
        api_key="api-key-secret-999",
        headers={"X-Auth-Token": "secret-session-token", "X-Custom-Env": "local-test"},
        cookies={"session": "cookie-secret-session-abc"},
    )

    # Redacted summary must mask secrets
    redacted_owner = owner.get_redacted_summary()
    assert "password" not in redacted_owner
    assert redacted_owner["has_password"] is True
    assert redacted_owner["has_token"] is True
    assert "AliceSecretPassword123!" not in str(redacted_owner)
    assert "jwt.secret.owner.token" not in str(redacted_owner)

    redacted_attacker = attacker.get_redacted_summary()
    assert redacted_attacker["has_api_key"] is True
    assert "api-key-secret-999" not in str(redacted_attacker)
    assert redacted_attacker["headers"]["X-Auth-Token"] == "[REDACTED]"
    assert redacted_attacker["headers"]["X-Custom-Env"] == "local-test"
    assert redacted_attacker["cookies"]["session"] == "[REDACTED]"


def test_parameter_fixtures_valid():
    """Valid path, query, and header parameters should instantiate correctly."""
    fixtures = ParameterFixtures(
        owner_path_params={"user_id": "user_101", "org_id": 42},
        attacker_path_params={"user_id": "user_202", "org_id": 42},
        query_params={"include_details": "true", "limit": 10},
        headers={"Accept": "application/json"},
    )
    assert fixtures.owner_path_params["user_id"] == "user_101"
    assert fixtures.attacker_path_params["user_id"] == "user_202"
    assert fixtures.query_params["limit"] == 10
    assert fixtures.headers["Accept"] == "application/json"


@pytest.mark.parametrize(
    "malicious_val",
    [
        "../admin",
        "..\\admin",
        "sub/user",
        "sub\\user",
        "%2e%2e%2fadmin",
        "%2e%2e/admin",
        "%5cadmin",
        "user\x00extra",
        "",
    ],
)
def test_parameter_fixtures_path_traversal_rejection(malicious_val):
    """Path parameters must reject traversal sequences, slashes, null bytes, and empty values."""
    with pytest.raises(ValidationError):
        ParameterFixtures(owner_path_params={"user_id": malicious_val})

    with pytest.raises(ValidationError):
        ParameterFixtures(attacker_path_params={"user_id": malicious_val})


def test_request_budget_enforcement():
    """RequestBudget must strictly enforce bounded counts and limit checks."""
    budget = RequestBudget(max_requests=3)
    assert budget.remaining == 3
    assert budget.can_request(2) is True
    assert budget.can_request(4) is False

    budget.record_request(2)
    assert budget.current_count == 2
    assert budget.remaining == 1
    assert budget.can_request(1) is True
    assert budget.can_request(2) is False

    budget.record_request(1)
    assert budget.remaining == 0

    # Over budget attempt must raise ValueError
    with pytest.raises(ValueError, match="Execution budget exceeded"):
        budget.record_request(1)


def test_request_budget_bounds():
    """RequestBudget max_requests must be strictly bounded between 1 and 10."""
    with pytest.raises(ValidationError):
        RequestBudget(max_requests=0)

    with pytest.raises(ValidationError):
        RequestBudget(max_requests=11)

    # Valid bounds
    b1 = RequestBudget(max_requests=1)
    assert b1.max_requests == 1
    b10 = RequestBudget(max_requests=10)
    assert b10.max_requests == 10


def test_execution_config_allowed_targets():
    """ExecutionConfig must enforce the authorized local mock targets allowlist."""
    cfg1 = ExecutionConfig(target_base_url="http://127.0.0.1:8001")
    assert cfg1.target_base_url == "http://127.0.0.1:8001"

    cfg2 = ExecutionConfig(target_base_url="http://localhost:8001/")
    assert cfg2.target_base_url == "http://localhost:8001"

    # Reject unauthorized targets
    with pytest.raises(ValidationError, match="not authorized"):
        ExecutionConfig(target_base_url="http://example.com")

    with pytest.raises(ValidationError, match="not authorized"):
        ExecutionConfig(target_base_url="http://localhost:8888")  # crAPI target is separate and forbidden

    with pytest.raises(ValidationError, match="not authorized"):
        ExecutionConfig(target_base_url="http://192.168.1.5:8001")


def test_execution_config_safety_controls():
    """ExecutionConfig must enforce approval requirement, redirects disabled, and timeout bounds."""
    # Approval must be required
    with pytest.raises(ValidationError, match="approval is strictly prohibited"):
        ExecutionConfig(require_approval=False)

    # Redirects must remain disabled
    with pytest.raises(ValidationError, match="follow_redirects must be False"):
        ExecutionConfig(follow_redirects=True)

    # Timeout limits (0.5s to 30.0s)
    with pytest.raises(ValidationError):
        ExecutionConfig(timeout_seconds=0.1)

    with pytest.raises(ValidationError):
        ExecutionConfig(timeout_seconds=35.0)

    valid_cfg = ExecutionConfig(timeout_seconds=10.0)
    assert valid_cfg.timeout_seconds == 10.0


def test_backward_compatibility_finding_and_execute_request():
    """Existing finding and execute request instantiations must continue to work seamlessly."""
    endpoint = EndpointModel(
        path="/users/{user_id}",
        method="get",
        responses={"200": {"description": "ok"}},
    )
    evidence = Evidence(request={"method": "GET", "url": "/test"}, response={"status_code": 200})

    # Legacy finding instantiation without new fields
    legacy_finding = Finding(
        test_id="test-123",
        endpoint=endpoint,
        evidence=evidence,
        severity="High",
        status=FindingStatus.SUSPECTED,
    )
    assert legacy_finding.status == FindingStatus.SUSPECTED
    assert legacy_finding.execution_status is None
    assert legacy_finding.assessment_outcome is None

    # Enhanced finding instantiation with new fields
    enhanced_finding = Finding(
        test_id="test-456",
        endpoint=endpoint,
        evidence=evidence,
        severity="High",
        status=FindingStatus.SUSPECTED,
        execution_status=ExecutionStatus.COMPLETED,
        assessment_outcome=AssessmentOutcome.SUSPECTED,
    )
    assert enhanced_finding.execution_status == ExecutionStatus.COMPLETED
    assert enhanced_finding.assessment_outcome == AssessmentOutcome.SUSPECTED

    # Legacy execute request without config
    req_legacy = ExecuteRequest(
        proposal_ids=["pid-1", "pid-2"],
        target="http://127.0.0.1:8001",
    )
    assert req_legacy.proposal_ids == ["pid-1", "pid-2"]
    assert req_legacy.target == "http://127.0.0.1:8001"
    assert req_legacy.config is None

    # Specification-driven execute request with full config
    req_spec = ExecuteRequest(
        proposal_ids=["pid-1"],
        target="http://127.0.0.1:8001",
        config=ExecutionConfig(
            mode=ExecutionMode.SPEC_DRIVEN,
            owner_identity=TestIdentity(identity_id="owner", username="alice", token="tok123"),
            attacker_identity=TestIdentity(identity_id="attacker", username="bob", token="tok456"),
            parameters=ParameterFixtures(
                owner_path_params={"user_id": "alice"},
                attacker_path_params={"user_id": "bob"},
            ),
            budget=RequestBudget(max_requests=3),
        ),
    )
    assert req_spec.config is not None
    assert req_spec.config.mode == ExecutionMode.SPEC_DRIVEN
    assert req_spec.config.budget.max_requests == 3
    assert req_spec.config.owner_identity.identity_id == "owner"

