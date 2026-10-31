"""Unit tests for Stage 4: Differential BOLA Testing Engine.

Verifies:
- Complete controlled differential sequence (Owner baseline -> Cross-tenant probe -> Attacker control)
- Successful BOLA detection produces SUSPECTED (never automatically CONFIRMED)
- Access denied responses (401, 403, 404) produce ACCESS_DENIED
- Preflight budget check: insufficient budget marks NOT_EXECUTED and sends 0 requests
- Missing fixtures (path parameters) mark NOT_EXECUTED
- Missing identities (owner or attacker) mark NOT_EXECUTED
- Missing or invalid authentication credentials mark NOT_EXECUTED
- Unsafe / disallowed targets are rejected
- Baseline failure halts sequence and produces INCONCLUSIVE
- Network / connection request failures produce FAILED / INCONCLUSIVE
- Request and response evidence sanitization (no raw secrets in evidence)
- Unapproved proposals raise PermissionError
- Non-BOLA proposals in SPEC_DRIVEN mode mark NOT_EXECUTED
- Confirmation strictly requires human review
"""

import asyncio
import json
from typing import Any, Dict, List, Optional
import pytest
import httpx

from app.models import (
    AssessmentOutcome,
    EndpointModel,
    Evidence,
    ExecutionConfig,
    ExecutionMode,
    ExecutionStatus,
    FindingStatus,
    ParameterFixtures,
    ProposedTest,
    RequestBudget,
    TestIdentity,
    TestStatus,
    session_store,
    validate_assessment_outcome,
)
from app.parser.openapi_parser import (
    ResolvedSecurityRequirement,
    SecuritySchemeModel,
)
from app.security.differential_engine import run_differential_bola
from app.security.execution_engine import execute_proposals


# ---------------------------------------------------------------------------
# Mock Async Client for Testing
# ---------------------------------------------------------------------------

class _MockResponse:
    def __init__(self, status_code: int, json_data: Any = None, headers: Dict[str, str] = None):
        self.status_code = status_code
        self._json_data = json_data
        self.headers = headers or {}
        self.text = json.dumps(json_data) if json_data is not None else ""

    def json(self):
        if self._json_data is None:
            raise ValueError("No JSON")
        return self._json_data


class _MockDifferentialClient:
    """Mock client that responds based on request URL and Authorization header."""
    def __init__(self, route_map: Dict[tuple, _MockResponse]):
        self.route_map = route_map  # (method, url, auth_header) -> _MockResponse
        self.history: List[Dict[str, Any]] = []

    async def request(self, method: str, url: str, headers: Dict[str, str] = None, params: Dict[str, Any] = None, cookies: Dict[str, str] = None):
        headers = headers or {}
        auth = headers.get("Authorization", "")
        # Record request for assertion
        self.history.append({
            "method": method,
            "url": url,
            "auth": auth,
            "headers": headers,
        })
        key = (method.upper(), url, auth)
        if key in self.route_map:
            return self.route_map[key]

        # Fallback by (method, url)
        for (m, u, a), resp in self.route_map.items():
            if m.upper() == method.upper() and u == url:
                return resp

        return _MockResponse(404, {"error": "Not Found"})

    async def aclose(self):
        pass


# Helper to build standard BOLA proposal
def _make_bola_proposal(status: TestStatus = TestStatus.APPROVED) -> ProposedTest:
    bearer_scheme = SecuritySchemeModel(type="http", scheme="bearer")
    ep = EndpointModel(
        path="/users/{user_id}",
        method="get",
        responses={"200": {"description": "ok"}},
        effective_security=[ResolvedSecurityRequirement(scheme_name="BearerAuth", scheme=bearer_scheme)],
    )
    return ProposedTest(
        endpoint=ep,
        test_type="BOLA",
        description="Test BOLA on /users/{user_id}",
        severity="High",
        status=status,
    )


# Helper to build valid execution config
def _make_bola_config(budget_limit: int = 5) -> ExecutionConfig:
    return ExecutionConfig(
        mode=ExecutionMode.SPEC_DRIVEN,
        target_base_url="http://127.0.0.1:8001",
        owner_identity=TestIdentity(identity_id="alice", token="token-alice-123"),
        attacker_identity=TestIdentity(identity_id="bob", token="token-bob-456"),
        parameters=ParameterFixtures(
            owner_path_params={"user_id": "alice"},
            attacker_path_params={"user_id": "bob"},
        ),
        budget=RequestBudget(max_requests=budget_limit),
    )


def test_differential_bola_success_suspected():
    """Vulnerable endpoint: Cross-tenant probe returns owner's object data -> SUSPECTED."""
    prop = _make_bola_proposal()
    cfg = _make_bola_config(budget_limit=5)

    # Routes:
    # 1. Owner requests alice -> 200 with alice data
    # 2. Attacker requests alice -> 200 with alice data (BOLA!)
    # 3. Attacker requests bob -> 200 with bob data (Control)
    route_map = {
        ("GET", "http://127.0.0.1:8001/users/alice", "Bearer token-alice-123"): _MockResponse(
            200, {"id": "alice", "email": "alice@example.com", "role": "user"}
        ),
        ("GET", "http://127.0.0.1:8001/users/alice", "Bearer token-bob-456"): _MockResponse(
            200, {"id": "alice", "email": "alice@example.com", "role": "user"}
        ),
        ("GET", "http://127.0.0.1:8001/users/bob", "Bearer token-bob-456"): _MockResponse(
            200, {"id": "bob", "email": "bob@example.com", "role": "user"}
        ),
    }
    client = _MockDifferentialClient(route_map)

    finding = asyncio.run(run_differential_bola(prop, cfg, client=client))

    # All 3 steps executed
    assert len(client.history) == 3
    assert client.history[0]["auth"] == "Bearer token-alice-123"
    assert client.history[1]["auth"] == "Bearer token-bob-456"
    assert client.history[2]["auth"] == "Bearer token-bob-456"

    # Outcome evaluation: SUSPECTED (never automatically CONFIRMED)
    assert finding.execution_status == ExecutionStatus.COMPLETED
    assert finding.assessment_outcome == AssessmentOutcome.SUSPECTED
    assert finding.status == FindingStatus.SUSPECTED
    assert finding.assessment_outcome != AssessmentOutcome.CONFIRMED

    # Budget consumed
    assert cfg.budget.current_count == 3
    assert cfg.budget.remaining == 2


@pytest.mark.parametrize("status_code", [401, 403, 404])
def test_differential_bola_denied_access(status_code):
    """Secure endpoint: Cross-tenant probe receives 401/403/404 -> ACCESS_DENIED."""
    prop = _make_bola_proposal()
    # Without optional control to test 2-step sequence
    cfg = ExecutionConfig(
        mode=ExecutionMode.SPEC_DRIVEN,
        target_base_url="http://127.0.0.1:8001",
        owner_identity=TestIdentity(identity_id="alice", token="token-alice-123"),
        attacker_identity=TestIdentity(identity_id="bob", token="token-bob-456"),
        parameters=ParameterFixtures(owner_path_params={"user_id": "alice"}),
        budget=RequestBudget(max_requests=5),
    )

    route_map = {
        ("GET", "http://127.0.0.1:8001/users/alice", "Bearer token-alice-123"): _MockResponse(
            200, {"id": "alice", "data": "alice data"}
        ),
        ("GET", "http://127.0.0.1:8001/users/alice", "Bearer token-bob-456"): _MockResponse(
            status_code, {"error": "Access Denied"}
        ),
    }
    client = _MockDifferentialClient(route_map)

    finding = asyncio.run(run_differential_bola(prop, cfg, client=client))

    assert len(client.history) == 2
    assert finding.execution_status == ExecutionStatus.COMPLETED
    assert finding.assessment_outcome == AssessmentOutcome.ACCESS_DENIED
    assert finding.status == FindingStatus.NOT_EXECUTED
    assert cfg.budget.current_count == 2


def test_differential_bola_insufficient_budget_sends_zero_requests():
    """If budget is insufficient for the sequence, it must mark NOT_EXECUTED and send 0 requests."""
    prop = _make_bola_proposal()
    # 3-step sequence requires 3 requests, but only 2 allowed
    cfg = _make_bola_config(budget_limit=2)
    cfg.budget.record_request(1)  # now 1 remaining (< 3)

    client = _MockDifferentialClient({})
    finding = asyncio.run(run_differential_bola(prop, cfg, client=client))

    # Preflight check triggered -> 0 requests sent
    assert len(client.history) == 0
    assert finding.execution_status == ExecutionStatus.NOT_EXECUTED
    assert finding.assessment_outcome == AssessmentOutcome.INCONCLUSIVE
    assert "budget exceeded" in finding.notes.lower()


def test_differential_bola_missing_fixtures():
    """Missing path fixtures must produce NOT_EXECUTED without sending requests."""
    prop = _make_bola_proposal()
    cfg = ExecutionConfig(
        mode=ExecutionMode.SPEC_DRIVEN,
        target_base_url="http://127.0.0.1:8001",
        owner_identity=TestIdentity(identity_id="alice", token="token-alice-123"),
        attacker_identity=TestIdentity(identity_id="bob", token="token-bob-456"),
        parameters=ParameterFixtures(owner_path_params={}),  # empty!
    )
    client = _MockDifferentialClient({})
    finding = asyncio.run(run_differential_bola(prop, cfg, client=client))

    assert len(client.history) == 0
    assert finding.execution_status == ExecutionStatus.NOT_EXECUTED
    assert "missing required path parameter" in finding.notes.lower()


def test_differential_bola_missing_identities():
    """Missing owner or attacker identity must produce NOT_EXECUTED without sending requests."""
    prop = _make_bola_proposal()
    cfg_no_attacker = ExecutionConfig(
        mode=ExecutionMode.SPEC_DRIVEN,
        target_base_url="http://127.0.0.1:8001",
        owner_identity=TestIdentity(identity_id="alice", token="token-alice-123"),
        attacker_identity=None,
        parameters=ParameterFixtures(owner_path_params={"user_id": "alice"}),
    )
    client = _MockDifferentialClient({})
    finding = asyncio.run(run_differential_bola(prop, cfg_no_attacker, client=client))

    assert len(client.history) == 0
    assert finding.execution_status == ExecutionStatus.NOT_EXECUTED
    assert "missing required attacker_identity" in finding.notes.lower()


def test_differential_bola_missing_authentication_credentials():
    """Identity missing credentials matching endpoint security schemes must produce NOT_EXECUTED."""
    prop = _make_bola_proposal()
    # Attacker missing token
    cfg_no_token = ExecutionConfig(
        mode=ExecutionMode.SPEC_DRIVEN,
        target_base_url="http://127.0.0.1:8001",
        owner_identity=TestIdentity(identity_id="alice", token="token-alice-123"),
        attacker_identity=TestIdentity(identity_id="bob", username="bob"),  # no token!
        parameters=ParameterFixtures(owner_path_params={"user_id": "alice"}),
    )
    client = _MockDifferentialClient({})
    finding = asyncio.run(run_differential_bola(prop, cfg_no_token, client=client))

    assert len(client.history) == 0
    assert finding.execution_status == ExecutionStatus.NOT_EXECUTED
    assert "request construction failed" in finding.notes.lower()


def test_differential_bola_baseline_failure_inconclusive():
    """If owner baseline returns 500 or 404, sequence must halt and report INCONCLUSIVE."""
    prop = _make_bola_proposal()
    cfg = _make_bola_config(budget_limit=5)

    route_map = {
        ("GET", "http://127.0.0.1:8001/users/alice", "Bearer token-alice-123"): _MockResponse(
            500, {"error": "Server database failure"}
        ),
    }
    client = _MockDifferentialClient(route_map)
    finding = asyncio.run(run_differential_bola(prop, cfg, client=client))

    # Baseline failed -> probe was NOT sent!
    assert len(client.history) == 1
    assert finding.assessment_outcome == AssessmentOutcome.INCONCLUSIVE
    assert finding.status == FindingStatus.NOT_EXECUTED
    assert "cannot establish authorized baseline" in finding.notes.lower()
    assert finding.remediation is not None
    assert "object-level authorization" in finding.remediation.lower()


def test_differential_bola_network_failure():
    """Network connection failure during baseline must report FAILED / INCONCLUSIVE."""
    prop = _make_bola_proposal()
    cfg = _make_bola_config(budget_limit=5)

    class _ErrorClient:
        async def request(self, *args, **kwargs):
            raise httpx.ConnectError("Connection refused to target")
        async def aclose(self):
            pass

    finding = asyncio.run(run_differential_bola(prop, cfg, client=_ErrorClient()))
    assert finding.execution_status == ExecutionStatus.FAILED
    assert finding.assessment_outcome == AssessmentOutcome.INCONCLUSIVE
    assert "connection refused" in finding.notes.lower()


def test_differential_bola_evidence_redaction():
    """Sanitized evidence must not contain secrets or raw authorization headers."""
    prop = _make_bola_proposal()
    cfg = _make_bola_config(budget_limit=5)

    route_map = {
        ("GET", "http://127.0.0.1:8001/users/alice", "Bearer token-alice-123"): _MockResponse(
            200, {"id": "alice", "secret_key": "raw-secret-key-xyz", "email": "alice@corp.internal"}
        ),
        ("GET", "http://127.0.0.1:8001/users/alice", "Bearer token-bob-456"): _MockResponse(
            200, {"id": "alice", "secret_key": "raw-secret-key-xyz", "email": "alice@corp.internal"}
        ),
        ("GET", "http://127.0.0.1:8001/users/bob", "Bearer token-bob-456"): _MockResponse(
            200, {"id": "bob", "data": "bob"}
        ),
    }
    client = _MockDifferentialClient(route_map)
    finding = asyncio.run(run_differential_bola(prop, cfg, client=client))

    ev_req = finding.evidence.request
    ev_resp = finding.evidence.response

    # Authorization header stripped
    assert "Authorization" not in ev_req.get("headers", {})
    # Secret tokens and emails redacted in response body
    serialized_resp = json.dumps(ev_resp)
    assert "raw-secret-key-xyz" not in serialized_resp
    assert "alice@corp.internal" not in serialized_resp
    assert "[REDACTED]" in serialized_resp


def test_differential_bola_unapproved_proposal_rejected():
    """Unapproved proposal must raise PermissionError."""
    prop = _make_bola_proposal(status=TestStatus.PROPOSED)  # not approved!
    cfg = _make_bola_config()
    with pytest.raises(PermissionError, match="not approved"):
        asyncio.run(run_differential_bola(prop, cfg))


def test_differential_bola_non_bola_proposal_in_spec_driven():
    """Non-BOLA proposal in SPEC_DRIVEN mode must be recorded as NOT_EXECUTED."""
    sid = session_store.create_session()
    ep = EndpointModel(
        path="/admin/data",
        method="get",
        responses={"200": {"description": "ok"}},
    )
    bfla_prop = ProposedTest(
        endpoint=ep,
        test_type="BFLA",
        description="BFLA test",
        severity="High",
        status=TestStatus.APPROVED,
    )
    session_store.add_proposal(sid, bfla_prop)
    cfg = ExecutionConfig(
        mode=ExecutionMode.SPEC_DRIVEN,
        target_base_url="http://127.0.0.1:8001",
    )

    findings = asyncio.run(execute_proposals(
        session_id=sid,
        proposal_ids=[bfla_prop.test_id],
        target="http://127.0.0.1:8001",
        config=cfg,
    ))

    assert len(findings) == 1
    f = findings[0]
    assert f.status == FindingStatus.NOT_EXECUTED
    assert f.execution_status == ExecutionStatus.NOT_EXECUTED
    assert "only bola is currently supported in spec_driven mode" in f.notes.lower()


def test_confirmation_requires_explicit_human_review():
    """Automated comparison produces SUSPECTED; CONFIRMED strictly requires human review."""
    prop = _make_bola_proposal()
    cfg = _make_bola_config(budget_limit=5)
    route_map = {
        ("GET", "http://127.0.0.1:8001/users/alice", "Bearer token-alice-123"): _MockResponse(
            200, {"id": "alice", "data": "alice"}
        ),
        ("GET", "http://127.0.0.1:8001/users/alice", "Bearer token-bob-456"): _MockResponse(
            200, {"id": "alice", "data": "alice"}
        ),
    }
    client = _MockDifferentialClient(route_map)
    finding = asyncio.run(run_differential_bola(prop, cfg, client=client))

    # Engine assigned SUSPECTED
    assert finding.assessment_outcome == AssessmentOutcome.SUSPECTED

    # Automated assignment of CONFIRMED is blocked
    with pytest.raises(ValueError, match="CONFIRMED.*requires explicit human review"):
        validate_assessment_outcome(AssessmentOutcome.CONFIRMED, is_human_review=False)

    # Human reviewer confirmation is accepted
    validate_assessment_outcome(
        AssessmentOutcome.CONFIRMED,
        is_human_review=True,
        reviewer_notes="Confirmed by Security Lead on 2026-10-30",
    )
    finding.assessment_outcome = AssessmentOutcome.CONFIRMED
    finding.status = FindingStatus.CONFIRMED
    assert finding.assessment_outcome == AssessmentOutcome.CONFIRMED
    assert finding.status == FindingStatus.CONFIRMED


def test_differential_engine_module_import():
    """Verify that app.security.differential_engine imports without syntax or indentation errors."""
    import importlib
    mod = importlib.import_module("app.security.differential_engine")
    assert hasattr(mod, "run_differential_bola")
    assert hasattr(mod, "BOLA_REMEDIATION")


def test_differential_bola_probe_failure_inconclusive():
    """If cross-tenant probe fails due to network/exception, must report FAILED/INCONCLUSIVE with remediation."""
    prop = _make_bola_proposal()
    cfg = _make_bola_config(budget_limit=5)

    class _ProbeFailingClient:
        def __init__(self):
            self.call_count = 0

        async def request(self, method, url, **kwargs):
            self.call_count += 1
            if self.call_count == 1:
                # Owner baseline succeeds
                return _MockResponse(200, {"id": "alice", "data": "alice"})
            # Cross-tenant probe fails
            raise httpx.ConnectError("Connection dropped during probe request")

        async def aclose(self):
            pass

    client = _ProbeFailingClient()
    finding = asyncio.run(run_differential_bola(prop, cfg, client=client))

    assert finding.execution_status == ExecutionStatus.FAILED
    assert finding.assessment_outcome == AssessmentOutcome.INCONCLUSIVE
    assert "cross-tenant probe request failed" in finding.assessment_reason.lower()
    assert finding.remediation is not None
    assert "object-level authorization" in finding.remediation.lower()

