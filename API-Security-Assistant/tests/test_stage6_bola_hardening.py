"""Stage 6.1 BOLA / IDOR Hardening — regression tests.

Covers 18 scenarios for the improved compare_bola_responses() function and the
enriched step_logs / Evidence.notes produced by run_differential_bola().

Scenarios:
 1. Owner baseline succeeds + probe contains owner data         → SUSPECTED
 2. Probe returns 200 but no owner data                         → INCONCLUSIVE
 3. Probe returns 403                                           → ACCESS_DENIED
 4. Probe returns 404                                           → ACCESS_DENIED
 5. Owner baseline returns 500                                  → INCONCLUSIVE (not executed)
 6. Probe network failure                                       → FAILED + INCONCLUSIVE
 7. Probe returns 500 (server error)                            → INCONCLUSIVE
 8. Empty probe body (204 / 200 no content)                     → INCONCLUSIVE
 9. Probe returns malformed / non-JSON body                     → no crash, graceful handling
10. Different content types between baseline and probe          → comparison metadata recorded
11. Attacker control succeeds (3-request sequence)              → step_logs contains control
12. Attacker control fails (exception)                          → finding still returned
13. Budget = 1 but 2 needed                                     → NOT_EXECUTED, 0 requests
14. Budget decrements per request                               → accurate current_count
15. Evidence sanitization: no raw credentials in step_logs      → secrets absent from notes
16. No automated CONFIRMED: SUSPECTED is max automated outcome  → blocked
17. Unapproved proposals raise PermissionError                  → confirmed
18. compare_bola_responses() unit tests: isolated function      → outcome / reason / metadata
"""

import asyncio
import json
from typing import Any, Dict, Optional
import pytest
import httpx

from app.models import (
    AssessmentOutcome,
    EndpointModel,
    ExecutionConfig,
    ExecutionMode,
    ExecutionStatus,
    FindingStatus,
    ParameterFixtures,
    ProposedTest,
    RequestBudget,
    TestIdentity,
    TestStatus,
    validate_assessment_outcome,
)
from app.parser.openapi_parser import (
    ResolvedSecurityRequirement,
    SecuritySchemeModel,
)
from app.security.differential_engine import (
    BOLA_REMEDIATION,
    compare_bola_responses,
    run_differential_bola,
    _body_hash,
    _body_size,
    _top_level_keys,
)


# ---------------------------------------------------------------------------
# Shared mock infrastructure
# ---------------------------------------------------------------------------

class _MockResponse:
    """Minimal mock of httpx.Response for testing."""

    def __init__(
        self,
        status_code: int,
        json_data: Any = None,
        headers: Dict[str, str] = None,
    ):
        self.status_code = status_code
        self._json_data = json_data
        self.headers = headers or {}
        self.text = json.dumps(json_data) if json_data is not None else ""

    def json(self):
        if self._json_data is None:
            raise ValueError("No JSON body")
        return self._json_data


class _MockDifferentialClient:
    """Mock async HTTP client keyed on (method, url, auth_header)."""

    def __init__(self, route_map: Dict[tuple, _MockResponse]):
        self.route_map = route_map
        self.history = []

    async def request(
        self,
        method: str,
        url: str,
        headers: Dict[str, str] = None,
        params: Dict[str, Any] = None,
        cookies: Dict[str, str] = None,
    ):
        headers = headers or {}
        auth = headers.get("Authorization", "")
        self.history.append({"method": method, "url": url, "auth": auth, "headers": headers})

        key = (method.upper(), url, auth)
        if key in self.route_map:
            return self.route_map[key]

        # Fallback: match by (method, url) ignoring auth
        for (m, u, _a), resp in self.route_map.items():
            if m.upper() == method.upper() and u == url:
                return resp

        return _MockResponse(404, {"error": "Not Found"})

    async def aclose(self):
        pass


# ---------------------------------------------------------------------------
# Shared fixtures / helpers
# ---------------------------------------------------------------------------

def _bearer_scheme() -> SecuritySchemeModel:
    return SecuritySchemeModel(type="http", scheme="bearer")


def _make_proposal(status: TestStatus = TestStatus.APPROVED, test_type: str = "BOLA") -> ProposedTest:
    ep = EndpointModel(
        path="/users/{user_id}",
        method="get",
        responses={"200": {"description": "ok"}},
        effective_security=[
            ResolvedSecurityRequirement(scheme_name="BearerAuth", scheme=_bearer_scheme())
        ],
    )
    return ProposedTest(
        endpoint=ep,
        test_type=test_type,
        description="Stage 6.1 test",
        severity="High",
        status=status,
    )


def _make_config(budget_limit: int = 10, attacker_params: bool = True) -> ExecutionConfig:
    return ExecutionConfig(
        mode=ExecutionMode.SPEC_DRIVEN,
        target_base_url="http://127.0.0.1:8001",
        owner_identity=TestIdentity(identity_id="alice", token="token-alice-123"),
        attacker_identity=TestIdentity(identity_id="bob", token="token-bob-456"),
        parameters=ParameterFixtures(
            owner_path_params={"user_id": "alice"},
            attacker_path_params={"user_id": "bob"} if attacker_params else {},
        ),
        budget=RequestBudget(max_requests=budget_limit),
    )


BASE_URL = "http://127.0.0.1:8001"
ALICE_URL = f"{BASE_URL}/users/alice"
BOB_URL = f"{BASE_URL}/users/bob"
ALICE_TOKEN = "Bearer token-alice-123"
BOB_TOKEN = "Bearer token-bob-456"


# ---------------------------------------------------------------------------
# Scenario 1: Owner baseline succeeds + probe contains owner data → SUSPECTED
# ---------------------------------------------------------------------------

def test_s01_suspected_when_probe_contains_owner_data():
    """Probe returns owner data → SUSPECTED (never CONFIRMED)."""
    prop = _make_proposal()
    cfg = _make_config()
    route_map = {
        (("GET", ALICE_URL, ALICE_TOKEN)): _MockResponse(200, {"id": "alice", "email": "a@test.com"}),
        (("GET", ALICE_URL, BOB_TOKEN)): _MockResponse(200, {"id": "alice", "email": "a@test.com"}),
        (("GET", BOB_URL, BOB_TOKEN)): _MockResponse(200, {"id": "bob", "email": "b@test.com"}),
    }
    client = _MockDifferentialClient(route_map)
    finding = asyncio.run(run_differential_bola(prop, cfg, client=client))

    assert finding.assessment_outcome == AssessmentOutcome.SUSPECTED
    assert finding.status == FindingStatus.SUSPECTED
    assert finding.execution_status == ExecutionStatus.COMPLETED
    assert finding.assessment_outcome != AssessmentOutcome.CONFIRMED

    # Notes must contain structured comparison metadata
    notes = json.loads(finding.notes)
    assert notes["outcome"] == "SUSPECTED"
    assert "comparison" in notes
    assert notes["comparison"]["owner_id_in_probe"] is True


# ---------------------------------------------------------------------------
# Scenario 2: Probe returns 200 but no owner data → INCONCLUSIVE
# ---------------------------------------------------------------------------

def test_s02_inconclusive_when_probe_200_no_owner_data():
    """Probe returns 200 with generic data (no owner identifiers) → INCONCLUSIVE."""
    prop = _make_proposal()
    cfg = _make_config(attacker_params=False)
    route_map = {
        (("GET", ALICE_URL, ALICE_TOKEN)): _MockResponse(200, {"id": "alice", "data": "alice"}),
        (("GET", ALICE_URL, BOB_TOKEN)): _MockResponse(200, {"id": "x999", "data": "other"}),
    }
    client = _MockDifferentialClient(route_map)
    finding = asyncio.run(run_differential_bola(prop, cfg, client=client))

    assert finding.assessment_outcome == AssessmentOutcome.INCONCLUSIVE
    assert finding.execution_status == ExecutionStatus.COMPLETED


# ---------------------------------------------------------------------------
# Scenario 3: Probe returns 403 → ACCESS_DENIED
# ---------------------------------------------------------------------------

def test_s03_access_denied_403():
    """Probe receives 403 → ACCESS_DENIED outcome."""
    prop = _make_proposal()
    cfg = _make_config(attacker_params=False)
    route_map = {
        (("GET", ALICE_URL, ALICE_TOKEN)): _MockResponse(200, {"id": "alice"}),
        (("GET", ALICE_URL, BOB_TOKEN)): _MockResponse(403, {"error": "Forbidden"}),
    }
    client = _MockDifferentialClient(route_map)
    finding = asyncio.run(run_differential_bola(prop, cfg, client=client))

    assert finding.assessment_outcome == AssessmentOutcome.ACCESS_DENIED
    assert finding.execution_status == ExecutionStatus.COMPLETED
    assert finding.status == FindingStatus.NOT_EXECUTED


# ---------------------------------------------------------------------------
# Scenario 4: Probe returns 404 → ACCESS_DENIED
# ---------------------------------------------------------------------------

def test_s04_access_denied_404():
    """Probe receives 404 → ACCESS_DENIED outcome."""
    prop = _make_proposal()
    cfg = _make_config(attacker_params=False)
    route_map = {
        (("GET", ALICE_URL, ALICE_TOKEN)): _MockResponse(200, {"id": "alice"}),
        (("GET", ALICE_URL, BOB_TOKEN)): _MockResponse(404, {"error": "Not Found"}),
    }
    client = _MockDifferentialClient(route_map)
    finding = asyncio.run(run_differential_bola(prop, cfg, client=client))

    assert finding.assessment_outcome == AssessmentOutcome.ACCESS_DENIED
    assert finding.execution_status == ExecutionStatus.COMPLETED


# ---------------------------------------------------------------------------
# Scenario 5: Owner baseline returns 500 → INCONCLUSIVE (sequence halted)
# ---------------------------------------------------------------------------

def test_s05_baseline_500_halts_sequence():
    """Owner baseline 500 → INCONCLUSIVE, probe NOT sent."""
    prop = _make_proposal()
    cfg = _make_config()
    route_map = {
        (("GET", ALICE_URL, ALICE_TOKEN)): _MockResponse(500, {"error": "DB error"}),
    }
    client = _MockDifferentialClient(route_map)
    finding = asyncio.run(run_differential_bola(prop, cfg, client=client))

    assert len(client.history) == 1  # only baseline sent
    assert finding.assessment_outcome == AssessmentOutcome.INCONCLUSIVE
    assert finding.status == FindingStatus.NOT_EXECUTED
    assert "cannot establish authorized baseline" in finding.notes.lower()


# ---------------------------------------------------------------------------
# Scenario 6: Probe network failure → FAILED + INCONCLUSIVE
# ---------------------------------------------------------------------------

def test_s06_probe_network_failure():
    """Network error during probe → FAILED execution_status, INCONCLUSIVE outcome."""
    prop = _make_proposal()
    cfg = _make_config(attacker_params=False)

    class _ProbeFailClient:
        def __init__(self):
            self.call_count = 0

        async def request(self, method, url, **kwargs):
            self.call_count += 1
            if self.call_count == 1:
                return _MockResponse(200, {"id": "alice"})
            raise httpx.ConnectError("Connection dropped during probe")

        async def aclose(self):
            pass

    client = _ProbeFailClient()
    finding = asyncio.run(run_differential_bola(prop, cfg, client=client))

    assert finding.execution_status == ExecutionStatus.FAILED
    assert finding.assessment_outcome == AssessmentOutcome.INCONCLUSIVE
    assert "cross-tenant probe request failed" in finding.assessment_reason.lower()
    assert finding.remediation is not None


# ---------------------------------------------------------------------------
# Scenario 7: Probe returns 500 → INCONCLUSIVE (server error)
# ---------------------------------------------------------------------------

def test_s07_probe_500_inconclusive():
    """Probe 5xx → INCONCLUSIVE (cannot determine access control from server error)."""
    prop = _make_proposal()
    cfg = _make_config(attacker_params=False)
    route_map = {
        (("GET", ALICE_URL, ALICE_TOKEN)): _MockResponse(200, {"id": "alice"}),
        (("GET", ALICE_URL, BOB_TOKEN)): _MockResponse(500, {"error": "Internal Server Error"}),
    }
    client = _MockDifferentialClient(route_map)
    finding = asyncio.run(run_differential_bola(prop, cfg, client=client))

    assert finding.assessment_outcome == AssessmentOutcome.INCONCLUSIVE
    assert finding.execution_status == ExecutionStatus.COMPLETED

    notes = json.loads(finding.notes)
    assert notes["outcome"] == "INCONCLUSIVE"
    assert "server error" in notes["reason"].lower()


# ---------------------------------------------------------------------------
# Scenario 8: Empty probe body → INCONCLUSIVE
# ---------------------------------------------------------------------------

def test_s08_empty_probe_body_inconclusive():
    """Probe 200 with empty body → INCONCLUSIVE (cannot determine data leakage)."""
    prop = _make_proposal()
    cfg = _make_config(attacker_params=False)
    route_map = {
        (("GET", ALICE_URL, ALICE_TOKEN)): _MockResponse(200, {"id": "alice"}),
        # Probe returns 200 with empty dict body
        (("GET", ALICE_URL, BOB_TOKEN)): _MockResponse(200, {}),
    }
    client = _MockDifferentialClient(route_map)
    finding = asyncio.run(run_differential_bola(prop, cfg, client=client))

    assert finding.assessment_outcome == AssessmentOutcome.INCONCLUSIVE
    notes = json.loads(finding.notes)
    assert notes["comparison"]["probe_body_present"] is False


# ---------------------------------------------------------------------------
# Scenario 9: Probe returns non-JSON body → no crash, graceful handling
# ---------------------------------------------------------------------------

def test_s09_non_json_probe_body_no_crash():
    """If probe response cannot be parsed as JSON, engine must not crash."""
    prop = _make_proposal()
    cfg = _make_config(attacker_params=False)

    class _TextResponse:
        status_code = 200
        headers = {}
        text = "<html>Not JSON</html>"

        def json(self):
            raise ValueError("Not valid JSON")

    class _NonJsonClient:
        def __init__(self):
            self.call_count = 0

        async def request(self, method, url, **kwargs):
            self.call_count += 1
            if self.call_count == 1:
                return _MockResponse(200, {"id": "alice"})
            return _TextResponse()

        async def aclose(self):
            pass

    client = _NonJsonClient()
    # Must not raise; result must be a Finding
    finding = asyncio.run(run_differential_bola(prop, cfg, client=client))
    assert finding is not None
    assert finding.assessment_outcome in {
        AssessmentOutcome.INCONCLUSIVE,
        AssessmentOutcome.SUSPECTED,
        AssessmentOutcome.ACCESS_DENIED,
    }


# ---------------------------------------------------------------------------
# Scenario 10: Different content types → comparison metadata recorded
# ---------------------------------------------------------------------------

def test_s10_content_type_metadata_recorded():
    """Content-type headers from baseline and probe are captured in step_logs."""
    prop = _make_proposal()
    cfg = _make_config(attacker_params=False)
    route_map = {
        (("GET", ALICE_URL, ALICE_TOKEN)): _MockResponse(
            200,
            {"id": "alice"},
            headers={"content-type": "application/json"},
        ),
        (("GET", ALICE_URL, BOB_TOKEN)): _MockResponse(
            200,
            {"id": "alice", "extra": "leaked"},  # contains owner id → SUSPECTED
            headers={"content-type": "application/json; charset=utf-8"},
        ),
    }
    client = _MockDifferentialClient(route_map)
    finding = asyncio.run(run_differential_bola(prop, cfg, client=client))

    notes = json.loads(finding.notes)
    steps = notes.get("steps", {})
    # Content-type recorded in step logs
    baseline_step = steps.get("owner_baseline", {})
    probe_step = steps.get("cross_tenant_probe", {})
    assert "content_type" in baseline_step
    assert "content_type" in probe_step
    # Comparison metadata present
    assert "comparison" in notes
    # content_type_match is populated
    assert "content_type_match" in notes["comparison"]


# ---------------------------------------------------------------------------
# Scenario 11: Attacker control succeeds (3-request sequence)
# ---------------------------------------------------------------------------

def test_s11_attacker_control_step_recorded():
    """Full 3-step sequence: attacker_control step appears in step_logs."""
    prop = _make_proposal()
    cfg = _make_config(attacker_params=True)
    route_map = {
        (("GET", ALICE_URL, ALICE_TOKEN)): _MockResponse(200, {"id": "alice"}),
        (("GET", ALICE_URL, BOB_TOKEN)): _MockResponse(200, {"id": "alice", "name": "Alice"}),
        (("GET", BOB_URL, BOB_TOKEN)): _MockResponse(200, {"id": "bob", "name": "Bob"}),
    }
    client = _MockDifferentialClient(route_map)
    finding = asyncio.run(run_differential_bola(prop, cfg, client=client))

    assert len(client.history) == 3

    notes = json.loads(finding.notes)
    steps = notes.get("steps", {})
    assert "attacker_control" in steps
    ctrl = steps["attacker_control"]
    assert ctrl["status_code"] == 200
    assert "timestamp" in ctrl


# ---------------------------------------------------------------------------
# Scenario 12: Attacker control fails (exception) → finding still returned
# ---------------------------------------------------------------------------

def test_s12_attacker_control_exception_still_returns_finding():
    """If attacker control request throws, probe outcome is still returned."""
    prop = _make_proposal()
    cfg = _make_config(attacker_params=True)

    class _ControlFailClient:
        def __init__(self):
            self.call_count = 0

        async def request(self, method, url, **kwargs):
            self.call_count += 1
            if self.call_count == 1:
                return _MockResponse(200, {"id": "alice"})
            if self.call_count == 2:
                # Probe succeeds and leaks owner data
                return _MockResponse(200, {"id": "alice", "leaked": True})
            raise httpx.TimeoutException("Attacker control timed out")

        async def aclose(self):
            pass

    client = _ControlFailClient()
    finding = asyncio.run(run_differential_bola(prop, cfg, client=client))

    # Finding must still be returned with probe outcome
    assert finding is not None
    assert finding.assessment_outcome in {AssessmentOutcome.SUSPECTED, AssessmentOutcome.INCONCLUSIVE}

    notes = json.loads(finding.notes)
    steps = notes.get("steps", {})
    # Control step must record the error, not silently drop it
    assert "attacker_control" in steps
    ctrl = steps["attacker_control"]
    assert "error" in ctrl


# ---------------------------------------------------------------------------
# Scenario 13: Budget = 1 but 2 needed → NOT_EXECUTED, 0 requests
# ---------------------------------------------------------------------------

def test_s13_insufficient_budget_sends_zero_requests():
    """Budget too small → NOT_EXECUTED before any request is sent."""
    prop = _make_proposal()
    cfg = _make_config(budget_limit=2, attacker_params=True)
    # Consume 2 of 2 upfront → 0 remaining (needs 3 for 3-step sequence)
    cfg.budget.record_request(2)

    client = _MockDifferentialClient({})
    finding = asyncio.run(run_differential_bola(prop, cfg, client=client))

    assert len(client.history) == 0
    assert finding.execution_status == ExecutionStatus.NOT_EXECUTED
    assert finding.assessment_outcome == AssessmentOutcome.INCONCLUSIVE
    assert "budget exceeded" in finding.notes.lower()


# ---------------------------------------------------------------------------
# Scenario 14: Budget decrements per request
# ---------------------------------------------------------------------------

def test_s14_budget_decrements_per_request():
    """Each sent request must decrement the budget accurately.

    Under Stage 6.1.1 request sequencing optimization:
    1. owner baseline  (request 1 recorded)
    2. cross-tenant probe  (request 2 recorded) -> returns 403
    3. Because 403 is a decisive access denial, the optional attacker control
       step is intentionally SKIPPED to preserve request budget and avoid
       unnecessary target traffic.

    Total requests executed: 2.
    """
    prop = _make_proposal()
    cfg = _make_config(budget_limit=10, attacker_params=True)
    initial_remaining = cfg.budget.remaining  # 10

    route_map = {
        (("GET", ALICE_URL, ALICE_TOKEN)): _MockResponse(200, {"id": "alice"}),
        (("GET", ALICE_URL, BOB_TOKEN)): _MockResponse(403, {}),
        (("GET", BOB_URL, BOB_TOKEN)): _MockResponse(200, {"id": "bob"}),
    }
    client = _MockDifferentialClient(route_map)
    asyncio.run(run_differential_bola(prop, cfg, client=client))

    # Decisive 403 denial skips step 3: exactly 2 requests consumed
    assert cfg.budget.current_count == 2
    assert cfg.budget.remaining == initial_remaining - 2


# ---------------------------------------------------------------------------
# Scenario 15: Evidence sanitization — no raw credentials in notes
# ---------------------------------------------------------------------------

def test_s15_no_raw_credentials_in_evidence():
    """Secrets (tokens, passwords) must not appear in evidence notes."""
    prop = _make_proposal()
    cfg = _make_config(attacker_params=False)
    route_map = {
        (("GET", ALICE_URL, ALICE_TOKEN)): _MockResponse(
            200,
            {"id": "alice", "secret_key": "supersecret-abc123", "email": "alice@corp.internal"},
        ),
        (("GET", ALICE_URL, BOB_TOKEN)): _MockResponse(
            200,
            {"id": "alice", "secret_key": "supersecret-abc123", "email": "alice@corp.internal"},
        ),
    }
    client = _MockDifferentialClient(route_map)
    finding = asyncio.run(run_differential_bola(prop, cfg, client=client))

    serialized = json.dumps({
        "notes": finding.notes,
        "assessment_reason": finding.assessment_reason,
        "evidence_notes": finding.evidence.notes,
        "evidence_request": finding.evidence.request,
        "evidence_response": finding.evidence.response,
    })

    # Raw secret values must not appear
    assert "supersecret-abc123" not in serialized
    assert "alice@corp.internal" not in serialized
    assert "token-alice-123" not in serialized
    assert "token-bob-456" not in serialized

    # Redaction markers must be present (in response at minimum)
    assert "[REDACTED]" in serialized


# ---------------------------------------------------------------------------
# Scenario 16: No automated CONFIRMED — SUSPECTED is max automated outcome
# ---------------------------------------------------------------------------

def test_s16_automated_confirmed_blocked():
    """validate_assessment_outcome blocks automated CONFIRMED; human review required."""
    with pytest.raises(ValueError, match="CONFIRMED.*requires explicit human review"):
        validate_assessment_outcome(AssessmentOutcome.CONFIRMED, is_human_review=False)

    # Human review path must succeed
    validate_assessment_outcome(
        AssessmentOutcome.CONFIRMED,
        is_human_review=True,
        reviewer_notes="Manually confirmed by Security Lead",
    )

    # Engine NEVER returns CONFIRMED automatically
    prop = _make_proposal()
    cfg = _make_config(attacker_params=False)
    route_map = {
        (("GET", ALICE_URL, ALICE_TOKEN)): _MockResponse(200, {"id": "alice"}),
        (("GET", ALICE_URL, BOB_TOKEN)): _MockResponse(200, {"id": "alice", "data": "alice"}),
    }
    client = _MockDifferentialClient(route_map)
    finding = asyncio.run(run_differential_bola(prop, cfg, client=client))
    assert finding.assessment_outcome != AssessmentOutcome.CONFIRMED


# ---------------------------------------------------------------------------
# Scenario 17: Unapproved proposals raise PermissionError
# ---------------------------------------------------------------------------

def test_s17_unapproved_proposal_raises_permission_error():
    """Proposal not in APPROVED state raises PermissionError immediately."""
    for bad_status in [TestStatus.PROPOSED, TestStatus.REJECTED]:
        prop = _make_proposal(status=bad_status)
        cfg = _make_config()
        with pytest.raises(PermissionError, match="not approved"):
            asyncio.run(run_differential_bola(prop, cfg))


# ---------------------------------------------------------------------------
# Scenario 18: compare_bola_responses() isolated unit tests
# ---------------------------------------------------------------------------

class TestCompareBOLAResponses:
    """Isolated unit tests for compare_bola_responses() function."""

    def _baseline(self, body=None):
        return {"body": body or {"id": "alice", "name": "Alice"}, "status_code": 200}

    def _probe(self, body=None):
        return {"body": body, "status_code": 200}

    def test_401_returns_access_denied(self):
        out, reason, meta = compare_bola_responses(
            self._baseline(), self._probe({"error": "Unauthorized"}),
            401, {"user_id": "alice"}, 200,
        )
        assert out == "ACCESS_DENIED"
        assert "401" in reason
        assert meta["probe_status"] == 401

    def test_403_returns_access_denied(self):
        out, reason, meta = compare_bola_responses(
            self._baseline(), self._probe({"error": "Forbidden"}),
            403, {"user_id": "alice"}, 200,
        )
        assert out == "ACCESS_DENIED"

    def test_404_returns_access_denied(self):
        out, reason, meta = compare_bola_responses(
            self._baseline(), self._probe({}),
            404, {"user_id": "alice"}, 200,
        )
        assert out == "ACCESS_DENIED"

    def test_500_returns_inconclusive(self):
        out, reason, meta = compare_bola_responses(
            self._baseline(), self._probe({"error": "ISE"}),
            500, {"user_id": "alice"}, 200,
        )
        assert out == "INCONCLUSIVE"
        assert "server error" in reason.lower()

    def test_503_returns_inconclusive(self):
        out, reason, meta = compare_bola_responses(
            self._baseline(), self._probe({}),
            503, {"user_id": "alice"}, 200,
        )
        assert out == "INCONCLUSIVE"

    def test_redirect_302_returns_inconclusive(self):
        out, reason, meta = compare_bola_responses(
            self._baseline(), self._probe({}),
            302, {"user_id": "alice"}, 200,
        )
        assert out == "INCONCLUSIVE"
        assert "redirect" in reason.lower()

    def test_200_with_owner_id_returns_suspected(self):
        out, reason, meta = compare_bola_responses(
            self._baseline(), self._probe({"id": "alice", "data": "secret"}),
            200, {"user_id": "alice"}, 200,
        )
        assert out == "SUSPECTED"
        assert meta["owner_id_in_probe"] is True

    def test_200_no_owner_id_returns_inconclusive(self):
        out, reason, meta = compare_bola_responses(
            self._baseline(), self._probe({"id": "x999", "data": "other"}),
            200, {"user_id": "alice"}, 200,
        )
        assert out == "INCONCLUSIVE"
        assert meta["owner_id_in_probe"] is False

    def test_empty_probe_body_returns_inconclusive(self):
        out, reason, meta = compare_bola_responses(
            self._baseline(), self._probe({}),
            200, {"user_id": "alice"}, 200,
        )
        assert out == "INCONCLUSIVE"
        assert meta["probe_body_present"] is False

    def test_body_hash_computed(self):
        baseline = self._baseline({"id": "alice"})
        probe = self._probe({"id": "alice"})
        out, reason, meta = compare_bola_responses(
            baseline, probe, 200, {"user_id": "alice"}, 200,
        )
        assert meta["body_hash_baseline"] is not None
        assert meta["body_hash_probe"] is not None
        assert meta["bodies_match"] is True

    def test_structural_match_recorded(self):
        baseline = self._baseline({"id": "alice", "name": "Alice"})
        probe = self._probe({"id": "alice", "name": "Alice"})
        out, reason, meta = compare_bola_responses(
            baseline, probe, 200, {"user_id": "alice"}, 200,
        )
        assert meta["structural_match"] is True

    def test_require_structural_match_downgrade(self):
        """SUSPECTED downgraded to INCONCLUSIVE when structural match required but missing."""
        baseline = self._baseline({"id": "alice", "name": "Alice"})
        # Probe has different keys; still contains owner id
        probe = self._probe({"user_id": "alice", "role": "admin"})
        out, reason, meta = compare_bola_responses(
            baseline, probe, 200, {"user_id": "alice"}, 200,
            require_structural_match=True,
        )
        # structural_match differs; even though owner id present, we check:
        # owner_id ("alice") is in probe body → still SUSPECTED unless keys differ
        # The key sets ARE different: {id, name} vs {user_id, role}
        # With require_structural_match=True → should downgrade
        assert out == "INCONCLUSIVE"

    def test_never_returns_confirmed(self):
        """compare_bola_responses must never return CONFIRMED."""
        out, reason, meta = compare_bola_responses(
            self._baseline(), self._probe({"id": "alice"}),
            200, {"user_id": "alice"}, 200,
        )
        assert out != "CONFIRMED"

    def test_metadata_dict_always_returned(self):
        """Comparison metadata dict must always be present regardless of outcome."""
        for status in [200, 401, 403, 500, 302]:
            out, reason, meta = compare_bola_responses(
                self._baseline(), self._probe({}),
                status, {"user_id": "alice"}, 200,
            )
            assert isinstance(meta, dict)
            assert "probe_status" in meta
            assert "baseline_status" in meta


# ---------------------------------------------------------------------------
# Bonus: internal helper unit tests
# ---------------------------------------------------------------------------

def test_body_hash_none_for_empty():
    assert _body_hash(None) is None
    # {} serializes to "{}" which is non-empty JSON; hash IS computed
    # (empty-body guard lives in compare_bola_responses, not _body_hash)
    assert _body_hash({}) is not None


def test_body_hash_deterministic():
    h1 = _body_hash({"b": 2, "a": 1})
    h2 = _body_hash({"a": 1, "b": 2})
    assert h1 == h2  # sort_keys=True


def test_top_level_keys_none_for_non_dict():
    assert _top_level_keys(None) is None
    assert _top_level_keys([]) is None
    assert _top_level_keys({}) is None
    assert _top_level_keys({"x": 1}) == frozenset({"x"})


def test_body_size_zero_for_none():
    assert _body_size(None) == 0


def test_enriched_step_logs_contain_timestamp():
    """Step logs must contain ISO 8601 timestamps."""
    prop = _make_proposal()
    cfg = _make_config(attacker_params=False)
    route_map = {
        (("GET", ALICE_URL, ALICE_TOKEN)): _MockResponse(200, {"id": "alice"}),
        (("GET", ALICE_URL, BOB_TOKEN)): _MockResponse(403, {}),
    }
    client = _MockDifferentialClient(route_map)
    finding = asyncio.run(run_differential_bola(prop, cfg, client=client))

    notes = json.loads(finding.notes)
    steps = notes.get("steps", {})
    baseline_step = steps.get("owner_baseline", {})
    probe_step = steps.get("cross_tenant_probe", {})

    assert "timestamp" in baseline_step
    assert "timestamp" in probe_step
    # Verify timestamp looks like ISO 8601
    from datetime import datetime, timezone
    for step_name, step in [("baseline", baseline_step), ("probe", probe_step)]:
        ts = step.get("timestamp", "")
        assert ts, f"Missing timestamp in {step_name} step"
        # Should parse without error
        datetime.fromisoformat(ts)


def test_bola_remediation_constant_present():
    """BOLA_REMEDIATION constant must be non-empty and reference object-level authorization."""
    assert BOLA_REMEDIATION
    assert "object-level authorization" in BOLA_REMEDIATION.lower()
