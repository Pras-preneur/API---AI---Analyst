"""Stage 6.1.1 BOLA Detection Accuracy Remediation — Regression Test Suite.

Verifies the 16 specific remediation scenarios from the Stage 6.1 security audit:
 1. Numeric owner ID "1" does not match unrelated numbers (status 100, count 10, etc.)
 2. Owner ID in harmless metadata does not imply exposure (e.g. requested_id in error wrapper)
 3. Owner data exposed without the path identifier (matching internal resource records)
 4. Identical protected owner data in baseline and attacker response -> SUSPECTED
 5. Different resource content does not automatically imply exposure -> INCONCLUSIVE
 6. Nested JSON objects comparison and exact identifier extraction
 7. JSON arrays comparison and unwrapping
 8. Volatile timestamps/request IDs excluded from comparison when configured
 9. Attacker control succeeds (establishes attacker identity functions)
10. Attacker control returns 401 when probe returns 200 (exposure noted despite control failure)
11. Both probe and control return 401 -> INCONCLUSIVE (invalid attacker identity setup)
12. Control failure with otherwise ambiguous probe -> INCONCLUSIVE
13. No unnecessary control request after a decisive denial (403, 404)
14. Request budget exhausted before execution (0 requests sent)
15. Request budget accurately counts attempted requests
16. Network exception during each execution step (baseline, probe, control)
"""

import asyncio
import json
from typing import Any, Dict, List, Optional
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
)
from app.parser.openapi_parser import (
    ResolvedSecurityRequirement,
    SecuritySchemeModel,
)
from app.security.differential_engine import (
    BOLA_REMEDIATION,
    DEFAULT_EXCLUDED_FIELDS,
    compare_bola_responses,
    extract_matching_resource_fields,
    find_exact_identifier_matches,
    normalize_data,
    run_differential_bola,
    unwrap_envelope,
)


# ---------------------------------------------------------------------------
# Test Doubles
# ---------------------------------------------------------------------------

class _MockResponse:
    def __init__(self, status_code: int, json_data: Any = None, headers: Dict[str, str] = None):
        self.status_code = status_code
        self._json_data = json_data
        self.headers = headers or {}
        self.text = json.dumps(json_data) if json_data is not None else ""

    def json(self):
        if self._json_data is None:
            raise ValueError("No JSON body")
        return self._json_data


class _MockDifferentialClient:
    def __init__(self, route_map: Dict[tuple, _MockResponse]):
        self.route_map = route_map
        self.history: List[Dict[str, Any]] = []

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

        for (m, u, _a), resp in self.route_map.items():
            if m.upper() == method.upper() and u == url:
                return resp

        return _MockResponse(404, {"error": "Not Found"})

    async def aclose(self):
        pass


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_proposal(path: str = "/items/{item_id}", status: TestStatus = TestStatus.APPROVED) -> ProposedTest:
    bearer_scheme = SecuritySchemeModel(type="http", scheme="bearer")
    ep = EndpointModel(
        path=path,
        method="get",
        responses={"200": {"description": "ok"}},
        effective_security=[ResolvedSecurityRequirement(scheme_name="BearerAuth", scheme=bearer_scheme)],
    )
    return ProposedTest(
        endpoint=ep,
        test_type="BOLA",
        description="BOLA assessment",
        severity="High",
        status=status,
    )


def _make_config(
    owner_id_val: Any = "1",
    attacker_id_val: Any = "2",
    has_control: bool = True,
    budget_limit: int = 10,
) -> ExecutionConfig:
    return ExecutionConfig(
        mode=ExecutionMode.SPEC_DRIVEN,
        target_base_url="http://127.0.0.1:8001",
        owner_identity=TestIdentity(identity_id="alice", token="token-alice"),
        attacker_identity=TestIdentity(identity_id="bob", token="token-bob"),
        parameters=ParameterFixtures(
            owner_path_params={"item_id": owner_id_val},
            attacker_path_params={"item_id": attacker_id_val} if has_control else {},
        ),
        budget=RequestBudget(max_requests=budget_limit),
    )


BASE_URL = "http://127.0.0.1:8001"


# ---------------------------------------------------------------------------
# Test 1: Numeric owner ID "1" does not match unrelated numbers
# ---------------------------------------------------------------------------

def test_01_numeric_owner_id_does_not_match_unrelated_numbers():
    """ID '1' must not trigger false positive on unrelated numbers (e.g. status 100, timestamp, count)."""
    baseline = {"body": {"item_id": 1, "name": "Secret Document"}, "status_code": 200}
    # Probe contains numbers with digit '1', but not item_id == 1
    probe = {
        "body": {
            "status": 100,
            "items_count": 10,
            "timestamp": 1730310000,
            "other_id": 21,
            "description": "Public directory",
        },
        "status_code": 200,
    }

    out, reason, meta = compare_bola_responses(
        baseline_data=baseline,
        probe_data=probe,
        probe_status=200,
        owner_path_params={"item_id": 1},
        baseline_status=200,
    )

    # Substring match is avoided: outcome must be INCONCLUSIVE, not SUSPECTED
    assert out == "INCONCLUSIVE"
    assert meta["owner_id_in_probe"] is False
    assert len(meta["owner_id_matches"]) == 0


# ---------------------------------------------------------------------------
# Test 2: Owner ID in harmless metadata does not imply exposure
# ---------------------------------------------------------------------------

def test_02_owner_id_in_harmless_metadata_does_not_imply_exposure():
    """Owner ID echoed inside error/query metadata wrapper with no data must not trigger SUSPECTED."""
    baseline = {"body": {"user_id": "alice", "email": "alice@corp.internal", "balance": 5000}, "status_code": 200}
    probe = {
        "body": {
            "requested_id": "alice",
            "found": False,
            "results": [],
            "message": "Resource empty or inaccessible",
        },
        "status_code": 200,
    }

    out, reason, meta = compare_bola_responses(
        baseline_data=baseline,
        probe_data=probe,
        probe_status=200,
        owner_path_params={"user_id": "alice"},
        baseline_status=200,
    )

    assert out == "INCONCLUSIVE"
    assert meta["owner_id_in_probe"] is False
    assert len(meta["harmless_metadata_matches"]) > 0
    assert "harmless metadata" in reason.lower()


# ---------------------------------------------------------------------------
# Test 3: Owner data exposed without the path identifier
# ---------------------------------------------------------------------------

def test_03_owner_data_exposed_without_path_identifier():
    """If path parameter (e.g. slug 'finance-team') is omitted from body, matching records still trigger SUSPECTED."""
    baseline = {
        "body": {
            "account_id": "ACC-998811",
            "balance_cents": 5000000,
            "billing_email": "finance@corp.internal",
            "status": "active",
        },
        "status_code": 200,
    }
    probe = {
        "body": {
            "account_id": "ACC-998811",
            "balance_cents": 5000000,
            "billing_email": "finance@corp.internal",
            "status": "active",
        },
        "status_code": 200,
    }

    # Path param is a slug not present in the body
    out, reason, meta = compare_bola_responses(
        baseline_data=baseline,
        probe_data=probe,
        probe_status=200,
        owner_path_params={"account_slug": "finance-team"},
        baseline_status=200,
    )

    assert out == "SUSPECTED"
    assert meta["bodies_match"] is True
    assert len(meta["matching_protected_fields"]) > 0


# ---------------------------------------------------------------------------
# Test 4: Identical protected owner data in baseline and attacker response
# ---------------------------------------------------------------------------

def test_04_identical_protected_owner_data_produces_suspected():
    """Exact identical protected owner payload returned to attacker triggers SUSPECTED."""
    data = {"id": "obj-101", "secret_info": "Top Secret Data", "owner": "alice"}
    out, reason, meta = compare_bola_responses(
        baseline_data={"body": data, "status_code": 200},
        probe_data={"body": data, "status_code": 200},
        probe_status=200,
        owner_path_params={"obj_id": "obj-101"},
        baseline_status=200,
    )

    assert out == "SUSPECTED"
    assert meta["bodies_match"] is True
    assert meta["owner_id_in_probe"] is True


# ---------------------------------------------------------------------------
# Test 5: Different resource content does not automatically imply exposure
# ---------------------------------------------------------------------------

def test_05_different_resource_content_does_not_imply_exposure():
    """If probe returns valid 200 but entirely different non-owner resource, outcome is INCONCLUSIVE."""
    baseline = {"body": {"id": "1", "data": "alice personal secret"}, "status_code": 200}
    probe = {"body": {"id": "99", "data": "public system status banner"}, "status_code": 200}

    out, reason, meta = compare_bola_responses(
        baseline_data=baseline,
        probe_data=probe,
        probe_status=200,
        owner_path_params={"item_id": "1"},
        baseline_status=200,
    )

    assert out == "INCONCLUSIVE"
    assert meta["bodies_match"] is False
    assert meta["owner_id_in_probe"] is False


# ---------------------------------------------------------------------------
# Test 6: Nested JSON objects
# ---------------------------------------------------------------------------

def test_06_nested_json_objects():
    """Nested JSON structures are recursively scanned for identifiers and protected fields."""
    baseline = {
        "body": {
            "organization": {
                "id": "org-42",
                "admin": {"user_id": 1, "email": "admin@org42.com"},
                "vault": {"secret_token": "vault-pass-99"},
            }
        },
        "status_code": 200,
    }
    probe = {
        "body": {
            "organization": {
                "id": "org-42",
                "admin": {"user_id": 1, "email": "admin@org42.com"},
                "vault": {"secret_token": "vault-pass-99"},
            }
        },
        "status_code": 200,
    }

    out, reason, meta = compare_bola_responses(
        baseline_data=baseline,
        probe_data=probe,
        probe_status=200,
        owner_path_params={"user_id": 1},
        baseline_status=200,
    )

    assert out == "SUSPECTED"
    assert meta["owner_id_in_probe"] is True
    assert meta["bodies_match"] is True


# ---------------------------------------------------------------------------
# Test 7: JSON arrays
# ---------------------------------------------------------------------------

def test_07_json_arrays():
    """Top-level and nested JSON arrays are handled cleanly without crashing or skipping."""
    baseline = {
        "body": [
            {"file_id": "f1", "owner_id": 1, "name": "tax_2025.pdf"},
            {"file_id": "f2", "owner_id": 1, "name": "medical.pdf"},
        ],
        "status_code": 200,
    }
    probe = {
        "body": [
            {"file_id": "f1", "owner_id": 1, "name": "tax_2025.pdf"},
            {"file_id": "f2", "owner_id": 1, "name": "medical.pdf"},
        ],
        "status_code": 200,
    }

    out, reason, meta = compare_bola_responses(
        baseline_data=baseline,
        probe_data=probe,
        probe_status=200,
        owner_path_params={"owner_id": 1},
        baseline_status=200,
    )

    assert out == "SUSPECTED"
    assert meta["bodies_match"] is True
    assert meta["owner_id_in_probe"] is True


# ---------------------------------------------------------------------------
# Test 8: Volatile timestamps excluded from comparison when configured
# ---------------------------------------------------------------------------

def test_08_volatile_timestamps_excluded_from_comparison():
    """Different timestamps/request IDs do not prevent bodies from matching when excluded."""
    baseline = {
        "body": {
            "id": "res-1",
            "data": "sensitive",
            "timestamp": "2026-10-30T10:00:00Z",
            "request_id": "req-aaa-111",
        },
        "status_code": 200,
    }
    probe = {
        "body": {
            "id": "res-1",
            "data": "sensitive",
            "timestamp": "2026-10-30T10:05:22Z",
            "request_id": "req-bbb-222",
        },
        "status_code": 200,
    }

    out, reason, meta = compare_bola_responses(
        baseline_data=baseline,
        probe_data=probe,
        probe_status=200,
        owner_path_params={"res_id": "res-1"},
        baseline_status=200,
        excluded_fields={"timestamp", "request_id"},
    )

    assert out == "SUSPECTED"
    assert meta["bodies_match"] is True


# ---------------------------------------------------------------------------
# Test 9: Attacker control succeeds
# ---------------------------------------------------------------------------

def test_09_attacker_control_succeeds():
    """Successful attacker control confirms attacker credentials work on own object."""
    prop = _make_proposal()
    cfg = _make_config(owner_id_val="1", attacker_id_val="2", has_control=True)

    route_map = {
        (("GET", f"{BASE_URL}/items/1", "Bearer token-alice")): _MockResponse(200, {"item_id": 1, "data": "alice"}),
        (("GET", f"{BASE_URL}/items/1", "Bearer token-bob")): _MockResponse(200, {"item_id": 1, "data": "alice"}),
        (("GET", f"{BASE_URL}/items/2", "Bearer token-bob")): _MockResponse(200, {"item_id": 2, "data": "bob"}),
    }
    client = _MockDifferentialClient(route_map)
    finding = asyncio.run(run_differential_bola(prop, cfg, client=client))

    assert finding.assessment_outcome == AssessmentOutcome.SUSPECTED
    notes = json.loads(finding.notes)
    assert notes["comparison"]["control_verified"] is True
    assert notes["comparison"]["control_status"] == 200
    assert len(client.history) == 3


# ---------------------------------------------------------------------------
# Test 10: Attacker control returns 401 when probe leaked owner data
# ---------------------------------------------------------------------------

def test_10_attacker_control_fails_with_clear_probe_leak():
    """If probe definitively leaked owner data, control failure does not suppress SUSPECTED."""
    prop = _make_proposal()
    cfg = _make_config(owner_id_val="1", attacker_id_val="2", has_control=True)

    route_map = {
        (("GET", f"{BASE_URL}/items/1", "Bearer token-alice")): _MockResponse(200, {"item_id": 1, "data": "alice"}),
        (("GET", f"{BASE_URL}/items/1", "Bearer token-bob")): _MockResponse(200, {"item_id": 1, "data": "alice"}),
        (("GET", f"{BASE_URL}/items/2", "Bearer token-bob")): _MockResponse(401, {"error": "Unauthorized"}),
    }
    client = _MockDifferentialClient(route_map)
    finding = asyncio.run(run_differential_bola(prop, cfg, client=client))

    # Definitive probe leak remains SUSPECTED, with note regarding control failure
    assert finding.assessment_outcome == AssessmentOutcome.SUSPECTED
    notes = json.loads(finding.notes)
    assert notes["comparison"]["control_verified"] is False
    assert "attacker control request failed" in finding.assessment_reason.lower()


# ---------------------------------------------------------------------------
# Test 11: Both probe and control return 401 -> INCONCLUSIVE
# ---------------------------------------------------------------------------

def test_11_both_probe_and_control_return_401_inconclusive():
    """If both cross-tenant probe and control return 401, identity setup is INCONCLUSIVE (not ACCESS_DENIED)."""
    prop = _make_proposal()
    cfg = _make_config(owner_id_val="1", attacker_id_val="2", has_control=True)

    route_map = {
        (("GET", f"{BASE_URL}/items/1", "Bearer token-alice")): _MockResponse(200, {"item_id": 1, "data": "alice"}),
        (("GET", f"{BASE_URL}/items/1", "Bearer token-bob")): _MockResponse(401, {"error": "Invalid token"}),
        (("GET", f"{BASE_URL}/items/2", "Bearer token-bob")): _MockResponse(401, {"error": "Invalid token"}),
    }
    client = _MockDifferentialClient(route_map)
    finding = asyncio.run(run_differential_bola(prop, cfg, client=client))

    assert finding.assessment_outcome == AssessmentOutcome.INCONCLUSIVE
    assert "identity setup is inconclusive" in finding.assessment_reason.lower()
    assert len(client.history) == 3


# ---------------------------------------------------------------------------
# Test 12: Control failure with otherwise ambiguous probe -> INCONCLUSIVE
# ---------------------------------------------------------------------------

def test_12_control_failure_with_ambiguous_probe():
    """When probe 200 body is ambiguous and control fails, outcome is strictly INCONCLUSIVE."""
    baseline = {"body": {"item_id": "1", "data": "private"}, "status_code": 200}
    probe = {"body": {"item_id": "99", "data": "generic"}, "status_code": 200}

    out, reason, meta = compare_bola_responses(
        baseline_data=baseline,
        probe_data=probe,
        probe_status=200,
        owner_path_params={"item_id": "1"},
        baseline_status=200,
        control_status=500,
    )

    assert out == "INCONCLUSIVE"
    assert "control request failed" in reason.lower()


# ---------------------------------------------------------------------------
# Test 13: No unnecessary control request after a decisive denial
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("denial_code", [403, 404])
def test_13_no_unnecessary_control_after_decisive_denial(denial_code):
    """When cross-tenant probe receives 403 or 404, attacker control request is SKIPPED."""
    prop = _make_proposal()
    cfg = _make_config(owner_id_val="1", attacker_id_val="2", has_control=True)

    route_map = {
        (("GET", f"{BASE_URL}/items/1", "Bearer token-alice")): _MockResponse(200, {"item_id": 1, "data": "alice"}),
        (("GET", f"{BASE_URL}/items/1", "Bearer token-bob")): _MockResponse(denial_code, {"error": "Denied"}),
        (("GET", f"{BASE_URL}/items/2", "Bearer token-bob")): _MockResponse(200, {"item_id": 2, "data": "bob"}),
    }
    client = _MockDifferentialClient(route_map)
    finding = asyncio.run(run_differential_bola(prop, cfg, client=client))

    # Decisive denial skips control: exactly 2 requests sent
    assert len(client.history) == 2
    assert cfg.budget.current_count == 2
    assert finding.assessment_outcome == AssessmentOutcome.ACCESS_DENIED


# ---------------------------------------------------------------------------
# Test 14: Request budget exhausted before execution
# ---------------------------------------------------------------------------

def test_14_budget_exhausted_before_execution():
    """Preflight check halts immediately with 0 requests when remaining budget is less than required."""
    prop = _make_proposal()
    cfg = _make_config(budget_limit=2, has_control=True)  # requires 3 requests
    client = _MockDifferentialClient({})

    finding = asyncio.run(run_differential_bola(prop, cfg, client=client))

    assert len(client.history) == 0
    assert cfg.budget.current_count == 0
    assert finding.execution_status == ExecutionStatus.NOT_EXECUTED
    assert "budget exceeded" in finding.notes.lower()


# ---------------------------------------------------------------------------
# Test 15: Request budget accurately counts attempted requests
# ---------------------------------------------------------------------------

def test_15_budget_accurately_counts_attempted_requests():
    """Each attempted request increments budget count immediately."""
    prop = _make_proposal()
    cfg = _make_config(budget_limit=10, has_control=True)

    # 401 on probe will trigger control step -> total 3 requests
    route_map = {
        (("GET", f"{BASE_URL}/items/1", "Bearer token-alice")): _MockResponse(200, {"item_id": 1}),
        (("GET", f"{BASE_URL}/items/1", "Bearer token-bob")): _MockResponse(401, {}),
        (("GET", f"{BASE_URL}/items/2", "Bearer token-bob")): _MockResponse(200, {"item_id": 2}),
    }
    client = _MockDifferentialClient(route_map)
    finding = asyncio.run(run_differential_bola(prop, cfg, client=client))

    assert len(client.history) == 3
    assert cfg.budget.current_count == 3
    assert cfg.budget.remaining == 7
    assert finding.assessment_outcome == AssessmentOutcome.ACCESS_DENIED


# ---------------------------------------------------------------------------
# Test 16: Network exception during each execution step
# ---------------------------------------------------------------------------

def test_16a_network_exception_during_baseline():
    """Connection failure during baseline halts execution and consumes 1 budget slot."""
    prop = _make_proposal()
    cfg = _make_config(budget_limit=5)

    class _FailBaselineClient:
        async def request(self, *args, **kwargs):
            raise httpx.ConnectError("Target down on baseline")
        async def aclose(self):
            pass

    finding = asyncio.run(run_differential_bola(prop, cfg, client=_FailBaselineClient()))
    assert finding.execution_status == ExecutionStatus.FAILED
    assert finding.assessment_outcome == AssessmentOutcome.INCONCLUSIVE
    assert cfg.budget.current_count == 1


def test_16b_network_exception_during_probe():
    """Connection failure during probe halts execution and consumes 2 budget slots."""
    prop = _make_proposal()
    cfg = _make_config(budget_limit=5)

    class _FailProbeClient:
        def __init__(self):
            self.call = 0
        async def request(self, *args, **kwargs):
            self.call += 1
            if self.call == 1:
                return _MockResponse(200, {"id": 1})
            raise httpx.ConnectTimeout("Timeout on probe")
        async def aclose(self):
            pass

    finding = asyncio.run(run_differential_bola(prop, cfg, client=_FailProbeClient()))
    assert finding.execution_status == ExecutionStatus.FAILED
    assert finding.assessment_outcome == AssessmentOutcome.INCONCLUSIVE
    assert cfg.budget.current_count == 2


def test_16c_network_exception_during_control():
    """Connection failure during control is recorded in step_logs and does not crash."""
    prop = _make_proposal()
    cfg = _make_config(owner_id_val="1", attacker_id_val="2", has_control=True, budget_limit=5)

    class _FailControlClient:
        def __init__(self):
            self.call = 0
        async def request(self, *args, **kwargs):
            self.call += 1
            if self.call == 1:
                return _MockResponse(200, {"item_id": 1, "data": "alice"})
            if self.call == 2:
                # Probe leaks owner data
                return _MockResponse(200, {"item_id": 1, "data": "alice"})
            raise httpx.ReadTimeout("Timeout on control")
        async def aclose(self):
            pass

    finding = asyncio.run(run_differential_bola(prop, cfg, client=_FailControlClient()))
    assert finding.execution_status == ExecutionStatus.COMPLETED
    assert finding.assessment_outcome == AssessmentOutcome.SUSPECTED
    assert cfg.budget.current_count == 3
    notes = json.loads(finding.notes)
    assert "attacker_control" in notes["steps"]
    assert "error" in notes["steps"]["attacker_control"]

