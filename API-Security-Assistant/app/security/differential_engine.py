"""Differential BOLA testing engine for specification-driven security assessments.

Executes a controlled differential assessment sequence:
1. Owner baseline: access the configured owner's own object using owner credentials.
2. Cross-tenant probe: attempt to access the owner's object using the attacker's credentials.
3. Attacker control (conditional): access the attacker's own object using the attacker's credentials.

Analyzes evidence conservatively:
- HTTP 200 alone does not prove BOLA.
- Response equality alone does not prove BOLA.
- Missing or failed baselines yield INCONCLUSIVE / NOT_EXECUTED.
- Access denials (401/403/404) yield ACCESS_DENIED / NOT_EXECUTED.
- 5xx responses yield INCONCLUSIVE (server error, not access control signal).
- 3xx responses yield INCONCLUSIVE (unexpected redirect — should not occur).
- Automated comparisons NEVER assign AssessmentOutcome.CONFIRMED.
- Full request budget is preflighted before sending any requests.
- All request/response evidence is sanitized without secrets or raw credentials.
- Every attempted request counts against the budget even if it fails.

Stage 6.1.2 Final Accuracy Hardening:
- Boolean/Integer distinction: explicitly guards against Python bool/int coercion (True != 1, False != 0).
- Low-cardinality attribute filtering: common fields (role, status, tier, country) cannot independently trigger SUSPECTED.
- Protected data requirement: an identifier match alone without substantive protected data yields INCONCLUSIVE.
- Partial array leakage inspection: safe element-by-element overlap detection for collection responses.
"""

import hashlib
import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

import httpx

from ..config import ALLOWED_TARGETS
from ..models import (
    AssessmentOutcome,
    EndpointModel,
    Evidence,
    ExecutionConfig,
    ExecutionStatus,
    Finding,
    FindingStatus,
    ProposedTest,
    TestIdentity,
    TestStatus,
)
from .sanitization import (
    sanitize_response as _sanitize_response_util,
    sanitize_url,
    sanitize_error_message,
    sanitize_data,
)
from .request_builder import PreparedRequest, build_request


# ---------------------------------------------------------------------------
# Module-level Constants
# ---------------------------------------------------------------------------

BOLA_REMEDIATION = (
    "Enforce object-level authorization on every request. Verify that the "
    "authenticated principal owns or has explicit access to the requested "
    "resource before returning any data."
)

DEFAULT_EXCLUDED_FIELDS: Set[str] = {
    "timestamp",
    "time",
    "date",
    "created_at",
    "updated_at",
    "generated_at",
    "request_id",
    "req_id",
    "trace_id",
    "correlation_id",
    "span_id",
    "nonce",
    "csrf_token",
    "etag",
    "server_time",
}

HARMLESS_METADATA_KEYS: Set[str] = {
    "requested_id",
    "requested_resource",
    "query",
    "param",
    "parameter",
    "target",
    "target_user",
    "filter",
    "path",
    "url",
    "error_details",
    "requested_user",
    "resource_id",
}

GENERIC_ENVELOPE_KEYS: Set[str] = {
    "status",
    "code",
    "success",
    "message",
    "error",
    "ok",
    "version",
    "type",
}

COMMON_LOW_CARDINALITY_KEYS: Set[str] = {
    "role",
    "roles",
    "tier",
    "plan",
    "status",
    "state",
    "country",
    "country_code",
    "language",
    "lang",
    "locale",
    "currency",
    "theme",
    "mode",
    "category",
    "gender",
    "active",
    "enabled",
    "verified",
    "public",
    "published",
    "default",
    "is_active",
    "is_admin",
    "is_verified",
    "kind",
    "scope",
}

BARE_IDENTIFIER_KEYS: Set[str] = {
    "id",
    "user_id",
    "item_id",
    "account_id",
    "resource_id",
    "owner_id",
    "obj_id",
}


# ---------------------------------------------------------------------------
# Internal Helpers
# ---------------------------------------------------------------------------

def _utc_now() -> str:
    """Return current UTC timestamp in ISO 8601 format."""
    return datetime.now(timezone.utc).isoformat()


def _sanitize_response_data(resp: httpx.Response) -> Dict[str, Any]:
    """Sanitize response for evidence storage, redacting tokens and email addresses."""
    return _sanitize_response_util(resp)


def _body_hash(body: Any) -> Optional[str]:
    """Compute a deterministic SHA-256 hex digest of a response body."""
    if body is None:
        return None
    try:
        canonical = json.dumps(body, sort_keys=True, ensure_ascii=True)
    except (TypeError, ValueError):
        canonical = str(body)
    if not canonical:
        return None
    return hashlib.sha256(canonical.encode()).hexdigest()


def _top_level_keys(body: Any) -> Optional[frozenset]:
    """Return the top-level keys of a dict body, or None for non-dict / empty bodies."""
    if isinstance(body, dict) and body:
        return frozenset(body.keys())
    return None


def _body_size(body: Any) -> int:
    """Approximate byte size of a serialized body (for evidence metadata only)."""
    if body is None:
        return 0
    try:
        return len(json.dumps(body, ensure_ascii=True).encode())
    except (TypeError, ValueError):
        return len(str(body).encode())


def unwrap_envelope(data: Any) -> Any:
    """Unwrap common single-key wrapper dictionaries (e.g. {'data': ...}, {'result': ...})."""
    if isinstance(data, dict) and len(data) == 1:
        single_key = next(iter(data.keys()))
        if single_key.lower() in {"data", "result", "item", "payload", "response"}:
            inner = data[single_key]
            if isinstance(inner, (dict, list)):
                return inner
    return data


def normalize_data(
    data: Any,
    excluded_fields: Optional[Set[str]] = None,
) -> Any:
    """Recursively strip volatile fields (e.g. timestamps, request IDs) from data."""
    if excluded_fields is None:
        excluded_fields = DEFAULT_EXCLUDED_FIELDS
    excluded_lower = {f.lower() for f in excluded_fields}

    if isinstance(data, dict):
        return {
            k: normalize_data(v, excluded_fields)
            for k, v in data.items()
            if str(k).lower() not in excluded_lower
        }
    elif isinstance(data, list):
        return [normalize_data(item, excluded_fields) for item in data]
    return data


def has_substantive_resource_content(data: Any, excluded_fields: Optional[Set[str]] = None) -> bool:
    """Return True if data contains substantive resource content beyond identifiers and envelope/low-cardinality metadata."""
    if excluded_fields is None:
        excluded_fields = DEFAULT_EXCLUDED_FIELDS
    excluded_lower = {f.lower() for f in excluded_fields}
    ignored_keys = (
        excluded_lower
        | HARMLESS_METADATA_KEYS
        | GENERIC_ENVELOPE_KEYS
        | COMMON_LOW_CARDINALITY_KEYS
        | BARE_IDENTIFIER_KEYS
    )

    if isinstance(data, dict):
        for k, v in data.items():
            if str(k).lower() not in ignored_keys:
                if v not in (None, "", [], {}):
                    return True
            if isinstance(v, (dict, list)) and has_substantive_resource_content(v, excluded_fields):
                return True
        return False
    elif isinstance(data, list):
        return any(has_substantive_resource_content(item, excluded_fields) for item in data)
    return False


def find_exact_identifier_matches(
    data: Any,
    target_values: Set[Any],
    current_key: str = "",
) -> List[Dict[str, Any]]:
    """Recursively find exact matches of target identifiers in JSON data.

    Explicitly separates boolean values from integers (True != 1, False != 0).
    Matches exact primitive values (preserving types like int/string) without substring containment.
    Tags whether the match occurred inside known harmless metadata fields.
    """
    matches: List[Dict[str, Any]] = []
    if isinstance(data, dict):
        for k, v in data.items():
            matches.extend(find_exact_identifier_matches(v, target_values, current_key=str(k)))
    elif isinstance(data, list):
        for item in data:
            matches.extend(find_exact_identifier_matches(item, target_values, current_key=current_key))
    else:
        # Explicitly guard boolean values: in Python, bool inherits from int (isinstance(True, int) is True).
        # Booleans must NEVER match numeric or string owner identifiers.
        if isinstance(data, bool):
            return []

        clean_targets = {t for t in target_values if not isinstance(t, bool)}

        is_match = False
        if data in clean_targets:
            is_match = True
        elif isinstance(data, int):
            for t in clean_targets:
                if isinstance(t, bool):
                    continue
                try:
                    if int(t) == data:
                        is_match = True
                        break
                except (ValueError, TypeError):
                    pass
        elif isinstance(data, str):
            for t in clean_targets:
                if isinstance(t, bool):
                    continue
                if data.strip().lower() == str(t).strip().lower():
                    is_match = True
                    break

        if is_match:
            k_lower = current_key.lower()
            is_meta = k_lower in HARMLESS_METADATA_KEYS
            matches.append({
                "key": current_key,
                "value": data,
                "is_metadata": is_meta,
            })
    return matches


def extract_matching_resource_fields(
    baseline: Any,
    probe: Any,
    excluded_fields: Optional[Set[str]] = None,
) -> Dict[str, Any]:
    """Find non-trivial, substantive protected resource field matches between baseline and probe.

    Excludes volatile fields, envelope metadata, harmless wrappers, and common low-cardinality keys.
    """
    if excluded_fields is None:
        excluded_fields = DEFAULT_EXCLUDED_FIELDS
    excluded_lower = {f.lower() for f in excluded_fields}
    non_resource_keys = (
        excluded_lower
        | HARMLESS_METADATA_KEYS
        | GENERIC_ENVELOPE_KEYS
        | COMMON_LOW_CARDINALITY_KEYS
    )

    matching: Dict[str, Any] = {}

    def _compare(b: Any, p: Any, prefix: str = ""):
        if isinstance(b, dict) and isinstance(p, dict):
            for k, b_val in b.items():
                k_str = str(k)
                if k_str.lower() in non_resource_keys:
                    continue
                if k_str in p:
                    p_val = p[k_str]
                    full_key = f"{prefix}.{k_str}" if prefix else k_str
                    if isinstance(b_val, (dict, list)) and isinstance(p_val, (dict, list)):
                        if b_val == p_val and b_val:
                            matching[full_key] = p_val
                        elif isinstance(b_val, dict) and isinstance(p_val, dict):
                            _compare(b_val, p_val, full_key)
                    else:
                        if b_val == p_val and b_val not in (None, "", [], {}):
                            matching[full_key] = p_val
        elif isinstance(b, list) and isinstance(p, list):
            if b == p and len(b) > 0:
                matching[prefix or "items"] = p

    _compare(baseline, probe)
    return matching


def check_array_resource_overlap(
    baseline_body: Any,
    probe_body: Any,
    owner_identifiers: Set[Any],
    excluded_fields: Optional[Set[str]] = None,
) -> Tuple[bool, List[Dict[str, Any]]]:
    """Inspect collection/array responses for genuine leaked owner elements.

    Verifies whether one or more records in probe_body match a baseline record
    or contain exact owner identifiers along with substantive protected content.
    Returns:
        (has_genuine_leak, matching_elements)
    """
    baseline_items = []
    if isinstance(baseline_body, list):
        baseline_items = baseline_body
    elif isinstance(baseline_body, dict):
        baseline_items = [baseline_body]

    if not isinstance(probe_body, list) or not baseline_items:
        return False, []

    leaked_elements: List[Dict[str, Any]] = []
    for p_elem in probe_body:
        if not isinstance(p_elem, dict):
            continue
        norm_p = normalize_data(p_elem, excluded_fields)

        # 1. Exact element match against normalized baseline records
        matched_baseline = False
        for b_elem in baseline_items:
            if isinstance(b_elem, dict):
                norm_b = normalize_data(b_elem, excluded_fields)
                if norm_p == norm_b and has_substantive_resource_content(norm_p, excluded_fields):
                    leaked_elements.append(p_elem)
                    matched_baseline = True
                    break
        if matched_baseline:
            continue

        # 2. Element contains exact owner identifier AND substantive protected content
        id_matches = find_exact_identifier_matches(p_elem, owner_identifiers)
        substantive_ids = [m for m in id_matches if not m["is_metadata"]]
        if substantive_ids and has_substantive_resource_content(p_elem, excluded_fields):
            leaked_elements.append(p_elem)

    return (len(leaked_elements) > 0), leaked_elements


# ---------------------------------------------------------------------------
# Stage 6.1.2: compare_bola_responses()
# ---------------------------------------------------------------------------

def compare_bola_responses(
    baseline_data: Dict[str, Any],
    probe_data: Dict[str, Any],
    probe_status: int,
    owner_path_params: Dict[str, Any],
    baseline_status: int,
    *,
    control_data: Optional[Dict[str, Any]] = None,
    control_status: Optional[int] = None,
    excluded_fields: Optional[Set[str]] = None,
    require_owner_id_in_body: bool = False,
    require_structural_match: bool = False,
) -> Tuple[str, str, Dict[str, Any]]:
    """Conservatively compare owner baseline, cross-tenant probe, and attacker control responses.

    Implements a structured, type-aware comparison:
    - Never uses raw substring matching.
    - Explicitly separates boolean values from integers (True != 1, False != 0).
    - Requires substantive protected content beyond identifiers alone.
    - Filters low-cardinality attributes (role, status, country, tier).
    - Supports partial array leakage inspection.
    - Evaluates attacker control: classifies identity setup as INCONCLUSIVE if both probe and control 401.
    - Never returns CONFIRMED.

    Returns:
        Tuple of (outcome_value, reason_string, comparison_metadata_dict).
    """
    if excluded_fields is None:
        excluded_fields = DEFAULT_EXCLUDED_FIELDS

    comparison: Dict[str, Any] = {
        "probe_status": probe_status,
        "baseline_status": baseline_status,
        "control_status": control_status,
        "owner_id_in_probe": False,
        "owner_id_matches": [],
        "harmless_metadata_matches": [],
        "matching_protected_fields": [],
        "has_substantive_data": False,
        "partial_array_leak": False,
        "leaked_array_elements_count": 0,
        "bodies_match": False,
        "structural_match": False,
        "owner_body_present": False,
        "probe_body_present": False,
        "control_verified": None,
        "content_type_match": None,
        "owner_identifiers_checked": [],
        "body_hash_baseline": None,
        "body_hash_probe": None,
    }

    # ---- Case 1: Both Probe and Control return 401 (Invalid Attacker Identity Setup) ----
    if probe_status == 401 and control_status == 401:
        comparison["control_verified"] = False
        reason = (
            "Both cross-tenant probe and attacker control returned HTTP 401. "
            "Attacker credentials failed authentication across all requests; "
            "cannot determine whether object-level authorization is enforced. "
            "Identity setup is inconclusive."
        )
        return "INCONCLUSIVE", reason, comparison

    # ---- Case 2: Access Denied (401, 403, 404) --------------------------------
    if probe_status in {401, 403, 404}:
        if probe_status == 401 and control_status in {200, 201, 204}:
            comparison["control_verified"] = True
            reason = (
                f"Cross-tenant probe received HTTP 401 while attacker control succeeded with "
                f"HTTP {control_status}. Attacker credentials are valid, and cross-tenant "
                "access was denied."
            )
        elif probe_status in {403, 404}:
            reason = (
                f"Cross-tenant probe received decisive denial HTTP {probe_status}. "
                "The endpoint enforced authorization boundaries against the cross-tenant probe."
            )
        else:
            reason = (
                f"Cross-tenant probe received HTTP {probe_status}. "
                "Endpoint denied access to the attacker identity."
            )
        return "ACCESS_DENIED", reason, comparison

    # ---- Case 3: Server Error (5xx) ----------------------------------------
    if 500 <= probe_status <= 599:
        reason = (
            f"Cross-tenant probe received HTTP {probe_status} (server error). "
            "Cannot determine authorization behaviour from a server-side error response."
        )
        return "INCONCLUSIVE", reason, comparison

    # ---- Case 4: Unexpected Redirect (3xx) ----------------------------------
    if 300 <= probe_status <= 399:
        reason = (
            f"Cross-tenant probe received HTTP {probe_status} (redirect). "
            "Redirects should be disabled; this is unexpected and may indicate a misconfiguration."
        )
        return "INCONCLUSIVE", reason, comparison

    # ---- Case 5: 2xx — Substantive Content and Identity Comparison ---------
    if probe_status in {200, 201, 204}:
        raw_baseline_body = baseline_data.get("body")
        raw_probe_body = probe_data.get("body")

        comparison["owner_body_present"] = bool(raw_baseline_body)
        comparison["probe_body_present"] = bool(raw_probe_body)

        # Guard: empty probe body
        if not raw_probe_body:
            reason = (
                f"Cross-tenant probe returned HTTP {probe_status} with an empty or absent body. "
                "Cannot determine whether owner data was leaked."
            )
            return "INCONCLUSIVE", reason, comparison

        # Normalize bodies by stripping volatile fields
        norm_baseline = normalize_data(raw_baseline_body, excluded_fields)
        norm_probe = normalize_data(raw_probe_body, excluded_fields)

        unwrapped_baseline = unwrap_envelope(norm_baseline)
        unwrapped_probe = unwrap_envelope(norm_probe)

        # Check substantive content presence (beyond identifiers and low-cardinality metadata)
        has_substantive = has_substantive_resource_content(unwrapped_probe, excluded_fields)
        comparison["has_substantive_data"] = has_substantive

        # Body hashes of normalized data
        baseline_hash = _body_hash(norm_baseline)
        probe_hash = _body_hash(norm_probe)
        comparison["body_hash_baseline"] = baseline_hash
        comparison["body_hash_probe"] = probe_hash

        # Body match
        bodies_match = (
            bool(norm_baseline)
            and bool(norm_probe)
            and (
                (baseline_hash is not None and baseline_hash == probe_hash)
                or (unwrapped_baseline == unwrapped_probe and bool(unwrapped_baseline))
            )
        )
        comparison["bodies_match"] = bodies_match

        # Structural match
        baseline_keys = _top_level_keys(unwrapped_baseline)
        probe_keys = _top_level_keys(unwrapped_probe)
        structural_match = (
            baseline_keys is not None
            and probe_keys is not None
            and baseline_keys == probe_keys
        )
        comparison["structural_match"] = structural_match

        # Structured Owner Identifier Matching (preserving types, excluding bool)
        target_ids: Set[Any] = set()
        for v in owner_path_params.values():
            if v is not None and str(v).strip() and not isinstance(v, bool):
                target_ids.add(v)
                target_ids.add(str(v))
                try:
                    target_ids.add(int(v))
                except (ValueError, TypeError):
                    pass

        comparison["owner_identifiers_checked"] = [str(x) for x in target_ids]
        id_matches = find_exact_identifier_matches(raw_probe_body, target_ids)

        substantive_id_matches = [m for m in id_matches if not m["is_metadata"]]
        harmless_id_matches = [m for m in id_matches if m["is_metadata"]]

        comparison["owner_id_matches"] = substantive_id_matches
        comparison["harmless_metadata_matches"] = harmless_id_matches
        has_owner_id = len(substantive_id_matches) > 0
        comparison["owner_id_in_probe"] = has_owner_id

        # Matching protected resource fields
        matching_fields = extract_matching_resource_fields(
            unwrapped_baseline, unwrapped_probe, excluded_fields
        )
        comparison["matching_protected_fields"] = list(matching_fields.keys())
        has_matching_fields = len(matching_fields) > 0

        # Partial array leakage check
        array_leak, matching_records = check_array_resource_overlap(
            unwrapped_baseline, unwrapped_probe, target_ids, excluded_fields
        )
        comparison["partial_array_leak"] = array_leak
        comparison["leaked_array_elements_count"] = len(matching_records)

        # Evaluate attacker control
        if control_status is not None:
            comparison["control_verified"] = (control_status in {200, 201, 204})

        # Determine evidence signals
        suspected = False
        reason_parts: List[str] = []

        if array_leak:
            suspected = True
            reason_parts.append(f"probe response array contains {len(matching_records)} protected owner resource record(s)")

        if has_owner_id and has_substantive:
            suspected = True
            matched_keys = [f"{m['key']}={m['value']}" for m in substantive_id_matches]
            reason_parts.append(f"probe response contains exact owner identifier in resource fields: {matched_keys}")
        elif bodies_match and has_substantive and not require_owner_id_in_body:
            suspected = True
            reason_parts.append("probe response content matches owner baseline resource data")
        elif has_matching_fields and has_substantive and not require_owner_id_in_body:
            suspected = True
            reason_parts.append(f"probe response shares protected resource fields with owner baseline: {list(matching_fields.keys())}")

        if suspected and require_owner_id_in_body and not has_owner_id:
            suspected = False
            reason_parts.append("(downgraded: require_owner_id_in_body=True but no non-metadata owner ID found)")

        if suspected and require_structural_match and not structural_match:
            suspected = False
            reason_parts.append("(downgraded: structural match required but key sets differ)")

        # Final outcome determination with control reasoning
        if suspected:
            control_note = ""
            if comparison["control_verified"] is True:
                control_note = f" Attacker control verified access on attacker resource (HTTP {control_status})."
            elif comparison["control_verified"] is False:
                control_note = f" Note: Attacker control request failed (HTTP {control_status}), but cross-tenant probe definitively returned owner data."

            reason = (
                f"Cross-tenant probe returned HTTP {probe_status}. "
                f"Evidence indicates lack of object-level authorization (BOLA suspected): "
                f"{'; '.join(reason_parts)}.{control_note}"
            )
            return "SUSPECTED", reason, comparison

        # Inconclusive paths
        if has_owner_id and not has_substantive:
            reason = (
                f"Cross-tenant probe returned HTTP {probe_status} with matching owner identifier, "
                "but no protected resource data was exposed beyond the identifier itself. "
                "Assessment is inconclusive."
            )
        elif harmless_id_matches and not substantive_id_matches:
            reason = (
                f"Cross-tenant probe returned HTTP {probe_status}. Owner identifier appeared only "
                f"in harmless metadata fields ({[m['key'] for m in harmless_id_matches]}) without "
                "protected resource data exposure. Assessment is inconclusive."
            )
        elif comparison["control_verified"] is False:
            reason = (
                f"Cross-tenant probe returned HTTP {probe_status} without clear owner data, and "
                f"attacker control request failed (HTTP {control_status}). Assessment is inconclusive."
            )
        else:
            reason = (
                f"Cross-tenant probe returned HTTP {probe_status}, but response data did not "
                "match the owner object baseline. Assessment is inconclusive."
            )
        return "INCONCLUSIVE", reason, comparison

    # ---- Case 6: Other Status Code -----------------------------------------
    reason = (
        f"Cross-tenant probe returned unexpected HTTP {probe_status}. "
        "Cannot interpret authorization signal from this status code."
    )
    return "INCONCLUSIVE", reason, comparison


# ---------------------------------------------------------------------------
# Not-Executed Finding Helper
# ---------------------------------------------------------------------------

def _create_not_executed_finding(
    proposal: ProposedTest,
    reason: str,
    error: Optional[str] = None,
    execution_status: ExecutionStatus = ExecutionStatus.NOT_EXECUTED,
    evidence_notes: Optional[str] = None,
) -> Finding:
    """Helper to construct a standardized NOT_EXECUTED finding."""
    note_payload = {"reason": reason}
    if error:
        note_payload["error"] = error
    return Finding(
        test_id=proposal.test_id,
        endpoint=proposal.endpoint,
        evidence=Evidence(request={}, response={}, notes=evidence_notes or reason),
        severity=proposal.severity,
        status=FindingStatus.NOT_EXECUTED,
        execution_status=execution_status,
        assessment_outcome=AssessmentOutcome.INCONCLUSIVE,
        assessment_reason=reason,
        remediation=BOLA_REMEDIATION,
        notes=json.dumps(note_payload),
    )


# ---------------------------------------------------------------------------
# Enriched Step Log Builder
# ---------------------------------------------------------------------------

def _build_step_log(
    identity_id: str,
    req: PreparedRequest,
    resp: httpx.Response,
    sanitized_data: Dict[str, Any],
) -> Dict[str, Any]:
    """Build an enriched step log entry for a single request-response pair."""
    content_type = resp.headers.get("content-type", "")
    body = sanitized_data.get("body")
    return {
        "timestamp": _utc_now(),
        "identity": identity_id,
        "url": sanitize_url(req.url),
        "method": req.method,
        "status_code": resp.status_code,
        "content_type": content_type,
        "body_present": bool(body),
        "body_size_bytes": _body_size(body),
    }


# ---------------------------------------------------------------------------
# Main Differential BOLA Function
# ---------------------------------------------------------------------------

async def run_differential_bola(
    proposal: ProposedTest,
    config: ExecutionConfig,
    client: Optional[httpx.AsyncClient] = None,
) -> Finding:
    """Run a specification-driven differential BOLA test sequence for an approved proposal."""
    bola_remediation = BOLA_REMEDIATION

    # 1. Proposal Validation
    if proposal.status != TestStatus.APPROVED:
        raise PermissionError(f"Proposal {proposal.test_id} is not approved for execution")
    if proposal.test_type != "BOLA":
        raise ValueError(f"Proposal {proposal.test_id} has test_type '{proposal.test_type}'; expected 'BOLA'")

    has_attacker_control = bool(config.parameters.attacker_path_params)
    planned_requests = 3 if has_attacker_control else 2

    # 2. Request Budget Preflight Check
    if not config.budget.can_request(planned_requests):
        return _create_not_executed_finding(
            proposal,
            f"Execution budget exceeded before sending request: sequence requires {planned_requests} request(s), "
            f"but only {config.budget.remaining} remaining",
        )

    # 3. Configuration & Fixture Validation
    if not config.parameters.owner_path_params:
        return _create_not_executed_finding(
            proposal,
            f"Missing required path parameter fixture for endpoint '{proposal.endpoint.path}'",
        )
    if config.owner_identity is None:
        return _create_not_executed_finding(
            proposal,
            "Missing required owner_identity in execution configuration",
        )
    if config.attacker_identity is None:
        return _create_not_executed_finding(
            proposal,
            "Missing required attacker_identity in execution configuration",
        )

    # 4. Request Construction (Dry Run)
    try:
        baseline_req = build_request(
            proposal.endpoint,
            config,
            identity=config.owner_identity,
            path_param_override=config.parameters.owner_path_params,
        )
        probe_req = build_request(
            proposal.endpoint,
            config,
            identity=config.attacker_identity,
            path_param_override=config.parameters.owner_path_params,
        )
        control_req = None
        if has_attacker_control:
            control_req = build_request(
                proposal.endpoint,
                config,
                identity=config.attacker_identity,
                path_param_override=config.parameters.attacker_path_params,
            )
    except (ValueError, PermissionError) as exc:
        return _create_not_executed_finding(
            proposal,
            f"Request construction failed: {exc}",
            error=str(exc),
        )

    # 5. Execute Controlled Sequence
    step_logs: Dict[str, Any] = {}
    should_close_client = False
    http_client = client
    if http_client is None:
        http_client = httpx.AsyncClient(
            timeout=config.timeout_seconds,
            follow_redirects=False,
        )
        should_close_client = True

    control_resp = None
    control_data = None
    control_status = None

    try:
        # Step 1: Owner Baseline
        config.budget.record_request(1)
        try:
            baseline_resp = await http_client.request(
                method=baseline_req.method,
                url=baseline_req.url,
                headers=baseline_req.headers,
                params=baseline_req.params,
                cookies=baseline_req.cookies,
            )
            baseline_data = _sanitize_response_data(baseline_resp)
            step_logs["owner_baseline"] = _build_step_log(
                config.owner_identity.identity_id,
                baseline_req,
                baseline_resp,
                baseline_data,
            )
        except Exception as exc:
            safe_err = sanitize_error_message(str(exc))
            return _create_not_executed_finding(
                proposal,
                f"Owner baseline request failed: {safe_err}",
                error=safe_err,
                execution_status=ExecutionStatus.FAILED,
            )

        # Baseline must succeed (2xx) to validate authorized access baseline
        if baseline_resp.status_code not in {200, 201, 204}:
            baseline_reason = (
                f"Owner baseline returned status {baseline_resp.status_code}; "
                "cannot establish authorized baseline for differential testing"
            )
            return Finding(
                test_id=proposal.test_id,
                endpoint=proposal.endpoint,
                evidence=Evidence(
                    request=baseline_req.to_evidence_dict(),
                    response=baseline_data,
                    notes=f"Owner baseline returned non-2xx status code {baseline_resp.status_code}",
                ),
                severity=proposal.severity,
                status=FindingStatus.NOT_EXECUTED,
                execution_status=ExecutionStatus.COMPLETED,
                assessment_outcome=AssessmentOutcome.INCONCLUSIVE,
                assessment_reason=baseline_reason,
                remediation=bola_remediation,
                is_human_reviewed=False,
                notes=json.dumps({
                    "reason": baseline_reason,
                    "steps": sanitize_data(step_logs),
                }),
            )

        # Step 2: Cross-Tenant Probe
        config.budget.record_request(1)
        try:
            probe_resp = await http_client.request(
                method=probe_req.method,
                url=probe_req.url,
                headers=probe_req.headers,
                params=probe_req.params,
                cookies=probe_req.cookies,
            )
            probe_data = _sanitize_response_data(probe_resp)
            step_logs["cross_tenant_probe"] = _build_step_log(
                config.attacker_identity.identity_id,
                probe_req,
                probe_resp,
                probe_data,
            )
        except Exception as exc:
            safe_err = sanitize_error_message(str(exc))
            return Finding(
                test_id=proposal.test_id,
                endpoint=proposal.endpoint,
                evidence=Evidence(
                    request=probe_req.to_evidence_dict(),
                    response={},
                    notes=f"Cross-tenant probe request failed: {safe_err}",
                ),
                severity=proposal.severity,
                status=FindingStatus.NOT_EXECUTED,
                execution_status=ExecutionStatus.FAILED,
                assessment_outcome=AssessmentOutcome.INCONCLUSIVE,
                assessment_reason=f"Cross-tenant probe request failed: {safe_err}",
                remediation=bola_remediation,
                is_human_reviewed=False,
                notes=json.dumps({"error": safe_err, "steps": sanitize_data(step_logs)}),
            )

        # Step 3: Attacker Control (Conditional Request Sequencing)
        should_run_control = (
            has_attacker_control
            and control_req is not None
            and (probe_resp.status_code in {200, 201, 204, 401})
        )

        if should_run_control:
            config.budget.record_request(1)
            try:
                control_resp = await http_client.request(
                    method=control_req.method,
                    url=control_req.url,
                    headers=control_req.headers,
                    params=control_req.params,
                    cookies=control_req.cookies,
                )
                control_data = _sanitize_response_data(control_resp)
                control_status = control_resp.status_code
                step_logs["attacker_control"] = _build_step_log(
                    config.attacker_identity.identity_id,
                    control_req,
                    control_resp,
                    control_data,
                )
            except Exception as exc:
                safe_err = sanitize_error_message(str(exc))
                step_logs["attacker_control"] = {
                    "timestamp": _utc_now(),
                    "identity": config.attacker_identity.identity_id,
                    "url": sanitize_url(control_req.url),
                    "method": control_req.method,
                    "error": safe_err,
                }

    finally:
        if should_close_client:
            await http_client.aclose()

    # 6. Conservative Evidence Analysis
    outcome_str, reason_text, comparison_meta = compare_bola_responses(
        baseline_data=baseline_data,
        probe_data=probe_data,
        probe_status=probe_resp.status_code,
        owner_path_params=config.parameters.owner_path_params,
        baseline_status=baseline_resp.status_code,
        control_data=control_data,
        control_status=control_status,
    )

    probe_log = step_logs.get("cross_tenant_probe", {})
    baseline_log = step_logs.get("owner_baseline", {})
    probe_ct = probe_log.get("content_type") or ""
    baseline_ct = baseline_log.get("content_type") or ""
    if probe_ct and baseline_ct:
        comparison_meta["content_type_match"] = (probe_ct == baseline_ct)
    else:
        comparison_meta["content_type_match"] = None
    comparison_meta["requests_consumed"] = config.budget.current_count

    step_logs["comparison"] = {
        "outcome": outcome_str,
        "reason": reason_text,
        **comparison_meta,
    }

    evidence_notes_dict = {
        "outcome": outcome_str,
        "reason": reason_text,
        "comparison": comparison_meta,
        "steps": sanitize_data(step_logs),
    }
    evidence_notes_str = json.dumps(evidence_notes_dict)

    outcome_enum = AssessmentOutcome(outcome_str)

    if outcome_enum == AssessmentOutcome.SUSPECTED:
        finding_status = FindingStatus.SUSPECTED
        evidence_note_short = reason_text
    elif outcome_enum == AssessmentOutcome.ACCESS_DENIED:
        finding_status = FindingStatus.NOT_EXECUTED
        evidence_note_short = f"Access denied to cross-tenant probe (HTTP {probe_resp.status_code})"
    else:
        finding_status = FindingStatus.NOT_EXECUTED
        evidence_note_short = reason_text

    return Finding(
        test_id=proposal.test_id,
        endpoint=proposal.endpoint,
        evidence=Evidence(
            request=probe_req.to_evidence_dict(),
            response=probe_data,
            notes=evidence_note_short,
        ),
        severity=proposal.severity,
        status=finding_status,
        execution_status=ExecutionStatus.COMPLETED,
        assessment_outcome=outcome_enum,
        assessment_reason=reason_text,
        remediation=bola_remediation,
        is_human_reviewed=False,
        notes=evidence_notes_str,
    )
