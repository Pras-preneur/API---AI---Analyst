"""Proposal engine for generating deterministic security test suggestions.

This module provides a single public function ``generate_proposals`` that inspects a list of
:class:`app.parser.openapi_parser.EndpointModel` objects and returns a list of
:class:`app.models.ProposedTest` instances.

The heuristics are intentionally simple and deterministic – they do **not** claim that an
endpoint is vulnerable, only that a particular test *might* be relevant based on observable
characteristics (path parameters, request bodies, response schemas, etc.).
"""

from __future__ import annotations

from typing import List, Set

from ..parser.openapi_parser import EndpointModel, RequestBodyModel, MediaTypeModel, SchemaModel
from ..models import AuthTestType, ProposedTest, TestStatus

# ---------------------------------------------------------------------------
# Helper functions – each returns a ``ProposedTest`` or ``None`` if the rule does not apply.
# ---------------------------------------------------------------------------

def _has_path_parameter(endpoint: EndpointModel) -> bool:
    """Return True if the endpoint path contains a ``{parameter}`` placeholder."""
    return "{" in endpoint.path and "}" in endpoint.path


def _is_admin_endpoint(endpoint: EndpointModel) -> bool:
    """Very naive admin detection – looks for the word ``admin`` in the path or tags.

    In a real system this would be much richer (role‑based metadata, OpenAPI security
    scopes, etc.).
    """
    if "admin" in endpoint.path.lower():
        return True
    if endpoint.tags:
        return any("admin" in tag.lower() for tag in endpoint.tags)
    return False


def _has_mass_assignment_potential(endpoint: EndpointModel) -> bool:
    """Detect a request body that defines an object schema with named properties.

    If the schema contains an ``additionalProperties`` flag (or a non‑empty ``properties``
    mapping) we consider it a candidate for mass‑assignment testing.
    """
    if not endpoint.request_body:
        return False
    for media in endpoint.request_body.content.values():
        schema = media.schema
        if not schema:
            continue
        # ``additionalProperties`` may be a bool or a schema – presence is enough.
        if getattr(schema, "additionalProperties", None) is not None:
            return True
        if schema.properties:
            return True
    return False


def _has_excessive_data_exposure(endpoint: EndpointModel) -> bool:
    """Very simple heuristic – if *any* 200‑type response contains more than 5 properties.

    The threshold is arbitrary but deterministic for the test suite.
    """
    for response in endpoint.responses.values():
        if not response.content:
            continue
        for media in response.content.values():
            schema = media.schema
            if schema and schema.properties and len(schema.properties) > 5:
                return True
    return False


def _missing_authentication(endpoint: EndpointModel) -> bool:
    """If the OpenAPI operation does not declare any security requirements.

    ``security`` may be ``None`` (unspecified) or an empty list (explicitly no auth). Both are
    treated as *missing authentication* candidates.
    """
    return not endpoint.security


def _has_effective_security(endpoint: EndpointModel) -> bool:
    """Return True if the endpoint declares one or more effective security requirements.

    Endpoints with effective_security=None or effective_security=[] are excluded.
    """
    return bool(endpoint.effective_security and len(endpoint.effective_security) > 0)


# ---------------------------------------------------------------------------
# Authentication-Specific Proposal Generation
# ---------------------------------------------------------------------------

def generate_auth_proposals(endpoints: List[EndpointModel]) -> List[ProposedTest]:
    """Generate authentication-enforcement proposals for endpoints declaring security requirements.

    Generates AUTH_MISSING_CREDENTIALS proposals only for endpoints with non-empty effective_security.
    Endpoints with no security or explicit security: [] are excluded.
    """
    proposals: List[ProposedTest] = []
    seen: Set[str] = set()

    for ep in endpoints:
        if _has_effective_security(ep):
            key = f"{ep.method.upper()}:{ep.path}"
            if key not in seen:
                seen.add(key)
                proposals.append(
                    ProposedTest(
                        endpoint=ep,
                        test_type=AuthTestType.AUTH_MISSING_CREDENTIALS.value,
                        description=(
                            f"Evaluate authentication enforcement on `{ep.method.upper()} {ep.path}` by probing with "
                            "deliberately omitted credentials to verify unauthenticated access is strictly rejected."
                        ),
                        severity="High",
                        status=TestStatus.PROPOSED,
                    )
                )
    return proposals


# ---------------------------------------------------------------------------
# Main engine function
# ---------------------------------------------------------------------------

def generate_proposals(
    endpoints: List[EndpointModel],
    include_auth_tests: bool = False,
) -> List[ProposedTest]:
    """Generate a list of :class:`ProposedTest` objects from an endpoint inventory.

    The function is deterministic – given the same list of ``EndpointModel`` instances it
    will always return the same proposals in the same order.
    By default (``include_auth_tests=False``), preserves legacy proposal behavior for
    backward compatibility. When ``include_auth_tests=True``, also generates
    ``AUTH_MISSING_CREDENTIALS`` proposals for endpoints with non-empty effective_security.
    """
    proposals: List[ProposedTest] = []

    for ep in endpoints:
        # 1. BOLA / IDOR – path parameter presence
        if _has_path_parameter(ep):
            proposals.append(
                ProposedTest(
                    endpoint=ep,
                    test_type="BOLA",
                    description=f"Check for Broken Object Level Authorization on `{ep.path}`.",
                    severity="High",
                    status=TestStatus.PROPOSED,
                )
            )

        # 2. BFLA – admin‑ish endpoint
        if _is_admin_endpoint(ep):
            proposals.append(
                ProposedTest(
                    endpoint=ep,
                    test_type="BFLA",
                    description=f"Assess Broken Function Level Authorization for potential privileged operation at `{ep.path}`.",
                    severity="Critical",
                    status=TestStatus.PROPOSED,
                )
            )

        # 3. Excessive Data Exposure – response schema with many properties
        if _has_excessive_data_exposure(ep):
            proposals.append(
                ProposedTest(
                    endpoint=ep,
                    test_type="ExcessiveData",
                    description=f"Verify that `{ep.path}` does not unintentionally return overly detailed data.",
                    severity="Medium",
                    status=TestStatus.PROPOSED,
                )
            )

        # 4. Mass Assignment – request body with object properties or additionalProperties
        if _has_mass_assignment_potential(ep):
            proposals.append(
                ProposedTest(
                    endpoint=ep,
                    test_type="MassAssignment",
                    description=f"Test for mass-assignment vulnerabilities in the payload of `{ep.path}`.",
                    severity="Medium",
                    status=TestStatus.PROPOSED,
                )
            )

        # 5. Missing Authentication – no security metadata
        if _missing_authentication(ep):
            proposals.append(
                ProposedTest(
                    endpoint=ep,
                    test_type="MissingAuth",
                    description=f"Determine whether `{ep.path}` incorrectly allows unauthenticated access.",
                    severity="High",
                    status=TestStatus.PROPOSED,
                )
            )

    # 6. Authentication Enforcement – non-empty effective security requirements
    if include_auth_tests:
        proposals.extend(generate_auth_proposals(endpoints))

    return proposals

