"""Stage 6.1.2 — Final BOLA Detection Accuracy Regression Tests.

Verifies:
 1. Boolean True vs numeric owner ID 1 (no false match).
 2. Boolean False vs numeric owner ID 0 (no false match).
 3. Legitimate numeric ID match (owner ID 1 vs response {"id": 1, "data": ...}).
 4. Legitimate string ID match (owner ID "1" vs response {"id": "1", "data": ...}).
 5. String/numeric compatibility policy (owner ID 1 vs response {"id": "1", "data": ...}).
 6. Different records sharing role/status/country/tier do NOT trigger SUSPECTED.
 7. Same resource with different volatile fields produces SUSPECTED.
 8. Same generic fields but different resource-specific values produces INCONCLUSIVE.
 9. Matching identifier without protected resource data produces INCONCLUSIVE.
10. Nested objects containing genuine owner data trigger SUSPECTED.
11. Arrays with one genuinely matching resource among different records trigger SUSPECTED.
12. Arrays with only generic overlapping values produce INCONCLUSIVE.
13. Ambiguous evidence produces INCONCLUSIVE.
"""

import asyncio
import json
from typing import Any, Dict
import pytest

from app.security.differential_engine import (
    compare_bola_responses,
    find_exact_identifier_matches,
    has_substantive_resource_content,
    check_array_resource_overlap,
)


class TestBooleanIntegerIdentifierMatching:
    """Verifies that Python bool/int inheritance does not cause cross-type false matches."""

    def test_boolean_true_does_not_match_numeric_id_1(self):
        """Boolean True in payload must not match numeric owner ID 1."""
        matches = find_exact_identifier_matches(
            data={"active": True, "count": 10},
            target_values={1, "1"},
        )
        assert len(matches) == 0

    def test_boolean_false_does_not_match_numeric_id_0(self):
        """Boolean False in payload must not match numeric owner ID 0."""
        matches = find_exact_identifier_matches(
            data={"deleted": False, "archived": False},
            target_values={0, "0"},
        )
        assert len(matches) == 0

    def test_legitimate_numeric_id_matches(self):
        """Exact integer 1 in resource field matches target integer 1."""
        matches = find_exact_identifier_matches(
            data={"user_id": 1, "name": "Alice"},
            target_values={1},
        )
        assert len(matches) == 1
        assert matches[0]["key"] == "user_id"
        assert matches[0]["value"] == 1
        assert matches[0]["is_metadata"] is False

    def test_legitimate_string_id_matches(self):
        """Exact string '1' in resource field matches target string '1'."""
        matches = find_exact_identifier_matches(
            data={"user_id": "1", "name": "Alice"},
            target_values={"1"},
        )
        assert len(matches) == 1
        assert matches[0]["key"] == "user_id"
        assert matches[0]["value"] == "1"

    def test_string_numeric_compatibility_policy(self):
        """Integer target 1 matches string '1' in JSON, and vice-versa, without bool coercion."""
        # Int target against string in JSON
        matches1 = find_exact_identifier_matches(
            data={"id": "1"},
            target_values={1},
        )
        assert len(matches1) == 1
        assert matches1[0]["value"] == "1"

        # String target against int in JSON
        matches2 = find_exact_identifier_matches(
            data={"id": 1},
            target_values={"1"},
        )
        assert len(matches2) == 1
        assert matches2[0]["value"] == 1


class TestResourceFieldComparison:
    """Verifies that low-cardinality attributes do not cause false-positive exposure findings."""

    def test_different_records_sharing_common_attributes_is_inconclusive(self):
        """Two different users sharing role, status, country, and tier must yield INCONCLUSIVE."""
        baseline = {
            "body": {
                "id": "alice",
                "role": "user",
                "status": "active",
                "country": "US",
                "tier": "free",
                "email": "alice@corp.internal",
            },
            "status_code": 200,
        }
        probe = {
            "body": {
                "id": "bob",
                "role": "user",
                "status": "active",
                "country": "US",
                "tier": "free",
                "email": "bob@corp.internal",
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
        assert meta["bodies_match"] is False
        assert meta["owner_id_in_probe"] is False

    def test_same_resource_with_different_volatile_fields_is_suspected(self):
        """Same resource differing only in timestamps/request IDs must yield SUSPECTED."""
        baseline = {
            "body": {
                "id": "res-999",
                "document": "Financial Report Q3",
                "timestamp": "2026-10-30T10:00:00Z",
                "request_id": "req-111",
            },
            "status_code": 200,
        }
        probe = {
            "body": {
                "id": "res-999",
                "document": "Financial Report Q3",
                "timestamp": "2026-10-30T10:05:00Z",
                "request_id": "req-222",
            },
            "status_code": 200,
        }

        out, reason, meta = compare_bola_responses(
            baseline_data=baseline,
            probe_data=probe,
            probe_status=200,
            owner_path_params={"res_id": "res-999"},
            baseline_status=200,
        )

        assert out == "SUSPECTED"
        assert meta["bodies_match"] is True

    def test_same_generic_fields_different_resource_data_is_inconclusive(self):
        """Matching generic status and category but different resource values yields INCONCLUSIVE."""
        baseline = {
            "body": {"status": "active", "category": "finance", "account_num": "AC-111"},
            "status_code": 200,
        }
        probe = {
            "body": {"status": "active", "category": "finance", "account_num": "AC-999"},
            "status_code": 200,
        }

        out, reason, meta = compare_bola_responses(
            baseline_data=baseline,
            probe_data=probe,
            probe_status=200,
            owner_path_params={"acc_id": "AC-111"},
            baseline_status=200,
        )

        assert out == "INCONCLUSIVE"

    def test_matching_identifier_without_protected_resource_data_is_inconclusive(self):
        """A response echoing only the requested ID with no protected data yields INCONCLUSIVE."""
        baseline = {
            "body": {"user_id": "alice", "email": "alice@corp.internal", "balance": 5000},
            "status_code": 200,
        }
        # Probe echoes ID but exposes no protected content
        probe = {
            "body": {"user_id": "alice"},
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
        assert meta["owner_id_in_probe"] is True
        assert meta["has_substantive_data"] is False
        assert "no protected resource data was exposed" in reason.lower()

    def test_nested_objects_genuine_leak_is_suspected(self):
        """Nested structure containing owner identifier and substantive data yields SUSPECTED."""
        baseline = {
            "body": {
                "profile": {
                    "identity": {"user_id": "alice"},
                    "private_notes": "Confidential medical record",
                }
            },
            "status_code": 200,
        }
        probe = {
            "body": {
                "profile": {
                    "identity": {"user_id": "alice"},
                    "private_notes": "Confidential medical record",
                }
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

        assert out == "SUSPECTED"
        assert meta["bodies_match"] is True


class TestPartialArrayLeakage:
    """Verifies collection/array comparison and partial leakage detection."""

    def test_array_with_one_genuinely_matching_resource_is_suspected(self):
        """Multi-record collection containing one leaked owner record yields SUSPECTED."""
        baseline = {
            "body": {"doc_id": "doc-alice-1", "title": "Secret Tax 2025", "owner": "alice"},
            "status_code": 200,
        }
        probe = {
            "body": [
                {"doc_id": "doc-bob-99", "title": "Bob Public Notes", "owner": "bob"},
                {"doc_id": "doc-alice-1", "title": "Secret Tax 2025", "owner": "alice"},
                {"doc_id": "doc-charlie-3", "title": "Charlie Doc", "owner": "charlie"},
            ],
            "status_code": 200,
        }

        out, reason, meta = compare_bola_responses(
            baseline_data=baseline,
            probe_data=probe,
            probe_status=200,
            owner_path_params={"doc_id": "doc-alice-1"},
            baseline_status=200,
        )

        assert out == "SUSPECTED"
        assert meta["partial_array_leak"] is True
        assert meta["leaked_array_elements_count"] == 1
        assert "protected owner resource record(s)" in reason.lower()

    def test_arrays_with_only_generic_overlapping_values_is_inconclusive(self):
        """Arrays sharing only generic status/type values must yield INCONCLUSIVE."""
        baseline = {
            "body": [
                {"id": "doc-1", "status": "active", "type": "pdf", "owner": "alice"}
            ],
            "status_code": 200,
        }
        probe = {
            "body": [
                {"id": "doc-99", "status": "active", "type": "pdf", "owner": "bob"},
                {"id": "doc-100", "status": "active", "type": "pdf", "owner": "charlie"},
            ],
            "status_code": 200,
        }

        out, reason, meta = compare_bola_responses(
            baseline_data=baseline,
            probe_data=probe,
            probe_status=200,
            owner_path_params={"doc_id": "doc-1"},
            baseline_status=200,
        )

        assert out == "INCONCLUSIVE"
        assert meta["partial_array_leak"] is False

    def test_ambiguous_evidence_returns_inconclusive(self):
        """Response with ambiguous non-owner payload yields INCONCLUSIVE."""
        baseline = {
            "body": {"account_id": "acc-101", "details": "Confidential Account"},
            "status_code": 200,
        }
        probe = {
            "body": {"message": "Operation completed", "code": 0},
            "status_code": 200,
        }

        out, reason, meta = compare_bola_responses(
            baseline_data=baseline,
            probe_data=probe,
            probe_status=200,
            owner_path_params={"account_id": "acc-101"},
            baseline_status=200,
        )

        assert out == "INCONCLUSIVE"

