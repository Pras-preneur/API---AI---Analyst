"""Tests for Phase 5 AI/ML and SLM Reasoning Integration in API Security Assistant."""

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.models import (
    session_store,
    Finding,
    FindingStatus,
    AssessmentOutcome,
    Evidence,
)
from app.parser.openapi_parser import EndpointModel, ResponseModel
from app.ai.ml.predict import predict_priority, get_model
from app.ai.ml.features import FEATURE_COLUMNS
from app.ai.slm.engine import slm_engine
from app.ai.slm.report_generator import report_generator
from app.ai.service import (
    finding_to_ml_features,
    finding_to_security_input,
    sanitize_text_evidence,
    analyze_security_finding_service,
    process_chat_service,
)
from app.ai.schemas import (
    SecurityFindingInput,
    ChatMessageRequest,
    ReportGenerationRequest,
)

client = TestClient(app)


# ============================================================================
# 1. ML Feature and Prediction Tests
# ============================================================================

def test_ml_model_loads_and_has_classes():
    model = get_model()
    assert model is not None
    assert set(model.classes_) == {"P1", "P2", "P3"}


def test_predict_priority_valid_p1_input():
    features = {
        "finding_type": "bola",
        "evidence_confidence": "high",
        "exposure": "internet_facing",
        "data_sensitivity": "sensitive",
        "auth_required": "true",
        "exploitability": "high",
    }
    result = predict_priority(features)
    assert result["recommended_priority"] in ["P1", "P2", "P3"]
    assert result["is_model_recommendation"] is True
    assert result["scanner_verdict_changed"] is False
    assert "class_probabilities" in result
    probs = result["class_probabilities"]
    assert sum(probs.values()) == pytest.approx(1.0, rel=1e-2)


def test_predict_priority_missing_feature_raises_error():
    features = {
        "finding_type": "bola",
        "evidence_confidence": "high",
        # missing exposure, data_sensitivity, auth_required, exploitability
    }
    with pytest.raises(ValueError, match="Missing required features"):
        predict_priority(features)


def test_predict_priority_invalid_value_raises_error():
    features = {
        "finding_type": "invalid_type_xyz",
        "evidence_confidence": "high",
        "exposure": "internet_facing",
        "data_sensitivity": "sensitive",
        "auth_required": "true",
        "exploitability": "high",
    }
    with pytest.raises(ValueError, match="Invalid value for finding_type"):
        predict_priority(features)


# ============================================================================
# 2. SLM Engine Reasoning & Intent Classification Tests
# ============================================================================

def test_slm_greeting_intent():
    res = slm_engine.process_chat("Hello there!")
    assert res["intent"] == "greeting"
    assert "ZYNORA AI" in res["message"]


def test_slm_vulnerability_explanation():
    res = slm_engine.process_chat("Can you explain Broken Object Level Authorization?")
    assert res["intent"] == "vulnerability_analysis"
    assert "BOLA" in res["message"] or "Broken Object Level Authorization" in res["message"]
    assert any(action["type"] == "show_test_proposals" for action in res["ui_actions"])


def test_slm_bola_vs_bfla():
    res = slm_engine.process_chat("What is the difference between BOLA and BFLA?")
    assert res["intent"] == "vulnerability_analysis"
    assert "API1:2023" in res["message"]
    assert "API5:2023" in res["message"]


def test_slm_mistake_detection_missing_endpoint():
    res = slm_engine.process_chat("analyze finding without endpoint")
    assert res["intent"] == "missing_information"
    assert "Incomplete Finding Metadata" in res["message"]


def test_slm_mistake_detection_malformed_json():
    res = slm_engine.process_chat("Here is a finding: {endpoint: '/api/v1', unquoted_key}")
    assert res["intent"] == "missing_information"
    assert "Malformed JSON" in res["message"]


def test_slm_report_request_selection():
    res = slm_engine.process_chat("I want to generate a report")
    assert res["intent"] == "report_request"
    assert res["requires_confirmation"] is True
    assert any(action["type"] == "show_report_options" for action in res["ui_actions"])


def test_slm_report_request_direct_pentest():
    res = slm_engine.process_chat("Generate pentest report")
    assert res["intent"] == "report_generation"
    assert res["report"]["format"] == "MARKDOWN"
    assert "Penetration Testing Report" in res["report"]["document"]["title"]


# ============================================================================
# 3. Document Generator Tests
# ============================================================================

def test_report_generator_catalog_complete():
    assert len(report_generator.REPORT_CATALOG) == 7
    ids = [r["id"] for r in report_generator.REPORT_CATALOG]
    assert "pentest_report" in ids
    assert "bug_bounty" in ids
    assert "executive_assessment" in ids
    assert "security_presentation" in ids
    assert "technical_assessment" in ids
    assert "remediation_report" in ids
    assert "complete_package" in ids


def test_report_generator_generates_pentest_21_sections():
    doc = report_generator.generate_report(
        report_type="pentest_report",
        spec_title="Test Gateway API",
        endpoints_count=4,
    )
    assert doc["report_type"] == "pentest_report"
    md = doc["markdown_content"]
    assert "## 1. Cover Page" in md
    assert "## 3. Executive Summary" in md
    assert "## 6. Testing Methodology" in md
    assert "## 12. Detailed Vulnerability Findings" in md
    assert "## 21. Appendices and References" in md


# ============================================================================
# 4. Backend Finding Model Mapping & Evidence Sanitization Tests
# ============================================================================

def test_evidence_sanitization_redacts_tokens_and_secrets():
    raw_text = 'Authorization: Bearer secret_token_xyz_12345678 and {"password": "supersecretpassword123"}'
    sanitized = sanitize_text_evidence(raw_text)
    assert "secret_token_xyz_12345678" not in sanitized
    assert "supersecretpassword123" not in sanitized
    assert "[REDACTED]" in sanitized


def test_finding_to_ml_features_and_security_input():
    evidence = Evidence(
        request={"method": "GET", "url": "http://127.0.0.1:8001/api/v1/accounts/123/statement"},
        response={"status_code": 200, "body": '{"account_id": "123", "balance": 5000}'},
        notes="Differential discrepancy observed on account path",
    )
    endpoint = EndpointModel(
        path="/api/v1/accounts/{id}/statement",
        method="get",
        summary="Get Account Statement",
        auth_required=True,
        responses={"200": ResponseModel(description="Success")},
    )
    finding = Finding(
        test_id="prop-1-bola",
        endpoint=endpoint,
        evidence=evidence,
        severity="Critical",
        status=FindingStatus.SUSPECTED,
        assessment_outcome=AssessmentOutcome.SUSPECTED,
        assessment_reason="Tenancy check omitted in query filter.",
    )

    features = finding_to_ml_features(finding)
    assert features["finding_type"] == "bola"
    assert features["evidence_confidence"] == "high"
    assert features["data_sensitivity"] == "sensitive"
    assert features["exploitability"] == "high"

    sec_input = finding_to_security_input(finding)
    assert sec_input.finding_id == finding.finding_id
    assert sec_input.finding_type == "bola"
    assert "200" in sec_input.evidence


# ============================================================================
# 5. REST API Endpoints Integration Tests
# ============================================================================

def test_api_v1_analyze_endpoint():
    payload = {
        "finding_id": "FIND-TEST-1",
        "scanner_verdict": "Vulnerability Confirmed",
        "finding_type": "bfla",
        "evidence_confidence": "high",
        "exposure": "internal",
        "data_sensitivity": "business",
        "auth_required": "true",
        "exploitability": "high",
        "endpoint": "/api/v1/admin/export",
        "http_method": "POST",
    }
    response = client.post("/api/v1/analyze", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["finding_id"] == "FIND-TEST-1"
    assert data["scanner_verdict"] == "Vulnerability Confirmed"
    assert data["priority"] in ["P1", "P2", "P3"]
    assert data["is_model_recommendation"] is True
    assert data["scanner_verdict_changed"] is False
    assert len(data["remediation_steps"]) > 0
    assert len(data["validation_steps"]) > 0


def test_api_v1_chat_endpoint():
    payload = {
        "message": "What is mass assignment?",
    }
    response = client.post("/api/v1/chat", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["intent"] == "vulnerability_analysis"
    assert "Mass Assignment" in data["message"]
    assert data["reply"] == data["message"]


def test_api_v1_reports_generate_endpoint():
    payload = {
        "report_type": "security_presentation",
        "spec_title": "FinTech Payments API",
        "endpoints_count": 6,
    }
    response = client.post("/api/v1/reports/generate", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert "report" in data
    assert data["report"]["report_type"] == "security_presentation"
    assert len(data["report"]["slides"]) >= 4


def test_session_finding_analyze_endpoint():
    session_id = session_store.create_session()
    endpoint = EndpointModel(
        path="/api/v1/users/{id}/financial-profile",
        method="get",
        summary="User Financial Profile",
        auth_required=True,
        responses={"200": ResponseModel(description="Success")},
    )
    evidence = Evidence(
        request={"method": "GET", "url": "http://127.0.0.1:8001/api/v1/users/99/financial-profile"},
        response={"status_code": 200, "body": '{"ssn": "123-45-6789"}'},
        notes="Cross-tenant access verified with User B token",
    )
    finding = Finding(
        test_id="prop-test-bola",
        endpoint=endpoint,
        evidence=evidence,
        severity="Critical",
        status=FindingStatus.SUSPECTED,
        assessment_outcome=AssessmentOutcome.SUSPECTED,
        assessment_reason="Cross-tenant profile query succeeded with 200 OK.",
    )
    session_store.add_finding(session_id, finding)

    response = client.post(
        f"/findings/{finding.finding_id}/analyze",
        headers={"X-Session-ID": session_id},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["finding_id"] == finding.finding_id
    assert data["priority"] in ["P1", "P2", "P3"]
    assert data["scanner_verdict_changed"] is False

    # Verify that the finding in session store was NOT modified to CONFIRMED
    persisted_finding = session_store.get_finding(session_id, finding.finding_id)
    assert persisted_finding.status == FindingStatus.SUSPECTED
    assert persisted_finding.assessment_outcome == AssessmentOutcome.SUSPECTED
    assert persisted_finding.is_human_reviewed is False
