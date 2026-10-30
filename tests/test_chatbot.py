
"""Tests for the chatbot analysis coordinator."""

from app.analyst.chatbot import analyze_finding


def test_analysis_returns_priority_without_changing_verdict():
    finding = {
        "finding_id": "finding-001",
        "scanner_verdict": "confirmed",
        "finding_type": "bola",
        "evidence_confidence": "high",
        "exposure": "internet_facing",
        "data_sensitivity": "sensitive",
        "auth_required": "true",
        "exploitability": "high",
    }

    result = analyze_finding(finding)

    assert result["priority"] in ["P1", "P2", "P3"]
    assert result["scanner_verdict"] == "confirmed"
    assert result["scanner_verdict_changed"] is False
    assert result["priority_source"] == "ml_recommendation"
