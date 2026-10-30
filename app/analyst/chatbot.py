
"""Coordinate ML triage and LLM-based API security analysis."""

import json

from app.analyst.llm_client import (
    generate_llm_response,
    LLMClientError,
)
from app.analyst.prompts import (
    SYSTEM_PROMPT,
    build_analysis_prompt,
)
from app.ml.predict import predict_priority


def analyze_finding(finding: dict) -> dict:
    """Analyze a finding without changing the scanner verdict."""

    if not isinstance(finding, dict):
        raise TypeError("finding must be a dictionary.")

    priority_features = {
        "finding_type": finding.get("finding_type"),
        "evidence_confidence": finding.get("evidence_confidence"),
        "exposure": finding.get("exposure"),
        "data_sensitivity": finding.get("data_sensitivity"),
        "auth_required": finding.get("auth_required"),
        "exploitability": finding.get("exploitability"),
    }

    # Step 1: Get ML priority recommendation.
    priority_result = predict_priority(priority_features)

    # Step 2: Generate concise security intelligence using local SLM engine.
    try:
        from app.slm.engine import slm_engine
        llm_analysis = slm_engine.summarize_finding(
            finding, 
            priority_result["recommended_priority"]
        )
    except Exception as slm_exc:
        # Fallback to prompt client if available
        try:
            user_prompt = build_analysis_prompt(finding, priority_result)
            llm_response = generate_llm_response(SYSTEM_PROMPT, user_prompt)
            llm_analysis = json.loads(llm_response)
        except Exception as exc:
            llm_analysis = {
                "error": "Analysis could not be completed.",
                "details": str(exc),
            }

    # Step 4: Return both results separately.
    return {
        "finding_id": finding.get("finding_id"),
        "scanner_verdict": finding.get("scanner_verdict"),
        "priority": priority_result["recommended_priority"],
        "priority_source": "ml_recommendation",
        "priority_probabilities": priority_result.get(
            "class_probabilities", {}
        ),
        "llm_analysis": llm_analysis,
        "scanner_verdict_changed": False,
    }
