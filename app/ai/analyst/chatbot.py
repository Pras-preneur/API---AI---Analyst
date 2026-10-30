"""Coordinate ML triage, SLM reasoning, and optional LLM-based API security analysis."""

import json
from typing import Dict, Any

from app.ai.analyst.llm_client import (
    generate_llm_response,
    LLMClientError,
)
from app.ai.analyst.prompts import (
    SYSTEM_PROMPT,
    build_analysis_prompt,
)
from app.ai.ml.predict import predict_priority
from app.ai.slm.engine import slm_engine
from app.ai.config import has_llm_config


def analyze_finding(finding: dict) -> dict:
    """Analyze a finding without changing the scanner verdict.

    Pipeline:
    1. Extract features and predict ML priority recommendation (P1/P2/P3).
    2. Generate high-fidelity evidence-grounded analysis via SLM engine.
    3. If external LLM is configured and reachable, attempt defensive refinement.
       If LLM fails or is unconfigured, seamlessly use local SLM reasoning.
    4. Guarantee immutable scanner verdict (`scanner_verdict_changed=False`).
    """
    if not isinstance(finding, dict):
        raise TypeError("finding must be a dictionary.")

    priority_features = {
        "finding_type": finding.get("finding_type", "other"),
        "evidence_confidence": finding.get("evidence_confidence", "high"),
        "exposure": finding.get("exposure", "internet_facing"),
        "data_sensitivity": finding.get("data_sensitivity", "sensitive"),
        "auth_required": finding.get("auth_required", "true"),
        "exploitability": finding.get("exploitability", "high"),
    }

    # Step 1: Get ML priority recommendation.
    priority_result = predict_priority(priority_features)
    rec_priority = priority_result.get("recommended_priority", "P2")

    # Step 2: Generate concise security intelligence using local SLM engine.
    slm_analysis = slm_engine.summarize_finding(finding, rec_priority)

    # Step 3: Optional external LLM refinement if configured
    llm_analysis = slm_analysis
    if has_llm_config():
        try:
            user_prompt = build_analysis_prompt(finding, priority_result)
            raw_llm = generate_llm_response(SYSTEM_PROMPT, user_prompt, timeout=10.0)
            parsed = json.loads(raw_llm)
            if isinstance(parsed, dict) and "remediation_steps" in parsed:
                llm_analysis = {
                    **slm_analysis,
                    **parsed,
                    "slm_engine": "NVIDIA Nemotron + Zynora-SLM",
                }
        except Exception:
            # Clean fallback to deterministic SLM engine
            llm_analysis = slm_analysis

    # Step 4: Return unified result adhering to FindingAnalysisOutput contract
    return {
        "finding_id": str(finding.get("finding_id", "unknown")),
        "scanner_verdict": str(finding.get("scanner_verdict", "Suspected")),
        "priority": rec_priority,
        "priority_source": "ml_recommendation",
        "priority_probabilities": priority_result.get("class_probabilities", {}),
        "finding_summary": llm_analysis.get("finding_summary", slm_analysis["finding_summary"]),
        "evidence_assessment": llm_analysis.get("evidence_assessment", slm_analysis["evidence_assessment"]),
        "potential_impact": llm_analysis.get("potential_impact", slm_analysis["potential_impact"]),
        "priority_explanation": llm_analysis.get("priority_explanation", slm_analysis["priority_explanation"]),
        "remediation_steps": llm_analysis.get("remediation_steps", slm_analysis["remediation_steps"]),
        "validation_steps": llm_analysis.get("validation_steps", slm_analysis["validation_steps"]),
        "limitations": llm_analysis.get("limitations", slm_analysis["limitations"]),
        "scanner_verdict_changed": False,
        "is_model_recommendation": True,
        "slm_engine": llm_analysis.get("slm_engine", "Zynora-SLM-API-v2.0"),
        # Nested llm_analysis dictionary for backward-compatibility with UI components
        "llm_analysis": llm_analysis,
    }

