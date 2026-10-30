"""FastAPI entry point for the ZYNORA AI API Security Analyst."""

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
import os

os.environ.setdefault("OPENBLAS_NUM_THREADS", "1")
os.environ.setdefault("OMP_NUM_THREADS", "1")

from pydantic import BaseModel, Field
from typing import Dict, Any, List, Optional

from app.analyst.chatbot import analyze_finding
from app.slm.engine import slm_engine
from app.slm.report_generator import report_generator
from app.schemas import (
    SecurityFindingInput,
    ChatMessageRequest,
    SLMStructuredResponse,
)


app = FastAPI(
    title="ZYNORA AI - API Security Analyst",
    description="Intelligent API security analysis and penetration testing workspace powered by SLM and ML.",
    version="2.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
def root():
    return {
        "platform": "ZYNORA AI",
        "product": "API Security Analysis & Penetration Testing Workspace",
        "status": "healthy",
        "version": "2.0.0",
        "slm_engine": "Zynora-SLM-API-v2.0"
    }


@app.get("/health")
def health_check():
    return {
        "status": "healthy",
        "slm_engine": "online",
        "ml_model": "loaded"
    }


@app.post("/api/v1/analyze")
def analyze_security_finding(finding: SecurityFindingInput):
    """Analyze a scanner finding using ML and the configured SLM."""
    try:
        return analyze_finding(finding.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except FileNotFoundError as exc:
        raise HTTPException(
            status_code=503,
            detail="ML model is not available. Train the model first.",
        ) from exc
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=f"An unexpected analysis error occurred: {str(exc)}",
        ) from None


@app.post("/api/v1/chat")
def chat_with_slm(req: ChatMessageRequest):
    """Conversational security copilot powered by local specialized ZYNORA SLM.
    
    Returns both backward-compatible string `reply` and full validated `structured` contract.
    """
    structured_data = slm_engine.process_chat(req.message, req.context)
    
    return {
        "reply": structured_data["message"],
        "intent": structured_data["intent"],
        "conversation_state": structured_data["conversation_state"],
        "ui_actions": structured_data.get("ui_actions", []),
        "report": structured_data.get("report"),
        "requires_confirmation": structured_data.get("requires_confirmation", False),
        "engine": "Zynora-SLM-API-v2.0",
        "structured": structured_data
    }


class ReportGenerateRequest(BaseModel):
    report_type: str = Field(..., description="ID from report catalog (e.g. pentest_report, bug_bounty, executive_assessment)")
    spec_title: str = "FinTech Core Banking Gateway API"
    endpoints_count: int = 5
    findings: Optional[List[Dict[str, Any]]] = None
    context: Optional[Dict[str, Any]] = None


@app.get("/api/v1/reports/catalog")
def get_report_catalog():
    """Retrieve catalog of available security documentation formats."""
    return {"catalog": report_generator.REPORT_CATALOG}


@app.post("/api/v1/reports/generate")
def generate_report_endpoint(req: ReportGenerateRequest):
    """Compile and return an audit-grade security documentation dossier."""
    try:
        report = report_generator.generate_report(
            report_type=req.report_type,
            spec_title=req.spec_title,
            endpoints_count=req.endpoints_count,
            findings=req.findings,
            context=req.context
        )
        return {"status": "success", "report": report}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to generate report: {str(exc)}")
