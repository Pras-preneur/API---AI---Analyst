"""
ZYNORA AI - Hugging Face + PyTorch Inference Pipeline
======================================================
Loads the fine-tuned BERT model from disk and performs
Pydantic-validated inference on a SecurityFindingRecord.
"""

import os
import sys

os.environ["OPENBLAS_NUM_THREADS"] = "1"
os.environ["OMP_NUM_THREADS"] = "1"
os.environ["MKL_NUM_THREADS"] = "1"
os.environ["NUMEXPR_NUM_THREADS"] = "1"

import json
from pathlib import Path
from typing import Optional

import torch
from transformers import BertTokenizer, BertForSequenceClassification

from app.ml_torch.schemas import (
    SecurityFindingRecord,
    PredictionRequest,
    PredictionResponse,
    TrainingConfig,
)
from app.ml_torch.dataset import LABEL2ID, ID2LABEL

LABEL_NAMES = ["P1", "P2", "P3"]
DEFAULT_MODEL_DIR = "models/zynora_hf_pytorch"


class ZynoraHFPredictor:
    """
    Loads the fine-tuned Hugging Face BERT model and runs
    Pydantic-validated inference on API security findings.
    """

    def __init__(self, model_dir: str = DEFAULT_MODEL_DIR):
        self.model_dir = Path(model_dir)
        if not self.model_dir.exists():
            raise FileNotFoundError(
                f"Fine-tuned model not found at {model_dir}. "
                "Run app/ml_torch/train_hf.py first."
            )

        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

        # Load training metadata to recover config
        meta_path = self.model_dir / "training_metadata.json"
        with open(meta_path, "r", encoding="utf-8") as f:
            self.metadata = json.load(f)

        self.model_name = self.metadata["base_model"]
        self.max_length = self.metadata["training_config"]["max_length"]

        # Load tokenizer and model
        self.tokenizer = BertTokenizer.from_pretrained(str(self.model_dir))
        self.model = BertForSequenceClassification.from_pretrained(str(self.model_dir))
        self.model.to(self.device)
        self.model.eval()

        print(f"[ZynoraHFPredictor] Loaded model: {self.model_name}")
        print(f"[ZynoraHFPredictor] Device: {self.device}")

    def predict(self, request: PredictionRequest) -> PredictionResponse:
        """Run inference on a Pydantic-validated security finding."""
        text = request.finding.to_nlp_text()

        encoding = self.tokenizer(
            text,
            truncation=True,
            padding="max_length",
            max_length=self.max_length,
            return_tensors="pt",
        )

        input_ids      = encoding["input_ids"].to(self.device)
        attention_mask = encoding["attention_mask"].to(self.device)

        with torch.no_grad():
            outputs = self.model(input_ids=input_ids, attention_mask=attention_mask)

        logits = outputs.logits.squeeze(0)
        probs  = torch.softmax(logits, dim=-1)

        pred_id    = int(torch.argmax(probs).item())
        confidence = float(probs[pred_id].item())

        # Build Pydantic-validated response
        return PredictionResponse(
            recommended_priority=LABEL_NAMES[pred_id],
            confidence=round(confidence, 4),
            class_probabilities={
                LABEL_NAMES[i]: round(float(probs[i].item()), 4)
                for i in range(len(LABEL_NAMES))
            },
            raw_logits=[round(float(v), 4) for v in logits.cpu().numpy().tolist()],
            model_name=self.model_name,
            framework="PyTorch + Hugging Face Transformers",
            is_neural_prediction=True,
        )


# ─────────────────────────────────────────────────────────────────────────────
# Quick demo
# ─────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    predictor = ZynoraHFPredictor()

    test_cases = [
        SecurityFindingRecord(
            finding_type="bola",
            endpoint="/api/v1/accounts/{id}/statement",
            http_method="GET",
            evidence_confidence="high",
            exposure="internet_facing",
            data_sensitivity="sensitive",
            auth_required="true",
            exploitability="high",
            description="BOLA detected: user can access other tenants' account statements.",
        ),
        SecurityFindingRecord(
            finding_type="information_disclosure",
            endpoint="/debug/env",
            http_method="GET",
            evidence_confidence="low",
            exposure="internal",
            data_sensitivity="public",
            auth_required="false",
            exploitability="low",
            description="Internal debug endpoint exposed in production.",
        ),
        SecurityFindingRecord(
            finding_type="bfla",
            endpoint="/api/v1/admin/tenants/export",
            http_method="POST",
            evidence_confidence="medium",
            exposure="internet_facing",
            data_sensitivity="business",
            auth_required="true",
            exploitability="medium",
            description="Standard user can invoke admin export without RBAC check.",
        ),
    ]

    print("\n" + "="*60)
    print("  ZYNORA AI - HF Inference Demo")
    print("="*60)

    for i, finding in enumerate(test_cases, 1):
        req      = PredictionRequest(finding=finding)
        response = predictor.predict(req)
        print(f"\n  Test {i}: {finding.finding_type.upper()} on {finding.endpoint}")
        print(f"    Predicted Priority : {response.recommended_priority}")
        print(f"    Confidence         : {response.confidence:.2%}")
        print(f"    Class Probs        : {response.class_probabilities}")
        print(f"    Neural Prediction  : {response.is_neural_prediction}")
