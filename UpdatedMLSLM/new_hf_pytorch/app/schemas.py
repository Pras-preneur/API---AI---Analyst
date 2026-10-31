"""Pydantic schemas for PyTorch + Hugging Face API Security Model."""

from typing import Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field, field_validator


class SecurityFindingRecord(BaseModel):
    """Pydantic schema representing an individual API security finding for training/inference."""

    model_config = ConfigDict(extra="ignore")

    finding_id: Optional[str] = Field(default=None, description="Unique identifier for the finding")
    finding_type: str = Field(..., description="Vulnerability category (e.g. bola, bfla, mass_assignment)")
    endpoint: Optional[str] = Field(default="/api/v1/endpoint", description="API endpoint path")
    http_method: Optional[str] = Field(default="GET", description="HTTP method evaluated")
    evidence_confidence: str = Field(default="medium", description="Confidence level of empirical evidence (low/medium/high)")
    exposure: str = Field(default="internet_facing", description="Network exposure (internet_facing/internal)")
    data_sensitivity: str = Field(default="business", description="Classification of underlying data (public/business/personal/sensitive)")
    auth_required: str = Field(default="false", description="Whether authentication was required (true/false)")
    exploitability: str = Field(default="medium", description="Observed exploitability rating (low/medium/high)")
    description: Optional[str] = Field(default="", description="Detailed description of the vulnerability")
    evidence: Optional[str] = Field(default="", description="Sanitized empirical evidence trace")
    priority_label: Optional[str] = Field(default=None, description="Ground truth priority label (P1, P2, P3)")

    @field_validator("finding_type", "evidence_confidence", "exposure", "data_sensitivity", "exploitability", mode="before")
    @classmethod
    def normalize_strings(cls, v: str) -> str:
        if isinstance(v, str):
            return v.strip().lower()
        return str(v).lower()

    def to_nlp_text(self) -> str:
        """Serialize structured security finding into rich textual context for Hugging Face tokenizer."""
        text_parts = [
            f"Vulnerability Type: {self.finding_type.upper()}.",
            f"Endpoint: {self.http_method.upper()} {self.endpoint}.",
            f"Network Exposure: {self.exposure.replace('_', ' ')}.",
            f"Data Sensitivity: {self.data_sensitivity}.",
            f"Evidence Confidence: {self.evidence_confidence}.",
            f"Authentication Required: {self.auth_required}.",
            f"Exploitability: {self.exploitability}."
        ]
        if self.description:
            text_parts.append(f"Description: {self.description}")
        if self.evidence:
            text_parts.append(f"Observed Evidence: {self.evidence}")
        return " ".join(text_parts)


class TrainingConfig(BaseModel):
    """Pydantic model validating training configuration and hyperparameters."""

    model_config = ConfigDict(extra="forbid")

    hf_base_model: str = Field(default="prajjwal1/bert-tiny", description="Hugging Face model identifier")
    num_labels: int = Field(default=3, description="Number of priority classification classes (P1, P2, P3)")
    num_epochs: int = Field(default=5, ge=1, le=50, description="Total training epochs")
    batch_size: int = Field(default=4, ge=1, le=64, description="Training batch size")
    learning_rate: float = Field(default=3e-5, gt=0.0, le=1e-2, description="Learning rate for AdamW")
    max_length: int = Field(default=128, ge=32, le=512, description="Maximum sequence length for tokenization")
    weight_decay: float = Field(default=0.01, ge=0.0, description="Weight decay for regularization")
    output_dir: str = Field(default="models/zynora_hf_pytorch", description="Directory to export fine-tuned weights")
    seed: int = Field(default=42, description="Random seed for reproducibility")


class PredictionRequest(BaseModel):
    """Pydantic schema for single-finding or batch inference request."""

    model_config = ConfigDict(extra="ignore")

    finding: SecurityFindingRecord


class PredictionResponse(BaseModel):
    """Pydantic schema returned by the PyTorch + Hugging Face model inference pipeline."""

    model_config = ConfigDict(extra="forbid")

    recommended_priority: str = Field(..., description="Predicted risk tier (P1, P2, or P3)")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Confidence score for predicted class")
    class_probabilities: Dict[str, float] = Field(..., description="Softmax probability distribution across P1, P2, P3")
    raw_logits: List[float] = Field(..., description="Raw output logits directly from the PyTorch neural network")
    model_name: str = Field(..., description="Hugging Face model identity")
    framework: str = Field(default="PyTorch + Hugging Face Transformers", description="Underlying deep learning framework")
    is_neural_prediction: bool = Field(default=True, description="Confirms prediction originated from a deep learning model")


class EvaluationMetrics(BaseModel):
    """Pydantic schema validating model evaluation metrics."""

    model_config = ConfigDict(extra="ignore")

    accuracy: float
    macro_f1: float
    per_class_f1: Dict[str, float]
    total_samples: int
    eval_loss: float
