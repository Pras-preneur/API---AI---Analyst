"""PyTorch Dataset implementation for API Security Findings using Hugging Face Tokenizers."""

import os
from pathlib import Path
from typing import List, Dict, Tuple, Optional
import pandas as pd
import torch
from torch.utils.data import Dataset
from transformers import PreTrainedTokenizer

from app.ml_torch.schemas import SecurityFindingRecord

LABEL2ID = {"P1": 0, "P2": 1, "P3": 2}
ID2LABEL = {0: "P1", 1: "P2", 2: "P3"}


class SecurityFindingsDataset(Dataset):
    """PyTorch Dataset wrapping security finding records with Hugging Face tokenization."""

    def __init__(
        self,
        records: List[SecurityFindingRecord],
        tokenizer: PreTrainedTokenizer,
        max_length: int = 128,
        is_training: bool = True
    ):
        self.records = records
        self.tokenizer = tokenizer
        self.max_length = max_length
        self.is_training = is_training

    def __len__(self) -> int:
        return len(self.records)

    def __getitem__(self, idx: int) -> Dict[str, torch.Tensor]:
        record = self.records[idx]
        text = record.to_nlp_text()

        # Hugging Face tokenization
        encoding = self.tokenizer(
            text,
            truncation=True,
            padding="max_length",
            max_length=self.max_length,
            return_tensors="pt"
        )

        item = {
            "input_ids": encoding["input_ids"].squeeze(0),
            "attention_mask": encoding["attention_mask"].squeeze(0)
        }

        if self.is_training and record.priority_label:
            norm_label = record.priority_label.strip().upper()
            label_id = LABEL2ID.get(norm_label, 1)
            item["labels"] = torch.tensor(label_id, dtype=torch.long)

        return item


def load_and_validate_dataset(csv_path: str = "data/priority_training.csv") -> List[SecurityFindingRecord]:
    """Load security findings from disk, validating every record against Pydantic schema."""
    path = Path(csv_path)
    if not path.exists():
        raise FileNotFoundError(f"Dataset not found at {csv_path}")

    df = pd.read_csv(path)
    records = []

    for idx, row in df.iterrows():
        # Validate through Pydantic
        record = SecurityFindingRecord(
            finding_id=f"rec-{idx+1:03d}",
            finding_type=str(row.get("finding_type", "other")),
            evidence_confidence=str(row.get("evidence_confidence", "medium")),
            exposure=str(row.get("exposure", "internet_facing")),
            data_sensitivity=str(row.get("data_sensitivity", "business")),
            auth_required=str(row.get("auth_required", "false")),
            exploitability=str(row.get("exploitability", "medium")),
            priority_label=str(row.get("priority_label", "P2"))
        )
        records.append(record)

    return records
