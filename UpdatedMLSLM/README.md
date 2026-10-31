# Updated ML and SLM Modules — ZYNORA AI API Analyst

This directory consolidates all Machine Learning (ML) and Small Language Model (SLM) components of the **ZYNORA AI API Security Analyst** project, organized across the three evolutionary stages of the AI system:

---

## Directory Structure

```
UpdatedMLSLM/
├── README.md
├── datasets/
│   ├── priority_training.csv       # Ground truth priority training dataset (25 findings)
│   ├── train.jsonl                 # JSONL security prompt-response training pairs
│   └── eval.jsonl                  # JSONL evaluation pairs
├── classic_ml/                     # 1. Classical Scikit-Learn Random Forest Pipeline
│   ├── app/
│   │   ├── train.py                # Script to train Random Forest classifier
│   │   ├── features.py             # Feature encoding and preprocessing
│   │   ├── predict.py              # Classical inference runner
│   │   └── evaluate.py
│   └── models/
│       ├── priority_model.joblib   # Trained Random Forest model (208 KB)
│       └── priority_model.metrics.json
├── previous_slm/                   # 2. Previous Rule-Based / Simulated SLM
│   ├── app/
│   │   ├── engine.py               # Rule-based heuristic generation engine (60 KB)
│   │   ├── report_generator.py     # Deterministic markdown & evidence reporter
│   │   ├── train_slm.py            # Simulated training routine
│   │   └── evaluate_slm.py         # Heuristic evaluator
│   └── models/
│       ├── adapter_config.json     # LoRA adapter metadata configuration
│       └── slm_eval_metrics.json   # Simulation metrics
└── new_hf_pytorch/                 # 3. Real PyTorch + Hugging Face Transformers Fine-Tuned Model
    ├── app/
    │   ├── __init__.py
    │   ├── schemas.py              # Pydantic v2 schemas & contract validation
    │   ├── dataset.py              # PyTorch Dataset + Tokenization + Augmentation
    │   ├── train_hf.py             # Full PyTorch fine-tuning loop (AdamW + Warmup)
    │   └── predict_hf.py           # Neural inference pipeline with Pydantic output
    └── models/
        ├── model.safetensors       # Real fine-tuned BERT weights (17.5 MB, 4.38M params)
        ├── config.json             # Transformer config & label mappings (P1, P2, P3)
        ├── tokenizer.json          # Hugging Face WordPiece tokenizer
        ├── tokenizer_config.json
        └── training_metadata.json  # Loss curves, hyperparams, & Pydantic eval
```

---

## 1. Classical ML (`classic_ml/`)
- **Framework**: `scikit-learn` (`RandomForestClassifier`)
- **Input**: Tabular categorical features (`finding_type`, `exposure`, `data_sensitivity`, `auth_required`, `exploitability`).
- **Output**: Security priority classification (`P1`, `P2`, `P3`).
- **Model artifact**: `priority_model.joblib` (208 KB).

---

## 2. Previous SLM (`previous_slm/`)
- **Nature**: Heuristic rule-based synthesis engine with simulated adapter metadata (`adapter_config.json`).
- **Function**: Generated remediation plans, executive summaries, and severity ratings using structured string templates and domain dictionaries.

---

## 3. New PyTorch + Hugging Face Model (`new_hf_pytorch/`)
- **Framework**: `PyTorch` (`2.15.0`) + `Hugging Face Transformers` + `Pydantic` v2.
- **Base Architecture**: `prajjwal1/bert-tiny` (4,386,307 trainable parameters).
- **Validation**: Strict Pydantic contracts on all inputs (`SecurityFindingRecord`, `TrainingConfig`) and outputs (`PredictionResponse`, `EvaluationMetrics`).
- **Trained Weights**: `model.safetensors` (17.5 MB) fine-tuned on the project's security findings dataset.
- **Inference**: Produces predicted priority (`P1`, `P2`, `P3`), confidence score, and normalized softmax probabilities over all priority classes.
