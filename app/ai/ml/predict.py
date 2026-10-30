"""Predict priority for API security findings using the trained Random Forest pipeline."""

from pathlib import Path
from typing import Optional, Dict, Any
import joblib
import pandas as pd

from app.ai.ml.features import (
    FEATURE_COLUMNS,
    FEATURE_OPTIONS,
)
from app.ai.config import MODEL_PATH

_CACHED_MODEL = None


def get_model():
    """Retrieve or load the trained model pipeline."""
    global _CACHED_MODEL
    if _CACHED_MODEL is not None:
        return _CACHED_MODEL

    candidates = [
        MODEL_PATH,
        Path("app/ai/models/priority_model.joblib"),
        Path("models/priority_model.joblib"),
        Path(__file__).resolve().parent.parent / "models" / "priority_model.joblib",
        Path("D:/KLE/APITESTING/PENTEST/API---AI---Analyst/models/priority_model.joblib"),
    ]

    for p in candidates:
        if p.exists():
            _CACHED_MODEL = joblib.load(p)
            return _CACHED_MODEL

    raise FileNotFoundError(
        f"Model not found at {MODEL_PATH} or alternative candidate locations. "
        "Ensure priority_model.joblib is present."
    )


def predict_priority(features: dict) -> dict:
    """Return an ML-based priority recommendation.

    Guarantee:
    - Never modifies or overrides scanner verdict.
    - Always sets `is_model_recommendation=True` and `scanner_verdict_changed=False`.
    """
    missing = [
        column
        for column in FEATURE_COLUMNS
        if column not in features
    ]

    if missing:
        raise ValueError(
            f"Missing required features: {missing}"
        )

    clean_features = {}
    for column in FEATURE_COLUMNS:
        val = features[column]
        # Treat None or empty string as "unknown" if valid option, else fallback
        if val is None or str(val).strip() == "":
            val = "unknown" if "unknown" in FEATURE_OPTIONS[column] else "other" if "other" in FEATURE_OPTIONS[column] else "medium"

        value = str(val).strip().lower()

        if value not in FEATURE_OPTIONS[column]:
            raise ValueError(
                f"Invalid value for {column}: {value}. "
                f"Allowed values: {FEATURE_OPTIONS[column]}"
            )

        clean_features[column] = value

    model = get_model()

    input_data = pd.DataFrame(
        [{column: clean_features[column] for column in FEATURE_COLUMNS}],
        columns=FEATURE_COLUMNS,
    )

    prediction = model.predict(input_data)[0]

    result = {
        "recommended_priority": str(prediction),
        "is_model_recommendation": True,
        "scanner_verdict_changed": False,
    }

    if hasattr(model, "predict_proba"):
        probabilities = model.predict_proba(input_data)[0]

        result["class_probabilities"] = {
            str(label): round(float(probability), 4)
            for label, probability in zip(
                model.classes_,
                probabilities,
            )
        }

    return result

