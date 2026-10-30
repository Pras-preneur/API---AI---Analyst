
"""Predict priority for API security findings."""

from pathlib import Path

import joblib
import pandas as pd

from app.ml.features import (
    FEATURE_COLUMNS,
    FEATURE_OPTIONS,
)

MODEL_PATH = Path("models/priority_model.joblib")


def predict_priority(features: dict) -> dict:
    """Return an ML-based priority recommendation."""

    missing = [
        column
        for column in FEATURE_COLUMNS
        if column not in features
    ]

    if missing:
        raise ValueError(
            f"Missing required features: {missing}"
        )

    for column in FEATURE_COLUMNS:
        value = str(features[column]).strip().lower()

        if value not in FEATURE_OPTIONS[column]:
            raise ValueError(
                f"Invalid value for {column}: {value}. "
                f"Allowed values: {FEATURE_OPTIONS[column]}"
            )

        features[column] = value

    if not MODEL_PATH.exists():
        raise FileNotFoundError(
            f"Model not found at {MODEL_PATH}. "
            "Train the model first."
        )

    model = joblib.load(MODEL_PATH)

    input_data = pd.DataFrame(
        [{column: features[column] for column in FEATURE_COLUMNS}],
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
