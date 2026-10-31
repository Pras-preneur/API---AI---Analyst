
"""Train and evaluate the API Security Analyst priority model."""

import argparse
import json
from pathlib import Path

import joblib
import pandas as pd

from sklearn.compose import ColumnTransformer
from sklearn.ensemble import RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    f1_score,
)
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder

from app.ml.features import (
    FEATURE_COLUMNS,
    PRIORITY_LABELS,
    TARGET_COLUMN,
)


def build_model():
    """Create preprocessing and ML model as one pipeline."""

    categorical_pipeline = Pipeline(
        steps=[
            (
                "imputer",
                SimpleImputer(strategy="most_frequent"),
            ),
            (
                "encoder",
                OneHotEncoder(handle_unknown="ignore"),
            ),
        ]
    )

    preprocessing = ColumnTransformer(
        transformers=[
            (
                "categorical",
                categorical_pipeline,
                FEATURE_COLUMNS,
            )
        ]
    )

    classifier = RandomForestClassifier(
        n_estimators=200,
        class_weight="balanced",
        random_state=42,
        min_samples_leaf=2,
    )

    model = Pipeline(
        steps=[
            ("preprocessing", preprocessing),
            ("classifier", classifier),
        ]
    )

    return model


def load_dataset(csv_path: Path) -> pd.DataFrame:
    """Load and validate labeled training examples."""

    if not csv_path.exists():
        raise FileNotFoundError(
            f"Dataset not found: {csv_path}\n"
            "Create data/priority_training.csv first."
        )

    data = pd.read_csv(csv_path)

    required_columns = FEATURE_COLUMNS + [TARGET_COLUMN]
    missing_columns = [
        column
        for column in required_columns
        if column not in data.columns
    ]

    if missing_columns:
        raise ValueError(
            f"Dataset is missing columns: {missing_columns}"
        )

    data = data[required_columns].dropna(
        subset=[TARGET_COLUMN]
    )

    if len(data) < 20:
        raise ValueError(
            "At least 20 labeled rows are required to run "
            "this initial training pipeline. More data is "
            "strongly recommended for meaningful evaluation."
        )

    data[TARGET_COLUMN] = (
        data[TARGET_COLUMN]
        .astype(str)
        .str.strip()
        .str.upper()
    )

    invalid_labels = set(data[TARGET_COLUMN]) - set(
        PRIORITY_LABELS
    )

    if invalid_labels:
        raise ValueError(
            f"Invalid priority labels: {sorted(invalid_labels)}. "
            f"Use {PRIORITY_LABELS}."
        )

    class_counts = data[TARGET_COLUMN].value_counts()

    if len(class_counts) < 2 or class_counts.min() < 2:
        raise ValueError(
            "The dataset must contain at least two priority "
            "classes, with at least two examples per class."
        )

    return data


def train_model(
    dataset_path: Path,
    model_path: Path,
) -> dict:
    """Train, evaluate, and save the model."""

    data = load_dataset(dataset_path)

    X = (
        data[FEATURE_COLUMNS]
        .fillna("unknown")
        .astype(str)
    )

    y = data[TARGET_COLUMN]

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.25,
        random_state=42,
        stratify=y,
    )

    model = build_model()

    print("Training the Random Forest model...")
    model.fit(X_train, y_train)

    predictions = model.predict(X_test)

    report = classification_report(
        y_test,
        predictions,
        labels=PRIORITY_LABELS,
        output_dict=True,
        zero_division=0,
    )

    matrix = confusion_matrix(
        y_test,
        predictions,
        labels=PRIORITY_LABELS,
    )

    metrics = {
        "total_examples": len(data),
        "training_examples": len(X_train),
        "testing_examples": len(X_test),
        "macro_f1": float(
            f1_score(
                y_test,
                predictions,
                average="macro",
                zero_division=0,
            )
        ),
        "classification_report": report,
        "confusion_matrix_labels": PRIORITY_LABELS,
        "confusion_matrix": matrix.tolist(),
        "note": (
            "Exploratory results only. Performance depends on "
            "the quality and representativeness of labeled data."
        ),
    }

    model_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    joblib.dump(model, model_path)

    metrics_path = model_path.with_suffix(".metrics.json")

    metrics_path.write_text(
        json.dumps(metrics, indent=2),
        encoding="utf-8",
    )

    print("\nEvaluation results:")
    print(
        classification_report(
            y_test,
            predictions,
            labels=PRIORITY_LABELS,
            zero_division=0,
        )
    )

    print(f"Model saved to: {model_path}")
    print(f"Metrics saved to: {metrics_path}")

    return metrics


def main():
    parser = argparse.ArgumentParser(
        description="Train the API AI Analyst ML model."
    )

    parser.add_argument(
        "--data",
        type=Path,
        default=Path("data/priority_training.csv"),
    )

    parser.add_argument(
        "--output",
        type=Path,
        default=Path("models/priority_model.joblib"),
    )

    args = parser.parse_args()

    train_model(
        dataset_path=args.data,
        model_path=args.output,
    )


if __name__ == "__main__":
    main()
