
"""Tests for the ML priority prediction module."""

import pytest

from app.ml.predict import predict_priority
from app.ml.features import FEATURE_COLUMNS


def valid_features():
    return {
        "finding_type": "bola",
        "evidence_confidence": "high",
        "exposure": "internet_facing",
        "data_sensitivity": "sensitive",
        "auth_required": "true",
        "exploitability": "high",
    }


def test_missing_feature_raises_error():
    features = valid_features()
    features.pop("finding_type")

    with pytest.raises(ValueError, match="Missing required features"):
        predict_priority(features)


def test_invalid_feature_value_raises_error():
    features = valid_features()
    features["finding_type"] = "not_a_real_finding"

    with pytest.raises(ValueError, match="Invalid value"):
        predict_priority(features)


def test_valid_features_have_all_required_columns():
    features = valid_features()

    assert all(column in features for column in FEATURE_COLUMNS)


def test_trained_model_returns_priority():
    from app.ml.predict import predict_priority

    features = valid_features()
    result = predict_priority(features)

    assert result["recommended_priority"] in ["P1", "P2", "P3"]
    assert result["is_model_recommendation"] is True
    assert result["scanner_verdict_changed"] is False
