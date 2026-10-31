"""Feature definitions for the API Security Analyst ML model."""

FEATURE_COLUMNS = [
    "finding_type",
    "evidence_confidence",
    "exposure",
    "data_sensitivity",
    "auth_required",
    "exploitability",
]

TARGET_COLUMN = "priority_label"

PRIORITY_LABELS = ["P1", "P2", "P3"]

FEATURE_OPTIONS = {
    "finding_type": [
        "bola",
        "bfla",
        "mass_assignment",
        "information_disclosure",
        "excessive_data_exposure",
        "input_validation",
        "other",
    ],
    "evidence_confidence": ["low", "medium", "high"],
    "exposure": ["internet_facing", "internal", "unknown"],
    "data_sensitivity": [
        "public",
        "business",
        "personal",
        "sensitive",
        "unknown",
    ],
    "auth_required": ["true", "false", "unknown"],
    "exploitability": ["low", "medium", "high", "unknown"],
}

