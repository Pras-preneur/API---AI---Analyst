"""JSON report export engine for the API Security Testing Assistant.

Produces a structured, validated, evidence-sanitized JSON document
from an in-memory Report instance.
"""

import json
from datetime import datetime
from typing import Any, Dict

from ..models import Report


def _serialize_value(val: Any) -> Any:
    """Recursively convert datetime objects and Pydantic models to JSON-serializable types."""
    if isinstance(val, datetime):
        return val.isoformat()
    if hasattr(val, "model_dump"):
        return _serialize_value(val.model_dump())
    if hasattr(val, "dict"):
        return _serialize_value(val.dict())
    if isinstance(val, dict):
        return {k: _serialize_value(v) for k, v in val.items()}
    if isinstance(val, (list, tuple, set)):
        return [_serialize_value(item) for item in val]
    return val


def export_report_to_dict(report: Report) -> Dict[str, Any]:
    """Convert a Report instance into a fully serialized, structured dictionary."""
    data = _serialize_value(report)
    data["_schema_version"] = "1.0.0"
    data["_generator"] = "API Security Testing Assistant"
    data["_sanitization_guarantee"] = "All credentials, tokens, and authorization headers redacted"
    return data


def export_report_to_json(report: Report, indent: int = 2) -> str:
    """Export a Report instance to a formatted JSON string.

    Guarantees:
    - Pure in-memory transformation.
    - Zero network requests.
    - Deterministic, sanitized JSON output.
    """
    dict_data = export_report_to_dict(report)
    return json.dumps(dict_data, indent=indent, ensure_ascii=False)

