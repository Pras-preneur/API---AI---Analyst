import io
import json
import os
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.config import MAX_SPEC_SIZE

client = TestClient(app)

# Helper to build multipart files
def _file_payload(content: bytes, filename: str):
    return {
        "file": (filename, io.BytesIO(content), "application/octet-stream")
    }

def test_upload_yaml_success():
    yaml_path = Path(__file__).parents[1] / "sample_specs" / "demo_api.yaml"
    with yaml_path.open("rb") as f:
        content = f.read()
    response = client.post("/parse-openapi", files=_file_payload(content, "demo_api.yaml"))
    assert response.status_code == 200
    data = response.json()
    # Expect at least the known endpoints from demo spec
    paths_methods = {(e["path"], e["method"]) for e in data}
    expected = {
        ("/users", "get"),
        ("/users", "post"),
        ("/users/{user_id}", "get"),
        ("/users/{user_id}", "delete"),
        ("/profile", "patch"),
    }
    assert expected.issubset(paths_methods)

def test_upload_json_success(tmp_path):
    # Convert the sample YAML to JSON on the fly
    yaml_path = Path(__file__).parents[1] / "sample_specs" / "demo_api.yaml"
    import yaml
    spec = yaml.safe_load(yaml_path.read_text())
    json_bytes = json.dumps(spec).encode()
    response = client.post("/parse-openapi", files=_file_payload(json_bytes, "demo_api.json"))
    assert response.status_code == 200
    data = response.json()
    # Simple sanity check – at least one endpoint returned
    assert any(e["path"] == "/users" and e["method"] == "get" for e in data)

def test_invalid_extension():
    response = client.post("/parse-openapi", files=_file_payload(b"{}", "spec.txt"))
    assert response.status_code == 400
    assert "Unsupported file type" in response.json()["detail"]

def test_oversized_file():
    # Build a payload just over the size limit (MAX_SPEC_SIZE + 1)
    payload = b"a" * (MAX_SPEC_SIZE + 1)
    response = client.post("/parse-openapi", files=_file_payload(payload, "big.yaml"))
    assert response.status_code == 413
    assert "Specification file too large" in response.json()["detail"]

def test_malformed_yaml(tmp_path):
    bad_yaml = tmp_path / "bad.yaml"
    bad_yaml.write_text("key: [unclosed", encoding="utf-8")
    response = client.post("/parse-openapi", files=_file_payload(bad_yaml.read_bytes(), "bad.yaml"))
    assert response.status_code == 400
    # The parser raises a generic ValueError for malformed YAML
    assert isinstance(response.json()["detail"], str)
def test_upload_returns_session_id():
    yaml_path = Path(__file__).parents[1] / "sample_specs" / "demo_api.yaml"

    with yaml_path.open("rb") as f:
        content = f.read()

    response = client.post(
        "/parse-openapi",
        files=_file_payload(content, "demo_api.yaml")
    )

    assert response.status_code == 200

    session_id = response.headers.get("X-Session-ID")

    assert session_id is not None
    assert len(session_id) > 0

    # The response must remain a JSON array
    assert isinstance(response.json(), list)
def test_upload_session_works_with_propose_endpoint():
    yaml_path = Path(__file__).parents[1] / "sample_specs" / "demo_api.yaml"

    with yaml_path.open("rb") as f:
        content = f.read()

    # Upload the OpenAPI specification
    upload_response = client.post(
        "/parse-openapi",
        files=_file_payload(content, "demo_api.yaml")
    )

    assert upload_response.status_code == 200

    session_id = upload_response.headers.get("X-Session-ID")
    assert session_id is not None

    # Generate proposals using the same session
    propose_response = client.post(
        "/tests/propose",
        headers={"X-Session-ID": session_id},
        json=upload_response.json()
    )

    assert propose_response.status_code == 200

    proposals = propose_response.json()
    assert isinstance(proposals, list)
    assert len(proposals) > 0

    # Verify proposals are stored in the same session
    from app.models import session_store

    session = session_store.get_session(session_id)

    assert len(session.proposals) == len(proposals)


def test_upload_session_works_with_propose_endpoint_no_body():
    """Option A: /tests/propose uses the session's stored endpoint inventory without needing body."""
    from app.models import session_store
    yaml_path = Path(__file__).parents[1] / "sample_specs" / "demo_api.yaml"
    with yaml_path.open("rb") as f:
        content = f.read()

    upload_response = client.post(
        "/parse-openapi",
        files=_file_payload(content, "demo_api.yaml")
    )
    assert upload_response.status_code == 200
    session_id = upload_response.headers.get("X-Session-ID")
    assert session_id is not None

    # Call /tests/propose with NO body
    propose_response = client.post(
        "/tests/propose",
        headers={"X-Session-ID": session_id}
    )
    assert propose_response.status_code == 200
    proposals = propose_response.json()
    assert isinstance(proposals, list)
    assert len(proposals) == 5

    session = session_store.get_session(session_id)
    assert len(session.proposals) == 5


def test_propose_endpoint_without_body_on_empty_session_returns_400():
    from app.models import session_store
    session_id = session_store.create_session()

    propose_response = client.post(
        "/tests/propose",
        headers={"X-Session-ID": session_id}
    )
    assert propose_response.status_code == 400
    assert "previously uploaded to this session" in propose_response.json()["detail"]


def test_failed_upload_does_not_create_session():
    from app.models import session_store
    initial_count = len(session_store._sessions)

    response = client.post(
        "/parse-openapi",
        files=_file_payload(b"key: [broken", "bad.yaml")
    )
    assert response.status_code == 400
    # No orphan session should have been created
    assert len(session_store._sessions) == initial_count


def test_propose_endpoint_invalid_session_returns_404():
    import uuid
    response = client.post(
        "/tests/propose",
        headers={"X-Session-ID": str(uuid.uuid4())}
    )
    assert response.status_code == 404
    assert "Session not found" in response.json()["detail"]
