"""End-to-end integration test covering the complete API Security Testing workflow:

OpenAPI Upload -> Session Creation -> Endpoint Inventory -> Proposal Generation ->
Human Approval -> Safe Execution -> Finding Verification -> Report Generation -> Report Retrieval.
"""

from pathlib import Path
from fastapi.testclient import TestClient

from app.main import app
from app.models import session_store, TestStatus, FindingStatus


def test_complete_end_to_end_assessment_workflow():
    client = TestClient(app)

    # 1. Health check
    res = client.get("/health")
    assert res.status_code == 200
    assert res.json() == {"status": "ok"}

    # 2. Upload OpenAPI specification
    yaml_path = Path(__file__).parents[1] / "sample_specs" / "demo_api.yaml"
    content = yaml_path.read_bytes()
    upload_res = client.post(
        "/parse-openapi",
        files={"file": ("demo_api.yaml", content, "application/octet-stream")}
    )
    assert upload_res.status_code == 200

    # 3. Verify session ID in header
    session_id = upload_res.headers.get("X-Session-ID")
    assert session_id is not None
    assert len(session_id) > 0

    # 4. Verify exactly five endpoint operations
    endpoints = upload_res.json()
    assert isinstance(endpoints, list)
    assert len(endpoints) == 5
    methods_paths = sorted([(e["method"].upper(), e["path"]) for e in endpoints])
    expected = [
        ("DELETE", "/users/{user_id}"),
        ("GET", "/users"),
        ("GET", "/users/{user_id}"),
        ("PATCH", "/profile"),
        ("POST", "/users"),
    ]
    assert methods_paths == expected

    # 5. Generate proposals using Option A (stored inventory, empty body)
    propose_res = client.post(
        "/tests/propose",
        headers={"X-Session-ID": session_id}
    )
    assert propose_res.status_code == 200
    proposals = propose_res.json()
    assert isinstance(proposals, list)
    assert len(proposals) == 5

    # 6. Verify proposals stored in session
    session = session_store.get_session(session_id)
    assert len(session.proposals) == 5
    for p in proposals:
        assert p["test_id"] in session.proposals

    # 7. Approve one specific proposal (human-in-the-loop)
    bola_prop = next(p for p in proposals if p["test_type"] == "BOLA" and p["endpoint"]["method"] == "get")
    target_test_id = bola_prop["test_id"]
    approve_res = client.post(
        f"/tests/{target_test_id}/approve",
        headers={"X-Session-ID": session_id}
    )
    assert approve_res.status_code == 200
    assert approve_res.json()["status"] == TestStatus.APPROVED.value

    # 8. Execute only the approved proposal against local mock API
    exec_res = client.post(
        "/tests/execute",
        headers={"X-Session-ID": session_id},
        json={"proposal_ids": [target_test_id], "target": "http://127.0.0.1:8001"}
    )
    assert exec_res.status_code == 200
    exec_findings = exec_res.json()
    assert len(exec_findings) == 1
    assert exec_findings[0]["test_id"] == target_test_id

    # 9. Verify findings for session
    findings_res = client.get("/findings", headers={"X-Session-ID": session_id})
    assert findings_res.status_code == 200
    findings = findings_res.json()
    assert len(findings) == 1
    assert findings[0]["test_id"] == target_test_id

    # 10. Generate security report
    report_res = client.post(
        "/reports",
        headers={"X-Session-ID": session_id},
        json={"target": "http://127.0.0.1:8001"}
    )
    assert report_res.status_code == 200
    report = report_res.json()
    report_id = report["report_id"]
    assert report["session_id"] == session_id
    assert report["severity_counts"]["high"] == 1
    assert len(report["finding_details"]) == 1
    assert report["finding_details"][0]["test_category"] == "BOLA"
    assert report["finding_details"][0]["endpoint_path"] == "/users/{user_id}"

    # 11. Retrieve report
    get_report_res = client.get(
        f"/reports/{report_id}",
        headers={"X-Session-ID": session_id}
    )
    assert get_report_res.status_code == 200
    assert get_report_res.json()["report_id"] == report_id

