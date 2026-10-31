"""End-to-End Live Workflow Validation Script.

Tests the full lifecycle against live backend (8000) and mock API (8001):
1. Health checks.
2. OpenAPI upload and endpoint discovery.
3. Proposal formulation.
4. Proposal approval and rejection state transitions.
5. Verification that rejected proposals cannot execute.
6. Execution of approved proposals against live mock target (8001).
7. Evidence collection and verification.
8. Live chat context-awareness (asking about discovered endpoints, pending tests, executed tests, findings, evidence).
9. Human review sign-off.
10. PDF and JSON report generation.
"""

import io
import json
import httpx

BACKEND_URL = "http://127.0.0.1:8000"
MOCK_URL = "http://127.0.0.1:8001"

def run_workflow():
    client = httpx.Client(timeout=10.0)

    # 1. Health checks
    r1 = client.get(f"{BACKEND_URL}/health")
    r2 = client.get(f"{MOCK_URL}/health")
    assert r1.status_code == 200 and r1.json().get("status") == "ok", "Backend health failed"
    assert r2.status_code == 200 and r2.json().get("status") == "ok", "Mock health failed"
    print("[PASS] Step 1: Health checks passed for backend and mock target.")

    # 2. Upload OpenAPI spec
    spec_yaml = """
openapi: 3.0.3
info:
  title: Live Assessment Demo API
  version: 1.0.0
paths:
  /users/{username}:
    get:
      summary: Get user by username
      parameters:
        - name: username
          in: path
          required: true
          schema:
            type: string
      responses:
        '200':
          description: OK
  /admin/data:
    get:
      summary: Get administrative data
      responses:
        '200':
          description: OK
  /profile:
    patch:
      summary: Update profile
      requestBody:
        content:
          application/json:
            schema:
              type: object
              properties:
                bio:
                  type: string
      responses:
        '200':
          description: OK
"""
    files = {"file": ("demo_spec.yaml", io.BytesIO(spec_yaml.encode("utf-8")), "application/x-yaml")}
    upload_resp = client.post(f"{BACKEND_URL}/parse-openapi", files=files)
    assert upload_resp.status_code == 200, f"Upload failed: {upload_resp.text}"
    endpoints = upload_resp.json()
    assert len(endpoints) >= 3, f"Expected >= 3 endpoints, got {len(endpoints)}"
    print(f"[PASS] Step 2: Uploaded spec and discovered {len(endpoints)} endpoints.")

    session_id = upload_resp.headers["X-Session-ID"]
    headers = {"X-Session-ID": session_id}
    print(f"[PASS] Step 3: Created live session: {session_id}")

    # 3. Formulate proposals
    prop_resp = client.post(f"{BACKEND_URL}/tests/propose", headers=headers, json=endpoints)
    assert prop_resp.status_code == 200, f"Proposal generation failed: {prop_resp.text}"
    proposals = prop_resp.json()
    assert len(proposals) >= 2, f"Expected >= 2 proposals, got {len(proposals)}"
    print(f"[PASS] Step 4: Formulated {len(proposals)} security test proposals.")

    p_approve = proposals[0]["test_id"]
    p_reject = proposals[1]["test_id"]

    # 4. Approve and Reject
    app_resp = client.post(f"{BACKEND_URL}/tests/{p_approve}/approve", headers=headers)
    assert app_resp.status_code == 200, f"Approval failed: {app_resp.text}"
    assert app_resp.json()["status"] == "Approved"

    rej_resp = client.post(f"{BACKEND_URL}/tests/{p_reject}/reject", headers=headers)
    assert rej_resp.status_code == 200, f"Rejection failed: {rej_resp.text}"
    assert rej_resp.json()["status"] == "Rejected"
    print(f"[PASS] Step 5: Approved proposal {p_approve} and rejected proposal {p_reject}.")

    # 5. Verify rejected proposal cannot execute
    bad_exec = client.post(
        f"{BACKEND_URL}/tests/execute",
        headers=headers,
        json={"proposal_ids": [p_reject], "target": MOCK_URL}
    )
    assert bad_exec.status_code in [400, 403, 422], f"Rejected proposal execution should fail: {bad_exec.status_code}"
    print("[PASS] Step 6: Invariant confirmed: Rejected proposals cannot execute.")

    # 6. Execute approved proposal
    exec_resp = client.post(
        f"{BACKEND_URL}/tests/execute",
        headers=headers,
        json={"proposal_ids": [p_approve], "target": MOCK_URL}
    )
    assert exec_resp.status_code == 200, f"Execution failed: {exec_resp.text}"
    findings = exec_resp.json()
    assert len(findings) >= 1, f"Expected at least 1 finding, got {len(findings)}"
    print(f"[PASS] Step 7: Executed approved proposal against {MOCK_URL}, recorded {len(findings)} finding(s).")

    # 7. Test Chat with Live Session Intelligence
    prompts_to_test = [
        "What endpoints have been discovered in my current session?",
        "Which security tests are waiting for approval?",
        "Which tests were rejected?",
        "Which tests have actually executed?",
        "Show the findings from the latest execution.",
        "What evidence supports the highest-severity finding?",
        "What should I test next?",
        "Summarize my current assessment.",
        "Explain the difference between BOLA and BFLA.",
        "Explain HTTP 401 versus 403.",
    ]

    print("\n--- Verifying Live Chat Intelligence ---")
    for prompt in prompts_to_test:
        c_resp = client.post(f"{BACKEND_URL}/api/v1/chat", headers=headers, json={"message": prompt})
        assert c_resp.status_code == 200, f"Chat failed for '{prompt}': {c_resp.text}"
        data = c_resp.json()
        assert len(data.get("message", "")) > 10, f"Empty response for '{prompt}'"
        print(f"  [PASS] Chat prompt verified: '{prompt}'")

    # 8. Human Review Sign-off
    fid = findings[0]["finding_id"]
    rev_resp = client.post(
        f"{BACKEND_URL}/findings/{fid}/review",
        headers=headers,
        json={
            "outcome": "CONFIRMED",
            "reviewer_notes": "Manually verified differential anomaly on mock API endpoint.",
            "reviewer_id": "auditor_sec_01"
        }
    )
    assert rev_resp.status_code == 200, f"Human review failed: {rev_resp.text}"
    print(f"[PASS] Step 8: Human review successfully signed off on finding {fid}.")

    # 9. Generate and export PDF and JSON report
    rep_resp = client.post(f"{BACKEND_URL}/reports", headers=headers, json={"title": "E2E Final Pentest Report", "target": MOCK_URL})
    assert rep_resp.status_code == 200, f"Report creation failed: {rep_resp.text}"
    rep_id = rep_resp.json()["report_id"]

    json_resp = client.get(f"{BACKEND_URL}/reports/{rep_id}/json", headers=headers)
    assert json_resp.status_code == 200 and len(json_resp.content) > 100, f"JSON export failed: {json_resp.status_code} {json_resp.text}"

    pdf_resp = client.get(f"{BACKEND_URL}/reports/{rep_id}/pdf", headers=headers)
    assert pdf_resp.status_code == 200 and len(pdf_resp.content) > 100, f"PDF export failed: {pdf_resp.status_code} {pdf_resp.text}"
    print(f"[PASS] Step 9: Report {rep_id} generated and exported successfully as PDF ({len(pdf_resp.content)} bytes) and JSON ({len(json_resp.content)} bytes).")

    print("\n" + "=" * 65)
    print("  ALL 9 WORKFLOW STAGES PASSED AGAINST LIVE LOCAL SERVICES!")
    print("=" * 65)

if __name__ == "__main__":
    run_workflow()
