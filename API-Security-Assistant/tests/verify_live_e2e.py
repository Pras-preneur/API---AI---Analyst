import httpx as requests

BASE = 'http://127.0.0.1:8000'
MOCK = 'http://127.0.0.1:8001'

print("--- STARTING LIVE LOCALHOST INTEGRATION WORKFLOW ---")

# 1. Health check
health_res = requests.get(f'{BASE}/health').json()
assert health_res == {'status': 'ok'}
print('1. Health check: OK')

# 2. Spec upload & Session creation
spec_content = '''openapi: 3.0.0
info:
  title: Banking Test Spec
  version: 1.0.0
paths:
  /api/v1/accounts/{id}/statement:
    get:
      summary: Statement
      responses:
        '200':
          description: OK
'''
res = requests.post(
    f'{BASE}/parse-openapi',
    files={'file': ('spec.yaml', spec_content, 'application/x-yaml')}
)
assert res.status_code == 200
session_id = res.headers['X-Session-ID']
endpoints = res.json()
assert len(endpoints) == 1
print(f'2. Parse OpenAPI & Session creation: session_id={session_id}, endpoints={len(endpoints)}')

# 3. Security test proposal generation
proposals = requests.post(
    f'{BASE}/tests/propose?include_auth=true',
    headers={'X-Session-ID': session_id}
).json()
assert len(proposals) > 0
prop_id = proposals[0]['test_id']
print(f'3. Propose tests: count={len(proposals)}, selected proposal={prop_id}')

# 4. Explicit operator approval
appr_res = requests.post(
    f'{BASE}/tests/{prop_id}/approve',
    headers={'X-Session-ID': session_id}
)
assert appr_res.status_code == 200
assert appr_res.json()['status'] == 'Approved'
print(f'4. Explicit human approval: proposal {prop_id} status=Approved')

# 5. Execution against local authorized mock target (http://127.0.0.1:8001)
exec_res = requests.post(
    f'{BASE}/tests/execute',
    headers={'X-Session-ID': session_id},
    json={'proposal_ids': [prop_id], 'target': MOCK}
)
assert exec_res.status_code == 200
findings = exec_res.json()
assert len(findings) > 0
f_id = findings[0]['finding_id']
initial_status = findings[0]['status']
print(f'5. Execution: finding_id={f_id}, status={initial_status}')

# 6. AI Analysis of Finding (Advisory Only)
ai_resp = requests.post(
    f'{BASE}/findings/{f_id}/analyze',
    headers={'X-Session-ID': session_id}
)
assert ai_resp.status_code == 200
ai_res = ai_resp.json()
assert ai_res['priority'] in ['P1', 'P2', 'P3']
assert ai_res['scanner_verdict_changed'] is False
assert ai_res['is_model_recommendation'] is True
print(f'6. AI Analysis: priority={ai_res["priority"]}, scanner_verdict_changed={ai_res["scanner_verdict_changed"]}, probabilities={ai_res.get("priority_probabilities")}')

# Verify that AI analysis did NOT change finding status
f_check = requests.get(f'{BASE}/findings/{f_id}', headers={'X-Session-ID': session_id}).json()
assert f_check['status'] == initial_status
assert f_check['is_human_reviewed'] is False
print('   -> Invariant verified: AI analysis did NOT change finding status or review state.')

# 7. Cross-Session Isolation Verification
session_id_other = requests.post(
    f'{BASE}/parse-openapi',
    files={'file': ('spec.yaml', spec_content, 'application/x-yaml')}
).headers['X-Session-ID']
iso_resp = requests.post(
    f'{BASE}/findings/{f_id}/analyze',
    headers={'X-Session-ID': session_id_other}
)
assert iso_resp.status_code == 404
print(f'7. Cross-session isolation: foreign session cannot analyze finding {f_id} (HTTP 404).')

# 8. Human Review via Existing Review Endpoint
review_resp = requests.post(
    f'{BASE}/findings/{f_id}/review',
    headers={'X-Session-ID': session_id},
    json={
        'outcome': 'CONFIRMED',
        'reviewer_id': 'lead_auditor_bob',
        'reviewer_notes': 'Manually inspected response evidence and confirmed cross-tenant BOLA leak.',
    }
)
assert review_resp.status_code == 200
reviewed_data = review_resp.json()
assert reviewed_data['status'] == 'Confirmed'
assert reviewed_data['is_human_reviewed'] is True
assert reviewed_data['reviewer_id'] == 'lead_auditor_bob'
print(f'8. Human Review: finding {f_id} is now CONFIRMED by {reviewed_data["reviewer_id"]}')

# 9. Report Generation & Exports (JSON & PDF)
rep_res = requests.post(
    f'{BASE}/reports',
    headers={'X-Session-ID': session_id},
    json={'target': MOCK}
)
assert rep_res.status_code == 200
report_id = rep_res.json()['report_id']
print(f'9. Report created in backend: report_id={report_id}')

# PDF export
pdf_res = requests.get(f'{BASE}/reports/{report_id}/pdf', headers={'X-Session-ID': session_id})
assert pdf_res.status_code == 200
assert pdf_res.headers['content-type'] == 'application/pdf'
assert len(pdf_res.content) > 1000
print(f'   -> PDF Export: HTTP 200, {len(pdf_res.content)} bytes generated.')

# JSON export
json_res = requests.get(f'{BASE}/reports/{report_id}/json', headers={'X-Session-ID': session_id})
assert json_res.status_code == 200
assert json_res.headers['content-type'] == 'application/json'
assert len(json_res.content) > 500
print(f'   -> JSON Export: HTTP 200, {len(json_res.content)} bytes generated.')

# 10. Conversational SLM Endpoint
chat_res = requests.post(
    f'{BASE}/api/v1/chat',
    json={
        'message': 'What is the risk of BOLA on account balance endpoints?',
        'context': {'specTitle': 'Banking Test Spec'}
    }
).json()
assert chat_res['intent'] == 'vulnerability_analysis'
assert len(chat_res['message']) > 100
print(f'10. SLM Chat interaction: intent={chat_res["intent"]}, message_length={len(chat_res["message"])}')

print("\n--- ALL LIVE LOCALHOST INTEGRATION WORKFLOW STEPS PASSED SUCCESSFULLY! ---")
