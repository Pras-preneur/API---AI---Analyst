import httpx as requests

BASE = 'http://127.0.0.1:8000'
MOCK = 'http://127.0.0.1:8001'

# 1. Health
assert requests.get(f'{BASE}/health').json() == {'status': 'ok'}
print('1. Health check: OK')

# 2. Spec upload
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
session_id = res.headers['X-Session-ID']
endpoints = res.json()
print(f'2. Parse OpenAPI: session_id={session_id}, endpoints={len(endpoints)}')

# 3. Propose
proposals = requests.post(
    f'{BASE}/tests/propose?include_auth=true',
    headers={'X-Session-ID': session_id}
).json()
assert len(proposals) > 0
print(f'3. Propose tests: count={len(proposals)}')

# 4. Approve
prop_id = proposals[0]['test_id']
requests.post(
    f'{BASE}/tests/{prop_id}/approve',
    headers={'X-Session-ID': session_id}
)
print(f'4. Approve test: {prop_id}')

# 5. Execute
exec_res = requests.post(
    f'{BASE}/tests/execute',
    headers={'X-Session-ID': session_id},
    json={'proposal_ids': [prop_id], 'target': MOCK}
)
findings = exec_res.json()
assert len(findings) > 0
f_id = findings[0]['finding_id']
status = findings[0]['status']
print(f'5. Execute test: finding_id={f_id}, status={status}')

# 6. AI Analyze finding
ai_resp = requests.post(
    f'{BASE}/findings/{f_id}/analyze',
    headers={'X-Session-ID': session_id}
)
print('ai_resp status:', ai_resp.status_code, 'text:', ai_resp.text)
ai_res = ai_resp.json()
print(f'6. AI Finding Analysis: priority={ai_res["priority"]}, verdict_changed={ai_res["scanner_verdict_changed"]}, summary_len={len(ai_res["finding_summary"])}')

# 7. Chat
chat_res = requests.post(
    f'{BASE}/api/v1/chat',
    json={
        'message': 'Give me an executive summary for this banking API',
        'context': {'specTitle': 'Banking Test Spec'}
    }
).json()
print(f'7. SLM Chat: intent={chat_res["intent"]}, message_preview={chat_res["message"][:60]}...')

# 8. Report generation
doc_res = requests.post(
    f'{BASE}/api/v1/reports/generate',
    json={
        'report_type': 'pentest_report',
        'spec_title': 'Banking Test Spec',
        'endpoints_count': 1
    }
).json()
print(f'8. Report generation: doc_title={doc_res["report"]["title"]}, format={doc_res["report"]["format"]}')

print('ALL LIVE INTEGRATION CHECKS PASSED!')
