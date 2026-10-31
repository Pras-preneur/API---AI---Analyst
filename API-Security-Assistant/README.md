# API Security Testing Assistant – Milestone 1

## Overview

This repository contains the **first milestone** of the *API Security Testing Assistant* project.  The goal of this milestone is to provide a solid foundation for later security‑testing capabilities:

* Parse a local OpenAPI 3.x specification (JSON or YAML) without making any network calls.
* Extract a deterministic, JSON‑serialisable inventory of API endpoints with all relevant metadata (method, path, parameters, request body, responses, security).
* Expose a minimal FastAPI service with a health‑check and an endpoint to upload a spec and receive the parsed inventory.

Only core Python libraries and a few well‑maintained third‑party packages are used.

---

## Prerequisites

* **Windows** (PowerShell)
* **Python 3.12+** – the runner reports `Python 3.13.5`.
* **Git** (optional, for cloning the repo).

---

## Setup

```powershell
# 1. Clone the repository (if not already)
# git clone <repo-url>
# cd API-Security-Assistant

# 2. Create a virtual environment
python -m venv venv

# 3. Activate the environment
.\venv\Scripts\Activate.ps1

# 4. Install dependencies
python -m pip install -r requirements.txt
```

---

## Running the Tests

```powershell
# From the project root
python -m pytest -q
```

All tests should pass:
```
10 passed, 2 warnings in ...s
```

---

## Starting the FastAPI Server

```powershell
uvicorn app.main:app --reload
```

* The server will be available at `http://127.0.0.1:8000`.
* Swagger/OpenAPI UI is automatically generated at `http://127.0.0.1:8000/docs`.

---

## API Endpoints

| Method | Path | Header | Description |
|---|---|---|---|
| GET | `/health` | — | Health check (`{"status": "ok"}`) |
| POST | `/parse-openapi` | — | Upload OpenAPI document (`.yaml`, `.yml`, `.json`). Returns parsed endpoint inventory and assigns a new session ID in `X-Session-ID` header. |
| POST | `/tests/propose` | `X-Session-ID` | Generate security test proposals using stored session endpoints (or an explicitly supplied inventory array). |
| GET | `/tests/{test_id}` | `X-Session-ID` | Inspect details of a specific test proposal. |
| POST | `/tests/{test_id}/approve` | `X-Session-ID` | Human-in-the-loop approval: transition proposal from `PROPOSED` to `APPROVED`. |
| POST | `/tests/{test_id}/reject` | `X-Session-ID` | Reject a proposal: transition proposal from `PROPOSED` to `REJECTED`. |
| POST | `/tests/execute` | `X-Session-ID` | Safely execute a batch of approved proposal IDs against the local mock API (`http://127.0.0.1:8001`). |
| GET | `/findings` | `X-Session-ID` | List all recorded evidence and findings for the session. |
| POST | `/reports` | `X-Session-ID` | Generate a structured, evidence-backed assessment report from session findings. |
| GET | `/reports/{report_id}` | `X-Session-ID` | Retrieve a generated security report by ID. |

> [!NOTE]
> **In-Memory Storage**: Assessment sessions, proposals, findings, and reports are held in memory. State is not persisted across application restarts.

---

## Complete End-to-End Workflow (PowerShell & curl.exe)

Start the mock target API and main service in separate terminals:

```powershell
# Terminal 1: Start local mock API (port 8001)
uvicorn app.mock_api:mock_app --host 127.0.0.1 --port 8001

# Terminal 2: Start API Security Assistant (port 8000)
uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Then execute the assessment steps in Terminal 3:

```powershell
# 1. Health check
curl.exe -s http://127.0.0.1:8000/health

# 2. Upload OpenAPI specification and capture session ID
$headers = curl.exe -s -i -X POST "http://127.0.0.1:8000/parse-openapi" -F "file=@sample_specs/demo_api.yaml"
$sessionId = ($headers | Select-String -Pattern "x-session-id:\s*([^\r\n]+)").Matches.Groups[1].Value.Trim()
Write-Host "Session ID: $sessionId"

# 3. Generate proposals (Option A: uses stored session inventory)
$proposals = curl.exe -s -X POST "http://127.0.0.1:8000/tests/propose" -H "X-Session-ID: $sessionId" | ConvertFrom-Json
$testId = $proposals[0].test_id
Write-Host "Selected Proposal Test ID: $testId ($($proposals[0].test_type))"

# 4. Human-in-the-loop approval
curl.exe -s -X POST "http://127.0.0.1:8000/tests/$testId/approve" -H "X-Session-ID: $sessionId"

# 5. Execute approved proposal against local mock API
$execPayload = @{ proposal_ids = @($testId); target = "http://127.0.0.1:8001" } | ConvertTo-Json -Compress
curl.exe -s -X POST "http://127.0.0.1:8000/tests/execute" -H "X-Session-ID: $sessionId" -H "Content-Type: application/json" -d $execPayload

# 6. View findings
curl.exe -s -X GET "http://127.0.0.1:8000/findings" -H "X-Session-ID: $sessionId"

# 7. Generate assessment report
$reportPayload = @{ target = "http://127.0.0.1:8001" } | ConvertTo-Json -Compress
$report = curl.exe -s -X POST "http://127.0.0.1:8000/reports" -H "X-Session-ID: $sessionId" -H "Content-Type: application/json" -d $reportPayload | ConvertFrom-Json
$reportId = $report.report_id

# 8. Retrieve report
curl.exe -s -X GET "http://127.0.0.1:8000/reports/$reportId" -H "X-Session-ID: $sessionId"
```

---

## What Is **Not** Implemented Yet

* Authentication manager, request engine, vulnerability scanners, databases, UI dashboards, or any LLM integration.
* Full OpenAPI schema validation (the parser extracts only the needed information).
* Persistent storage of uploaded specifications.
* Docker or any external services – the code runs purely locally.

---

## Next Steps

The next milestone will focus on:
* Adding an authentication manager to handle different security schemes.
* Implementing request generation and basic security‑testing checks (e.g., missing auth, injection vectors).
* Extending the FastAPI service with endpoints for automated scans and results reporting.

Feel free to explore the code, add new tests, or suggest improvements!

