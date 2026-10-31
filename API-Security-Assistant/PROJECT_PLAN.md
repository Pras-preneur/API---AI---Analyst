# Project Plan – API Security Testing Assistant

## Evaluation Feedback (Phase 0)
1. **Conversational UI** – design a chat‑style endpoint (later).  Not part of this milestone.
2. **API documentation intake** – already covered by the OpenAPI parser.
3. **Human‑in‑the‑loop testing** – will be orchestrated through explicit approval endpoints.
4. **Automatic CVE mapping** – defer to Phase 5.
5. **Automated VPTA/bug‑bounty reports** – defer to Phase 5 (VPTA pending clarification).
6. **Small language model (SLM) experiment** – Phase 7.
7. **API‑key video generation feature** – Phase 8.

## Current Repository State
```
D:\KLE\APITESTING\PENTEST\API-Security-Assistant
├─ app/
│   ├─ __init__.py
│   ├─ main.py               # FastAPI entry point (health + parser upload)
│   ├─ config.py             # MAX_SPEC_SIZE, SUPPORTED_METHODS
│   ├─ parser/
│   │   ├─ __init__.py
│   │   └─ openapi_parser.py # Robust OpenAPI 3.x parser (Pydantic models)
│   └─ mock_api.py           # Isolated mock API with vulnerable/secure endpoints
├─ tests/
│   ├─ __init__.py
│   ├─ test_openapi_parser.py
│   └─ test_mock_api.py      # FastAPI TestClient validation of mock API
├─ sample_specs/
│   └─ demo_api.yaml
├─ requirements.txt          # fastapi, pydantic>=2.0, pyyaml, uvicorn, pytest, python‑multipart, httpx2, rich
├─ README.md
└─ .gitignore
```

* All existing tests (`test_openapi_parser.py` + `test_mock_api.py`) **pass** (18 tests).
* The mock API starts with `uvicorn app.mock_api:mock_app --host 127.0.0.1 --port 8001`.
* The TestClient warning: **StarletteDeprecationWarning** – it falls back to the older `httpx` package because **httpx2** is not installed.

## Diagnosed Dependency Issue
- `requirements.txt` lists `httpx2` and `rich`.
- Running `python -c "import httpx2"` fails with `ModuleNotFoundError: No module named 'httpx2'`.
- `rich` imports fine (no error shown), but the previous PowerShell quoting attempts gave misleading parser errors.
- FastAPI TestClient prefers `httpx2`; without it the library uses the legacy `httpx` and emits the deprecation warning observed in the test output.
- **Root cause:** the virtual environment does **not** have `httpx2` (and possibly `rich`) installed despite being listed in `requirements.txt`.

## Immediate Action Items (Phase 0 – Stabilization)
1. **Install missing dependencies** in the current virtual environment:
   ```powershell
   .\.venv\Scripts\Activate.ps1   # or source .venv/bin/activate on *nix
   python -m pip install -r requirements.txt
   ```
   This will pull `httpx2` (which provides a modern `httpx` client) and `rich`.
2. **Verify installation** by importing the modules.
   ```powershell
   python - <<'PY'
   import httpx2, rich
   print('httpx2', httpx2.__version__)
   print('rich', rich.__version__)
   PY
   ```
3. **Re‑run the full test suite** – expect no deprecation warnings.
4. **Document exact commands** in `README.md` (already present) and add a short section in `PROJECT_PLAN.md` for reproducing the environment.
5. **Create `DEVELOPMENT_LOG.md`** to capture this inspection, findings, and next‑step decision.

## Next Milestone Recommendation
After confirming the environment is stable (no missing packages, all tests passing without warnings), move to **Phase 1 – API Specification Intake**:
- Add a dedicated endpoint `/spec/upload` that delegates to the existing parser.
- Return a deterministic JSON inventory.
- Validate file size and type as already done in `app/main.py`.
- Write unit tests for the new endpoint.

---

*All changes respect the requirement to keep the mock API isolated and do not modify existing functional code.*

