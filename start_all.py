#!/usr/bin/env python3
"""Antigravity HACKFUSION 2.0 - Unified Multi-Service Launch & Health Orchestrator.

Spawns and monitors:
1. Mock Vulnerable Target API (port 8001)
2. FastAPI Main Pentest Backend (port 8000)
3. React Vite Analyst Frontend (port 5173)

Monitors readiness, reports live URLs, and guarantees clean process teardown on Ctrl+C.
"""

import sys
import os
import time
import signal
import subprocess
import urllib.request
import urllib.error

ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
if os.path.exists(os.path.join(ROOT_DIR, "API-Security-Assistant")):
    BACKEND_DIR = os.path.join(ROOT_DIR, "API-Security-Assistant")
    FRONTEND_DIR = os.path.join(ROOT_DIR, "frontend")
else:
    BACKEND_DIR = os.path.join(ROOT_DIR, "API-Security-Assistant")
    FRONTEND_DIR = os.path.join(ROOT_DIR, "API---AI---Analyst", "frontend")

venv_py_win = os.path.join(BACKEND_DIR, ".venv", "Scripts", "python.exe")
venv_py_unix = os.path.join(BACKEND_DIR, ".venv", "bin", "python")
if os.path.exists(venv_py_win):
    PYTHON_EXE = venv_py_win
elif os.path.exists(venv_py_unix):
    PYTHON_EXE = venv_py_unix
else:
    PYTHON_EXE = sys.executable

processes = []

def check_health(url: str, timeout: float = 2.0) -> bool:
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "HealthChecker/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status in (200, 204)
    except Exception:
        return False

def terminate_all():
    print("\n[Antigravity Orchestrator] Stopping all services...")
    for p, name in processes:
        if p.poll() is None:
            print(f"  -> Terminating {name} (PID {p.pid})...")
            p.terminate()
            try:
                p.wait(timeout=3)
            except subprocess.TimeoutExpired:
                p.kill()
    print("[Antigravity Orchestrator] All processes cleanly terminated.")

def main():
    def sig_handler(sig, frame):
        terminate_all()
        sys.exit(0)

    signal.signal(signal.SIGINT, sig_handler)
    signal.signal(signal.SIGTERM, sig_handler)

    print("=" * 65)
    print("  HACKFUSION 2.0 - API SECURITY TESTING ASSISTANT LAUNCHER")
    print("=" * 65)

    # 1. Start Mock Target API (port 8001)
    print("\n[1/3] Starting Mock Vulnerable Target API on http://127.0.0.1:8001...")
    mock_cmd = [PYTHON_EXE, "-m", "uvicorn", "app.mock_api:mock_app", "--host", "127.0.0.1", "--port", "8001"]
    p_mock = subprocess.Popen(mock_cmd, cwd=BACKEND_DIR)
    processes.append((p_mock, "Mock API (8001)"))

    # 2. Start Main FastAPI Pentest Backend (port 8000)
    print("[2/3] Starting Main Security Assistant Backend on http://127.0.0.1:8000...")
    backend_cmd = [PYTHON_EXE, "-m", "uvicorn", "app.main:app", "--host", "127.0.0.1", "--port", "8000"]
    p_backend = subprocess.Popen(backend_cmd, cwd=BACKEND_DIR)
    processes.append((p_backend, "FastAPI Backend (8000)"))

    # 3. Start Frontend Dev Server (port 5173)
    print("[3/3] Starting React/TypeScript Frontend on http://localhost:5173...")
    npm_cmd = ["npm.cmd" if os.name == "nt" else "npm", "run", "dev"]
    p_frontend = subprocess.Popen(npm_cmd, cwd=FRONTEND_DIR)
    processes.append((p_frontend, "Vite Frontend (5173)"))

    # Wait and verify readiness
    print("\n[Antigravity Orchestrator] Verifying service readiness...")
    max_wait = 20
    start_time = time.time()
    mock_ready = False
    backend_ready = False

    while time.time() - start_time < max_wait:
        if not mock_ready and check_health("http://127.0.0.1:8001/health"):
            mock_ready = True
            print("  ✔ Mock Target API is HEALTHY (http://127.0.0.1:8001)")
        if not backend_ready and check_health("http://127.0.0.1:8000/health"):
            backend_ready = True
            print("  ✔ FastAPI Backend is HEALTHY (http://127.0.0.1:8000)")

        if mock_ready and backend_ready:
            break
        time.sleep(1)

    if not (mock_ready and backend_ready):
        print("  ⚠ Warning: Some services did not report ready within timeout.")
    else:
        print("\n" + "=" * 65)
        print("  ALL SERVICES RUNNING & HEALTHY:")
        print("  - Frontend UI:       http://localhost:5173")
        print("  - Backend API:       http://127.0.0.1:8000")
        print("  - Backend Swagger:   http://127.0.0.1:8000/docs")
        print("  - Mock Target API:   http://127.0.0.1:8001")
        print("  - Mock Swagger:      http://127.0.0.1:8001/docs")
        print("=" * 65)
        print("Press Ctrl+C to stop all services.\n")

    try:
        while True:
            for p, name in processes:
                if p.poll() is not None:
                    print(f"[Antigravity Orchestrator] Process {name} exited with code {p.returncode}")
                    terminate_all()
                    sys.exit(1)
            time.sleep(1)
    except KeyboardInterrupt:
        terminate_all()

if __name__ == "__main__":
    main()

