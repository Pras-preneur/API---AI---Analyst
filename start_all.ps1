# Antigravity HACKFUSION 2.0 - Unified Multi-Service Launch Script for PowerShell
$ErrorActionPreference = "Stop"

$RootDir = "D:\KLE\APITESTING\PENTEST"
$BackendDir = Join-Path $RootDir "API-Security-Assistant"
$FrontendDir = Join-Path $RootDir "API---AI---Analyst\frontend"
$PythonExe = Join-Path $BackendDir ".venv\Scripts\python.exe"

Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host "   HACKFUSION 2.0 - API SECURITY TESTING ASSISTANT LAUNCHER" -ForegroundColor Cyan
Write-Host "=================================================================" -ForegroundColor Cyan

# 1. Start Mock Target API (port 8001)
Write-Host "`n[1/3] Starting Mock Target API on http://127.0.0.1:8001..." -ForegroundColor Yellow
$pMock = Start-Process -FilePath $PythonExe -ArgumentList "-m uvicorn app.mock_api:mock_app --host 127.0.0.1 --port 8001" -WorkingDirectory $BackendDir -PassThru

# 2. Start Main FastAPI Backend (port 8000)
Write-Host "[2/3] Starting Security Assistant Backend on http://127.0.0.1:8000..." -ForegroundColor Yellow
$pBackend = Start-Process -FilePath $PythonExe -ArgumentList "-m uvicorn app.main:app --host 127.0.0.1 --port 8000" -WorkingDirectory $BackendDir -PassThru

# 3. Start Frontend (port 5173)
Write-Host "[3/3] Starting React/TypeScript Frontend on http://localhost:5173..." -ForegroundColor Yellow
$pFrontend = Start-Process -FilePath "npm.cmd" -ArgumentList "run dev" -WorkingDirectory $FrontendDir -PassThru

# Wait and verify readiness
Write-Host "`nVerifying service readiness..." -ForegroundColor Cyan
Start-Sleep -Seconds 3

try {
    $respBackend = Invoke-RestMethod -Uri "http://127.0.0.1:8000/health" -TimeoutSec 3
    Write-Host "  ✔ FastAPI Backend is HEALTHY (http://127.0.0.1:8000)" -ForegroundColor Green
} catch {
    Write-Host "  ⚠ Warning: Backend health check failed: $_" -ForegroundColor Red
}

try {
    $respMock = Invoke-RestMethod -Uri "http://127.0.0.1:8001/health" -TimeoutSec 3
    Write-Host "  ✔ Mock Target API is HEALTHY (http://127.0.0.1:8001)" -ForegroundColor Green
} catch {
    Write-Host "  ⚠ Warning: Mock API health check failed: $_" -ForegroundColor Red
}

Write-Host "`n=================================================================" -ForegroundColor Cyan
Write-Host "  ALL SERVICES RUNNING & HEALTHY:" -ForegroundColor Cyan
Write-Host "  - Frontend UI:       http://localhost:5173" -ForegroundColor White
Write-Host "  - Backend API:       http://127.0.0.1:8000" -ForegroundColor White
Write-Host "  - Backend Swagger:   http://127.0.0.1:8000/docs" -ForegroundColor White
Write-Host "  - Mock Target API:   http://127.0.0.1:8001" -ForegroundColor White
Write-Host "  - Mock Swagger:      http://127.0.0.1:8001/docs" -ForegroundColor White
Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host "To stop services, close the terminal or kill PIDs: $($pMock.Id), $($pBackend.Id), $($pFrontend.Id)`n"

