# ============================================================================
# AuditGuard — Single-Command Local Startup Script (Windows PowerShell)
# Initializes SQLite DB, generates/seeds synthetic dataset, verifies health,
# and launches the FastAPI Gateway + Analyst Web Workbench on port 8000.
# ============================================================================
$ErrorActionPreference = "Stop"

$ProjectRoot = Split-Path -Parent $PSScriptRoot
Set-Location $ProjectRoot

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  AuditGuard — Local Startup & Initialization" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan

if (-not (Test-Path ".env")) {
    Copy-Item ".env.example" ".env"
    Write-Host "[1/3] Created default .env from .env.example" -ForegroundColor Green
} else {
    Write-Host "[1/3] Found existing .env configuration" -ForegroundColor Green
}

Write-Host "[2/3] Generating 60-case synthetic dataset & seeding SQLite database..." -ForegroundColor Yellow
python -m data.synthetic_generator

Write-Host "[3/3] Starting AuditGuard FastAPI Server + Analyst Workbench..." -ForegroundColor Green
Write-Host "      -> Analyst Workbench : http://localhost:8000/" -ForegroundColor Cyan
Write-Host "      -> Swagger API Docs  : http://localhost:8000/api/docs" -ForegroundColor Cyan
Write-Host "      -> Health Endpoint   : http://localhost:8000/health" -ForegroundColor Cyan
Write-Host "      -> Prometheus Metrics: http://localhost:8000/metrics" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan

python -m uvicorn src.api.main:app --host 127.0.0.1 --port 8000 --reload
