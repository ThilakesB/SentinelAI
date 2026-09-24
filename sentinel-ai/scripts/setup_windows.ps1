# ============================================================
# SentinelAI — Windows Setup Script
# Run as Administrator in PowerShell
# Usage: .\scripts\setup_windows.ps1
# ============================================================

$ErrorActionPreference = "Stop"

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  SentinelAI Windows Setup" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

# -- 1. Check Python version
$pythonVersion = python --version 2>&1
if ($pythonVersion -notmatch "3\.(1[0-9]|[2-9][0-9])") {
    Write-Host "ERROR: Python 3.10+ required. Found: $pythonVersion" -ForegroundColor Red
    exit 1
}
Write-Host "[OK] $pythonVersion" -ForegroundColor Green

# -- 2. Check admin privileges
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "WARNING: Not running as Administrator. Some features require elevated privileges." -ForegroundColor Yellow
    Write-Host "         Re-run as Administrator for full ETW and network monitoring capability." -ForegroundColor Yellow
}

# -- 3. Create virtual environment
if (-not (Test-Path "venv")) {
    Write-Host "`n[1/6] Creating virtual environment..." -ForegroundColor Cyan
    python -m venv venv
} else {
    Write-Host "`n[1/6] Virtual environment already exists." -ForegroundColor Green
}

# -- 4. Activate venv and install dependencies
Write-Host "`n[2/6] Installing Python dependencies..." -ForegroundColor Cyan
& "venv\Scripts\pip.exe" install --upgrade pip --quiet
& "venv\Scripts\pip.exe" install -r requirements.txt --quiet
Write-Host "[OK] Dependencies installed." -ForegroundColor Green

# -- 5. Copy .env.example to .env if not exists
if (-not (Test-Path ".env")) {
    Write-Host "`n[3/6] Creating .env from template..." -ForegroundColor Cyan
    Copy-Item ".env.example" ".env"
    Write-Host "[ACTION REQUIRED] Edit .env and fill in:" -ForegroundColor Yellow
    Write-Host "  - DATABASE_URL (Supabase PostgreSQL connection string)" -ForegroundColor Yellow
    Write-Host "  - APP_SECRET_KEY (random 32+ char string)" -ForegroundColor Yellow
    Write-Host "  - JWT_SECRET_KEY (random 64+ char string)" -ForegroundColor Yellow
    Write-Host "  - ABUSEIPDB_API_KEY (from abuseipdb.com)" -ForegroundColor Yellow
    Write-Host "  - MALWAREBAZAAR_API_KEY (from auth.abuse.ch)" -ForegroundColor Yellow
    Write-Host "  - NVD_API_KEY (from nvd.nist.gov)" -ForegroundColor Yellow
} else {
    Write-Host "`n[3/6] .env already exists. Skipping." -ForegroundColor Green
}

# -- 6. Create required directories
Write-Host "`n[4/6] Creating required directories..." -ForegroundColor Cyan
@("data", "models", "rules", "logs") | ForEach-Object {
    if (-not (Test-Path $_)) { New-Item -ItemType Directory -Path $_ | Out-Null }
}
Write-Host "[OK] Directories created." -ForegroundColor Green

# -- 7. Windows Firewall check
Write-Host "`n[5/6] Checking Windows Firewall service..." -ForegroundColor Cyan
$fwService = Get-Service -Name "mpssvc" -ErrorAction SilentlyContinue
if ($fwService -and $fwService.Status -eq "Running") {
    Write-Host "[OK] Windows Firewall service is running." -ForegroundColor Green
} else {
    Write-Host "WARNING: Windows Firewall service not running. IP block feature disabled." -ForegroundColor Yellow
}

# -- 8. YARA rules info
Write-Host "`n[6/6] YARA rules setup..." -ForegroundColor Cyan
Write-Host "  To enable YARA scanning, clone community rule repos into ./rules/:" -ForegroundColor DarkGray
Write-Host "  git clone https://github.com/Yara-Rules/rules rules/yara-rules" -ForegroundColor DarkGray
Write-Host "  git clone https://github.com/Neo23x0/signature-base rules/signature-base" -ForegroundColor DarkGray

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "  Setup complete!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Next steps:" -ForegroundColor White
Write-Host "  1. Edit .env with your API keys and database URL"
Write-Host "  2. Run DB migrations: psql `$DATABASE_URL -f database/migrations/001_initial_schema.sql"
Write-Host "  3. Train initial model: venv\Scripts\python.exe scripts\train_baseline.py"
Write-Host "  4. Start the API: venv\Scripts\uvicorn.exe backend.main:app --host 127.0.0.1 --port 8000"
Write-Host ""
