# ARGOS Defense launcher (Windows PowerShell). Does NOT change the execution policy.
# If scripts are blocked, run it for this process only:
#   powershell -ExecutionPolicy Bypass -File scripts\start.ps1 -Demo
# (that flag applies to this single process; nothing global is modified)
param([switch]$Demo, [int]$Port = 8789)
$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root
$py = Get-Command py -ErrorAction SilentlyContinue
if ($py) { $Python = "py"; $PyArgs = @("-3") } else {
  $p = Get-Command python -ErrorAction SilentlyContinue
  if (-not $p) { Write-Error "Python >= 3.11 not found on PATH"; exit 1 }
  $Python = "python"; $PyArgs = @()
}
& $Python @PyArgs -c "import sys; sys.exit(0 if sys.version_info >= (3,11) else 1)"
if ($LASTEXITCODE -ne 0) { Write-Error "Python >= 3.11 required"; exit 1 }
$VenvPy = Join-Path $Root ".venv\Scripts\python.exe"
if (-not (Test-Path $VenvPy)) {
  Write-Host "Creating virtual environment in $Root\.venv"
  & $Python @PyArgs -m venv .venv
  & $VenvPy -m pip install -r requirements.lock
  if ($LASTEXITCODE -ne 0) { Write-Error "Dependency install failed (offline?)."; exit 1 }
  & $VenvPy -m pip install --no-deps --no-build-isolation -e .
}
& $VenvPy -m argos doctor
if ($Demo) { & $VenvPy -m argos demo }
Write-Host "Activate later with:  .\.venv\Scripts\Activate.ps1"
& $VenvPy -m argos serve --host 127.0.0.1 --port $Port
