param(
    [string]$Target = ".",
    [string]$RequirementsFile = "requirements-security.txt"
)

$ErrorActionPreference = "Continue"
$RepoRoot = (Resolve-Path $Target).Path
$ReportDir = Join-Path $RepoRoot "reports"
New-Item -ItemType Directory -Path $ReportDir -Force | Out-Null

$CortexJson = Join-Path $ReportDir "scan-report.json"
$CortexSarif = Join-Path $ReportDir "scan-report.sarif"
$BanditJson = Join-Path $ReportDir "bandit-report.json"
$BanditSarif = Join-Path $ReportDir "bandit-report.sarif"
$AuditJson = Join-Path $ReportDir "pip-audit-report.json"
$StatusJson = Join-Path $ReportDir "audit-run-status.json"

Write-Host "`n=== Cortex Security v0.4 unified audit ===" -ForegroundColor Cyan
Write-Host "Target: $RepoRoot"
Write-Host "Reports: $ReportDir"
Write-Host "Read-only audit: no automatic fixes will be applied."

# Remove prior tool outputs so missing/failed tools cannot accidentally reuse stale reports.
@($CortexJson, $CortexSarif, $BanditJson, $BanditSarif, $AuditJson, $StatusJson) |
    ForEach-Object { if (Test-Path $_) { Remove-Item $_ -Force } }

$RunStatus = @{
    cortex = @{ available = $true; success = $false; exit_code = $null }
    bandit = @{ available = $false; success = $false; exit_code = $null }
    pip_audit = @{ available = $false; success = $false; exit_code = $null }
}

$Scanner = Join-Path $RepoRoot "scripts\cortex_scan.py"
if ((Test-Path $Scanner -PathType Leaf) -and (Get-Command python -ErrorAction SilentlyContinue)) {
    Write-Host "`n[1/3] Cortex heuristic scanner..."
    & python $Scanner $RepoRoot `
    --output $CortexJson `
    --sarif-output $CortexSarif `
    --exclude ".venv-security" `
    --exclude ".venv" `
    --exclude "venv" `
    --exclude ".git" `
    --exclude "reports" `
	--exclude "scripts/cortex_scan.py" `
    --exclude "tests/test_cortex_scan.py"`
    --exclude "__pycache__"
    $code = $LASTEXITCODE
    $RunStatus.cortex.exit_code = $code
    $RunStatus.cortex.success = (($code -eq 0) -and (Test-Path $CortexJson))
} else {
    $RunStatus.cortex.available = $false
    Write-Warning "Cortex scanner or Python was not available."
}

$bandit = Get-Command bandit -ErrorAction SilentlyContinue
$BanditTarget = $RepoRoot
$ScriptsDir = Join-Path $RepoRoot "scripts"
if ((Split-Path $RepoRoot -Leaf) -eq "CortexSecurity" -and (Test-Path $ScriptsDir -PathType Container)) {
    $BanditTarget = $ScriptsDir
}
if ($bandit) {
    $RunStatus.bandit.available = $true
    Write-Host "`n[2/3] Bandit static analysis..."
    & bandit -r $BanditTarget -f json -o $BanditJson
    $code = $LASTEXITCODE
    $RunStatus.bandit.exit_code = $code
    $RunStatus.bandit.success = (($code -le 1) -and (Test-Path $BanditJson))
    & bandit -r $BanditTarget -f sarif -o $BanditSarif
    if (($LASTEXITCODE -gt 1) -or -not (Test-Path $BanditSarif)) {
        Write-Warning "Bandit SARIF was not produced; JSON is the primary report."
    }
} else {
    Write-Warning "Bandit is not installed or not on PATH."
}

$audit = Get-Command pip-audit -ErrorAction SilentlyContinue
$reqPath = Join-Path $RepoRoot $RequirementsFile
if ($audit -and (Test-Path $reqPath -PathType Leaf)) {
    $RunStatus.pip_audit.available = $true
    Write-Host "`n[3/3] pip-audit against $reqPath..."
    Write-Host "pip-audit may contact public vulnerability services."
    & pip-audit -r $reqPath --format=json --output=$AuditJson
    $code = $LASTEXITCODE
    $RunStatus.pip_audit.exit_code = $code
    $RunStatus.pip_audit.success = (($code -eq 0 -or $code -eq 1) -and (Test-Path $AuditJson))
} else {
    if (-not $audit) { Write-Warning "pip-audit is not installed or not on PATH." }
    else { Write-Warning "Requirements file not found: $reqPath." }
}

$RunStatus | ConvertTo-Json -Depth 6 | Set-Content -Path $StatusJson -Encoding UTF8
$Builder = Join-Path $RepoRoot "scripts\build_unified_report.py"
if (Test-Path $Builder -PathType Leaf) {
    & python $Builder --target $RepoRoot --report-dir $ReportDir --requirements-file $RequirementsFile
    if ($LASTEXITCODE -ne 0) { Write-Warning "Unified report generation failed." }
} else {
    Write-Warning "Unified report builder missing: $Builder"
}

Write-Host "`nDone. Review the unified summary and original tool reports; these tools do not guarantee security."
