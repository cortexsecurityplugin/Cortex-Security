param(
    [string]$Target = ".",
    [string]$RequirementsFile = "requirements.txt"
)

$ErrorActionPreference = "Continue"
$RepoRoot = (Resolve-Path $Target).Path
$ReportDir = Join-Path $RepoRoot "reports"
New-Item -ItemType Directory -Path $ReportDir -Force | Out-Null

$BanditJson = Join-Path $ReportDir "bandit-report.json"
$BanditSarif = Join-Path $ReportDir "bandit-report.sarif"
$AuditJson = Join-Path $ReportDir "pip-audit-report.json"

Write-Host "`n=== Cortex Security: external tool checks ===" -ForegroundColor Cyan
Write-Host "Target: $RepoRoot"
Write-Host "Reports: $ReportDir"
Write-Host "This script does not apply fixes or modify application source."

$bandit = Get-Command bandit -ErrorAction SilentlyContinue
if ($bandit) {
    # For Cortex Security itself, scan the production scanner directory directly.
    # This avoids test-fixture findings without broadly suppressing test paths.
    $BanditTarget = $RepoRoot
    $ScriptsDir = Join-Path $RepoRoot "scripts"
    if ((Split-Path $RepoRoot -Leaf) -eq "CortexSecurity" -and (Test-Path $ScriptsDir -PathType Container)) {
        $BanditTarget = $ScriptsDir
    }

    Write-Host "`n[1/2] Running Bandit (Python static analysis) on: $BanditTarget"
    & bandit -r $BanditTarget -f json -o $BanditJson
    $banditExit = $LASTEXITCODE
    if (($banditExit -le 1) -and (Test-Path $BanditJson)) {
        Write-Host "Bandit JSON report: $BanditJson"
    } else {
        Write-Warning "Bandit exited with code $banditExit. Check installation and console output."
    }

    & bandit -r $BanditTarget -f sarif -o $BanditSarif
    $sarifExit = $LASTEXITCODE
    if (($sarifExit -le 1) -and (Test-Path $BanditSarif)) {
        Write-Host "Bandit SARIF report: $BanditSarif"
    } else {
        Write-Warning "Bandit SARIF output was not produced. JSON output remains the primary report."
    }
} else {
    Write-Warning "Bandit is not installed or not on PATH. Activate the security virtual environment first."
}

$audit = Get-Command pip-audit -ErrorAction SilentlyContinue
$reqPath = Join-Path $RepoRoot $RequirementsFile
if ($audit -and (Test-Path $reqPath -PathType Leaf)) {
    Write-Host "`n[2/2] Running pip-audit against $reqPath..."
    Write-Host "Note: pip-audit may resolve dependencies and contact public vulnerability services."
    & pip-audit -r $reqPath --format=json --output=$AuditJson
    $auditExit = $LASTEXITCODE
    if (Test-Path $AuditJson) {
        Write-Host "pip-audit JSON report: $AuditJson"
        try {
            $auditReport = Get-Content $AuditJson -Raw | ConvertFrom-Json
            $dependencyCount = @($auditReport.dependencies).Count
            $vulnerabilityCount = 0
            foreach ($dependency in @($auditReport.dependencies)) {
                $vulnerabilityCount += @($dependency.vulns).Count
            }
            Write-Host "Dependencies in report: $dependencyCount; known vulnerabilities listed: $vulnerabilityCount"
        } catch {
            Write-Warning "Could not summarize pip-audit JSON. Review the report directly."
        }
    }
    if ($auditExit -eq 1) {
        Write-Warning "pip-audit reported known vulnerabilities. Review the report; no packages were changed."
    } elseif ($auditExit -ne 0) {
        Write-Warning "pip-audit exited with code $auditExit. Check console output and report."
    }
} elseif (-not $audit) {
    Write-Warning "pip-audit is not installed or not on PATH."
} else {
    Write-Warning "Requirements file not found: $reqPath. Skipping dependency audit."
}

Write-Host "`nFinished. Review reports manually; these tools do not guarantee security."
