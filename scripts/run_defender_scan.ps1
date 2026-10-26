param(
    [Parameter(Mandatory = $true)]
    [string]$Target,
    [string]$Output = ".\reports\defender-report.json"
)

$ErrorActionPreference = "Stop"

$TargetPath = (Resolve-Path -LiteralPath $Target).Path
$OutputPath = if ([System.IO.Path]::IsPathRooted($Output)) {
    $Output
} else {
    Join-Path (Resolve-Path ".").Path $Output
}
New-Item -ItemType Directory -Path (Split-Path $OutputPath -Parent) -Force | Out-Null

if (-not (Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue) -or
    -not (Get-Command Start-MpScan -ErrorAction SilentlyContinue) -or
    -not (Get-Command Get-MpThreatDetection -ErrorAction SilentlyContinue)) {
    throw "Required Microsoft Defender PowerShell cmdlets are unavailable."
}

function Get-DefenderHistorySnapshot {
    try {
        @(
            Get-MpThreatDetection -ErrorAction Stop |
            ForEach-Object {
                [ordered]@{
                    ThreatID = $_.ThreatID
                    ThreatName = $_.ThreatName
                    InitialDetectionTime = if ($_.InitialDetectionTime) {
                        ([datetime]$_.InitialDetectionTime).ToUniversalTime().ToString("o")
                    } else { $null }
                    LastThreatStatusChangeTime = if ($_.LastThreatStatusChangeTime) {
                        ([datetime]$_.LastThreatStatusChangeTime).ToUniversalTime().ToString("o")
                    } else { $null }
                    ActionSuccess = $_.ActionSuccess
                    CleaningActionID = $_.CleaningActionID
                    ThreatStatusID = $_.ThreatStatusID
                    Resources = @($_.Resources | ForEach-Object { [string]$_ })
                }
            }
        )
    } catch {
        Write-Warning "Could not read Defender threat history: $($_.Exception.Message)"
        return $null
    }
}

$status = Get-MpComputerStatus
$statusSummary = [ordered]@{
    AMRunningMode = $status.AMRunningMode
    AMServiceEnabled = $status.AMServiceEnabled
    AntivirusEnabled = $status.AntivirusEnabled
    RealTimeProtectionEnabled = $status.RealTimeProtectionEnabled
    BehaviorMonitorEnabled = $status.BehaviorMonitorEnabled
    IsTamperProtected = $status.IsTamperProtected
    AntivirusSignatureLastUpdated = $status.AntivirusSignatureLastUpdated
}

$scanId = [guid]::NewGuid().ToString()
$scanStartedUtc = (Get-Date).ToUniversalTime()
$historyBefore = Get-DefenderHistorySnapshot

Write-Host "Scan ID: $scanId"
Write-Host "Target: $TargetPath"
Write-Host "Starting Microsoft Defender custom scan. This may take time."

$commandCompleted = $false
$scanError = $null
try {
    Start-MpScan -ScanType CustomScan -ScanPath $TargetPath
    $commandCompleted = $true
} catch {
    $scanError = $_.Exception.Message
    Write-Warning "Defender scan command failed: $scanError"
}

$scanCompletedUtc = (Get-Date).ToUniversalTime()
$historyAfter = Get-DefenderHistorySnapshot

$report = [ordered]@{
    schema_version = "0.5.3"
    generated_utc = (Get-Date).ToUniversalTime().ToString("o")
    scan = [ordered]@{
        scan_id = $scanId
        engine = "Microsoft Defender"
        scan_type = "CustomScan"
        target = $TargetPath
        started_utc = $scanStartedUtc.ToString("o")
        command_returned_utc = $scanCompletedUtc.ToString("o")
        command_completed = $commandCompleted
        command_error = $scanError
        result_attribution = "not_confirmed_by_command_completion"
        note = "Command completion does not prove that every file was scanned or clean."
    }
    defender_status = $statusSummary
    history_snapshot_before = $historyBefore
    history_snapshot_after = $historyAfter
    threat_detections = $historyAfter
    threat_history_note = "Defender threat history is system-wide. Differences between snapshots are temporal evidence only, not proof that a record was caused by this scan."
}
$report | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $OutputPath -Encoding UTF8

Write-Host "Defender report saved: $OutputPath" -ForegroundColor Green
Write-Host "No Defender settings were changed by this script."
if (-not $commandCompleted) {
    throw "Defender scan command failed. Review the report and error above."
}