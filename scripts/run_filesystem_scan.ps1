param(
    [Parameter(Mandatory = $true)]
    [string]$Target,
    [string]$Report = ".\reports\filesystem-scan.json",
    [int]$MaxFileMB = 50
)
$ErrorActionPreference = "Stop"
$RepoRoot = (Resolve-Path ".").Path
$Scanner = Join-Path $RepoRoot "scripts\filesystem_scan.py"
if (-not (Test-Path $Scanner -PathType Leaf)) {
    throw "Filesystem scanner not found: $Scanner"
}
$TargetPath = (Resolve-Path $Target).Path
$ReportPath = if ([System.IO.Path]::IsPathRooted($Report)) { $Report } else { Join-Path $RepoRoot $Report }
New-Item -ItemType Directory -Path (Split-Path $ReportPath -Parent) -Force | Out-Null
& python $Scanner $TargetPath --output $ReportPath --max-file-mb $MaxFileMB
if ($LASTEXITCODE -ne 0) { throw "Filesystem scan failed with exit code $LASTEXITCODE" }
Write-Host "Read-only filesystem scan complete. No files were modified." -ForegroundColor Green
Write-Host "Report: $ReportPath"
