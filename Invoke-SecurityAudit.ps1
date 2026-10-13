#requires -Version 5.1
<#
.SYNOPSIS
Review eight Windows security settings and create an HTML or JSON report.
.EXAMPLE
.\Invoke-SecurityAudit.ps1 -Demo
.EXAMPLE
.\Invoke-SecurityAudit.ps1 -Format Html -OutputPath .\reports\audit.html
#>
[CmdletBinding()]
param(
    [switch]$Demo,
    [ValidateSet('Console', 'Html', 'Json')][string]$Format = 'Console',
    [string]$OutputPath
)

$ErrorActionPreference = 'Stop'
try {
    if ($Format -eq 'Console' -and $OutputPath) { throw 'Use -Format Html or Json when specifying -OutputPath.' }
    Import-Module (Join-Path $PSScriptRoot 'src/WindowsSecurityAudit.psm1') -Force
    if ($Demo) {
        $snapshot = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'examples/sample_snapshot.json') -Raw | ConvertFrom-Json
    } else { $snapshot = Get-WsaSnapshot }
    $report = ConvertTo-WsaReport -Snapshot $snapshot
    if ($Format -eq 'Console') {
        Write-Output "Windows Security Audit | $($report.Mode) | $($report.CollectedAtUtc)"
        $report.Findings | Format-Table Id, Status, Severity, Title -AutoSize | Out-String | Write-Output
        Write-Output ($report.Summary | ConvertTo-Json -Compress)
        Write-Output 'Export HTML or JSON to see evidence and review guidance. Unknown findings are collection gaps.'
    } else {
        $content = if ($Format -eq 'Html') { ConvertTo-WsaHtml $report } else { $report | ConvertTo-Json -Depth 8 }
        if ($OutputPath) {
            Write-WsaFile -Path $OutputPath -Content $content
            Write-Output "Report written: $([IO.Path]::GetFullPath($OutputPath))"
        } else { Write-Output $content }
    }
    exit 0
} catch {
    [Console]::Error.WriteLine('Audit failed: ' + $_.Exception.Message)
    exit 1
}
