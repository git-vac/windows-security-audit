#requires -Version 5.1
# Dependency-free regression suite: runs in Windows PowerShell 5.1 and PowerShell 7.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$root = Split-Path $PSScriptRoot -Parent
Import-Module (Join-Path $root 'src/WindowsSecurityAudit.psm1') -Force
$script:count = 0

function Assert-Equal {
    param($Actual, $Expected, [string]$Message)
    if ($Actual -cne $Expected) { throw "$Message (expected '$Expected', got '$Actual')" }
    $script:count++
}
function New-Snapshot {
    Get-Content -LiteralPath (Join-Path $root 'examples/sample_snapshot.json') -Raw | ConvertFrom-Json
}
function Get-Status {
    param($Snapshot, [string]$Id)
    (ConvertTo-WsaReport $Snapshot).Findings | Where-Object { $_.Id -eq $Id } | Select-Object -ExpandProperty Status
}
function Assert-Throws {
    param([scriptblock]$Action, [string]$Message)
    $threw = $false
    try { & $Action | Out-Null } catch { $threw = $true }
    Assert-Equal $threw $true $Message
}

$snapshot = New-Snapshot
$report = ConvertTo-WsaReport $snapshot
Assert-Equal $report.Findings.Count 8 'Always emit all eight findings'
Assert-Equal $report.Summary.Pass 4 'Demo pass count'
Assert-Equal $report.Summary.Fail 1 'Demo fail count'
Assert-Equal $report.Summary.Warning 2 'Demo warning count'
Assert-Equal $report.Summary.Unknown 1 'Demo unknown count'
Assert-Equal (@($report.Findings.Id | Select-Object -Unique).Count) 8 'Stable unique IDs'

$snapshot = New-Snapshot
$snapshot.Sources = [pscustomobject]@{}
Assert-Equal (ConvertTo-WsaReport $snapshot).Summary.Unknown 8 'Absent sources never pass'
$snapshot.SchemaVersion = 2
Assert-Throws { ConvertTo-WsaReport $snapshot } 'Reject unsupported schema'

$snapshot = New-Snapshot
$snapshot.Sources.Firewall.Data[2].Enabled = 1
Assert-Equal (Get-Status $snapshot 'WSA-01') 'Pass' 'All firewall profiles enabled'
$snapshot.Sources.Firewall.Data = @($snapshot.Sources.Firewall.Data[0])
Assert-Equal (Get-Status $snapshot 'WSA-01') 'Unknown' 'Partial firewall evidence'
$snapshot = New-Snapshot
$snapshot.Sources.Firewall.Data[2].Name = 'Private'
Assert-Equal (Get-Status $snapshot 'WSA-01') 'Unknown' 'Duplicate profile cannot hide Public'
$snapshot = New-Snapshot
$snapshot.Sources.Firewall.Data[2].Enabled = 2
Assert-Equal (Get-Status $snapshot 'WSA-01') 'Unknown' 'NotConfigured is not enabled'

$snapshot = New-Snapshot
$snapshot.Sources.Defender.Data.RealTimeProtectionEnabled = $false
Assert-Equal (Get-Status $snapshot 'WSA-02') 'Fail' 'Disabled real-time protection'
$snapshot.Sources.Defender.Data.AMRunningMode = 'Passive'
Assert-Equal (Get-Status $snapshot 'WSA-02') 'Warning' 'Passive antivirus requires review'
$snapshot.Sources.Defender.Data.AMRunningMode = 'Normal'
$snapshot.Sources.Defender.Data.RealTimeProtectionEnabled = 'false'
Assert-Equal (Get-Status $snapshot 'WSA-02') 'Unknown' 'String false is not a Boolean'
$snapshot.Sources.Defender.Available = 'true'
Assert-Equal (Get-Status $snapshot 'WSA-02') 'Unknown' 'Availability must be a Boolean'

$snapshot = New-Snapshot
$snapshot.Sources.BitLocker = [pscustomobject]@{ Available = $true; Data = [pscustomobject]@{ ProtectionStatus = 1; VolumeStatus = 1 } }
Assert-Equal (Get-Status $snapshot 'WSA-03') 'Pass' 'Fully encrypted with protection on'
$snapshot.Sources.BitLocker.Data.ProtectionStatus = 0
Assert-Equal (Get-Status $snapshot 'WSA-03') 'Fail' 'Suspended encryption is not protected'
$snapshot.Sources.BitLocker.Data.ProtectionStatus = 2
Assert-Equal (Get-Status $snapshot 'WSA-03') 'Unknown' 'Provider Unknown remains Unknown'
$snapshot.Sources.BitLocker.Data.ProtectionStatus = 1
$snapshot.Sources.BitLocker.Data.VolumeStatus = 2
Assert-Equal (Get-Status $snapshot 'WSA-03') 'Warning' 'Encryption in progress is not complete'

$snapshot = New-Snapshot
$snapshot.Sources.Uac.Data.EnableLUA = 0
Assert-Equal (Get-Status $snapshot 'WSA-04') 'Fail' 'UAC disabled'
$snapshot.Sources.Uac.Data.EnableLUA = 1
$snapshot.Sources.Uac.Data.ConsentPromptBehaviorAdmin = 0
Assert-Equal (Get-Status $snapshot 'WSA-04') 'Fail' 'Silent elevation fails'
$snapshot.Sources.Uac.Data.ConsentPromptBehaviorAdmin = 5
$snapshot.Sources.Uac.Data.PromptOnSecureDesktop = 0
Assert-Equal (Get-Status $snapshot 'WSA-04') 'Fail' 'Secure desktop disabled'

$snapshot = New-Snapshot
$snapshot.Sources.Rdp.Data.DenyConnections = 1
$snapshot.Sources.Rdp.Data.NlaRequired = $null
Assert-Equal (Get-Status $snapshot 'WSA-05') 'Pass' 'Disabled RDP does not require NLA evidence'
$snapshot.Sources.Rdp.Data.DenyConnections = 0
$snapshot.Sources.Rdp.Data.NlaRequired = 0
Assert-Equal (Get-Status $snapshot 'WSA-05') 'Fail' 'Enabled RDP without NLA'
$snapshot.Sources.Rdp.Data.NlaRequired = $null
Assert-Equal (Get-Status $snapshot 'WSA-05') 'Unknown' 'Enabled RDP with unknown NLA'

$snapshot = New-Snapshot
$snapshot.Sources.Smb1.Data.ServerEnabled = $true
Assert-Equal (Get-Status $snapshot 'WSA-06') 'Fail' 'Legacy SMB server enabled'
$snapshot.Sources.Guest.Data.Enabled = $true
Assert-Equal (Get-Status $snapshot 'WSA-07') 'Fail' 'Guest enabled'
$snapshot.Sources.Logging.Data.PowerShellCore = 1
Assert-Equal (Get-Status $snapshot 'WSA-08') 'Pass' 'Both explicit logging policies'
$snapshot.Sources.Logging.Data = [pscustomobject]@{}
Assert-Equal (Get-Status $snapshot 'WSA-08') 'Unknown' 'Malformed logging evidence'

# Every rule must reject incomplete data and preserve provider errors.
foreach ($source in (New-Snapshot).Sources.PSObject.Properties.Name) {
    $snapshot = New-Snapshot
    $snapshot.Sources.$source = [pscustomobject]@{ Available = $true; Data = [pscustomobject]@{} }
    $finding = (ConvertTo-WsaReport $snapshot).Findings | Where-Object { $_.Id -eq @{
        Firewall='WSA-01'; Defender='WSA-02'; BitLocker='WSA-03'; Uac='WSA-04'; Rdp='WSA-05'; Smb1='WSA-06'; Guest='WSA-07'; Logging='WSA-08'
    }[$source] }
    Assert-Equal $finding.Status 'Unknown' "Malformed $source evidence"
}

$snapshot = New-Snapshot
$snapshot.Sources.BitLocker.Error = '<script>alert("x")</script> & access denied'
$snapshot.Mode = '<img src=x onerror=alert(1)>'
$report = ConvertTo-WsaReport $snapshot
$html = ConvertTo-WsaHtml $report
Assert-Equal ($html.Contains('<script>')) $false 'Provider error cannot inject HTML'
Assert-Equal ($html.Contains('<img src=x')) $false 'Metadata cannot inject HTML'
Assert-Equal ($html.Contains('&lt;script&gt;')) $true 'Escaped evidence remains visible'
Assert-Equal ($html.Contains('&amp; access denied')) $true 'Escape ampersands'
$roundtrip = $report | ConvertTo-Json -Depth 8 | ConvertFrom-Json
Assert-Equal $roundtrip.Findings[2].Evidence $report.Findings[2].Evidence 'JSON preserves evidence'

# Exercise collection failures without changing settings or contacting providers.
$module = Get-Module WindowsSecurityAudit
& $module {
    function Get-NetFirewallProfile { throw 'Stub firewall unavailable' }
    function Get-MpComputerStatus { throw 'Stub Defender unavailable' }
    function Get-BitLockerVolume { throw 'Stub BitLocker unavailable' }
    function Get-ItemProperty { throw 'Stub registry unavailable' }
    function Get-SmbServerConfiguration { throw 'Stub SMB unavailable' }
    function Get-LocalUser { throw 'Stub accounts unavailable' }
    function Test-Path { throw 'Stub registry unavailable' }
    if ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT -and [Environment]::Is64BitProcess) {
        $r = ConvertTo-WsaReport (Get-WsaSnapshot)
        if ($r.Summary.Unknown -ne 8) { throw 'Provider failures must yield eight Unknown findings.' }
        if ($r.Findings[0].Evidence -notlike '*Stub firewall unavailable*') { throw 'Provider error was lost.' }
    } else {
        $threw = $false
        try { Get-WsaSnapshot | Out-Null } catch { $threw = $true }
        if (-not $threw) { throw 'Unsupported platforms must reject live collection.' }
    }
}
$script:count++

# Isolated temporary directory; no personal reports touched.
$temporary = Join-Path ([IO.Path]::GetTempPath()) ('wsa-tests-' + [Guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($temporary) | Out-Null
try {
    $output = Join-Path $temporary 'report with spaces.json'
    Write-WsaFile $output '{"ok":true}'
    Assert-Equal (Get-Content -LiteralPath $output -Raw) '{"ok":true}' 'Write report with spaces'
    Assert-Throws { Write-WsaFile $output 'replacement' } 'Refuse existing output'
    Assert-Equal (Get-Content -LiteralPath $output -Raw) '{"ok":true}' 'Existing file preserved'
    Assert-Throws { Write-WsaFile (Join-Path $temporary 'missing/report.html') 'x' } 'Missing parent directory fails'
    $entry = Join-Path $root 'Invoke-SecurityAudit.ps1'
    $engine = (Get-Process -Id $PID).Path
    & $engine -NoProfile -File $entry -Demo -Format Json -OutputPath (Join-Path $temporary 'cli.json') | Out-Null
    Assert-Equal $LASTEXITCODE 0 'Demo CLI succeeds'
    $cli = Get-Content -LiteralPath (Join-Path $temporary 'cli.json') -Raw | ConvertFrom-Json
    Assert-Equal $cli.Mode 'Demo' 'Demo does not collect live values'
    Assert-Equal $cli.Findings.Count 8 'CLI serializes all findings'
    $ErrorActionPreference = 'Continue' # Windows PowerShell maps native stderr to error records.
    & $engine -NoProfile -File $entry -Demo -Format Json -OutputPath (Join-Path $temporary 'cli.json') 2>$null | Out-Null
    $ErrorActionPreference = 'Stop'
    Assert-Equal $LASTEXITCODE 1 'CLI refuses overwrite'
    $ErrorActionPreference = 'Continue'
    & $engine -NoProfile -File $entry -Demo -OutputPath (Join-Path $temporary 'invalid.txt') 2>$null | Out-Null
    $ErrorActionPreference = 'Stop'
    Assert-Equal $LASTEXITCODE 1 'Console output path rejected'
    # All code files must parse; catches syntax errors before deployment.
    foreach ($file in Get-ChildItem -LiteralPath $root -Recurse -File | Where-Object { $_.Extension -in @('.ps1', '.psm1') }) {
        $tokens = $null; $errors = $null
        [Management.Automation.Language.Parser]::ParseFile($file.FullName, [ref]$tokens, [ref]$errors) | Out-Null
        Assert-Equal $errors.Count 0 "Parse $($file.Name)"
    }
} finally {
    # Verify the resolved disposable target before recursive cleanup.
    $resolved = [IO.Path]::GetFullPath($temporary)
    $tempRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
    if ($resolved.StartsWith($tempRoot, [StringComparison]::OrdinalIgnoreCase) -and (Split-Path $resolved -Leaf) -like 'wsa-tests-*') {
        Remove-Item -LiteralPath $resolved -Recurse -Force
    }
}
Write-Output "Passed $script:count assertions."
# Expected failing CLI subprocesses leave LASTEXITCODE=1. Report suite success explicitly.
exit 0
