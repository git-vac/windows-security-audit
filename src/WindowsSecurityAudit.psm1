#requires -Version 5.1
Set-StrictMode -Version Latest

function Get-Field {
    param($Object, [string]$Name)
    if ($null -eq $Object) { return $null }
    $property = $Object.PSObject.Properties[$Name]
    if ($null -ne $property) { return $property.Value }
    return $null
}

function Assert-Boolean {
    param($Value)
    if ($Value -isnot [bool]) { throw 'Missing or invalid Boolean evidence.' }
}

function Assert-Number {
    param($Value, [int[]]$Allowed)
    if (($Value -isnot [int] -and $Value -isnot [long] -and $Value -isnot [double]) -or
        $Value -notin $Allowed) { throw 'Missing or invalid numeric evidence.' }
}

function Invoke-Collector {
    param([scriptblock]$Query)
    try {
        $data = & $Query
        if ($null -eq $data) { throw 'The provider returned no data.' }
        [pscustomobject]@{ Available = $true; Data = $data; Error = $null }
    } catch {
        [pscustomobject]@{ Available = $false; Data = $null; Error = $_.Exception.Message }
    }
}

function Get-LoggingPolicy {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path -ErrorAction Stop)) { return 0 }
    $value = Get-Field (Get-ItemProperty -LiteralPath $Path -ErrorAction Stop) 'EnableScriptBlockLogging'
    if ($null -eq $value) { return 0 }
    return $value
}

function Get-WsaSnapshot {
    <# .SYNOPSIS Collect local Windows settings without modifying them. #>
    [CmdletBinding()]
    param()
    if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
        throw 'Live collection requires Windows. Use -Demo on other platforms.'
    }
    if (-not [Environment]::Is64BitProcess) { throw 'Use a 64-bit PowerShell process for live collection.' }

    $sources = [ordered]@{}
    $sources.Firewall = Invoke-Collector {
        @(Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop | ForEach-Object {
            [pscustomobject]@{ Name = [string]$_.Name; Enabled = [int]$_.Enabled }
        })
    }
    $sources.Defender = Invoke-Collector {
        $d = Get-MpComputerStatus -ErrorAction Stop
        [pscustomobject]@{
            AMRunningMode = Get-Field $d 'AMRunningMode'
            AntivirusEnabled = Get-Field $d 'AntivirusEnabled'
            RealTimeProtectionEnabled = Get-Field $d 'RealTimeProtectionEnabled'
        }
    }
    $sources.BitLocker = Invoke-Collector {
        $b = Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction Stop
        [pscustomobject]@{
            ProtectionStatus = if ($null -ne (Get-Field $b 'ProtectionStatus')) { [int]$b.ProtectionStatus } else { $null }
            VolumeStatus = if ($null -ne (Get-Field $b 'VolumeStatus')) { [int]$b.VolumeStatus } else { $null }
        }
    }
    $sources.Uac = Invoke-Collector {
        $u = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -ErrorAction Stop
        [pscustomobject]@{
            EnableLUA = Get-Field $u 'EnableLUA'
            ConsentPromptBehaviorAdmin = Get-Field $u 'ConsentPromptBehaviorAdmin'
            PromptOnSecureDesktop = Get-Field $u 'PromptOnSecureDesktop'
        }
    }
    $sources.Rdp = Invoke-Collector {
        $r = Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -ErrorAction Stop
        $n = Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -ErrorAction Stop
        [pscustomobject]@{ DenyConnections = Get-Field $r 'fDenyTSConnections'; NlaRequired = Get-Field $n 'UserAuthentication' }
    }
    $sources.Smb1 = Invoke-Collector {
        $s = Get-SmbServerConfiguration -ErrorAction Stop
        [pscustomobject]@{ ServerEnabled = Get-Field $s 'EnableSMB1Protocol' }
    }
    $sources.Guest = Invoke-Collector {
        # RID 501 survives account renaming and localized Windows installations.
        $g = @(Get-LocalUser -ErrorAction Stop | Where-Object { $_.SID.Value -match '-501$' })
        if ($g.Count -ne 1) { throw 'A unique built-in Guest account was not found (domain controllers have no local SAM).' }
        [pscustomobject]@{ Enabled = $g[0].Enabled }
    }
    $sources.Logging = Invoke-Collector {
        [pscustomobject]@{
            WindowsPowerShell = Get-LoggingPolicy 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
            PowerShellCore = Get-LoggingPolicy 'HKLM:\SOFTWARE\Policies\Microsoft\PowerShellCore\ScriptBlockLogging'
        }
    }
    [pscustomobject]@{
        SchemaVersion = 1
        Mode = 'Live'
        CollectedAtUtc = [DateTime]::UtcNow.ToString('o')
        Sources = [pscustomobject]$sources
    }
}

function Get-WsaRules {
    # These are project review rules, not a certification or a CIS benchmark.
    @(
        @{ Id = 'WSA-01'; Source = 'Firewall'; Title = 'Firewall profiles'; Severity = 'High'
           Guidance = 'Enable the Domain, Private and Public firewall profiles. Review effective rules separately.'
           Evaluate = {
               param($d)
               $profiles = @($d)
               if ($profiles.Count -ne 3) { throw 'Expected exactly three firewall profiles.' }
               foreach ($name in @('Domain', 'Private', 'Public')) {
                   $p = @($profiles | Where-Object { (Get-Field $_ 'Name') -eq $name })
                   if ($p.Count -ne 1) { throw "Missing or duplicated profile: $name." }
                   Assert-Number (Get-Field $p[0] 'Enabled') @(0, 1)
               }
               $disabled = @($profiles | Where-Object { $_.Enabled -eq 0 } | ForEach-Object { $_.Name })
               if ($disabled.Count) { return @('Fail', "Disabled profiles: $($disabled -join ', ').") }
               @('Pass', 'Domain, Private and Public profiles are enabled in ActiveStore.')
           }
        }
        @{ Id = 'WSA-02'; Source = 'Defender'; Title = 'Microsoft Defender protection'; Severity = 'High'
           Guidance = 'Review Windows Security and your approved antivirus product. Passive Defender can be intentional with another antivirus; this tool does not validate that product.'
           Evaluate = {
               param($d)
               $mode = Get-Field $d 'AMRunningMode'
               if ($mode -in @('Passive', 'SxS Passive Mode', 'EDR Block Mode')) {
                   return @('Warning', "Defender mode: $mode. Verify the primary antivirus separately.")
               }
               if ($mode -ne 'Normal') { throw 'Defender running mode is missing or not recognized.' }
               $av = Get-Field $d 'AntivirusEnabled'; $rt = Get-Field $d 'RealTimeProtectionEnabled'
               Assert-Boolean $av; Assert-Boolean $rt
               if ($av -and $rt) { return @('Pass', 'Defender is in Normal mode with antivirus and real-time protection enabled.') }
               @('Fail', "Defender Normal mode: antivirus=$av; real-time protection=$rt.")
           }
        }
        @{ Id = 'WSA-03'; Source = 'BitLocker'; Title = 'System drive BitLocker'; Severity = 'High'
           Guidance = 'Review system-drive encryption and protection in BitLocker settings. Back up recovery keys securely before changing protection.'
           Evaluate = {
               param($d)
               $p = Get-Field $d 'ProtectionStatus'; $v = Get-Field $d 'VolumeStatus'
               Assert-Number $p @(0, 1, 2); Assert-Number $v @(0, 1, 2, 3, 4, 5)
               if ($p -eq 2) { throw 'BitLocker protection status is Unknown.' }
               if ($p -eq 0) { return @('Fail', "System-drive protection is off (volume status code $v); encryption may be suspended or absent.") }
               if ($v -eq 1) { return @('Pass', 'System drive is fully encrypted and BitLocker protection is on.') }
               @('Warning', "Protection is on, but the system drive is not fully encrypted (volume status code $v).")
           }
        }
        @{ Id = 'WSA-04'; Source = 'Uac'; Title = 'User Account Control'; Severity = 'High'
           Guidance = 'Review UAC policy: enable Admin Approval Mode and prompts on the secure desktop. This check does not inspect standard-user or built-in Administrator policies.'
           Evaluate = {
               param($d)
               $lua = Get-Field $d 'EnableLUA'; Assert-Number $lua @(0, 1)
               if ($lua -eq 0) { return @('Fail', 'EnableLUA=0: Admin Approval Mode is disabled.') }
               $consent = Get-Field $d 'ConsentPromptBehaviorAdmin'; $desktop = Get-Field $d 'PromptOnSecureDesktop'
               Assert-Number $consent @(0, 1, 2, 3, 4, 5); Assert-Number $desktop @(0, 1)
               if ($consent -eq 0 -or $desktop -eq 0) { return @('Fail', "EnableLUA=1; admin prompt=$consent; secure desktop=$desktop.") }
               @('Pass', "EnableLUA=1; admin prompt=$consent; secure desktop=1. A restart may be needed after policy changes.")
           }
        }
        @{ Id = 'WSA-05'; Source = 'Rdp'; Title = 'Remote Desktop configuration'; Severity = 'Medium'
           Guidance = 'Disable Remote Desktop when unused. If needed, require NLA and review policy overrides, firewall scope and access groups. Registry settings alone do not establish network reachability.'
           Evaluate = {
               param($d)
               $deny = Get-Field $d 'DenyConnections'; Assert-Number $deny @(0, 1)
               if ($deny -eq 1) { return @('Pass', 'Local Terminal Server registry denies RDP connections; policy overrides are not assessed.') }
               $nla = Get-Field $d 'NlaRequired'; Assert-Number $nla @(0, 1)
               if ($nla -eq 0) { return @('Fail', 'Local RDP configuration allows connections without requiring NLA.') }
               @('Warning', 'Local RDP configuration allows connections with NLA. Confirm that remote access is intended and review effective policy.')
           }
        }
        @{ Id = 'WSA-06'; Source = 'Smb1'; Title = 'SMBv1 server protocol'; Severity = 'High'
           Guidance = 'Disable the SMBv1 server protocol after reviewing legacy dependencies. This check covers the server configuration only; the SMBv1 client and optional feature need separate review.'
           Evaluate = {
               param($d)
               $v = Get-Field $d 'ServerEnabled'; Assert-Boolean $v
               if ($v) { return @('Fail', 'EnableSMB1Protocol=True on the SMB server.') }
               @('Pass', 'EnableSMB1Protocol=False on the SMB server; client state is not assessed.')
           }
        }
        @{ Id = 'WSA-07'; Source = 'Guest'; Title = 'Built-in local Guest account'; Severity = 'Medium'
           Guidance = 'Disable the built-in local Guest account unless an approved workflow explicitly requires it. Other local accounts and group memberships are outside this check.'
           Evaluate = {
               param($d)
               $v = Get-Field $d 'Enabled'; Assert-Boolean $v
               if ($v) { return @('Fail', 'Built-in local Guest account (RID 501) is enabled.') }
               @('Pass', 'Built-in local Guest account (RID 501) is disabled.')
           }
        }
        @{ Id = 'WSA-08'; Source = 'Logging'; Title = 'PowerShell script block logging policy'; Severity = 'Low'
           Guidance = 'Review script block logging for both Windows PowerShell and PowerShell 7. This checks explicit HKLM policies only; HKCU settings, Core policy inheritance, log retention and event delivery are not assessed. Logged script content can contain secrets.'
           Evaluate = {
               param($d)
               $w = Get-Field $d 'WindowsPowerShell'; $c = Get-Field $d 'PowerShellCore'
               Assert-Number $w @(0, 1); Assert-Number $c @(0, 1)
               if ($w -eq 1 -and $c -eq 1) { return @('Pass', 'Explicit HKLM script block logging policies are enabled for both engines.') }
               @('Warning', "Explicit HKLM policies: Windows PowerShell=$w; PowerShell Core=$c (0 includes absent values). Other policy paths may still enable logging.")
           }
        }
    )
}

function ConvertTo-WsaReport {
    <# .SYNOPSIS Evaluate a snapshot; missing evidence always becomes Unknown. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Snapshot)
    if ((Get-Field $Snapshot 'SchemaVersion') -ne 1) { throw 'Unsupported snapshot schema version.' }
    $findings = @(foreach ($rule in Get-WsaRules) {
        $status = 'Unknown'; $evidence = 'Evidence was not collected.'
        $source = Get-Field (Get-Field $Snapshot 'Sources') $rule.Source
        $available = Get-Field $source 'Available'
        if ($available -is [bool] -and $available) {
            try {
                $result = & $rule.Evaluate (Get-Field $source 'Data')
                $status = $result[0]; $evidence = $result[1]
            } catch { $evidence = $_.Exception.Message }
        } elseif ($null -ne (Get-Field $source 'Error')) {
            $evidence = 'Collection failed: ' + (Get-Field $source 'Error')
        }
        [pscustomobject]@{
            Id = $rule.Id; Title = $rule.Title; Status = $status; Severity = $rule.Severity
            Evidence = $evidence; Guidance = $rule.Guidance
        }
    })
    $counts = [ordered]@{}
    foreach ($s in @('Pass', 'Fail', 'Warning', 'Unknown')) { $counts[$s] = @($findings | Where-Object { $_.Status -eq $s }).Count }
    [pscustomobject]@{
        SchemaVersion = 1; ToolVersion = '1.0.0'
        Mode = Get-Field $Snapshot 'Mode'; CollectedAtUtc = Get-Field $Snapshot 'CollectedAtUtc'
        Summary = [pscustomobject]$counts; Findings = $findings
    }
}

function ConvertTo-WsaHtml {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Report)
    $encode = { param($s) [System.Net.WebUtility]::HtmlEncode([string]$s) }
    $cards = foreach ($f in $Report.Findings) {
        $status = & $encode $f.Status
        '<article><header><span class="badge {0}">{0}</span><span class="severity">{1} priority</span></header><h2>{2} &middot; {3}</h2><p>{4}</p><p class="guidance"><strong>Review:</strong> {5}</p></article>' -f
            $status, (& $encode $f.Severity), (& $encode $f.Id), (& $encode $f.Title), (& $encode $f.Evidence), (& $encode $f.Guidance)
    }
    $counts = foreach ($s in @('Pass', 'Fail', 'Warning', 'Unknown')) {
        '<div class="stat"><strong>{0}</strong><span>{1}</span></div>' -f $Report.Summary.$s, $s
    }
    @"
<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Windows Security Audit</title><style>
:root{color-scheme:dark}*{box-sizing:border-box}body{margin:0;background:#101923;color:#e5edf5;font:16px/1.6 system-ui,sans-serif}main{max-width:1020px;margin:auto;padding:48px 24px}h1{font-size:clamp(30px,5vw,46px);line-height:1.15;margin:12px 0}h2{font-size:20px;margin:16px 0 10px}.eyebrow{color:#6bdbcd;font-size:13px;letter-spacing:.16em;text-transform:uppercase}.muted,.severity{color:#abbccd}.stats{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin:28px 0}.stat{background:#1b2a39;border:1px solid #334658;border-radius:12px;padding:16px}.stat strong{font-size:32px;display:block}.stat span{color:#b4c6d5}.grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:18px}article{background:#182633;border:1px solid #334658;border-radius:12px;padding:22px;overflow-wrap:anywhere}header{display:flex;gap:12px;align-items:center;flex-wrap:wrap}.badge{font-size:13px;font-weight:700;border-radius:6px;padding:3px 10px}.Pass{background:#17483c;color:#9ce9c8}.Fail{background:#552b35;color:#ffb5bd}.Warning{background:#4a3b1b;color:#ffe0a1}.Unknown{background:#333d50;color:#cdd7ef}.severity{font-size:13px}.guidance{color:#bacbd9;font-size:14px;border-top:1px solid #334658;padding-top:12px}.notice{border-left:3px solid #6bdbcd;padding-left:14px;margin:24px 0;color:#bbcbd8}footer{margin-top:28px;color:#a3b7c8;font-size:13px}@media(max-width:700px){.grid{grid-template-columns:1fr}.stats{grid-template-columns:repeat(2,1fr)}main{padding:28px 16px}}@media print{:root{color-scheme:light}body{background:white;color:black}article,.stat{background:white;color:black;break-inside:avoid}.muted,.guidance,.severity,.notice,footer,.stat span{color:#333}}
</style></head><body><main>
<div class="eyebrow">Local configuration review / v1.0.0</div><h1>Windows Security Audit</h1>
<p class="muted">Mode: $(& $encode $Report.Mode) &middot; Collected: $(& $encode $Report.CollectedAtUtc)</p>
<div class="notice">Eight focused checks. Pass means a specific rule matched, not that the machine is secure. Unknown means evidence is missing. Demo data is synthetic. Settings are never changed.</div>
<section class="stats" aria-label="Finding counts">$($counts -join "`n")</section>
<section class="grid" aria-label="Security findings">$($cards -join "`n")</section>
<footer>Review findings in context. This project does not certify CIS compliance or establish network exposure. No scripts, remote fonts or external assets are loaded by this report.</footer>
</main></body></html>
"@
}

function Write-WsaFile {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$Content)
    # CreateNew protects existing reports even when two writers race. No overwrite flag.
    $fullPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path)
    $stream = [IO.File]::Open($fullPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try {
        $bytes = [Text.UTF8Encoding]::new($false).GetBytes($Content)
        $stream.Write($bytes, 0, $bytes.Length)
    } finally { $stream.Dispose() }
}

Export-ModuleMember -Function Get-WsaSnapshot, ConvertTo-WsaReport, ConvertTo-WsaHtml, Write-WsaFile
