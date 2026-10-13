# Code walkthrough

## Follow one finding

Take WSA-01 (firewall). `Get-WsaSnapshot` calls `Get-NetFirewallProfile -PolicyStore ActiveStore` and keeps only the profile name and numeric enabled state. `Invoke-Collector` wraps the result in an object with `Available`, `Data` and `Error`.

`ConvertTo-WsaReport` finds the firewall rule in `Get-WsaRules`. The rule requires exactly one Domain, Private and Public profile, each with a recognized numeric state. If any is disabled, it returns Fail and lists the disabled profiles. Three enabled profiles produce Pass. Missing, duplicate or unrecognized evidence throws an error that the evaluator records as Unknown.

This separation keeps collection and assessment independent. You can reproduce a finding with the synthetic fixture without changing Windows settings.

## Project map

| File | Responsibility |
| --- | --- |
| `Invoke-SecurityAudit.ps1` | Parameters, demo/live selection, console output, report output and exit codes. |
| `src/WindowsSecurityAudit.psm1` | Windows collectors, eight review rules, HTML rendering and protected file creation. |
| `examples/sample_snapshot.json` | Invented source data for a reproducible demo. |
| `examples/sample_report.*` | Reports generated from the demo fixture. |
| `tests/Run-Tests.ps1` | Regression assertions, provider stubs and CLI subprocess checks. |
| `.github/workflows/tests.yml` | Windows PowerShell / PowerShell 7 and Linux demo tests. |

## Design choices worth studying

**Explicit data types.** PowerShell treats nonempty strings such as `"false"` as truthy. Boolean evidence must actually be a Boolean; numeric settings must be a recognized code. Partial data cannot produce a clean audit by accident.

**Provider errors stay visible.** A missing module, unavailable service or denied query is not interpreted as a disabled setting. Each collection failure affects its own finding. The other checks continue.

**Context instead of a score.** A passive Defender instance can be expected with another antivirus. RDP with NLA may be an approved administrative workflow. The tool reports Warning in those situations and asks the reviewer to examine the context.

**Small evidence surface.** The tool collects control state, not user inventories, event-log contents, process command lines, BitLocker recovery keys or network addresses. BitLocker cmdlet objects are reduced to two state codes; full objects are never exported.

**Text remains text.** The renderer HTML-encodes all dynamic strings, including provider errors. The report contains inline styles but no JavaScript or external requests.

**Protect previous work.** `Write-WsaFile` resolves the PowerShell path and opens it with .NET `FileMode.CreateNew`. Existing files are refused atomically. Output follows the current filesystem's permissions; it does not harden ACLs or create parent folders.

## Use the module interactively

```powershell
Import-Module .\src\WindowsSecurityAudit.psm1
$snapshot = Get-Content .\examples\sample_snapshot.json -Raw | ConvertFrom-Json
$report = ConvertTo-WsaReport $snapshot
$report.Findings | Where-Object Status -ne Pass | Format-List
```

The fixture has `SchemaVersion: 1`, a mode and collection timestamp, plus one source per check. Each source has a Boolean `Available` field and `Data`, or an error message. The module evaluator is useful for synthetic experiments; the CLI intentionally does not accept arbitrary snapshot files.

## Extend it carefully

Add a collector, then a rule with a stable ID, specific evidence requirements and honest scope. Add synthetic cases for the expected setting, the conflicting setting and absent evidence. Update the check count, sample data and README. Keep collection read-only and do not add automatic remediation to the audit path.

Possible next learning exercises: effective RDP policy resolution, SMBv1 client checks, audit-policy collection, or comparisons between two JSON reports. Those features are not implemented in version 1.0.0.
