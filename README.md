# Windows Security Audit

A PowerShell tool for reviewing eight Windows security settings. It collects local evidence, applies clear review rules, and produces a console summary or a self-contained HTML / JSON report with findings and follow-up guidance.

Designed as a small Blue Team portfolio project: understand what was checked, what needs attention, and where evidence is missing. It never changes security settings, scans the network, installs software or sends reports anywhere.

## Try the synthetic demo

Requires **Windows PowerShell 5.1 or PowerShell 7**. No external packages. Demo mode also works with PowerShell 7 on Linux and macOS.

```powershell
git clone https://github.com/git-vac/windows-security-audit.git
cd windows-security-audit
.\Invoke-SecurityAudit.ps1 -Demo
.\Invoke-SecurityAudit.ps1 -Demo -Format Html -OutputPath .\reports\demo.html
```

Open `reports/demo.html` in a browser. The demo uses invented values, with an intentionally disabled Public firewall profile and an unavailable BitLocker provider. It does not inspect your computer.

[Example report](examples/sample_report.html) · [Example JSON](examples/sample_report.json) · [Code walkthrough](docs/walkthrough.md)

## Audit a Windows machine

Use a **64-bit** PowerShell process on Windows. Start with the console summary:

```powershell
.\Invoke-SecurityAudit.ps1
.\Invoke-SecurityAudit.ps1 -Format Html -OutputPath .\reports\audit.html
.\Invoke-SecurityAudit.ps1 -Format Json -OutputPath .\reports\audit.json
```

Some providers require administrator rights, a particular Windows edition, or an available module. Those failures become **Unknown** findings with the provider error. For the widest native-module compatibility, use Windows PowerShell 5.1; PowerShell 7 may have module compatibility gaps. The tool never elevates itself. Domain controllers have no built-in local Guest account and that check is Unknown.

If Windows blocks downloaded scripts, review the source and follow your organization's script-signing and execution-policy requirements. This project does not change execution policy.

| Option | Behavior |
| --- | --- |
| `-Demo` | Evaluate the bundled synthetic fixture; no live collection. |
| `-Format Console` | Print finding IDs, status, priority and title (default). |
| `-Format Html` | Render evidence and guidance as a standalone HTML document. |
| `-Format Json` | Emit a report suitable for scripts and comparisons. |
| `-OutputPath FILE` | Write HTML / JSON as UTF-8; parent directory must exist. |

HTML and JSON print to standard output if no output path is supplied. Existing files are refused; choose a new filename for each audit. There is no overwrite option. `Get-Help .\Invoke-SecurityAudit.ps1 -Examples` shows usage examples.

## What it checks

| ID | Check | Evidence and scope |
| --- | --- | --- |
| WSA-01 | Firewall | Domain, Private and Public profiles in `ActiveStore`; rules are not evaluated. |
| WSA-02 | Defender | Normal / passive mode, antivirus and real-time protection; other antivirus products are not validated. |
| WSA-03 | BitLocker | System-drive encryption state and protection status; other drives and recovery-key backup are not checked. |
| WSA-04 | UAC | Admin Approval Mode, admin prompt behavior and secure desktop; not the complete UAC policy. |
| WSA-05 | Remote Desktop | Local deny-connections and NLA registry settings; policy overrides and reachability are not assessed. |
| WSA-06 | SMBv1 server | `EnableSMB1Protocol`; client and optional-feature states need separate review. |
| WSA-07 | Guest | Built-in local Guest account identified by SID suffix `-501`, even if renamed or localized. |
| WSA-08 | PowerShell logging | Explicit HKLM script block logging policies for Windows PowerShell and PowerShell Core. |

The logging check does not resolve HKCU policy, PowerShell Core policy inheritance, `powershell.config.json`, event delivery or retention. Absent explicit HKLM values produce **Warning**, rather than claiming logging is definitely disabled. RDP results describe local registry values and explicitly flag their policy limitations.

## Read findings correctly

- **Pass:** evidence matches this project's specific review rule.
- **Fail:** evidence shows a setting that conflicts with the rule.
- **Warning:** review the setting in context (such as intentional RDP or passive Defender).
- **Unknown:** the provider failed, evidence is missing, or a value is unrecognized.

Priority is the check's review priority, not a CVSS score. Counts deliberately replace an overall security score so unavailable checks cannot inflate a result. This is a focused configuration review, not a CIS certification, vulnerability scanner or proof that a device is secure. Collection is sequential, so settings can change during a run.

Exit code **0** means a report was successfully produced, even if findings are Fail or Unknown. Exit code **1** means invalid option combinations, platform, schema, collection setup or output errors. PowerShell handles parameter-binding failures before script execution. Automation should inspect `Findings[].Status` rather than treating exit 0 as a clean audit.

## Tests

```powershell
.\tests\Run-Tests.ps1
```

The dependency-free suite covers missing evidence, disabled controls, passive antivirus, suspended BitLocker, malformed fields, collection failures, HTML injection protection, JSON preservation, CLI behavior and existing-file protection. It uses synthetic fixtures and provider stubs. GitHub Actions runs it on Windows with both PowerShell engines and on Linux with PowerShell 7.

## Local report data

Keep real reports in `reports/`, which Git ignores. Provider errors and security settings can reveal machine details. Reports elsewhere are not automatically ignored. Review files before publishing. The HTML report escapes dynamic text and loads no JavaScript, remote fonts or external assets. Only synthetic examples are included in this repository.

## References

- [Firewall profile cmdlet](https://learn.microsoft.com/en-us/powershell/module/netsecurity/get-netfirewallprofile): profile state and policy stores.
- [Defender status cmdlet](https://learn.microsoft.com/en-us/powershell/module/defender/get-mpcomputerstatus): antivirus status properties.
- [BitLocker volume cmdlet](https://learn.microsoft.com/en-us/powershell/module/bitlocker/get-bitlockervolume): volume and protection state.
- [UAC policy settings](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/user-account-control/settings-and-configuration): registry policy values and their effects.
- [SMB protocol review](https://learn.microsoft.com/en-us/windows-server/storage/file-server/troubleshoot/detect-enable-and-disable-smbv1-v2-v3): server / client distinction.
- [PowerShell logging on Windows](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging_windows): logging policy and limitations.

MIT licensed. See [LICENSE](LICENSE).
