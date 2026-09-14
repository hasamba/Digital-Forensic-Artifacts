# 054 - 2021 Year In Review composite

Lab-safe PowerShell companion to The DFIR Report's [2021 Year In Review](https://thedfirreport.com/2022/03/07/2021-year-in-review/).

This source aggregates 20 public incidents rather than documenting one intrusion. The scenario therefore creates 20 explicitly synthetic case lanes and preserves the report's published counts without claiming false per-case correlation: 16 phishing cases, persistence in 14 cases, security-tool impairment in five, and exfiltration in six. It also represents vulnerable web applications, TrickBot/Bazar/IcedID/Hancitor, Cobalt Strike's common `jquery-3.3.1.min.js`/`rundll32.exe` pattern, scheduled tasks/BITS/Run keys/RMM, LSASS/NTDS/hive access, rapid native-tool and AdFind discovery, RDP/WMI/PsExec movement, Rclone/FileZilla/WinSCP exfiltration, and ransomware/cryptominer outcomes.

All executable names are signed `cmd.exe` copies whose executed arguments are fixed benign text; reported command lines remain telemetry metadata. Network attempts terminate on `127.0.0.1` with no proxy and zero bytes transferred. No phishing, exploit, malware, persistence, credential access, directory/share query, scan, remote action, data collection, exfiltration, mining, or encryption occurs.

```powershell
.\Year2021Sim-Complete.ps1 -LabConfirmed
```

Artifacts remain under `%PUBLIC%\YearReview2021Sim`; cleanup is separately gated. See [scenario-manifest.json](scenario-manifest.json) for the aggregate-provenance warning and [IOC-METADATA.json](IOC-METADATA.json) for the report's behavior metadata.
