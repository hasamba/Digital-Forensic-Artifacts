# 012 - Flash Alert: Bumblebee and AdaptixC2 Deliver Akira

Lab-safe PowerShell adversary emulation based on The DFIR Report's [August 5, 2025 flash alert](https://thedfirreport.com/2025/08/05/from-bing-search-to-ransomware-bumblebee-and-adaptixc2-deliver-akira-2/).

This is a dedicated scenario for the flash alert. It is intentionally distinct from `004-Bing_Search_Bumblebee_AdaptixC2_Akira`, which represents the expanded June 2026 public report.

## Flash-alert chain

| Time | Reported behavior represented by the scenario |
|---|---|
| Initial access | Bing search for ManageEngine OpManager, `opmanager.pro`, and `ManageEngine-OpManager.msi` |
| Minutes | `consent.exe` loads `msimg32.dll` Bumblebee and contacts two IP C2s plus DGA domains |
| +5 hours | `AdgNsy.exe` AdaptixC2, rapid domain discovery, `backup_DA`/`backup_EA`, and Enterprise Administrators membership |
| Later session | RDP to the root DC, `wbadmin` NTDS/hive collection, RustDesk, reverse SSH, renamed NetScan `n.exe`, Veeam PostgreSQL query, LSASS dumping, and FileZilla SFTP |
| ~44 hours | First `locker.exe` Akira wave across the root domain |
| +2 days | RustDesk return, child-domain ShareFinder/DNS exports, and second Akira wave |

The generated `attack-timeline.jsonl` and backdated file timestamps preserve these clusters. Runtime process events occur at execution time.

## High-fidelity inert substitutions

- A local lure retains the OpManager URL as a non-navigating data attribute.
- `%USERPROFILE%\Downloads\ManageEngine-OpManager.msi` contains report metadata but is deliberately invalid and non-executable. The real `msiexec.exe` attempts to parse it and exits without installation.
- `consent.exe`, `AdgNsy.exe`, `RustDesk.exe`, `ssh.exe`, `n.exe`, `mstsc.exe`, `wbadmin.exe`, `psql.exe`, `rundll32.exe`, `FileZilla.exe`, and `locker.exe` are renamed copies of signed Windows `cmd.exe`. They generate process-name, shortcut, Prefetch, Amcache, and command-line evidence while executing only `echo` canaries.
- Shell shortcuts provide Explorer-brokered interactive ancestry where Windows Shell automation is available.
- Published Bumblebee and AdaptixC2 domains/IPs are used in `curl.exe` command lines, but `--resolve` or `--connect-to` forces `127.0.0.1`, `--noproxy *` disables proxy use, no redirect following is enabled, and the request times out after two seconds.
- The SSH, SFTP, RDP, SMB, PostgreSQL, and scan attempts target loopback only.
- Domain accounts, group changes, RustDesk service state, NTDS/hives, Veeam credentials, and LSASS dump output are generated canaries. No real credential source is opened.
- Root- and child-domain documents are generated beneath `%PUBLIC%\AkiraFlashSim`. `.akira` representation files are created beside intact originals; no cryptography or user-data traversal occurs.
- No security control, GPO/SYSVOL object, backup, log, shadow copy, remote system, or real IOC is modified or contacted.

Every decoy's actual SHA-256 is recorded alongside the report hash, with `hashMatchExpected: false`.

## Run

Use an elevated Windows PowerShell 5.1 or later session on a disposable lab VM:

```powershell
.\AkiraFlashSim-Complete.ps1 -LabConfirmed
```

The script refuses domain controllers using both `Win32_ComputerSystem.DomainRole` and the `NTDS` service. It refuses to overwrite an existing `ManageEngine-OpManager.msi` without the matching ownership marker.

Artifacts remain beneath `%PUBLIC%\AkiraFlashSim` and in the owned Downloads MSI path for acquisition and timeline work.

## Cleanup

Cleanup is a separate explicit action:

```powershell
.\Cleanup-AkiraFlashSim.ps1 -LabConfirmed -WhatIf
.\Cleanup-AkiraFlashSim.ps1 -LabConfirmed
```

The cleanup validates the fixed scenario root and MSI ownership marker before removal.

## Scenario ATT&CK mapping

The flash alert does not publish an ATT&CK table; these mappings are derived from its observed behavior:

| Behavior | Technique |
|---|---|
| SEO lure and malicious installer | T1189, T1204.002 |
| MSI execution | T1218.007 |
| `msimg32.dll` side-loading | T1574.002 |
| Bumblebee/Adaptix web C2 | T1071.001 |
| Windows/domain discovery | T1082, T1016, T1018, T1482, T1069.002 |
| Create `backup_DA` and `backup_EA` | T1136.002 |
| Add Enterprise Administrators membership | T1098.007 |
| RDP lateral movement | T1021.001 |
| NTDS and registry hive collection | T1003.003 |
| LSASS dump representation | T1003.001 |
| RustDesk | T1219 |
| Reverse SSH tunnel | T1572 |
| NetScan | T1046 |
| FileZilla SFTP exfiltration | T1048.002 |
| Archive generated collection canaries | T1560.001 |
| Akira impact representation | T1486 |

## Investigation cues

- Correlate `msiexec.exe` with the user Downloads path, `consent.exe`, `msimg32.dll`, and Bumblebee loopback command lines.
- Locate the five-hour Adaptix transition and rapid discovery sequence.
- Review synthetic account/group, NTDS, Veeam, LSASS, RustDesk, SSH, NetScan, and FileZilla artifacts.
- Compare the root- and child-domain ransomware waves and confirm originals remain intact.
- Use [IOC-METADATA.json](IOC-METADATA.json) offline; never attempt to retrieve its reported samples.
