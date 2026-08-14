# EtherRAT → TukTuk → The Gentlemen lab emulation

This workspace contains a lab-safe PowerShell emulation of the intrusion in The DFIR Report's [May 11, 2026 flash alert](https://thedfirreport.com/2026/05/11/flash-alert-etherrat-and-tuktuk-c2-end-in-the-gentleman-ransomware/).

The script creates useful endpoint artifacts and process command lines while keeping the dangerous portions inert. It does not contain malware and does not perform real credential theft, remote execution, cloud exfiltration, security-control impairment, log clearing, shadow-copy deletion, Group Policy modification, propagation, or user-data encryption.

## What is represented

| Reported phase | Lab representation | ATT&CK examples |
|---|---|---|
| Fake RAMMap MSI | Invalid `RAMMap.msi`, `msiexec.exe`, benign `MVnVmUYj.cmd` | T1204.002, T1218.007, T1036 |
| EtherRAT/Node execution | Renamed signed `cmd.exe` as `node.exe`; inert `.cfg`/`.ini` | T1059.007, T1105 |
| Persistence | HKCU Run value whose command exits immediately | T1547.001 |
| EtherHiding and tunnel C2 | Report IOC hostnames in `curl.exe` command lines, forcibly resolved to `127.0.0.1` with proxy bypass | T1102.002, T1102.003 |
| Host/domain discovery | Read-only native discovery commands; domain queries require an explicit domain-lab switch | T1082, T1518.001, T1482, T1069.002 |
| TukTuk sideloading | Greenshot/SyncTrayzor/DocFX/Cake-shaped renamed binaries with inert adjacent `log4net.dll` text files | T1574.001, T1036 |
| Kerberoasting/LSASS | Synthetic Kerberos string; optional dump of a script-started Notepad process only | T1558.003, T1003.001 |
| Mimikatz/NetExec/RDP/SMB/WinRM | Renamed signed shims and documentation-only IP artifacts; no remote socket | T1003, T1021 |
| GoTo Resolve | Invalid installer; optional disabled inert service | T1219, T1543.003 |
| Rclone/Wasabi | Local copy/archive of generated canaries; Wasabi hostname pinned to loopback | T1074.001, T1560.001, T1567.002 |
| Defense evasion | Dangerous commands recorded as blocked markers; only read-only `vssadmin`/`wevtutil` operations execute | T1562.001, T1490, T1070.001 |
| GPO ransomware deployment | Fake SYSVOL tree and disabled fake-GPO XML; optional disabled local task | T1484.001, T1053.005 |
| Ransomware impact | Only generated canary filenames gain `.gentlemen`; originals are retained | T1486, T1491.001 |

## Run it

Take a VM snapshot first and ensure your EDR/Sysmon/PowerShell logging is configured. Run from Windows PowerShell 5.1 or later on an authorized workstation/member-server lab VM:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\Invoke-GentlemenEmulation.ps1 -ConfirmLab
```

The script refuses domain controllers. A domain-joined member VM additionally requires:

```powershell
.\Invoke-GentlemenEmulation.ps1 -ConfirmLab -AllowDomainJoinedLab
```

For disabled service-install and scheduled-task artifacts, use an elevated lab session and opt in:

```powershell
.\Invoke-GentlemenEmulation.ps1 -ConfirmLab -AllowDomainJoinedLab `
  -EnableServiceArtifact -EnableScheduledTaskArtifact
```

You can slow the scenario down or run selected phases:

```powershell
.\Invoke-GentlemenEmulation.ps1 -ConfirmLab -StepDelaySeconds 10 `
  -Phase InitialAccess,PersistenceAndC2,Discovery,TukTuk
```

## Investigate it

Each run is stored under:

```text
%LOCALAPPDATA%\DFIR-Lab\Gentlemen-Emulation\GENT-<UTC timestamp>-<random id>
```

Start with:

- `Timeline.jsonl`: ground-truth event sequence and safety disposition.
- `ProcessLogs\`: commands, exit codes, and captured output.
- `Scenario.json`: source metadata and report IOCs.
- `State.json`: exact artifacts tracked for cleanup.
- `CanaryData\` and `CanaryOriginals\`: impacted and preserved synthetic files.
- `Impact\FakeDomain\SYSVOL\`: staged GPO/scheduled-task evidence that never touched real SYSVOL.

The report's hashes are metadata only. Generated placeholders intentionally do not match malware hashes.

## Clean up

After collecting evidence, use the exact `RunId` printed by the simulation:

```powershell
.\Invoke-GentlemenEmulation.ps1 -Action Cleanup -ConfirmLab `
  -RunId GENT-20260814T120000Z-1a2b3c4d
```

Cleanup validates the manifest, registry values, task/service prefixes, and every removal path. It removes only tracked scenario artifacts. Historical Windows/EDR/Sysmon telemetry is intentionally not cleared.

## Safety notes

- IOC-shaped requests always use `curl.exe --resolve <host>:<port>:127.0.0.1 --noproxy "*"`.
- Real domain discovery is off unless `-AllowDomainJoinedLab` is supplied.
- A domain controller is refused even with that switch.
- The LSASS technique is represented by dumping only a new Notepad process owned by the current user. LSASS and NTDS are never opened.
- Dangerous response-prevention actions are written to a marker file but never invoked.
- The fake SYSVOL tree lives inside the run directory. No real GPO or domain share is modified.
