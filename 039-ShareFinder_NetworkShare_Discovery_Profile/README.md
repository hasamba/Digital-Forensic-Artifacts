# 039 - ShareFinder network-share discovery profile

Lab-safe PowerShell reconstruction of The DFIR Report's [ShareFinder: How Threat Actors Discover File Shares](https://thedfirreport.com/2023/01/23/sharefinder-how-threat-actors-discover-file-shares/).

This source is a technique and detection profile rather than one intrusion, so the generated chronology is explicitly synthetic. It preserves the useful forensic signals: direct and Cobalt Strike proxy invocation strings, `shares.txt`, PowerShell 4103/4104, the broad LDAP computer filter and Event 1644, one-to-many ICMP and SMB/445 patterns, `IPC$`/`C$`/`ADMIN$` plus `Files` and `SYSVOL` share names, Security 5145 records, and `ExcludeStandard`, `Ping`, `Delay`, and `Jitter` variants.

The mandatory gate refuses domain controllers. The exercise does not contain or run PowerView/ShareFinder code, query LDAP, send ICMP, connect to remote SMB, enumerate or access shares, touch `SYSVOL`, or write real Windows event logs. Documentation-range addresses and generated hostnames appear only in evidence files; all socket markers terminate at `127.0.0.1` with zero bytes transferred.

```powershell
$env:DFIR_LAB_CONFIRMATION = 'I_UNDERSTAND_THIS_IS_A_LAB'
.\ShareFinderSim-Complete.ps1 -LabConfirmed
```

Artifacts remain under `%PUBLIC%\ShareFinderSim`; cleanup is separately gated:

```powershell
.\Cleanup-ShareFinderSim.ps1 -LabConfirmed
```

See [scenario-manifest.json](scenario-manifest.json) and [IOC-METADATA.json](IOC-METADATA.json).
