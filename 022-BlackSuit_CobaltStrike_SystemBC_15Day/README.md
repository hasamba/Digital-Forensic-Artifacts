# 022 - BlackSuit Ransomware

Lab-safe PowerShell reconstruction of The DFIR Report's [BlackSuit Ransomware](https://thedfirreport.com/2024/08/26/blacksuit-ransomware/) (August 26, 2024).

The scripts compress a roughly 328-hour, 15-calendar-day intrusion into a short run while retaining relative timestamps in `intrusion-timeline.jsonl`.

## Evidence generated

- Signed `RtWin64.exe` beacon decoy and Cobalt Strike HTTPS/SMB profiles: Cloudflare-to-AWS history, `svchorst.com`, `regsvcast.com` domains, URI paths, sleep/jitter, license IDs, spawnto processes, port 4444, and `WkSvcPipeMgr_JORW2e`.
- Six-hour discovery command telemetry plus Rubeus AS-REP/Kerberoasting, injected `mstsc.exe`, LSASS mask `0x1010`, SharpHound CLR/default collection, SAMR/SRVSVC/LDAP, and service event 7045 as negative-execution records.
- Synthetic host folders and events 4624/4778/4779/5145 for PsExec, SMB `ADMIN$`, RDP, and pass-the-hash reconstruction without a remote connection, service, ticket, or credential.
- Signed `SC.exe`/`socks32.exe` SystemBC decoys, `socks5` Run-key and proxy metadata, and loopback-only C2 attempts with zero bytes transferred.
- Day-seven C2 migration and day-eight/day-ten beacon activity, plus ADFind path failures, Get-DataInfo `method` bug, 7-Zip archive, interesting-file browsing, and administrative-console evidence.
- Signed `qwe.exe` BlackSuit decoy with reported hash, `123.txt`, and SMB/RDP deployment records. Twelve `.BLACKSUIT-CANARY` markers and notes sit beside intact generated files.

## Safety boundaries

Explicit lab confirmation is required and domain controllers are refused. The scenario contains no live malware and never connects to an IOC, requests Kerberos tickets, opens LSASS, queries a directory, uses a remote share or RDP, creates a service/task/run key, changes RDP or GPO, opens a tunnel, reads user data, deletes shadow copies, or encrypts files.

## Run and cleanup

```powershell
$env:DFIR_LAB_CONFIRMATION = 'I_UNDERSTAND_THIS_IS_A_LAB'
.\BlackSuitSim-Complete.ps1 -LabConfirmed
```

Artifacts remain under `%PUBLIC%\BlackSuit15DaySim` with a runtime manifest and relative timeline.

```powershell
.\Cleanup-BlackSuitSim.ps1 -LabConfirmed -WhatIf
.\Cleanup-BlackSuitSim.ps1 -LabConfirmed
```

ATT&CK from the report: T1548, T1560, T1558.004, T1486, T1069.002, T1482, T1490, T1558.003, T1003.001, T1204.002, T1112, T1059.001, T1055, T1090, T1547.001, T1021.001, T1018, T1518.001, T1569.002, T1021.002, T1518, T1082, T1071.001, T1059.003, and T1550.002.

See [IOC-METADATA.json](IOC-METADATA.json) and [scenario-manifest.json](scenario-manifest.json).
