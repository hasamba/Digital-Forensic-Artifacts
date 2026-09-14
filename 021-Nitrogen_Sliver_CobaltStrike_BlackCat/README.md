# 021 - Nitrogen Campaign Drops Sliver and Ends With BlackCat Ransomware

Lab-safe PowerShell reconstruction of The DFIR Report's [Nitrogen Campaign Drops Sliver and Ends With BlackCat Ransomware](https://thedfirreport.com/2024/09/30/nitrogen-campaign-drops-sliver-and-ends-with-blackcat-ransomware/) (September 30, 2024).

The scenario preserves the report's eight-day, roughly 156-hour sequence while compressing execution to a few minutes. Timestamps in `intrusion-timeline.jsonl` retain the relative chronology.

## Evidence generated

- A fake Advanced IP Scanner `Version.zip`, signed `setup.exe` decoy, hidden Python DLL canaries, `%AppData%\Notepad` layout, Py-Fuscate/AES loader records, and Sliver `StartW` command-line telemetry.
- Sliver and Cobalt Strike network indicators, ports, JA3/JA3s, Amazon-like profile paths, sleep/jitter, watermark, spawnto, and loader filenames. Every attempted connection goes to `127.0.0.1` and transfers zero bytes.
- Scheduled-task, Winlogon Userinit, access mask `0x143A`, self-injection, API-unhooking, and evasion details as JSON only; no task, registry value, process handle, or injected thread is created.
- Echo-only domain/trust/host/share discovery, PowerView and BloodHound canaries, synthetic local hosts, and WMI/RDP/SMB/PsExec evidence without touching another machine or directory service.
- Restic command lines, password-file and REST v2 content-type evidence against a generated share tree. The reported repository remains metadata; the connection is loopback-only, transfers zero bytes, and creates no VSS snapshot.
- Day-eight account reset, safe-boot, RunOnce/Winlogon, reboot, service, IIS, shadow-copy, and log-clearing commands as inert records. No such command is invoked.
- Signed `example.exe` BlackCat decoy, service GUID and reported hashes, plus `.BLACKCAT-CANARY` markers beside twelve intact generated originals and an inert ransom note.

## Safety boundaries

The scripts require explicit lab confirmation and refuse domain controllers. They contain no live malware and never contact reported infrastructure, read credentials or LSASS, change accounts, propagate remotely, execute WMI/PsExec remotely, create tasks or services, modify the registry or boot configuration, impair security controls, clear logs, delete shadow copies, reboot, or encrypt data. Reported hashes and infrastructure are investigation metadata only.

## Run and cleanup

```powershell
.\NitrogenSim-Complete.ps1 -LabConfirmed
```

Artifacts remain under `%PUBLIC%\NitrogenBlackCatSim`, including `artifact-manifest.jsonl` and the relative timeline.

```powershell
.\Cleanup-NitrogenSim.ps1 -LabConfirmed -WhatIf
.\Cleanup-NitrogenSim.ps1 -LabConfirmed
```

ATT&CK from the report: T1098, T1070.001, T1486, T1039, T1574.002, T1069.002, T1482, T1189, T1055.001, T1027.013, T1048, T1105, T1490, T1570, T1087.001, T1069.001, T1003.001, T1204.002, T1036, T1036.005, T1135, T1059.001, T1055, T1059.006, T1021.001, T1018, T1562.009, T1053.005, T1569.002, T1021.002, T1071.001, T1059.003, T1047, and T1547.004.

See [IOC-METADATA.json](IOC-METADATA.json) and [scenario-manifest.json](scenario-manifest.json).
