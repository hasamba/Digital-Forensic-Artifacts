# 025 - From IcedID to Dagon Locker Ransomware in 29 Days

Lab-safe PowerShell reconstruction of The DFIR Report's [From IcedID to Dagon Locker Ransomware in 29 Days](https://thedfirreport.com/2024/04/29/from-icedid-to-dagon-locker-ransomware-in-29-days/) (April 29, 2024).

The scripts compress the 684-hour, 29-day intrusion while preserving relative event timestamps in `intrusion-timeline.jsonl`.

## Evidence generated

- PrometheusTDS/Azure-lookalike lure, `Document_Scan_468.js`, three-character obfuscation record, `magni.w.bat`, `magni.w`, `scab` export/key, IcedID task/injection metadata, and loopback-only IcedID infrastructure.
- Thirty-hour Cobalt delay, file.io `update.dll`, export `HTVIyKUVoTzv`, XOR key 35, `MZARUH`, allocation/injection metadata, named-pipe/GetSystem/LSASS records, and SMB/service pivot evidence.
- Synthetic hosts and generated share data with AdFind, Sharefinder, Seatbelt, Netscan, Nbtscan, Speedtest, Rclone, and AWSCollector artifacts. No remote host, directory, or real share is accessed.
- Rclone/AWS S3 exfiltration, Telegram status, WMI/WinRM/systeminfo, virtualization, password-document, and event-log activities as zero-byte negative-execution records.
- AnyDesk client ID, VPN-related IPs, `oldadministrator`, service/account/group/hide-value evidence, administrative-console activity, and a strictly local GPO/SYSVOL replica containing `test.bat`.
- Day-28 failed netsh 3390→3389 portproxy and SPN discovery metadata without firewall or portproxy changes.
- AWSCollector locker command, service list, `sysfunc.dll` signed decoy, inert `sysfunc.cmd`, Dagon-style log, and eighteen `.dagoned-CANARY` markers beside intact generated originals.

## Safety boundaries

The scenario requires explicit lab confirmation and refuses domain controllers. It contains no live malware and never contacts IOCs, accesses LSASS or credentials, propagates remotely, reads real shares, creates accounts/tasks/services, installs AnyDesk, modifies GPO/SYSVOL, changes a firewall or portproxy, stops services or security tools, contacts S3/Telegram, deletes backups or shadow copies, changes boot settings, or encrypts files.

## Run and cleanup

```powershell
.\DagonSim-Complete.ps1 -LabConfirmed
```

Artifacts remain under `%PUBLIC%\IcedIDAWSDagonSim` with a runtime manifest and relative timeline.

```powershell
.\Cleanup-DagonSim.ps1 -LabConfirmed -WhatIf
.\Cleanup-DagonSim.ps1 -LabConfirmed
```

ATT&CK and all published indicators/hashes are preserved in [scenario-manifest.json](scenario-manifest.json) and [IOC-METADATA.json](IOC-METADATA.json).
