# 023 - Threat Actors' Toolkit: Sliver, PoshC2, and Batch Scripts

Lab-safe PowerShell reconstruction of The DFIR Report's [Threat Actors' Toolkit: Leveraging Sliver, PoshC2 & Batch Scripts](https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/) (August 12, 2024).

This is an open-directory capability report with no identified victim or intrusion timeline. The scenario recreates the recovered inventory and intelligence context without inventing victim activity.

## Evidence generated

- Two local open-directory replicas preserve the reported addresses, ports, HTML hash, collection dates, and filenames; nothing is retrieved from either public system.
- Eighteen batch canaries map Atera removal, backup/shadow destruction, log and RDP-trace clearing, accessibility backdoors, Defender/UAC impairment, SQL/Exchange/Hyper-V/AV service termination, session logoff, and network-service changes. They contain only `REM` and `echo` lines.
- Negative-execution JSON records enumerate the utilities and intended outcomes while recording zero registry/task/service/boot/firewall/share/security/log/backup/process/session changes.
- Signed decoys preserve PoshC2, SystemBC, Sliver, Ngrok, and Atera filenames. PoshC2 URL paths and configuration, SystemBC dual endpoints/run value, and Sliver version evidence are metadata; all socket attempts are loopback-only.
- `poshc2+user.txt` evidence retains the mistyped `WDAGUtilltyAccount`, public report credential, RDP/firewall and Atera actions without creating an account, installing software, opening RDP, or making a tunnel.
- All published SHA-256 values are in `IOC-METADATA.json`; generated canaries deliberately do not match them and the runtime manifest records actual hashes.

## Safety boundaries

The scenario requires explicit lab confirmation and refuses domain controllers. It does not download or execute source artifacts, contact IOCs, create accounts or shares, enable RDP, alter firewall/registry/tasks/services/boot/accessibility settings, impair security tools or workloads, clear logs, delete backups or shadow copies, log off sessions, install remote-access software, or open a proxy/tunnel.

## Run and cleanup

```powershell
.\ToolkitSim-Complete.ps1 -LabConfirmed
```

Artifacts remain under `%PUBLIC%\SliverPoshC2ToolkitSim` with a runtime manifest and capability timeline.

```powershell
.\Cleanup-ToolkitSim.ps1 -LabConfirmed -WhatIf
.\Cleanup-ToolkitSim.ps1 -LabConfirmed
```

ATT&CK from the report: T1546.008, T1531, T1071, T1573.002, T1070.001, T1140, T1562.001, T1562.002, T1573, T1490, T1112, T1059.001, T1090, T1059.006, T1547.001, T1219, T1489, T1033, T1071.001, and T1059.003.

See [IOC-METADATA.json](IOC-METADATA.json) and [scenario-manifest.json](scenario-manifest.json).
