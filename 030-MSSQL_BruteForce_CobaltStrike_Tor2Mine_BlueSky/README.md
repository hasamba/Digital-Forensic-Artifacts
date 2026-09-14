# 030 - MSSQL Brute Force, Tor2Mine, and BlueSky

Lab-safe PowerShell reconstruction of The DFIR Report's [SQL Brute Force Leads to BlueSky Ransomware](https://thedfirreport.com/2023/12/04/sql-brute-force-leads-to-bluesky-ransomware/) (December 4, 2023).

The scenario retains the report's 32-minute sequence: 10,000 MSSQL `sa` authentication failures, a synthetic success and `xp_cmdshell` ancestry, Cobalt Strike and winlogon injection evidence, Tor2Mine checking/miner/driver activity, 16 masqueraded tasks, AV and credential-access records, minute-15 remote-service movement, and minute-32 BlueSky impact.

It requires explicit lab confirmation and refuses domain controllers. It never authenticates to SQL, enables `xp_cmdshell`, downloads malware, injects winlogon, accesses LSASS, changes AV, loads a driver, creates tasks/services, scans or moves remotely, mines cryptocurrency, encrypts files, or accesses real user data. BlueSky creates `.bluesky` marker files beside intact generated originals and connects only to loopback.

```powershell
.\BlueSkySQLSim-Complete.ps1 -LabConfirmed
```

Artifacts remain under `%PUBLIC%\BlueSkySQLSim`; cleanup is separately gated:

```powershell
.\Cleanup-BlueSkySQLSim.ps1 -LabConfirmed -WhatIf
.\Cleanup-BlueSkySQLSim.ps1 -LabConfirmed
```

See [scenario-manifest.json](scenario-manifest.json) and [IOC-METADATA.json](IOC-METADATA.json).
