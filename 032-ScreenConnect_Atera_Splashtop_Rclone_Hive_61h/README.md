# 032 - ScreenConnect, Atera, Splashtop, Rclone, and Hive

Lab-safe PowerShell reconstruction of The DFIR Report's [From ScreenConnect to Hive Ransomware in 61 hours](https://thedfirreport.com/2023/09/25/from-screenconnect-to-hive-ransomware-in-61-hours/).

The scenario preserves the 61-hour multi-RMM chronology, Cobalt and Metasploit channels, WMI/service/RDP movement, Mimikatz and discovery evidence, 90-minute Rclone SFTP window, and Hive's manual impact plus failed user-configuration GPO deployment.

The explicit lab gate and domain-controller refusal are mandatory. No RMM or malware installs, process injection, LSASS access, remote movement, scan, exfiltration, password change, encryption, recovery impairment, GPO, SYSVOL, or NETLOGON change occurs. All connections use loopback; impact markers sit beside intact generated originals.

```powershell
$env:DFIR_LAB_CONFIRMATION = 'I_UNDERSTAND_THIS_IS_A_LAB'
.\Hive61Sim-Complete.ps1 -LabConfirmed
```

Artifacts remain under `%PUBLIC%\Hive61Sim`; cleanup is separate:

```powershell
.\Cleanup-Hive61Sim.ps1 -LabConfirmed -WhatIf
.\Cleanup-Hive61Sim.ps1 -LabConfirmed
```

See [scenario-manifest.json](scenario-manifest.json) and [IOC-METADATA.json](IOC-METADATA.json).
