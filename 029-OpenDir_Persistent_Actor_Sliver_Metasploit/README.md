# 029 - OpenDir Persistent Actor, Sliver, and Metasploit

Lab-safe PowerShell reconstruction of The DFIR Report's [Lets Open(Dir) Some Presents: An Analysis of a Persistent Actor’s Activity](https://thedfirreport.com/2023/12/18/lets-opendir-some-presents-an-analysis-of-a-persistent-actors-activity/) (December 18, 2023).

Unlike a single intrusion, the source profiles more than a year of activity recovered from an exposed actor host. This scenario therefore builds a forensic replica of that host: reconnaissance and exploit histories, generated target lists and results, Sliver database statistics, Metasploit/Cobalt artifacts, synthetic victim directories, post-exploitation commands, persistence records, and all published sample hashes.

The scenario requires the explicit lab gate and refuses domain controllers. It never scans or exploits real targets, runs public exploits or malware, creates a web shell/service/task/cron job, changes Defender/UFW, reads SAM/NTDS/credentials/private keys, performs DCSync, forges tickets, propagates over SSH, mines cryptocurrency, proxies traffic, or exfiltrates data. All reported commands are escaped echo-only telemetry using a signed `cmd.exe` copy; network markers are literal loopback with zero bytes transferred.

```powershell
.\OpenDirActorSim-Complete.ps1 -LabConfirmed
```

Artifacts remain under `%PUBLIC%\OpenDirActorSim`; cleanup is separate:

```powershell
.\Cleanup-OpenDirActorSim.ps1 -LabConfirmed -WhatIf
.\Cleanup-OpenDirActorSim.ps1 -LabConfirmed
```

See [scenario-manifest.json](scenario-manifest.json) and [IOC-METADATA.json](IOC-METADATA.json).
