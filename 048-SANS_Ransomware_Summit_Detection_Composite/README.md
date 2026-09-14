# 048 - SANS Ransomware Summit 2022: Can You Detect This?

Lab-safe PowerShell implementation of The DFIR Report's [SANS Ransomware Summit 2022, Can You Detect This?](https://thedfirreport.com/2022/06/16/sans-ransomware-summit-2022-can-you-detect-this/).

This source is a detection companion assembled from multiple investigations, not a single intrusion report. Accordingly, the scenario creates a clearly labeled composite sequence covering Office/ISO delivery, scheduled-task/BITS/web-shell/RMM persistence, GetSystem and credential-access evidence, Defender impairment, native and third-party discovery, PsExec/WMI/Cobalt movement, Rclone/WinSCP/FileZilla transfer evidence, operator bloopers, and recurring BYOT batch names. It does not invent a victim, chronology, malware hash, or C2 address that the source did not publish.

The mandatory gate refuses domain controllers. Every executable decoy is a signed `cmd.exe` copy, every socket marker is loopback-only with zero bytes, and all privileged, credential, directory, remote, collection, security-control, deletion, shadow-copy, encryption, and impact behaviors are negative records.

```powershell
.\SummitDetectSim-Complete.ps1 -LabConfirmed
```

Artifacts remain under `%PUBLIC%\SummitDetectSim`; cleanup is separately gated. See [scenario-manifest.json](scenario-manifest.json) and [IOC-METADATA.json](IOC-METADATA.json).
