# 036 - ISO IcedID, Cobalt Strike, Rclone, and Quantum

Lab-safe PowerShell reconstruction of The DFIR Report's [Malicious ISO File Leads to Domain Wide Ransomware](https://thedfirreport.com/2023/04/03/malicious-iso-file-leads-to-domain-wide-ransomware/).

The scripts retain the just-over-78-hour sequence: malspam ZIP/ISO and `documents.lnk`, hidden `eyewear.bat`/`easygoing.dat`, IcedID persistence, Cobalt Strike beacon failures, ZeroLogon and credential-access evidence, extensive RSAT/AdFind/ADGet discovery, WMI/RDP and remote-access tooling, Rclone-to-MEGA, and Quantum deployment through password-reset/copy/PsExec batch files.

The mandatory gate refuses domain controllers. No ISO is mounted; no live payload or IOC is contacted; no task, exploit, credential/DCSync/LSASS action, Defender/GPO/SYSVOL change, remote execution, account reset, real collection, exfiltration, or encryption occurs. All originals remain intact beside `.Quantum.marker` files; network attempts use loopback only.

```powershell
.\ISOQuantumSim-Complete.ps1 -LabConfirmed
```

Artifacts remain under `%PUBLIC%\ISOQuantumSim`; cleanup is separately gated. See [scenario-manifest.json](scenario-manifest.json) and [IOC-METADATA.json](IOC-METADATA.json).
