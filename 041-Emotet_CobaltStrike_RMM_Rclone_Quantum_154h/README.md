# 041 - Emotet, Cobalt Strike, RMM, Rclone, and Quantum

Lab-safe PowerShell reconstruction of The DFIR Report's [Emotet Strikes Again - LNK File Leads to Domain Wide Ransomware](https://thedfirreport.com/2022/11/28/emotet-strikes-again-lnk-file-leads-to-domain-wide-ransomware/).

The scripts preserve the 154-hour/eight-day sequence: malspam `K-1 06.13.2022.lnk`, obfuscated PowerShell and `regsvr32` Emotet loading, Run-key evidence, daily discovery and spam, two Cobalt Strike waves, failed remote PowerShell, SMB/WMI/service movement, ShareFinder, LSASS access indicators, failed ZeroLogon evidence, `find.bat`/AdFind and `p.bat`, Tactical RMM/AnyDesk, Rclone-to-MEGA, Network Scanner, RDP, `Powertool64.exe`, `dontsleep.exe`, and Quantum `locker.dll` deployment.

The mandatory gate refuses domain controllers. No live payload, email, registry/service change, exploit, injection, LSASS/credential access, directory/share query, remote action, RMM install, real collection/exfiltration, security impairment, or encryption occurs. All socket markers are loopback-only with zero bytes; generated originals remain intact beside `.Quantum.marker` files. The report's 60-character `rclone.exe` SHA-256 and its narrative/atomic `96.125.171.16` versus `.165` discrepancy are preserved explicitly.

```powershell
.\EmotetQuantumSim-Complete.ps1 -LabConfirmed
```

Artifacts remain under `%PUBLIC%\EmotetQuantumSim`; cleanup is separately gated:

```powershell
.\Cleanup-EmotetQuantumSim.ps1 -LabConfirmed
```

See [scenario-manifest.json](scenario-manifest.json) and [IOC-METADATA.json](IOC-METADATA.json).
