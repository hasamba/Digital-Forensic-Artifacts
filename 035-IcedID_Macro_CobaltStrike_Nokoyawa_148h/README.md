# 035 - IcedID Macro, Cobalt Strike, and Nokoyawa

Lab-safe PowerShell reconstruction of The DFIR Report's [IcedID Macro Ends in Nokoyawa Ransomware](https://thedfirreport.com/2023/05/22/icedid-macro-ends-in-nokoyawa-ransomware/).

The scripts retain the roughly 148-hour sequence: an Italian-targeted Excel/VBA lure, numeric IcedID payload and renamed `calc.exe`, hourly persistence, Cobalt Strike and BackConnect VNC, multi-day GetSystem/LSASS and discovery evidence, WinRM/WMI/RDP pivots, and domain-wide `AWAYOKON` Nokoyawa deployment through batch files and renamed PsExec.

The lab gate and domain-controller refusal are mandatory. No macro, download, malware, task, injection, credential access, directory/share/scan operation, remote session, WMI/PsExec action, real collection, exfiltration, shadow deletion, or encryption occurs. Reported network traffic is represented only by loopback attempts; generated originals remain intact beside marker files.

```powershell
.\MacroNokoSim-Complete.ps1 -LabConfirmed
```

Artifacts remain under `%PUBLIC%\MacroNokoSim`; cleanup is separately gated. See [scenario-manifest.json](scenario-manifest.json) and [IOC-METADATA.json](IOC-METADATA.json).
