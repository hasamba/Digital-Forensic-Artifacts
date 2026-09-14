# 051 - Quantum Ransomware

Lab-safe PowerShell reconstruction of The DFIR Report's [Quantum Ransomware](https://thedfirreport.com/2022/04/25/quantum-ransomware/).

The 224-minute timeline preserves `docs_invoice_173.iso`, `document.lnk`, `dar.dll`, hourly IcedID persistence, automatic native discovery, Cobalt hollowing/injection at roughly two hours, AdFind/`ns.bat`, LSASS access, WMI credential testing, RDP, failed `p227.dll`, successful PowerShell Cobalt, domain-wide `ttsel.exe` C$ copies, and PsExec `mstdc`/WMI detonation. Eight file-hash triplets and all IcedID/Cobalt infrastructure remain investigation metadata.

The final phase creates generated host folders, untouched source canaries, inert `ttsel.exe`/`mstdc.exe` names, ransom-note canaries, and extension markers. It never encrypts or modifies the generated source files. The mandatory gate refuses domain controllers; no malware, credential access, remote authentication/action, share copy, ransomware execution, shadow/log/security change, IOC contact, or exfiltration occurs.

```powershell
.\QuantumFastSim-Complete.ps1 -LabConfirmed
```

Artifacts remain under `%PUBLIC%\QuantumFastSim`; cleanup is separately gated. See [scenario-manifest.json](scenario-manifest.json) and [IOC-METADATA.json](IOC-METADATA.json).
