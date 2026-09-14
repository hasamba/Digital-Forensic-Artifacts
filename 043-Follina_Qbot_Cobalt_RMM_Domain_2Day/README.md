# 043 - Follina, Qbot, Cobalt Strike, and RMM

Lab-safe PowerShell reconstruction of The DFIR Report's [Follina Exploit Leads to Domain Compromise](https://thedfirreport.com/2022/10/31/follina-exploit-leads-to-domain-compromise/).

The two-day sequence preserves the weaponized Word/HTML relationship, `ms-msdt`/`sdiagnhost`, `PCW.debugreport.xml`, three Qbot download names and `regsvr32`, random task/registry persistence, injected-explorer discovery, browser and credential-access evidence, SMB/service propagation and Defender exclusion indicators, Cobalt/AdFind/LSASS, NetSupport, RDP to a DC, Atera/Splashtop, SoftPerfect 445/3389 scanning, and file-server document viewing.

The mandatory gate refuses domain controllers. No exploit, live payload, task/registry/Defender modification, injection, credential/browser/LSASS access, directory/share query, remote action, RMM install, scan packet, real document access, or exfiltration occurs. All socket markers are loopback-only and artifacts remain for investigation.

```powershell
.\FollinaQbotSim-Complete.ps1 -LabConfirmed
```

Artifacts remain under `%PUBLIC%\FollinaQbotSim`; cleanup is separately gated. See [scenario-manifest.json](scenario-manifest.json) and [IOC-METADATA.json](IOC-METADATA.json).
