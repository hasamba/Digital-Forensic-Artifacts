# 033 - HTML Smuggling, IcedID, Cobalt Strike, and Nokoyawa

Lab-safe PowerShell reconstruction of The DFIR Report's [HTML Smuggling Leads to Domain Wide Ransomware](https://thedfirreport.com/2023/08/28/html-smuggling-leads-to-domain-wide-ransomware/).

The scripts retain the report's just-over-12-hour sequence: HTML-smuggled password ZIP and ISO, LNK/IcedID execution and hourly task, three-hour Cobalt handoff, RDP and AdFind/SessionGopher discovery, then redundant WMIC/PsExec Nokoyawa distribution.

The lab gate and domain-controller refusal are mandatory. No HTML payload downloads, ISO mounts, malware/task/injection/LSASS access, directory or session credential query, RDP, scan, WMIC/PsExec/service, shadow deletion, or encryption occurs. All network markers use loopback; impact markers sit beside intact generated originals.

```powershell
$env:DFIR_LAB_CONFIRMATION = 'I_UNDERSTAND_THIS_IS_A_LAB'
.\SmuggleNokoSim-Complete.ps1 -LabConfirmed
```

Artifacts remain under `%PUBLIC%\SmuggleNokoSim`; cleanup is separately gated. See [scenario-manifest.json](scenario-manifest.json) and [IOC-METADATA.json](IOC-METADATA.json).
