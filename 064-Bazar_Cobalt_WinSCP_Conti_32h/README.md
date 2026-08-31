# 064 - BazarLoader to Conti Ransomware in 32 Hours

Lab-safe PowerShell reconstruction of The DFIR Report's [BazarLoader to Conti Ransomware in 32 Hours](https://thedfirreport.com/2021/09/13/bazarloader-to-conti-ransomware-in-32-hours/), internal case 5087.

The generated 32-hour chronology preserves the assessed zipped-JavaScript email vector, rundll32 BazarLoader, 20-minute discovery, one-hour Cobalt transition, process injection, pass-the-hash, SMB scanning, LSASS dumping, hour-2.5 SMB/WMIC movement, the 12-hour lull, encoded PowerShell and `Get-DataInfo.ps1` discovery, WinSCP/SCP exfiltration to Romania, TOR anomalies, hour-31 `test.exe` WMIC trials, RDP-launched `backup.exe`, SMB spread, and domain-wide Conti impact.

All tools are inert text or signed `cmd.exe` decoys with fixed benign arguments. Network attempts are loopback-only and generated staged files contain no sensitive data. No malware, authentication/PTH, injection, LSASS access, remote action, query, WinSCP installation, real collection/exfiltration, TOR access, ransomware, C$ mount, propagation, or encryption occurs. Generated originals remain intact beside markers and sanitized notes.

```powershell
$env:DFIR_LAB_CONFIRMATION = 'I_UNDERSTAND_THIS_IS_A_LAB'
.\WinContiSim-Complete.ps1 -LabConfirmed
```

Artifacts remain under `%PUBLIC%\WinContiSim`; cleanup is separately gated. The script refuses domain controllers. See [scenario-manifest.json](scenario-manifest.json) and [IOC-METADATA.json](IOC-METADATA.json).
