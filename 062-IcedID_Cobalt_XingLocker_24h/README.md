# 062 - IcedID to XingLocker Ransomware in 24 hours

Lab-safe PowerShell reconstruction of The DFIR Report's [IcedID to XingLocker Ransomware in 24 hours](https://thedfirreport.com/2021/10/18/icedid-to-xinglocker-ransomware-in-24-hours/).

The generated 24-hour chronology preserves phishing-origin IcedID, `ikaqkk.dll`, hourly persistence, Cobalt process hollowing, `kaslose` Beacons, the four-minute LSASS/administrative-credential transition, `jump psexec_psh`, `spoolsv.exe`, `HpSupport`/`star.bat`, `kasper` and `fed1`–`fed3`, AdFind, BloodHound, PowerView, exhaustive scanning, manual searches, and hour-23 WMIC/`start.bat` XingLocker deployment. Generated DC, server, and external-server originals remain intact beside markers and sanitized `RecoveryManual.html` canaries.

Scripts and DLLs are inert text; executable names are signed `cmd.exe` copies with fixed benign arguments. Published hashes are metadata and all network attempts are loopback-only. No malware, scheduled task/service, injection, LSASS access, remote action, security/backup impairment, AD/share query, scanning, collection/exfiltration, ransomware, or encryption occurs. The report observed no overt exfiltration, which is retained as a negative finding.

```powershell
.\XingSim-Complete.ps1 -LabConfirmed
```

Artifacts remain under `%PUBLIC%\XingSim`; cleanup is separately gated. The script refuses domain controllers. See [scenario-manifest.json](scenario-manifest.json) and [IOC-METADATA.json](IOC-METADATA.json).
