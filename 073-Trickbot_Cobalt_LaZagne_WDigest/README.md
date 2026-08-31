# 073 - Trickbot Brief: Creds and Beacons

Lab-safe companion to The DFIR Report's [Trickbot Brief: Creds and Beacons](https://thedfirreport.com/2021/05/02/trickbot-brief-creds-and-beacons/) (case 3521). It preserves moderate-confidence Office delivery, manual `click.php.dll`, wermgr injection, two Cobalt Beacon chains, scheduled-task persistence, Net/Nltest/PowerView/SMB discovery, LaZagne `all`, saved-hive filenames, WDigest enablement, LSASS access, continued beaconing, and the absence of lateral movement or mission execution.

The one-hour exercise axis is generated ordering because the report provides only “minutes later” timing. Executables are signed `cmd.exe` decoys. No malware, injection, task, registry/hive change, browser/LSASS/credential access, discovery/scan, external C2, lateral movement, or impact occurs. Network attempts are loopback-only with zero bytes; real DCs are refused.

```powershell
$env:DFIR_LAB_CONFIRMATION = 'I_UNDERSTAND_THIS_IS_A_LAB'
.\TrickCredSim-Complete.ps1 -LabConfirmed
```

Artifacts remain under `%PUBLIC%\TrickCredSim`; run `.\Cleanup-TrickCredSim.ps1 -LabConfirmed` separately.
