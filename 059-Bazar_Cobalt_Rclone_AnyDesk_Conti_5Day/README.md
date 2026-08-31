# 059 - CONTInuing the Bazar Ransomware Story

Lab-safe PowerShell reconstruction of The DFIR Report's [CONTInuing the Bazar Ransomware Story](https://thedfirreport.com/2021/11/29/continuing-the-bazar-ransomware-story/).

The generated five-day chronology preserves the password ZIP/Word macro/HTA Bazar chain, D574/D8B3/143 Cobalt beacons, Winlogon injection, playbook discovery mistakes, ShareFinder, WMI pivot, backup-server RDP, two three-hour Rclone/MEGA windows, portable AnyDesk, ProcessHacker LSASS access, `locker.bat`, and Conti execution through C$ paths. Generated originals remain intact beside Conti markers and inert `readme.txt` notes.

No domain-controller lane exists because the report observed no DC interaction. Executable names are signed `cmd.exe` copies with fixed benign arguments; reported commands are metadata. No malware, remote action, credential access, collection, exfiltration, admin-share mount, ransomware execution, or encryption occurs.

```powershell
$env:DFIR_LAB_CONFIRMATION = 'I_UNDERSTAND_THIS_IS_A_LAB'
.\ContiBazarSim-Complete.ps1 -LabConfirmed
```

Artifacts remain under `%PUBLIC%\ContiBazarSim`; cleanup is separately gated. See [scenario-manifest.json](scenario-manifest.json) and [IOC-METADATA.json](IOC-METADATA.json).
