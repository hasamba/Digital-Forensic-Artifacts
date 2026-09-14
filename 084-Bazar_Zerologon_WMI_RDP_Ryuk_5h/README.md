# 084 - Bazar, Zerologon, WMI, RDP, and Ryuk in five hours

Lab-safe companion to The DFIR Report's [Ryuk in 5 Hours](https://thedfirreport.com/2020/10/18/ryuk-in-5-hours/) (internal case 1006). It preserves the low-privileged `Report_Print.exe` phish, Bazar injection/shell behavior, beachhead discovery, Zerologon reset metadata, SMB/WMI deployment of `servisses.exe`, Cobalt trial/EICAR indicator, named-pipe escalation, SQL/arti64/socks64 DLL execution, RDP between two DC representations, untouched GPO access, AD-module inventory, AdFind, and the final `xxx.exe` Ryuk wave. The exact time axis keeps the sub-two-hour Zerologon event, hour-four readiness, 4h10m backup pivot, roughly 4h30m ransomware activity, and five-hour completion.

Run elevated on a disposable Windows member workstation or member server—not a domain controller:

```powershell
.\RyukFiveHourSim-Complete.ps1 -LabConfirmed
```

Artifacts remain under `%PUBLIC%\RyukFiveHourSim`; cleanup is a separate explicit action with `.\Cleanup-RyukFiveHourSim.ps1 -LabConfirmed`.

Begin with `artifact-manifest.jsonl` and `evidence\exercise-timeline.jsonl`. Then inspect the Zerologon, SMB/WMI, named-pipe, DLL proxy-execution, GPO, discovery, and impact records, plus synthetic `AllWindows.csv` and generated host trees.

All executable and DLL names are copied, signed `cmd.exe` decoys; only executable decoys run, always with fixed benign `echo` arguments. DLL stand-ins are never loaded or registered. Every endpoint attempt is forced to `127.0.0.1`, uses no proxy, and transfers zero bytes. No malware, credential reset, process injection, WMI, SMB/RDP, named pipe, AD/PowerShell query, DLL load, GPO/SYSVOL access or change, remote propagation, or user-data encryption occurs. Real domain controllers are refused.

The report's legacy ATT&CK mapping is preserved: T1192, T1076, T1105, T1047, T1059, T1482, T1018, T1124, T1486, T1043, T1071, T1032, T1204, T1078, T1068, T1218, T1085, and T1117.
