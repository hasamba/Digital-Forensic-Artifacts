# 089 - RDP, Tor, Meterpreter-like C2, and Snatch in under five hours

Lab-safe companion to The DFIR Report's [Snatch Ransomware](https://thedfirreport.com/2020/06/21/snatch-ransomware/). It preserves the 05:15 DA RDP entry, 07:53 discovery, DC pivot, WMI-masqueraded Tor RDP tunnel, unknown Go tool, `cplXen.exe` reverse shell and named-pipe evidence, `x3.exe` loader/config/task persistence, Ditsnap/NTDS metadata, backup-first manual RDP deployment, Defender-disable metadata, `safe.exe` service/batch/safe-mode/reboot behavior, and 15-minute domain impact.

Run elevated on a disposable Windows member workstation or member server—not a domain controller:

```powershell
$env:DFIR_LAB_CONFIRMATION = 'I_UNDERSTAND_THIS_IS_A_LAB'
.\SnatchFiveSim-Complete.ps1 -LabConfirmed
```

Artifacts remain under `%PUBLIC%\SnatchFiveSim`; cleanup is separate with `.\Cleanup-SnatchFiveSim.ps1 -LabConfirmed`.

All executables are signed `cmd.exe` decoys invoked only with fixed benign `echo`; DLL/dat files are inert. IOC attempts are loopback-only with proxy false and zero bytes. No authentication, RDP, Tor, proxy/tunnel, reverse shell, named pipe, task, snapshot/NTDS access, Defender change, service, boot setting, shutdown/reboot, or encryption occurs. Impact touches generated host data only; real DCs are refused.

The report does not publish ATT&CK IDs; observed behavior maps to T1110, T1078, T1021.001, T1016, T1033, T1090.003, T1071.001, T1053.005, T1003.003, T1562.001, T1543.003, T1529, and T1486.
