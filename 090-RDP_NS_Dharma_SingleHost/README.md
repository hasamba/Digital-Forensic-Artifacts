# 090 - RDP, NS.exe, and single-host Dharma

Lab-safe companion to The DFIR Report's [The Little Ransomware That Couldn’t (Dharma)](https://thedfirreport.com/2020/06/16/the-little-ransomware-that-couldnt-dharma/). It preserves the 08:58 local-admin RDP entry, 09:36 `NS.exe` share scanner, `shadow.bat`, `LogDelete.bat`, `closeapps.bat`, two Startup paths, HKLM Run marker, `1pgp.exe`, and the decisive outcome: despite Domain Administrator privileges, the actor made no lateral-movement or propagation attempt.

Run elevated on a disposable Windows member workstation or member server—not a domain controller:

```powershell
$env:DFIR_LAB_CONFIRMATION = 'I_UNDERSTAND_THIS_IS_A_LAB'
.\DharmaSingleSim-Complete.ps1 -LabConfirmed
```

Artifacts remain under `%PUBLIC%\DharmaSingleSim`; cleanup is separate. All executables are fixed-echo signed `cmd.exe` decoys and batches are inert. The RDP marker is loopback-only. No authentication, scan, mount, shadow deletion, log clearing, process kill, startup/registry change, lateral movement, or encryption occurs. Only generated data receives impact markers; real DCs are refused.

The report does not publish ATT&CK IDs; observed behavior maps to T1133, T1078, T1046, T1135, T1490, T1070.001, T1489, T1547.001, and T1486.
