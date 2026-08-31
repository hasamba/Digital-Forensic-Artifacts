# 086 - RDP, Cobalt Strike, ProcDump, Mimikatz, and NetWalker in one hour

Lab-safe companion to The DFIR Report's [NetWalker Ransomware in 1 Hour](https://thedfirreport.com/2020/08/31/netwalker-ransomware-in-1-hour/) (internal case 1003). It preserves the likely VPN-origin RDP entry with `DomainName\Administrator`, `c37.ps1` at minute 16, `c37.exe`, the default-certificate Cobalt endpoint, AdFind/`adf.bat`, manually typed discovery, `pcr.bat`, synthetic `domains.txt`/`ips.log`, prohibited ProcDump/Mimikatz telemetry, RDP to a DC representation, `ip-list.txt`, `P100119.ps1`, and the final PsExec/share/PowerShell NetWalker command. The complete approximate one-hour axis is retained.

Run elevated on a disposable Windows member workstation or member server—not a domain controller:

```powershell
$env:DFIR_LAB_CONFIRMATION = 'I_UNDERSTAND_THIS_IS_A_LAB'
.\NetWalkerHourSim-Complete.ps1 -LabConfirmed
```

Artifacts remain under `%PUBLIC%\NetWalkerHourSim`; cleanup is separate with `.\Cleanup-NetWalkerHourSim.ps1 -LabConfirmed`.

Begin with `artifact-manifest.jsonl` and `evidence\exercise-timeline.jsonl`, then inspect RDP, discovery, credential-access, DC-pivot, PsExec, and impact records. The report-provided password token is retained only inside a reported command string and is never used.

All executable names are copied, signed `cmd.exe` decoys invoked only with fixed benign `echo`. Script/batch files are inert. IOC sockets are forced to `127.0.0.1`, use no proxy, and transfer zero bytes. No authentication, RDP, malware, LSASS access, dump, credential collection, ping, directory query, SMB/PsExec service, share mount, PowerShell, remote execution, or encryption occurs. Real domain controllers are refused.

The report does not publish an ATT&CK table; observed behavior maps to T1133, T1021.001, T1078, T1059.001, T1018, T1482, T1087.002, T1046, T1003.001, T1021.002, T1569.002, T1105, and T1486.
