# 068 - IcedID and Cobalt Strike vs Antivirus

Lab-safe companion to The DFIR Report's [IcedID and Cobalt Strike vs Antivirus](https://thedfirreport.com/2021/07/19/icedid-and-cobalt-strike-vs-antivirus/) (case 4485). It preserves the Word → HTA → JPG-disguised DLL chain, IcedID/Cobalt loading, hourly GUID task, Fodhelper/service/GetSystem activity, overpass-the-hash and failed ProcDump, extensive discovery, AV-thwarted movement, the 11-day beacon-only gap, new Cobalt infrastructure, renewed WMI movement, and the absence of final impact.

All executables are signed `cmd.exe` decoys with fixed benign arguments. No malware, script, task, injection, UAC/service/security change, credentials, LSASS, AD/WMI query, authentication, remote movement, external C2, or impact occurs. DC evidence is generated only and real DCs are refused; network attempts are loopback-only with zero bytes.

```powershell
$env:DFIR_LAB_CONFIRMATION = 'I_UNDERSTAND_THIS_IS_A_LAB'
.\IcedAVSim-Complete.ps1 -LabConfirmed
```

Artifacts remain under `%PUBLIC%\IcedAVSim`; run `.\Cleanup-IcedAVSim.ps1 -LabConfirmed` separately.
