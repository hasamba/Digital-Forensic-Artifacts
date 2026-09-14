# 070 - From Word to Lateral Movement in 1 Hour

Lab-safe companion to The DFIR Report's [From Word to Lateral Movement in 1 Hour](https://thedfirreport.com/2021/06/20/from-word-to-lateral-movement-in-1-hour/) (case 3930). It preserves the medium-confidence ZIP/Word origin, Regsvr32 IcedID, hourly `upefkuin4.dll`/`license.dat` task, Cobalt at minute 35, WUAUCLT-to-LSASS and AdFind discovery, domain-admin SMB/service movement five minutes later, `halfduplux_9e`, AV failures, and over an hour of RDP file-server browsing without exfiltration or impact.

Executables are signed `cmd.exe` decoys with fixed benign arguments. No malware, macro, task, injection, credential/LSASS access, AD query, token/authentication, SMB/service/RDP action, named pipe, external C2, exfiltration, impact, or actor cleanup occurs. Network attempts are loopback-only with zero bytes. Generated DC paths are canary-only and real DCs are refused.

```powershell
.\IcedMoveSim-Complete.ps1 -LabConfirmed
```

Artifacts remain under `%PUBLIC%\IcedMoveSim`; run `.\Cleanup-IcedMoveSim.ps1 -LabConfirmed` separately.
