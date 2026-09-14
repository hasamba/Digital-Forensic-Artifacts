# 047 - SELECT XMRig FROM SQLServer

Lab-safe PowerShell reconstruction of The DFIR Report's [SELECT XMRig FROM SQLServer](https://thedfirreport.com/2022/07/11/select-xmrig-from-sqlserver/).

The scenario preserves the 24,000 SQL `sa` failures over 27 hours, synthetic SQL events 18456/15457, `xp_cmdshell` ancestry, AV `taskkill` commands, `1.bat` and Certutil-decoded `bigfile.exe`, `Adminv$`, RDP/WDigest/hidden-user settings, BMOF/VBE WMI persistence at 23:00, hourly `ngm` task, IFEO, UnRAR staging, WinRing0, and `smss.exe` XMRig/pool evidence. Published hashes and infrastructure remain metadata only.

The mandatory lab gate refuses domain controllers. No SQL connection or password attempt, xp_cmdshell, process termination, account/registry/security change, privilege escalation, WMI subscription, scheduled task, archive extraction, driver/miner execution, deletion, or IOC contact occurs. Executable decoys are signed `cmd.exe` copies; sockets are loopback-only with zero bytes transferred.

```powershell
.\SqlMinerSim-Complete.ps1 -LabConfirmed
```

Artifacts remain under `%PUBLIC%\SqlMinerSim`; cleanup is separately gated. See [scenario-manifest.json](scenario-manifest.json) and [IOC-METADATA.json](IOC-METADATA.json).
