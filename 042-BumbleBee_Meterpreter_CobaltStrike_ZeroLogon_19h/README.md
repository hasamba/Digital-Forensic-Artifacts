# 042 - BumbleBee, Meterpreter, Cobalt Strike, and ZeroLogon

Lab-safe PowerShell reconstruction of The DFIR Report's [BumbleBee Zeros in on Meterpreter](https://thedfirreport.com/2022/11/14/bumblebee-zeros-in-on-meterpreter/).

The scripts retain the 19-hour sequence: DMCA contact-form lure, Google-hosted ZIP, `StolenImages_Evidence.iso`, `documents.lnk`, rundll32 `mkl2n.dll`, delayed WMI-spawned `ImagingDevices.exe` Meterpreter injection, migration to `svchost.exe`, WSReset/slui UAC attempts, getsystem, Cobalt `n23.dll`, native/AdFind/ShareFinder discovery, ProcDump LSASS and SAM/SECURITY/SYSTEM hive evidence, named-pipe metadata, successful ZeroLogon/4742 and pass-the-hash indicators, and SMB/remote-service movement.

The mandatory gate refuses domain controllers. No live payload, ISO mount, injection, UAC bypass, getsystem, process/hive/credential access, ZeroLogon traffic, password/account change, pass-the-hash, directory/share query, SMB copy, remote service, authentication impairment, or deletion occurs. Executable telemetry uses signed `cmd.exe` stand-ins and network markers remain loopback-only. The report's Meterpreter port discrepancy—80/443 in narrative versus 80/44 in atomic indicators—is preserved explicitly.

```powershell
.\BeeMeterSim-Complete.ps1 -LabConfirmed
```

Artifacts remain under `%PUBLIC%\BeeMeterSim`; cleanup is separately gated:

```powershell
.\Cleanup-BeeMeterSim.ps1 -LabConfirmed
```

See [scenario-manifest.json](scenario-manifest.json) and [IOC-METADATA.json](IOC-METADATA.json).
