# 044 - BumbleBee Round Two

Lab-safe PowerShell reconstruction of The DFIR Report's [BumbleBee: Round Two](https://thedfirreport.com/2022/09/26/bumblebee-round-two/).

The scenario preserves `document.iso`, `documents.lnk`, `tamirlan.dll`, rundll32 execution, WMI-spawned `ImagingDevices.exe`/`wabmig.exe`, Meterpreter and Cobalt pivots, native and AdFind discovery, remote ProcDump/C$ copy/7-Zip evidence, `sql_admin`, AnyDesk, RDP/SMB document access, backup-console and OWA checks, and the final `1.bat` ping sweep. The report does not publish an exact total duration, so the 12-hour generated axis preserves relative ordering without asserting a case duration.

The mandatory gate refuses domain controllers. No ISO is mounted; no live payload, injection, credential access, account/service change, remote action, real archive/collection/exfiltration, backup/mail access, or impact occurs. All socket markers are loopback-only with zero bytes transferred.

```powershell
$env:DFIR_LAB_CONFIRMATION = 'I_UNDERSTAND_THIS_IS_A_LAB'
.\BeeRound2Sim-Complete.ps1 -LabConfirmed
```

Artifacts remain under `%PUBLIC%\BeeRound2Sim`; cleanup is separately gated. See [scenario-manifest.json](scenario-manifest.json) and [IOC-METADATA.json](IOC-METADATA.json).
