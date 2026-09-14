# 046 - BumbleBee Roasts Its Way to Domain Admin

Lab-safe PowerShell reconstruction of The DFIR Report's [BumbleBee Roasts Its Way to Domain Admin](https://thedfirreport.com/2022/08/08/bumblebee-roasts-its-way-to-domain-admin/).

The generated 11-day timeline preserves the password-protected ZIP/ISO and `document.lnk`, `namr.dll` BumbleBee loader, WMI-launched `wab.exe` Cobalt beacon, process-injection ancestry, native discovery, RDP/AnyDesk, three AdFind occasions, VulnRecon on two hosts, remote ProcDump and comsvcs LSASS dump evidence, Seatbelt, PowerShell Cobalt staging, Kerberoasting, ShareFinder, `s.bat`/`w.bat` target lists, and the weak service-account PsExec pivot to a domain controller before eviction. Published hashes, C2 profiles, named pipes, and AnyDesk details are preserved only as investigation metadata.

The mandatory gate refuses domain controllers. No ISO is mounted; no malware is retrieved or executed; no injection, credential access, Kerberos request or password cracking, remote login/service/share operation, RMM install, tool deletion, or impact occurs. Executable decoys are signed `cmd.exe` copies, and all socket markers target loopback with zero bytes transferred.

```powershell
.\BumbleRoastSim-Complete.ps1 -LabConfirmed
```

Artifacts remain under `%PUBLIC%\BumbleRoastSim`; cleanup is separately gated. See [scenario-manifest.json](scenario-manifest.json) and [IOC-METADATA.json](IOC-METADATA.json).
