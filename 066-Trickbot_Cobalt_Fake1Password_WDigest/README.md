# 066 - Trickbot Leads Up to Fake 1Password Installation

Lab-safe PowerShell companion to The DFIR Report's [Trickbot Leads Up to Fake 1Password Installation](https://thedfirreport.com/2021/08/16/trickbot-leads-up-to-fake-1password-installation/) (internal case 4778).

The scenario reconstructs Trickbot execution and `wermgr.exe` injection metadata; AppData persistence with `settings.ini`, `launcher.bat`, and a scheduled-task marker; PowerShell-delivered Cobalt Strike; native/domain/WMI discovery; WDigest enablement; ProcDump/WMIC LSASS-dump command telemetry; the collection toolkit; fake `Setup1.exe` deployment; and the `1Password\filepass.exe` → `theora2.dll` → `cds.xml` chain with the default `MSSE-*-server` pipe pattern. It ends with the report's negative finding: no exfiltration or impact was observed.

The report does not state a complete incident duration, so the six-hour exercise axis is generated ordering. The only precise relative timing retained is that WDigest changed within two minutes of discovery. The suspected password-protected macro archive is labeled medium confidence because it was not directly observed.

No malware is included. Executable names are signed `cmd.exe` decoys run with fixed benign arguments; published hashes remain metadata and deliberately do not match those decoys. No macro, injection, task, registry change, LSASS access, credential collection, AD/WMI query, remote execution, named pipe, shellcode, external IOC connection, exfiltration, or impact occurs. Network attempts are loopback-only with proxy disabled and zero bytes transferred. DC-related evidence exists only beneath generated canary paths, while real domain-controller execution is refused.

```powershell
.\TrickPassSim-Complete.ps1 -LabConfirmed
```

Artifacts remain under `%PUBLIC%\TrickPassSim`; cleanup is separately gated:

```powershell
.\Cleanup-TrickPassSim.ps1 -LabConfirmed
```

See [scenario-manifest.json](scenario-manifest.json) for the phase/ATT&CK map and [IOC-METADATA.json](IOC-METADATA.json) for published investigation metadata.
