# 026 - From OneNote to RansomNote: An Ice Cold Intrusion

Lab-safe PowerShell reconstruction of The DFIR Report's [From OneNote to RansomNote: An Ice Cold Intrusion](https://thedfirreport.com/2024/04/01/from-onenote-to-ransomnote-an-ice-cold-intrusion/) (April 1, 2024).

The scripts compress the report's 812-hour, just-over-34-day intrusion while retaining relative timestamps and its deliberately narrow two-server impact.

## Evidence generated

- OneNote secure-message lure, `O p e n.cmd`, Mark-of-the-Web context, `COIm.jpg` DLL masquerade, IcedID `Cadiak.dll`/`license.dat`, task XML fields, campaign ID, and loopback-only C2.
- Twenty-one beacon-only days, day-22 hard-coded IcedID discovery burst, and day-33 Cobalt `agaloz.dll` failure followed by `Funa2.exe`, default pipes, Gmail-like URI, and `svchost.exe` injection evidence.
- Inert `INSTALL.ps1`, AnyDesk install/password/service/client-ID/trace records, LSASS mask `0x1FFFFF`, Sysmon event IDs 8/10/17, and credential-document evidence without access.
- AdFind, `AD.bat`, `ns.bat`, `nsser.bat`, all reported NetScan ports, GUI discovery, synthetic RDP path, and generated share files containing no real credentials, PII, or financial data.
- FileZilla SFTP version/host-key/XML evidence and 18-hour exfiltration timeline with a loopback port-22 attempt and zero bytes transferred.
- Nokoyawa config, file/backup-server scope, eleven reported backup-server retries, IOBit/ProcessHacker/notepad++ debugging metadata, and eight markers beside intact originals.

## Safety boundaries

The scenario requires explicit lab confirmation and refuses domain controllers. It contains no live malware and never contacts IOCs, accesses LSASS or credentials, queries a real directory/share, moves via RDP, installs AnyDesk/FileZilla, creates tasks/services, scans beyond loopback, transfers data, removes tools or backup software, changes Group Policy, deletes shadows, or encrypts files.

## Run and cleanup

```powershell
.\IceColdSim-Complete.ps1 -LabConfirmed
```

Artifacts remain under `%PUBLIC%\OneNoteIceColdSim` with a runtime manifest and relative timeline.

```powershell
.\Cleanup-IceColdSim.ps1 -LabConfirmed -WhatIf
.\Cleanup-IceColdSim.ps1 -LabConfirmed
```

ATT&CK and published IOCs/hashes are recorded in [scenario-manifest.json](scenario-manifest.json) and [IOC-METADATA.json](IOC-METADATA.json).
