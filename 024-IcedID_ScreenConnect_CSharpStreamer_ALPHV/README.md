# 024 - IcedID, ScreenConnect, CSharp Streamer, and ALPHV

Lab-safe PowerShell reconstruction of The DFIR Report's [IcedID Brings ScreenConnect and CSharp Streamer to ALPHV Ransomware Deployment](https://thedfirreport.com/2024/06/10/icedid-brings-screenconnect-and-csharp-streamer-to-alphv-ransomware-deployment/) (June 10, 2024).

The scenario compresses the report's roughly 180-hour, eight-day intrusion while retaining relative timestamps in `intrusion-timeline.jsonl`.

## Evidence generated

- Spam ZIP, Readme, VBS, `0370-1.dll`, second-stage DLL, WScript/regsvr32/rundll32 chain, hourly-logon task XML, immediate native discovery, and forked IcedID TLS indicators.
- Renamed `toovey.exe` ScreenConnect decoy and service/relay parameters, plus BITS, certutil, and PowerShell download attempts including the `temp.sh` HTML-page failure.
- Cobalt Strike HTTP profile and `http64.dll`, CSharp Streamer `cslite.exe`, `.tmp` assembly marker, WebSocket/socket.io ports, self-signed TLS fingerprints, LSASS masks, and DCSync event/GUID evidence without credential access.
- Synthetic DC, backup, file-server, SMB/WMI/RDP/ScreenConnect records and repeated day-two/day-five/day-eight SoftPerfect scan telemetry; no remote system is contacted.
- Generated finance/security files, inert `confucius_cpp.exe` and Rclone decoys, LDAP/keyword/archive/VBS/batch chain, and loopback SSH exfiltration with zero bytes.
- Signed ALPHV `BNUfUOmFT2.exe` decoy, ScreenConnect/WMI/xcopy deployment records, fifteen ransomware markers beside intact originals, and inert notes. Backups remain untouched.

## Safety boundaries

Explicit lab confirmation is required and domain controllers are refused. The scripts contain no live malware and never contact IOCs, query a directory or real share, access LSASS or replication, install ScreenConnect, create tasks/services, perform WMI/RDP/SMB lateral movement, scan beyond loopback, collect user data, exfiltrate bytes, delete backups, or encrypt files.

## Run and cleanup

```powershell
$env:DFIR_LAB_CONFIRMATION = 'I_UNDERSTAND_THIS_IS_A_LAB'
.\IcedAlphvSim-Complete.ps1 -LabConfirmed
```

Artifacts remain under `%PUBLIC%\IcedIDScreenConnectALPHVSim` with a runtime manifest and relative timeline.

```powershell
.\Cleanup-IcedAlphvSim.ps1 -LabConfirmed -WhatIf
.\Cleanup-IcedAlphvSim.ps1 -LabConfirmed
```

ATT&CK from the report is recorded in [scenario-manifest.json](scenario-manifest.json). See [IOC-METADATA.json](IOC-METADATA.json) for all published infrastructure and sample hashes.
