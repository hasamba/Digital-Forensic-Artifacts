# 067 - BazarCall to Conti Ransomware via Trickbot and Cobalt Strike

Lab-safe PowerShell companion to The DFIR Report's [BazarCall to Conti Ransomware via Trickbot and Cobalt Strike](https://thedfirreport.com/2021/08/01/bazarcall-to-conti-ransomware-via-trickbot-and-cobalt-strike/) (internal case 4641).

The scenario preserves the report's two-day chronology: an XLSB lure; renamed CertUtil and Regsvr32 Trickbot loading; `wermgr.exe`/`svchost.exe` injection metadata and `pwgrab`; Cobalt hands-on activity at two hours; Nltest/Net/AdFind/BloodHound/PowerSploit discovery; two-host WMIC movement; eight service-loader attempts; Defender-disable, ProcDump LSASS, and GetSystem markers; a near-four-hour DC pivot with two `ntdsutil` IFM snapshots; generated discovery-exfil records; a two-day pause; and the under-30-minute `_COPY.bat`/`_EXE.bat` PsExec Conti deployment ending in `.KCRAO` and `readme.txt` canaries.

No malware or shellcode is included. Executable names are signed `cmd.exe` decoys with fixed benign arguments, and published hashes deliberately remain metadata. No macro, injection, security-control change, credential/LSASS/NTDS access, AD/WMI query, named-pipe/token action, authentication, remote copy/execution, real share, external C2, real exfiltration, or user-data encryption occurs. DC evidence lives only in a generated host tree; execution on a real domain controller is refused. Network attempts are loopback-only, proxy-free, and transfer zero bytes.

```powershell
.\BazarContiSim-Complete.ps1 -LabConfirmed
```

Artifacts remain under `%PUBLIC%\BazarContiSim`; cleanup is separately gated:

```powershell
.\Cleanup-BazarContiSim.ps1 -LabConfirmed
```

See [scenario-manifest.json](scenario-manifest.json) and [IOC-METADATA.json](IOC-METADATA.json).
