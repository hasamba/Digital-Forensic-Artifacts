# 065 - Cobalt Strike, a Defender's Guide

Lab-safe PowerShell companion to The DFIR Report's [Cobalt Strike, a Defender's Guide](https://thedfirreport.com/2021/08/29/cobalt-strike-a-defenders-guide/).

This source is a defender guide, not one incident, so the three-hour axis is explicitly an ordered composite exercise. It covers PowerShell/on-disk/in-memory Beacon delivery, rundll32 hosting, default pipe patterns, jQuery malleable C2, injection and hollowing, native/AdFind/BloodHound/PowerView discovery, `getsystem`, `svc-exe`, UAC token duplication, `hashdump`, `logonpasswords`, browser/Lazagne/DCSync context, SMB/WMI/psexec/WinRM, pass-the-hash, SOCKS/RDP, remote services, aggressor automation, and the report's Windows/Sysmon detection trail.

No Cobalt Strike or exploit code is included. Tools and aggressor files are inert text; executable names are signed `cmd.exe` decoys with fixed benign arguments. Pipe and event artifacts are ordinary files/JSON, not real named pipes or event-log writes. All network attempts are loopback-only. No injection, credential access, service/registry/token/authentication action, remote movement, Zerologon, or external C2 occurs.

```powershell
.\CSGuide1Sim-Complete.ps1 -LabConfirmed
```

Artifacts remain under `%PUBLIC%\CSGuide1Sim`; cleanup is separately gated. The script refuses domain controllers. See [scenario-manifest.json](scenario-manifest.json) and [IOC-METADATA.json](IOC-METADATA.json).
