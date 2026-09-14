# 034 - Truebot, FlawedGrace, Cobalt Strike, and MBR Killer

Lab-safe PowerShell reconstruction of The DFIR Report's [A Truly Graceful Wipe Out](https://thedfirreport.com/2023/06/12/a-truly-graceful-wipe-out/).

The scripts retain the observed 29-hour sequence: a 404 TDS link and fake Adobe Truebot executable, renamed `RuntimeBroker.exe`, FlawedGrace registry/task and process-injection evidence, Cobalt Strike discovery and pass-the-hash lateral-movement evidence, two exfiltration periods, and MBR Killer deployment.

The lab gate and domain-controller refusal are mandatory. No payload is downloaded; no reported IOC is contacted; no account, group, task, registry, service, Defender setting, process memory, registry hive, LSASS memory, remote host, share, or physical drive is changed or accessed. Exfiltration and C2 attempts terminate on loopback. Wiper evidence uses identical generated 512-byte sector files and never requests a reboot.

```powershell
.\GraceWipeSim-Complete.ps1 -LabConfirmed
```

Artifacts remain under `%PUBLIC%\GraceWipeSim`; cleanup is separately gated. See [scenario-manifest.json](scenario-manifest.json) and [IOC-METADATA.json](IOC-METADATA.json).
