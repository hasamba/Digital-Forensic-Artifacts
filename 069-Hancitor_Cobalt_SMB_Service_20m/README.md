# 069 - Hancitor Continues to Push Cobalt Strike

Lab-safe companion to The DFIR Report's [Hancitor Continues to Push Cobalt Strike](https://thedfirreport.com/2021/06/28/hancitor-continues-to-push-cobalt-strike/) (case 4301). It reconstructs the macro/OLE `rem.r` chain, Rundll32 execution, Hancitor-to-svchost and Cobalt-to-rundll32 injection metadata, Ficker/Cobalt download attempts, Class-A ICMP and SMB discovery, the roughly 20-minute `95.bat`/`95.dll` movement, remote-service execution, unsuccessful LSASS access, and eviction before impact.

Executable names are signed `cmd.exe` decoys with fixed benign arguments. No malware, macro, injection, scan, share, credential, service, remote execution, self-deletion, external C2, or impact occurs. Network attempts use loopback only and transfer zero bytes. Generated DC evidence is canary-only and real DC execution is refused.

```powershell
.\Hancitor20Sim-Complete.ps1 -LabConfirmed
```

Artifacts remain under `%PUBLIC%\Hancitor20Sim`; run `.\Cleanup-Hancitor20Sim.ps1 -LabConfirmed` separately.
