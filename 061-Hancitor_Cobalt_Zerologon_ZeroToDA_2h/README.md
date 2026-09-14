# 061 - From Zero to Domain Admin

Lab-safe PowerShell reconstruction of The DFIR Report's [From Zero to Domain Admin](https://thedfirreport.com/2021/11/01/from-zero-to-domain-admin/), internal case 5295.

The generated two-hour chronology preserves the FeedProxy/Word macro Hancitor chain, two Cobalt stagers and Ficker Stealer, process injection, backup-product/SMB scanning, domain discovery, C$ checks, `cor`/`GAS` remote-service movement, obfuscated `agent1.ps1`, sub-hour `zero.exe` Zerologon privilege escalation, 7045/4624/4648 evidence, `comp2.ps1`/`check.exe` host sweeps, key-system footholds, and defender eviction before impact.

All scripts and DLLs are inert text; executable names are signed `cmd.exe` copies with fixed benign arguments. Published hashes remain metadata and network attempts are loopback-only. No macro/download, malware, injection, scan or AD query, share access, remote transfer/service, shellcode/compiler, Zerologon, machine-password reset, NTLM/credential access, DC action, ICMP sweep, or impact occurs.

```powershell
.\ZeroDASim-Complete.ps1 -LabConfirmed
```

Artifacts remain under `%PUBLIC%\ZeroDASim`; cleanup is separately gated. The script refuses domain controllers. See [scenario-manifest.json](scenario-manifest.json) and [IOC-METADATA.json](IOC-METADATA.json).
