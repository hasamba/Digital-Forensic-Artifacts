# 049 - Will the Real Msiexec Please Stand Up?

Lab-safe PowerShell reconstruction of The DFIR Report's [Will the Real Msiexec Please Stand Up? Exploit Leads to Data Exfiltration](https://thedfirreport.com/2022/06/06/will-the-real-msiexec-please-stand-up-exploit-leads-to-data-exfiltration/).

The eight-day timeline preserves the two CVE-2021-44077 requests from different Tor exits, failed and successful `msiexec.exe` impostors, `fm2.jsp` SYSTEM web shell, WDigest query/change, repeated session checks, day-seven comsvcs LSASS dump, renamed Plink `ekern.exe` with `FXS.bat`, Bitvise SSH-over-443 reverse RDP forwarding, movement to a domain controller/file server/third server, and selective database, certificate, Visio, accounts, and partner-document theft. Five published file-hash triplets and all atomic network indicators remain investigation metadata.

The mandatory gate refuses domain controllers. No exploit request, web shell, SYSTEM execution, WDigest/registry change, credential access, download, SSH/RDP tunnel, remote session, real file/certificate/database access, deletion, or exfiltration occurs. Executable decoys are signed `cmd.exe` copies and every socket marker targets loopback with zero bytes transferred. The plaintext Plink password published by the source is intentionally redacted from scenario execution evidence.

```powershell
.\MsiPlinkSim-Complete.ps1 -LabConfirmed
```

Artifacts remain under `%PUBLIC%\MsiPlinkSim`; cleanup is separately gated. See [scenario-manifest.json](scenario-manifest.json) and [IOC-METADATA.json](IOC-METADATA.json).
