# 056 - Qbot Likes to Move It, Move It

Lab-safe PowerShell reconstruction of The DFIR Report's [Qbot Likes to Move It, Move It](https://thedfirreport.com/2022/02/07/qbot-likes-to-move-it-move-it/).

The generated timeline preserves the assessed XLS 4.0 macro delivery, HTML-disguised `ocrafh.html` Qbot DLL, one-time `juqpxmakfk` SYSTEM task, `msra.exe` injection, Defender exclusions, LSASS access, native discovery, minute-30 EmailStorage/WebCache collection, and minute-50 DLL/service movement that rapidly compromised all workstations. Six workstation lanes represent that spread without inventing the report's unpublished host count; no server lane is created because the report says servers were not accessed.

Executable names are signed `cmd.exe` copies with fixed benign executed arguments; reported commands are metadata. Collection and deletion are retained as canaries so evidence remains until separate cleanup. Network attempts terminate on `127.0.0.1` with no proxy and zero bytes transferred. No macro, malware, system change, credential/user-data access, deletion, remote service/copy, server access, IOC contact, or exfiltration occurs.

```powershell
.\QbotMoveSim-Complete.ps1 -LabConfirmed
```

Artifacts remain under `%PUBLIC%\QbotMoveSim`; cleanup is separately gated. See [scenario-manifest.json](scenario-manifest.json) and [IOC-METADATA.json](IOC-METADATA.json).
