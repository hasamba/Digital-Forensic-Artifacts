# 019 - The Curious Case of an Egg-Cellent Resume

Lab-safe PowerShell adversary emulation based on The DFIR Report's [The Curious Case of an Egg-Cellent Resume](https://thedfirreport.com/2024/12/02/the-curious-case-of-an-egg-cellent-resume/) (December 2, 2024).

## Campaign evidence reproduced

| Cluster | Artifacts |
|---|---|
| Resume lure | `John Shimkus.zip`, `John-_Shimkus.lnk`, padding `2.jpg`, generated browser-origin metadata, and lure-domain IOC records |
| more_eggs | `ieuinit.inf`, `ie4uinit.exe` process-name canary, DLL names, three XML/JScript-as-text files, `msxsl.exe`, task `8766714F94DD`, 20 `typeperf` process events, discovery commands, and loopback C2 |
| Cobalt Strike | `31765.ocx`, partial beacon profile, `\postex_18ab`/`\postex_77cb` pipe records, CLR `rundll32.exe.log`, Seatbelt/SharpShares outputs, and process-access metadata |
| Discovery/recovery | Non-executed VSSAdmin attempts, AdFind commands, `scaner.zip`/NetScan process and loopback port evidence, and local synthetic share trees |
| Pyramid | Masqueraded embedded-Python ZIP, Python file-creation sprawl, inert `cradle.py`, and the published Pyramid configuration redirected to loopback |
| Veeam/lateral | CVE-2023-27532/VeeamHax command lines, xp_cmdshell/account/crash events, generated Veeam credential output, LSASS metadata, RDP/remote-service events, and actor workstation names |
| Cloudflared/eviction | MSI/service/tunnel records for two hosts, loopback connection, reported more_eggs removal, and explicit defender-eviction/no-ransomware record |

## Safety boundaries

- Explicit lab confirmation is required and domain controllers are refused.
- Executable decoys are renamed signed `cmd.exe` files; all reported commands are escaped `echo` arguments.
- The LNK, INF, DLL, OCX, JScript/XML, Python, and MSI artifacts contain no executable payload. No COM scriptlet, WMI, task, service, SQL, xp_cmdshell, remote service, or account operation occurs.
- Every IOC remains metadata and all TCP attempts use `127.0.0.1`; no DNS, proxy, Cloudflare tunnel, or remote host is used.
- VSSAdmin commands are telemetry only. No shadow copy or credential store is created or accessed.
- LSASS, Veeam data, AD, local/domain accounts, and shares are untouched; credentials are generated canaries.
- The report ended with eviction and did not observe ransomware impact. No encryption or other fabricated impact is included.

## Run and cleanup

From elevated Windows PowerShell 5.1 or later on a disposable VM:

```powershell
.\EggResumeSim-Complete.ps1 -LabConfirmed
```

Artifacts remain under `%PUBLIC%\EggCellentResumeSim`, including `artifact-manifest.jsonl` and `evidence\campaign-timeline.jsonl`.

```powershell
.\Cleanup-EggResumeSim.ps1 -LabConfirmed -WhatIf
.\Cleanup-EggResumeSim.ps1 -LabConfirmed
```

## ATT&CK mapping

T1217, T1136, T1555, T1562.001, T1087.002, T1069.002, T1482, T1068,
T1083, T1070.004, T1105, T1087.001, T1069.001, T1003.001, T1204.002,
T1046, T1135, T1566, T1059.001, T1572, T1090, T1059.006, T1021.001,
T1018, T1053.005, and T1518.001.

See [IOC-METADATA.json](IOC-METADATA.json) and [scenario-manifest.json](scenario-manifest.json).
