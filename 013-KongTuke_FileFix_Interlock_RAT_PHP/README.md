# 013 - KongTuke FileFix Leads to Interlock RAT PHP Variant

Lab-safe PowerShell adversary emulation based on The DFIR Report's [KongTuke FileFix Leads to New Interlock RAT Variant](https://thedfirreport.com/2025/07/14/kongtuke-filefix-leads-to-new-interlock-rat-variant/) (July 14, 2025).

## Report-faithful chain

1. A local compromised-site canary contains a KongTuke/LandUpdate808-style web inject and fake “Verify you are human” flow.
2. Verification instructions represent the reported Run-dialog/FileFix transition. The exact PowerShell command is preserved in a clipboard artifact and escaped process telemetry; the real clipboard is never changed.
3. The reported task deletion, WebClient `DownloadString`, and `iex` are metadata only. No task is queried or deleted and no PowerShell payload is downloaded or evaluated.
4. `%APPDATA%\php\php.exe` is a renamed signed `cmd.exe` decoy. It launches with `-d extension=zip -d extension_dir=ext ...\wefs.cfg 1` telemetry.
5. `wefs.cfg` and `wefs-alt.cfg` are inert files with the exact published sizes—27,392 and 28,268 bytes—and explicit reported-hash headers.
6. Automated discovery creates a local JSON profile covering system details, processes, services, drives, IPv4 neighbors, and USER/ADMIN/SYSTEM context.
7. Interactive AD, user-description, Veeam/backup-host, task, DC, identity, and AppData discovery commands are preserved, while directory results are synthetic and no LDAP/domain query occurs.
8. All six Cloudflare Tunnel domains and two fallback IPs produce `curl.exe` telemetry forced to `127.0.0.1` with proxy bypass.
9. EXE, DLL/rundll32, AUTORUN, CMD, and OFF capabilities are represented. The Run entry is real but targets only the signed PHP-name decoy and inert config.
10. RDP lateral movement is represented by a signed `mstsc.exe`-named decoy and a loopback port attempt.

The report describes an Interlock RAT campaign, not a completed ransomware incident. This scenario deliberately does not invent encryption, exfiltration, credential dumping, or later ransomware phases.

## Safety controls

- Requires both `-LabConfirmed` and `DFIR_LAB_CONFIRMATION=I_UNDERSTAND_THIS_IS_A_LAB`.
- Refuses systems with domain-controller roles or an `NTDS` service.
- Refuses an existing non-scenario `%APPDATA%\php` directory or pre-existing canary Run value.
- Copies no PHP runtime and contains no executable PHP, live malware, shellcode, downloader, or attacker command.
- Escapes CMD metacharacters before placing report commands into `echo`-only decoy launches.
- Uses `curl --resolve` for domains and `curl --connect-to` for IPs, always to `127.0.0.1`, with `--noproxy *`, no redirect following, and a two-second maximum.
- Performs no real AD query, remote authentication, C2, RDP, credential access, scheduled-task operation, security-control impairment, or destructive impact.
- Leaves all evidence in place. Cleanup is a separate fixed-target action with ownership and value checks.

## Run

From an elevated Windows PowerShell 5.1 or later console on a disposable lab VM:

```powershell
$env:DFIR_LAB_CONFIRMATION = 'I_UNDERSTAND_THIS_IS_A_LAB'
.\InterlockSim-Complete.ps1 -LabConfirmed
```

Primary artifact locations:

- `%PUBLIC%\InterlockFileFixSim`
- `%APPDATA%\php\php.exe`
- `%APPDATA%\php\wefs.cfg`
- `%APPDATA%\php\wefs-alt.cfg`
- `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\InterlockRatCanary`

Review `artifact-manifest.jsonl`, `attack-timeline.jsonl`, shortcuts, Prefetch, Amcache, registry, process creation, discovery JSON, and loopback command lines before cleanup.

## Cleanup

```powershell
.\Cleanup-InterlockSim.ps1 -LabConfirmed -WhatIf
.\Cleanup-InterlockSim.ps1 -LabConfirmed
```

Cleanup removes the Run value only if its contents still match the scenario. It removes only known AppData files with the matching ownership marker, leaves a non-empty PHP directory intact, and validates the fixed scenario root.

## Scenario ATT&CK mapping

| Behavior | Technique |
|---|---|
| Compromised web-inject delivery | T1189 - Drive-by Compromise |
| FileFix / copied verification command | T1204.004 - Malicious Copy and Paste |
| PowerShell | T1059.001 |
| PHP command interpreter | T1059 - Command and Scripting Interpreter |
| Payload/config transfer representation | T1105 - Ingress Tool Transfer |
| System information | T1082 |
| Process discovery | T1057 |
| Service discovery | T1007 |
| Drive discovery | T1081 |
| Network-neighbor discovery | T1016 |
| Permission context | T1033, T1069 |
| Domain computer/user/backup-host discovery | T1018, T1087.002, T1069.002 |
| Cloudflare Tunnel C2 | T1071.001, T1102.002 |
| DLL execution with rundll32 | T1218.011 |
| HKCU Run persistence | T1547.001 |
| Shell command capability | T1059.003 |
| RDP lateral movement | T1021.001 |

See [IOC-METADATA.json](IOC-METADATA.json) for the complete public hash, size, domain, and fallback-IP set.
