# 020 - Inside the Open Directory of the “You Dun” Threat Group

Lab-safe PowerShell reconstruction of The DFIR Report's [Inside the Open Directory of the “You Dun” Threat Group](https://thedfirreport.com/2024/10/28/inside-the-open-directory-of-the-you-dun-threat-group/) (October 28, 2024).

This is a threat-actor infrastructure and capability report, not a single endpoint intrusion. The scenario creates a forensic replica of the exposed workflow without targeting public systems.

## Evidence generated

- Country-separated WebLogicScan/Vulmap/Weaver lists use only reserved `.invalid` names, followed by echo-only WebLogicScan, Vulmap, Xray, dirsearch, sqlmap, Seeyon, and Weaver command telemetry and synthetic findings.
- The Cobalt Strike record preserves port 80, x86/x64 GET paths, `/submit.php`, sleep, watermark `987654321`, spawnto, and injection API metadata; actual connections are loopback.
- `红队版.zip`, TaoWu, Ladon/Landon, and CrossC2 filenames are inert inventory files. Representative high-signal tools span credential theft, recon, privilege escalation, remote execution, evasion, and proxying without containing tool code.
- Viper/f8x, default port/certificate, WPCargo CVE-2021-25003, AWS/Bitnami activity, CDK mount-cgroup, and `traitor-amd64` are negative-execution JSON records.
- Open-directory ports `8000`, `28888`, `55918`, and `60000`, SSH fingerprint, eight proxy IPs, and actor IP remain metadata with loopback-only connection attempts.
- `LB3.exe` is a renamed signed decoy. Generated `.LOCKBIT-YOUDUN-CANARY` markers sit beside intact originals, and the note preserves the public actor attribution without a live contact or payment path.

## Safety boundaries

The scenario requires explicit lab confirmation, refuses domain controllers, contacts only `127.0.0.1`, and never performs web exploitation, SQL injection, web-shell upload, scanning outside loopback, process injection, Docker/Kubernetes operations, container escape, privilege escalation, C2 setup, proxying, ransomware execution, or encryption.

## Run and cleanup

```powershell
$env:DFIR_LAB_CONFIRMATION = 'I_UNDERSTAND_THIS_IS_A_LAB'
.\YouDunSim-Complete.ps1 -LabConfirmed
```

Artifacts remain under `%PUBLIC%\YouDunOpenDirectorySim` with a runtime manifest and capability timeline.

```powershell
.\Cleanup-YouDunSim.ps1 -LabConfirmed -WhatIf
.\Cleanup-YouDunSim.ps1 -LabConfirmed
```

ATT&CK from the report: T1071, T1486, T1068, T1190, T1105, T1595.002, T1071.001, and T1595.003.

See [IOC-METADATA.json](IOC-METADATA.json) and [scenario-manifest.json](scenario-manifest.json).
