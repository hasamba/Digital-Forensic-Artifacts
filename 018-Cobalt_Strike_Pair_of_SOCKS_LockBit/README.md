# 018 - Cobalt Strike and a Pair of SOCKS Lead to LockBit

Lab-safe PowerShell adversary emulation based on The DFIR Report's [Cobalt Strike and a Pair of SOCKS Lead to LockBit Ransomware](https://thedfirreport.com/2025/01/27/cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware/) (January 27, 2025).

## Eleven-day evidence sequence

| Time | Generated evidence |
|---|---|
| Day 1 / initial | `setup_wm.exe` masquerade, published Cobalt Strike profile, C2 connection canaries, WUAUCLT injection and Seatbelt/SharpView records |
| +30–60 min | `nltest`, synthetic LSASS access, SystemBC `svc.dll`/`svcmcc.dll`, GhostSOCKS `svcmc.dll`/`svchosts.exe`, SYSTEM task and Run-key metadata, SMB service, WinRM, WMI, RDP, and `\\.\pipe\fullduplex_84` records |
| Day 1 / +4h | IE visits to `qaz.im` and `temp.sh`, failed Rclone FTP attempt to `93.115.26.127:21`, then a 40-minute MEGA transfer record |
| Day 2 | DNS-manager activity, second Rclone FTP configuration to `46.21.250.52:21`, 16-hour/several-GB report metadata, Veeam credential-script canary |
| Day 11 | `SETUP.bat`, `share$`, `ds.exe`, WMI/BITS and PsExec redundant deployment scripts, synthetic 7045/PSEXESVC events, local target trees, impact markers, note, and wallpaper metadata |

## Safety boundaries

- Explicit lab confirmation is required and domain controllers are refused.
- Every `.exe`/`.dll` decoy is a renamed signed `cmd.exe`; report SHA-256 values remain separate metadata and are never represented as matching.
- Report commands run only as escaped `echo` arguments. Scheduled tasks, services, Run keys, policies, Windows Defender, WinRM, WMI, SMB shares, RDP, PsExec, and BITS are not changed or used.
- All published IPs and domains are metadata. Actual TCP attempts use `127.0.0.1` only, with proxies and DNS disabled.
- Process injection, CLR module loading, named pipes, and LSASS access are synthetic JSON. NTDSUtil is recorded as a blocked, non-executed attempt. No credential store or domain is accessed.
- `Veeam-Get-Creds.ps1` and shared-account contents return generated canaries only.
- Rclone process telemetry does not read the generated collection or transfer bytes. The report's durations and volumes are recorded as metadata.
- The final deployment creates only local synthetic host trees. `.LOCKBIT-CANARY` files sit beside intact generated originals; no ransomware, encryption, user traversal, or wallpaper change occurs.

## Run and cleanup

From elevated Windows PowerShell 5.1 or later on a disposable VM:

```powershell
$env:DFIR_LAB_CONFIRMATION = 'I_UNDERSTAND_THIS_IS_A_LAB'
.\CobaltSocksSim-Complete.ps1 -LabConfirmed
```

Artifacts remain below `%PUBLIC%\CobaltSocksLockBitSim`, with a runtime manifest and `evidence\eleven-day-timeline.jsonl`.

Cleanup is separate and ownership-checked:

```powershell
.\Cleanup-CobaltSocksSim.ps1 -LabConfirmed -WhatIf
.\Cleanup-CobaltSocksSim.ps1 -LabConfirmed
```

## ATT&CK mapping

T1552.001, T1486, T1562.001, T1087.002, T1069.002, T1482, T1048,
T1567.002, T1615, T1003.001, T1204.002, T1036, T1036.005, T1003.003,
T1059.001, T1057, T1055, T1090, T1547.001, T1021.001, T1018, T1053.005,
T1569.002, T1021.002, T1071.001, T1059.003, T1047, and T1028.

See [IOC-METADATA.json](IOC-METADATA.json) and [scenario-manifest.json](scenario-manifest.json).
