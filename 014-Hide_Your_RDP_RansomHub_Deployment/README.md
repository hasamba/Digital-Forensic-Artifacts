# 014 - Hide Your RDP: Password Spray Leads to RansomHub

Lab-safe PowerShell adversary emulation based on The DFIR Report's [Hide Your RDP: Password Spray Leads to RansomHub Deployment](https://thedfirreport.com/2025/06/30/hide-your-rdp-password-spray-leads-to-ransomhub-deployment/) (June 30, 2025).

## Six-day report timeline

| Report time | Scenario evidence |
|---|---|
| Before Day 1 | Four-hour RDP password spray from `185.190.24.54` and `185.190.24.33`, including failed 4625 and six successful-account 4624 canaries |
| Day 1 | Elevated RDP from `164.138.90.2`, native discovery, CredentialsFileView, Mimikatz/LSASS and DCSync representations, Advanced IP Scanner, NetScan, DC/server RDP, and MMC commands |
| Day 2 | Repeat scanning plus Atera and Splashtop process/service-event canaries |
| Day 3 | `wscript.exe → nocmd.vbs → rcl.bat → rclone.exe`, exact extension filters, SFTP-on-443 metadata, and reported 2.03 GB/40-minute transfer |
| Day 3 +20h | Generated `rclone.conf` deletion and tombstone |
| Day 5 | Splashtop return (`johnattan johnattan`, `WINVM`, `10.0.2.15`), NetScan, RDP, and same-password reset canaries |
| Day 6 / ~118h | `amd64.exe`, VM-stop/shadow/symlink/log-clear command telemetry, SMB propagation copies, random six-letter services, RansomHub extension files, and note |

The runtime `six-day-timeline.jsonl` and backdated files preserve these clusters. Current process events occur when the scenario runs.

## Fidelity and inert substitutions

- Password spraying and all 4624/4625, 5379, 4662, Sysmon 10, and 7045 evidence are synthetic JSON records. No authentication occurs.
- Discovery and destructive command lines run through a signed `cmd.exe` decoy with CMD metacharacters escaped before an `echo`-only launch.
- `Advanced_IP_Scanner.exe`, `netscan.exe`, `CredentialsFileView.exe`, `mimikatz.exe`, `AteraAgent.exe`, `SplashtopRemoteService.exe`, `mstsc.exe`, `rclone.exe`, and `amd64.exe` are renamed signed command-shell decoys.
- `setup.msi` is an invalid MSI containing the published hash as metadata. The public IOC table does not assign it to a specific tool, so the scenario does not claim one.
- NetScan covers the reported 16 ports using `127.0.0.1`; its `delete.me` write checks occur only in generated local share trees.
- Mimikatz and NirSoft outputs contain only generated identities and passwords. LSASS, Credential Manager, DPAPI, and Active Directory are never opened.
- Atera and Splashtop services are not installed. Their event/log artifacts reproduce the report's names and actor identifiers locally.
- The VBS/batch chain is genuinely executed, but `rclone.exe` is a signed `cmd.exe` copy whose arguments explicitly perform only `echo`.
- SFTP uses a single TCP attempt to `127.0.0.1:443`; `38.180.245.207` remains metadata. No proxy, SSH client, or remote storage is used.
- The 2.03 GB transfer is recorded as the reported byte count without generating or moving a multi-gigabyte file.
- `amd64.exe` and synthetic remote copies are identical signed decoys. SMB is loopback-only and remote-service creation is represented by JSON plus escaped `sc.exe` command lines.
- VM shutdown, shadow deletion, symlink changes, and event-log clearing are never invoked. The scenario records each as non-executed.
- `.RANSOMHUB-CANARY` files sit beside intact generated originals; no cryptography or user-data traversal occurs.

## Run

Use an elevated Windows PowerShell 5.1 or later session on a disposable lab VM:

```powershell
.\RansomHubSim-Complete.ps1 -LabConfirmed
```

The scenario refuses domain controllers and refuses an existing unowned `%USERPROFILE%\Desktop\RansomHubSim` directory.

Primary runtime artifacts:

- `%PUBLIC%\RansomHubRdpSim`
- `%USERPROFILE%\Desktop\RansomHubSim`
- `%PUBLIC%\RansomHubRdpSim\ProgramData\Veeam\nocmd.vbs`
- `%PUBLIC%\RansomHubRdpSim\ProgramData\Veeam\rcl.bat`
- `%PUBLIC%\RansomHubRdpSim\ProgramData\Veeam\include.txt`
- `%PUBLIC%\RansomHubRdpSim\ProgramData\Veeam\rclone.exe`

Artifacts remain until explicit cleanup.

## Cleanup

```powershell
.\Cleanup-RansomHubSim.ps1 -LabConfirmed -WhatIf
.\Cleanup-RansomHubSim.ps1 -LabConfirmed
```

Cleanup validates the fixed root and Desktop ownership marker, removes only known Desktop artifacts, and leaves a non-empty Desktop folder intact if an analyst added files.

## ATT&CK mapping from the report

T1070.001, T1486, T1003.006, T1087.002, T1069.002, T1482, T1048, T1133,
T1083, T1222, T1070, T1490, T1570, T1087.001, T1069.001, T1003.001,
T1046, T1110.003, T1059.001, T1057, T1219, T1021.001, T1018, T1016,
T1078, T1059.005, T1059.003, and T1543.003.

Destructive techniques are represented by canary telemetry only. See [IOC-METADATA.json](IOC-METADATA.json) for the complete public indicator set.
