# 016 - Navigating Through The Fog

Lab-safe PowerShell reconstruction of the Fog-ransomware affiliate toolkit described in The DFIR Report's [Navigating Through The Fog](https://thedfirreport.com/2025/04/28/navigating-through-the-fog/) (April 28, 2025).

This report analyzes a threat-actor open directory discovered at `194.48.154.79:80` in December 2024. It is not a chronological endpoint intrusion report, so the scenario organizes the observed files and commands by capability and does not invent a ransomware deployment.

## What the scenario creates

| Capability | Forensic artifacts |
|---|---|
| Open directory | Reported dot-directories, victim-named folder metadata, tool folders, ZIP filenames, `.bash_history`, Sliver names, and a captured listing under `194.48.154.79-open-directory` |
| Initial access | `sonic_scan/data.txt` with generated accounts, inert `main.py`, renamed `netextender.exe`, echo-only command telemetry, VPN result JSON, and loopback port attempts |
| Persistence | Reconstructed but inert `any.ps1`, renamed `AnyDesk.exe`, password/install/get-ID command lines, and synthetic 7045/4697 events |
| Lateral movement | NetExec process telemetry plus local `DC01`, `FILE01`, and `APP01` `ADMIN$` canary trees |
| Credential access | DonPAPI and `dpapi.py` options, generated browser/certificate/hash output, and explicit negative DPAPI assertions |
| AD exploitation | Certipy, Orpheus, Zer0dump, Pachine, and noPac filenames and command lines with negative AD CS, Kerberos, machine-account, DC-password, and shell assertions |
| C2 and tunneling | Sliver client/server/implant names, loopback-only Sliver config, Proxychains config fixed to `127.0.0.1:1080`, inert Powercat, and connection records |

## Safety substitutions

- Execution requires the lab environment variable and `-LabConfirmed`, and refuses domain controllers.
- Executable decoys are renamed copies of signed Windows `cmd.exe`; Python and PowerShell tool files contain inert documentation only.
- Reported command lines pass to an escaped `echo` process. No Python toolkit, VPN client, AnyDesk installer, proxy client, Sliver implant, or Powercat socket runs.
- `194.48.154.79`, `AS62240`, and the public victim references are investigation metadata only. All TCP attempts use `127.0.0.1`; proxies and DNS are not used.
- SonicWall credentials in `data.txt` are generated canaries. No real credentials, password store, browser profile, certificate store, DPAPI key, Credential Manager, vault, or registry hive is read.
- There are no AD, AD CS, Kerberos, Netlogon, SMB, remote-service, remote-shell, remote-share, or machine-account operations.
- The report only observed that Orpheus was downloaded, so the scenario preserves its file and a non-executing command canary without claiming successful Kerberoasting.
- No Fog ransomware binary or impact was observed in this report. The scenario explicitly records that no ransomware or encryption is simulated.

## Run

From an elevated Windows PowerShell 5.1 or later session on a disposable VM:

```powershell
.\FogToolkitSim-Complete.ps1 -LabConfirmed
```

Artifacts remain under `%PUBLIC%\FogOpenDirectorySim` for investigation. Review `artifact-manifest.jsonl`, `evidence\capability-timeline.jsonl`, and `operator-summary.txt`.

## Cleanup

Cleanup is separate and validates the fixed root plus ownership marker:

```powershell
.\Cleanup-FogToolkitSim.ps1 -LabConfirmed -WhatIf
.\Cleanup-FogToolkitSim.ps1 -LabConfirmed
```

## ATT&CK mapping

T1078, T1133, T1046, T1021.002, T1219, T1543.003, T1555, T1555.003,
T1649, T1558.003, T1068, T1090, T1071.001, T1572, T1105, and T1059.001.

See [IOC-METADATA.json](IOC-METADATA.json) and [scenario-manifest.json](scenario-manifest.json) for machine-readable details.
