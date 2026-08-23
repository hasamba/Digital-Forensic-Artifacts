# 008 - From a Single Click: Lunar Spider (Latrodectus / Brute Ratel / BackConnect)

Source report: [From a Single Click: How Lunar Spider Enabled a Near-Two-Month Intrusion](https://thedfirreport.com/2025/09/29/from-a-single-click-how-lunar-spider-enabled-a-near-two-month-intrusion/) (The DFIR Report, September 29, 2025)

A malvertising-delivered JavaScript "tax form" led to a **~60-day** intrusion by **Lunar Spider**, layering Brute Ratel C4, Latrodectus, BackConnect, Cobalt Strike, and a custom .NET backdoor. Notably, **no ransomware was deployed** - the impact was data exfiltration and long-term access.

## Attack chain simulated

1. **Initial Access** - malicious ad -> obfuscated `Form_W-9_Ver-i40_53b043910-86g91352u7972-6495q3.js` -> HTTP GET `hxxp://91.194.11[.]64/MSI.msi` -> MSI custom action `rundll32 upfilles.dll,stow`.
2. **Execution / Injection** - Brute Ratel C4 loader (XOR + RC4 decrypt) injects **Latrodectus** (v1.3, campaign `2221766521`) into `explorer.exe` via `CreateRemoteThread`; stealer module `fxrm_vn_9.557302425.bin` pulled via command ID 21; Day-4 Cobalt Strike `cron801.dl_`/`system.dl_`.
3. **Persistence** - HKCU Run key `Update` (upfilles.dll -> wscadminui.dll), scheduled task **`SchedulerLsass`** -> `%ALLUSERSPROFILE%\USOShared\lsassa.exe` (onstart).
4. **Privilege Escalation** - `runas` via Secondary Logon (domain-admin creds from `unattend.xml`) -> `gpupdate.exe`; UAC bypass via `ms-settings` handler hijack fired by `ComputerDefaults.exe`.
5. **Defense Evasion** - process injection into `explorer/dllhost/sihost/spoolsv/gpupdate`; anti-forensic deletion of >50% of downloaded tools.
6. **Credential Access** - `unattend.xml` plaintext creds, LSASS access (`0x1010` + `0x1FFFFF` handle pattern), Latrodectus stealer (`cr_pass/ff_pass/edge_pass/outlook_pass`, 29+ Chromium browsers), Day-26 `Veeam-Get-Creds.ps1` (encoded PowerShell).
7. **Discovery** - `ipconfig`/`systeminfo`/`nltest`/`net`/`whoami`/WMIC-AV, **AdFind** (`ad_users/computers/ous/subnets/trustdmp/servers`), DNS zone enum, Day-28 **rustscan**/**nmap** SMB(445) sweeps.
8. **Lateral Movement** - WMIC remote exec (failed), **PsExec** of `system.dl_` to DC/file-share/backup, **Zerologon** (CVE-2020-1472) x8 via `zero.exe`, rejected Metasploit to `217.196.98[.]61:4444`, RDP pivots leaking operator host `VPS2DAY-32220LE`.
9. **Command and Control** - beacons to Latrodectus, Brute Ratel, BackConnect, Cobalt Strike (`sys.dll` -> `avtechupdate[.]com`), and the .NET backdoor (`cloudmeri[.]com/comm.php`, 250s).
10. **Collection / Exfiltration** - Day-20 (~9h46m) **Rclone renamed `sihosts.exe`** + `rclone.conf` -> FTP `45.135.232[.]3` (user `J0eBidenAbrabdy1aS3ha2Yeami`), launched by `start.vbs` -> `run.bat`.
11. **Impact** - **NO ransomware.** Dwell + exfiltration marker written (deliberately different from the ransomware cases in this repo).

## Usage

```powershell
# Run everything end-to-end (requires admin, run on a disposable VM only)
.\LunarSpiderSim-Complete.ps1

# Optional: also dump the REAL lsass.exe (default dumps a decoy process instead)
.\LunarSpiderSim-Complete.ps1 -DumpRealLsass
```

Individual phases can be dot-sourced and run separately for step-by-step training/detection-engineering walkthroughs; each phase file exports one `Simulate-*` function taking the `$SimPaths` hashtable produced by `Initialize-SimulationEnvironment` in `LunarSpiderSim-utilities.ps1`.

## Safety notes

- **Isolated lab VM only.** Snapshot before running. The script creates real local registry keys, scheduled tasks, and dropped files, and attempts real outbound connections to actual reported threat-actor infrastructure (which should fail closed off the internet or on an isolated network, but do not assume that).
- All malware components (Brute Ratel badger, Latrodectus DLL, Cobalt Strike beacons, `zero.exe`, `lsassa.exe`, `sihosts.exe`/Rclone) are **inert placeholder binaries** with authentic filenames/paths - no functional malware or exploit runs.
- The process-injection demo (Phase 2) performs a **real** `CreateRemoteThread` but injects an inert `RET` (`0xC3`) stub into a **sacrificial `notepad.exe`** we spawn - never the real `explorer.exe`.
- LSASS dumping defaults to a **decoy process**; pass `-DumpRealLsass` only if the VM holds no credential material you care about.
- The UAC-bypass `ms-settings` key is written, fired via `ComputerDefaults.exe`, then removed so no live bypass primitive is left behind.
- Zerologon / PsExec / WMIC / Metasploit are represented as command-line + IOC artifacts (no real domain-controller attack is performed).
- **No encryption is performed** - consistent with the report's finding of no ransomware.

## Key IOCs (from the report)

| Type | Value | Role |
|---|---|---|
| File | `Form_W-9_Ver-i40_53b043910-86g91352u7972-6495q3.js` | Malvertising lure |
| IP | `91.194.11[.]64` | JS -> `MSI.msi` staging host |
| File / hash | `upfilles.dll` (MD5 `ccb6d3cb020f56758622911ddd2f1fcb`) | Brute Ratel C4 loader |
| File / hash | `wscadminui.dll` (MD5 `d7bd590b6c660716277383aa23cb0aa9`) | BRC4 replacement (Day 5) |
| Domain | `workspacin[.]cloud`, `illoskanawer[.]com`, `grasmetral[.]com`, `jarkaairbo[.]com`, `scupolasta[.]store` | Latrodectus C2 (`/live/`) |
| Domain | `anikvan[.]com`, `erbolsan[.]com`, `samderat200[.]com`, `kasymdev[.]com` | Brute Ratel C4 |
| IP | `193.168.143[.]196`, `185.93.221[.]12` | BackConnect (VNC) |
| File / hash | `sys.dll` (MD5 `ad3c52316e0059c66bc1dd680cf9edad`) | Cobalt Strike beacon |
| File / hash | `cron801.dl_` / `system.dl_` (MD5 `495363b0262b62dfc38d7bfb7b5541aa`) | Cobalt Strike beacon |
| IP / domain | `206.206.123[.]209:443`, `avtechupdate[.]com` | Cobalt Strike (`sys.dll`) |
| IP | `45.129.199[.]214` | Cobalt Strike (`/vodeo/wg01ck01`) |
| File / hash | `lsassa.exe` (MD5 `50abc42faa70062e20cd5e2a2e2b6633`) | Custom .NET backdoor |
| IP / domain | `162.0.209.121`, `cloudmeri[.]com/comm.php` | .NET backdoor C2 (250s) |
| File / hash | `zero.exe` (MD5 `91889658f1c8e1462f06f019b842f109`) | Zerologon (CVE-2020-1472) |
| File / hash | `rustscan.exe` (MD5 `9eaa8464110883a15115b68ffa1ecf7d`) | Network scanner |
| IP | `217.196.98[.]61:4444` | Metasploit (rejected) |
| IP / user | `45.135.232[.]3`, `J0eBidenAbrabdy1aS3ha2Yeami` | Rclone FTP exfil |
| Hostname | `VPS2DAY-32220LE` | Operator RDP source host |

## MITRE ATT&CK

T1189, T1204.002, T1027, T1218.007, T1218.011, T1055, T1055.002, T1620, T1547.001, T1053.005, T1548.002, T1134, T1078.002, T1070.004, T1036, T1552.001, T1003.001, T1555.003, T1059.001, T1016, T1082, T1482, T1087, T1018, T1069, T1046, T1518.001, T1047, T1021.002, T1210, T1021.001, T1570, T1071.001, T1571, T1105, T1074, T1560, T1048, T1567.

See the source report's full Indicators / Detections / MITRE ATT&CK sections for Sigma/YARA/Suricata rule IDs to validate against the artifacts this simulation produces.
