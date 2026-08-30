# 009 - Blurring the Lines: Play / RansomHub / DragonForce

Lab-only, high-fidelity simulation of the intrusion documented in The DFIR
Report, **"Blurring the Lines: Intrusion Shows Connection with Three Major
Ransomware Gangs"** (2025-09-08).

Source: https://thedfirreport.com/2025/09/08/blurring-the-lines-intrusion-shows-connection-with-three-major-ransomware-gangs/

## What makes this case interesting

One affiliate used tooling attributed to **three** different ransomware
operations in a single six-day intrusion:

| Tool / TTP | Attributed group |
|---|---|
| Grixba recon (`GT_NET.exe`, `GRB_NET.exe`) | **Play** |
| SystemBC proxy (`WakeWordEngine.dll` / `conhost.dll`) | **Play + DragonForce** |
| Betruger backdoor (`ccs.exe`) | **RansomHub** |
| `C:\Users\Public\Music` staging pattern | **RansomHub** |
| Prior-victim NetScan output file | **DragonForce** |
| Impacket / NetScan / AdFind / WinRAR / PsExec | shared kit |

**Ransomware was never deployed** - detection and response prevented encryption.
The realized impact was **data exfiltration** and persistent access, so Phase 11
records that outcome by default (no `T1486`). For detection testing you can opt
into a real, sandbox-scoped encryption impact with `-DeployRansomware` (see
[Optional ransomware detonation](#optional-ransomware-detonation--deployransomware)).

## Attack chain (6-day timeline)

- **Day 1** - User runs trojanized `EarthTime.exe` (revoked signer *"Brave
  Pragmatic Network Technology Co., Ltd."*). Process tree
  `explorer.exe -> EarthTime.exe -> cmd.exe -> MSBuild.exe`. MSBuild pulls its
  SectopRAT config from Pastebin and drops
  `C:\Users\Public\Music\WakeWordEngine.dll`, run via `rundll32 <dll>,Reset`.
  SystemBC stands up a proxy tunnel; persistence via a BITS job
  (`QuickAgent2\ChromeAlt_dbg.exe` + Startup `.lnk`) and a new local admin
  `Admon`. PsExec `-s` relaunches the loader as SYSTEM. DCSync against the DC.
- **Day 2** - Lateral movement to the backup and file servers over RDP (through
  the SystemBC proxy). Grixba scanning, Veeam SQL credential theft, SharpHound,
  AdFind, SoftPerfect NetScan. WinRAR archiving and **~15-minute clear-text FTP
  exfiltration** (WinSCP) to `144.202.61.209`.
- **Day 6** - MSBuild drops `ccs.exe` (Betruger), which injects into 172
  processes and beacons to `504e1c95.host.njalla[.]net` / `80.78.28.149`.
  Impacket `wmiexec` runs DC enumeration (`WmiPrvSE.exe -> cmd.exe`).

## Files

| File | Phase |
|---|---|
| `BlurringLinesSim-utilities.ps1` | Shared helpers, IOC table, timeline anchors |
| `BlurringLinesSim-Phase1-InitialAccess.ps1` | EarthTime.exe -> MSBuild -> SectopRAT |
| `BlurringLinesSim-Phase2-Execution.ps1` | Injection, SystemBC, stealer |
| `BlurringLinesSim-Phase3-Persistence.ps1` | BITS, Startup `.lnk`, local admin |
| `BlurringLinesSim-Phase4-PrivilegeEscalation.ps1` | PsExec `-s` (PSEXESVC) -> SYSTEM |
| `BlurringLinesSim-Phase5-DefenseEvasion.ps1` | Defender off, masquerade, timestomp |
| `BlurringLinesSim-Phase6-CredentialAccess.ps1` | Veeam DB, DCSync, LSASS |
| `BlurringLinesSim-Phase7-Discovery.ps1` | native recon, Grixba, NetScan, SharpHound, AdFind |
| `BlurringLinesSim-Phase8-LateralMovement.ps1` | RDP-over-proxy, wmiexec |
| `BlurringLinesSim-Phase9-CommandAndControl.ps1` | Betruger (Day 6) + full C2 stack |
| `BlurringLinesSim-Phase10-CollectionExfiltration.ps1` | WinRAR, FS64, WinSCP FTP |
| `BlurringLinesSim-Phase11-Impact.ps1` | 3-gang attribution; optional real encryption |
| `BlurringLinesSim-Complete.ps1` | Runs all phases in order |

## How to run

On an **isolated, snapshot-able lab VM only**, in an elevated PowerShell:

```powershell
.\BlurringLinesSim-Complete.ps1
```

Type `EXECUTE-BLURRINGLINES-SIM` at the prompt to confirm. Options:

- `-SkipDefenderDisable` - leave Microsoft Defender enabled.
- `-DumpRealLsass` - dump the **real** `lsass.exe` in Phase 6 (default dumps a
  decoy process). Use only on a fully disposable VM.
- `-DeployRansomware` - Phase 11 also detonates a **real** encryption impact
  (see below). Default off - the real intrusion was stopped before encryption.
- `-RansomFamily <RansomHub|Play|DragonForce>` - which gang's extension + ransom
  note to emulate when `-DeployRansomware` is set. Default `RansomHub` (the
  backdoor and staging TTP actually on the box).

Example - detonate the "if it had not been stopped" DragonForce outcome:

```powershell
.\BlurringLinesSim-Complete.ps1 -DeployRansomware -RansomFamily DragonForce
```

Phase scripts can also be dot-sourced and called individually (each defines one
`Simulate-*` function). After execution, collect with KAPE (see
`kape command.bat` in the repo root) and build a timeline.

### Optional ransomware detonation (`-DeployRansomware`)

The report states encryption was **prevented**, so it is **off by default**.
When enabled, Phase 11 performs a real impact you can use for detection testing:

- **AES-256 encryption** of the seeded victim documents, appending the family
  extension (`.<6-hex>` for RansomHub, `.play`, or `.dragonforce`). The pass is
  **hard-scoped** to `...\BlurringLinesSim\victim_files` and `...\staging` by an
  explicit under-sim-root guard - it refuses to touch anything outside the sim
  root, and the `_*.txt` summary/attribution files are never encrypted.
- **Ransom note** matching the chosen family (`README_<ext>.txt`, `ReadMe.txt`,
  or `readme.txt`) dropped in the sandbox folders and on the Desktop. Contact
  details are redacted placeholders.
- **Volume Shadow Copy deletion** (`Get-WmiObject Win32_Shadowcopy | Remove-WmiObject`
  + `vssadmin delete shadows /all /quiet`) - T1490.
- **Wallpaper defacement** (cosmetic, reversible; set env
  `BLURRINGLINESSIM_SKIP_WALLPAPER=1` to log-only).

Snapshot the VM before running with this flag.

## Fidelity model

- Dropped tools that must **launch** (`EarthTime.exe`, `ccs.exe`, `GT_NET.exe`,
  `netscan.exe`, `sh.exe`, `adfind.exe`, `FS64.exe`, `WinRAR.exe`, `PsExec.exe`)
  are **real signed Windows binaries** copied to the malware's name/path with
  the report's IOC strings appended as a benign overlay - so process-creation,
  Prefetch, Amcache and YARA-string artifacts are authentic while nothing
  malicious runs.
- Files that only need to **exist** on disk (`WakeWordEngine.dll`,
  `conhost.dll`, `ExportData.db`, `data.zip`) are inert `MZ`-headed decoys.
- Real system changes are performed: Defender policy keys, BITS job, Startup
  shortcut, local admin account, `PSEXESVC` service install, RDP enable,
  `wmic process call create`, registry writes, timestomp to 2037.
- Every C2 IOC (`45.141.87.55`, `149.28.101.219`, `80.78.28.149`,
  `504e1c95.host.njalla[.]net`, `144.202.61.209`, `pastebin.com`) gets a real
  DNS + TCP connection attempt for authentic network telemetry; all fail closed.

## Key IOCs (see the report's Indicators section for the full set)

- **C2** - `45.141.87.55:9000,15647` (SectopRAT), `149.28.101.219:443`
  (SystemBC), `80.78.28.149:80,443` + `504e1c95.host.njalla[.]net` (Betruger)
- **Exfil** - `144.202.61.209` (clear-text FTP)
- **Staging** - `C:\Users\Public\Music\`
- **Account** - `Admon` / `Qwerty12345!`
- **Actor RDP hostnames** - `DESCTOP-QPITRY`, `DESKTOP-A1HRTMJ`,
  `DESKTOP-PGD76HT`, `WIN-FLGU1CC210K`

## MITRE ATT&CK coverage

T1204.002, T1036.005, T1059.003, T1127.001, T1105, T1102, T1218.011, T1055,
T1555, T1197, T1547.001, T1136.001, T1098.007, T1543.003, T1569.002, T1134,
T1562.001, T1070.006, T1027, T1003.006, T1003.001, T1016, T1018, T1046,
T1069.001, T1069.002, T1087.001, T1087.002, T1482, T1135, T1615, T1021.001,
T1047, T1090, T1572, T1570, T1078, T1560.001, T1119, T1074, T1048, T1657.

With `-DeployRansomware`, Phase 11 additionally covers **T1486** (Data Encrypted
for Impact), **T1490** (Inhibit System Recovery), and **T1491.001** (Internal
Defacement).

## Safety

Every script here makes real, system-modifying changes and reaches real
threat-actor infrastructure. **Never run outside an isolated, snapshot VM** with
no access to production data or networks. The impact phase performs **no**
encryption unless you pass `-DeployRansomware`, and even then encryption is
hard-scoped to the sim's own `victim_files` / `staging` folders.
