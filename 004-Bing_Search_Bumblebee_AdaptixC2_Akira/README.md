# 004 - Bing Search to Ransomware: BumbleBee, AdaptixC2, Akira

Source report: [From Bing Search to Ransomware: Bumblebee and AdaptixC2 Deliver Akira](https://thedfirreport.com/2026/06/29/from-bing-search-to-ransomware-bumblebee-and-adaptixc2-deliver-akira-3/) (The DFIR Report, June 29, 2026)

Artifacts: https://mega.nz/folder/NINxlJwL#GbSw5u_1lRgg2qtKhbHBCA

## Attack chain simulated

1. **Initial Access** - Bing SEO poisoning to `opmanager[.]pro` / `download-center[.]online` lookalike domains, trojanized `ManageEngine-OpManager.msi`.
2. **Execution / Process Injection** - DLL search-order hijack (`consent.exe` sideloads `msimg32.dll`, the BumbleBee loader), WMI-spawned `AdgNsy.exe` (renamed `wab.exe`) with a real (harmless no-op) remote process injection to reproduce the RWX/unbacked-memory forensic signature, AdaptixC2 HTTP beacon.
3. **Persistence** - rogue `backup_DA` / `backup_EA` accounts escalated to Enterprise Admins / local Administrators, RustDesk installed as a service, `cloudflared` service (Swisscom variant, `1.ps1`).
4. **Defense Evasion** - mixed-case command execution (`CmD.eXe`, `pOWerShELl.exE`), secure deletion of staged loaders, decoy BYOVD driver service registration (`mgdsrv`/`KMHLPSVC`).
5. **Credential Access** - `wbadmin.exe` NTDS.dit/SYSTEM/SECURITY extraction (against decoy files), Veeam PostgreSQL credential dump via encoded PowerShell, `comsvcs.dll` MiniDump LSASS technique (lsassy pattern).
6. **Discovery** - `net`/`nltest`/`quser` enumeration, SPN enumeration to `spn.txt`, `Invoke-ShareFinder` (real PowerView), SoftPerfect Network Scanner artifact (`n.exe`/`delete.me`), `Get-ADComputer`/`Get-ADUser` export.
7. **Lateral Movement** - reverse SSH tunnel (`ssh -R *:10400 -p22`) to real reported threat-actor infrastructure, RDP pivot workstation-name artifacts (`WORK`, `kali`, `DESKTOP-HPLM2TD`, ...).
8. **Collection** - sweep of credential stores, browser data, cloud CLI configs, password managers, dev source trees, remote-access tool configs.
9. **Exfiltration** - FileZilla (`recentservers.xml`, user `Stark`) + SFTP to the reported exfil server IP.
10. **Impact** - Akira ransomware (`locker.exe`), real AES encryption confined to a sandbox folder, ransom note, real Volume Shadow Copy deletion via WMI/PowerShell.

## Usage

```powershell
# Run everything end-to-end (requires admin, run on a disposable VM only)
.\AkiraSim-Complete.ps1

# Optional: also dump the REAL lsass.exe (default dumps a decoy process instead)
.\AkiraSim-Complete.ps1 -DumpRealLsass
```

Individual phases can be dot-sourced and run separately for step-by-step training/detection-engineering walkthroughs; each phase file exports one `Simulate-*` function taking the `$SimPaths` hashtable produced by `Initialize-SimulationEnvironment` in `AkiraSim-utilities.ps1`.

## Safety notes

- **Isolated lab VM only.** Snapshot before running. This script creates real local accounts, services, scheduled artifacts, deletes real Volume Shadow Copies, and attempts real outbound connections to actual reported threat-actor infrastructure (which should fail closed off the internet or on an isolated network, but do not assume that).
- File "encryption" in Phase 10 is real AES-256 but is hard-scoped to `C:\AkiraSim\victim_files` - it never touches the analyst's real user data.
- `comsvcs.dll` LSASS dumping defaults to a decoy process; pass `-DumpRealLsass` only if the VM contains no real credential material you care about.
- BYOVD driver services register inert placeholder `.sys` files, not the real (dangerous) vulnerable drivers - kernel access is never actually obtained.
- RustDesk/cloudflared/FileZilla/SoftPerfect binaries are either the real, legitimate installers (downloaded live where internet egress and the vendor endpoint are available) or benign placeholder binaries as an offline fallback.

## Key IOCs (from the report)

| Type | Value | Role |
|---|---|---|
| Domain | `opmanager[.]pro`, `download-center[.]online`, `ip-scanner[.]org` | SEO poisoning lure |
| IP | `188.40.187.145`, `109.205.195.211`, `171.22.183.43` | BumbleBee C2 |
| IP | `172.96.137.160` | AdaptixC2 C2 |
| IP | `193.242.184.150` | Reverse SSH tunnel endpoint |
| IP | `185.174.100.203` | Exfil server (Ukraine, AS-COLOCROSSING) |

## MITRE ATT&CK

T1189, T1204.002, T1574.001, T1036, T1055, T1047, T1136, T1543.003, T1078, T1027.010, T1070.004, T1003.003, T1555, T1003.001, T1087, T1482, T1018, T1135, T1090, T1021.001, T1021.003, T1005, T1552.001, T1048.001, T1041, T1486, T1490.

See the source report's full Indicators / Detections / MITRE ATT&CK sections for Sigma/YARA/Suricata rule IDs to validate against the artifacts this simulation produces.
