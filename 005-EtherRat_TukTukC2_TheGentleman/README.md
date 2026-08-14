# 005 - EtherRAT and TukTuk C2 End in The Gentlemen Ransomware

Source report: [Flash Alert: EtherRat and TukTuk C2 End in The Gentleman Ransomware](https://thedfirreport.com/2026/05/11/flash-alert-etherrat-and-tuktuk-c2-end-in-the-gentleman-ransomware/) (The DFIR Report, May 11, 2026)

A user executed a trojanized MSI masquerading as the Sysinternals RAMMap utility, which dropped **EtherRAT** - a malware family that uses "EtherHiding" (querying Ethereum smart contracts via `1rpc.io`) to dynamically resolve its C2 configuration from the blockchain, then pointed itself at a real TryCloudflare tunnel while also pushing decoy domains to complicate analysis. After extensive host/domain recon, the actor deployed **TukTuk** - a newer, reportedly AI-generated malware framework - sideloaded via `log4net.dll` next to trojanized copies of Greenshot, SyncTrayzor, DocFX, and Cake, communicating over abused SaaS platforms (ClickHouse, Supabase, with Ably/Dropbox/GitHub Issues/Arweave as backup/dead-drop channels). The actor then went hands-on-keyboard with Kerberoasting, LSASS/NTDS dumping, and NetExec-driven lateral movement, used the legitimate RMM tool GoTo Resolve to expand access to servers and domain controllers, exfiltrated data via Rclone to Wasabi cloud storage, and finished by deploying **The Gentlemen** ransomware domain-wide through a malicious Group Policy Object that executed staged binaries from SYSVOL/NETLOGON via scheduled tasks.

## Attack chain simulated

1. **Initial Access** - trojanized `RAMMap.msi` (masquerading as Sysinternals RAMMap) executed from Desktop/Downloads, spawning `msiexec.exe -> cmd.exe /c start /min "" "MVnVmUYj.cmd"`.
2. **Execution** - portable Node.js runtime downloaded via `curl` (real download from nodejs.org), obfuscated JS payload + `A7Pnj975bl.cfg` config launched via `conhost --headless node.exe`, EtherRAT resolving C2 config from Ethereum smart contracts through `1rpc.io` (EtherHiding), then rotating to a real TryCloudflare tunnel plus decoy domains.
3. **Persistence** - `HKCU\...\Run\AppResolver` registry key re-launching `node.exe` on logon (exact reported command line), later GoTo Resolve RMM service installation (`GoToResolve_*`) and `smokymo.msi` installer staging.
4. **Discovery** - automated PowerShell one-liners (locale, GPU, AV product, domain membership, `ProductName`, `MachineGuid`), manual `whoami /all`, `net group "Domain Admins"/"Enterprise Admins" /domain`, `nltest /domain_trusts`/`dclist`, and SoftPerfect Network Scanner (`netscan.exe`).
5. **Defense Evasion** - TukTuk sideloaded via `log4net.dll` next to trojanized Greenshot/SyncTrayzor/DocFX/Cake binaries (T1574.002); Arweave dead-drop resolver capability exercised against real Arweave gateways (present in code, use in this intrusion unconfirmed per report).
6. **Command and Control** - TukTuk primary channels over ClickHouse and Supabase, fallback HTTP C2, secondary/backup transports (Ably, Dropbox, GitHub Issues), plus GoTo Resolve as a blended RMM/C2 channel.
7. **Credential Access** - Kerberoasting/SPN enumeration, exact reported `comsvcs.dll` MiniDump + `tasklist`/`find lsass` one-liner (mixed-case `CmD.eXe`), NTDS dumping via NetExec, decoy Mimikatz artifact.
8. **Lateral Movement** - GoTo Resolve deployed to additional servers/domain controllers using compromised service-account credentials, RDP/SMB/WinRM pivot patterns, exact reported NetExec (`nxc`) command lines, privileged account password resets.
9. **Collection / Exfiltration** - sensitive data staged, then Rclone (real v1.73.5 binary) run with the exact reported flag set, copying to a local-remote sandbox standing in for Wasabi cloud storage.
10. **Impact** - Defender disabled/excluded, VMs stopped, The Gentlemen ransomware (`gentlemen_locker.exe`) with real AES-256 encryption confined to a sandbox folder, ransom note, real Volume Shadow Copy deletion via WMI, decoy event-log clearing, and domain-wide propagation reproduced via a scheduled task standing in for the reported malicious GPO/SYSVOL/NETLOGON deployment mechanism.

## Lab-safe alternative

For a guarded version that preserves representative process, registry, staging, IOC, and impact artifacts without live C2, real credential access, security-control impairment, shadow-copy deletion, or user-data encryption, use:

- [`Invoke-GentlemenEmulation.ps1`](Invoke-GentlemenEmulation.ps1)
- [`README-LabSafe.md`](README-LabSafe.md)

The guarded emulator requires `-ConfirmLab`, refuses domain controllers, pins every IOC-shaped request to `127.0.0.1`, records exact cleanup state, and uses the current `T1574.001` ATT&CK mapping for DLL side-loading.

## Usage

```powershell
# Run everything end-to-end (requires admin, run on a disposable VM only)
.\GentlemanSim-Complete.ps1

# Optional: also dump the REAL lsass.exe (default dumps a decoy process instead)
.\GentlemanSim-Complete.ps1 -DumpRealLsass
```

Individual phases can be dot-sourced and run separately for step-by-step training/detection-engineering walkthroughs; each phase file exports one `Simulate-*` function taking the `$SimPaths` hashtable produced by `Initialize-SimulationEnvironment` in `GentlemanSim-utilities.ps1`.

## Safety notes / deliberate substitutions

- **Isolated lab VM only.** Snapshot before running. This script creates real local accounts, services, scheduled tasks, registry keys, deletes real Volume Shadow Copies, and attempts real outbound connections to actual reported threat-actor/blockchain/SaaS infrastructure (which should fail closed off the internet or on an isolated network, but do not assume that).
- File "encryption" in Phase 10 is real AES-256 but is hard-scoped to `C:\GentlemanSim\victim_files` - it never touches the analyst's real user data.
- `comsvcs.dll` LSASS dumping defaults to a decoy `notepad.exe` process; pass `-DumpRealLsass` only if the VM contains no real credential material you care about.
- Event log "clearing" in Phase 10 targets a dedicated decoy custom log (`GentlemanSim-DecoyForensicLog`), never the real Security/System/Application logs.
- The malicious-GPO domain-wide deployment mechanism is reproduced via a local Scheduled Task (create/remove) rather than an actual Group Policy Object, since GPO creation requires a real AD forest with Group Policy Management tools - the scheduled-task execution pattern from SYSVOL/NETLOGON staged binaries is preserved.
- Node.js and Rclone are downloaded live from their legitimate official sources when internet egress is available (matching the exact versions/URLs in the report), falling back to inert decoy binaries offline.
- EtherRAT/TukTuk/The Gentlemen malware components themselves (obfuscated JS payload, sideloaded DLLs, locker binary) are always inert `New-DecoyBinary` placeholders - never functional malicious code.
- Kerberoasting/NTDS/domain-group discovery steps branch on `Test-DomainJoined` and fall back to local-only equivalents on a standalone (non-domain) lab VM.

## Key IOCs (from the report)

| Type | Value | Role |
|---|---|---|
| Domain | `1rpc[.]io` | EtherHiding - Ethereum smart contract RPC endpoint used for C2 resolution |
| Domain | `*.trycloudflare.com` (11 subdomains) | EtherRAT active C2 tunnel + decoy domains |
| Domain | `vefbdzzuaadnascpeqcn.supabase[.]co` | TukTuk primary C2 (Supabase) |
| Domain | `k135neflez.westus3.azure.clickhouse[.]cloud` | TukTuk primary C2 (ClickHouse) |
| Domain | `borjumaniya[.]store` | TukTuk fallback HTTP C2 |
| Domain | `gotoresolve[.]com` | RMM tool abused for lateral movement/C2 |
| Domain | `wasabisys[.]com` | Exfiltration destination (Wasabi cloud storage) |
| Ethereum contracts | `0xdf0b529043ef7a2bb9111bad26de624a326bacf9`, `0x5953f27F044779a3AFCd2BF56a4B712583Dd2E4e` | EtherHiding config storage |
| Arweave Drive-Id | `a6278417-39f4-407e-90bf-599f74726e66` | TukTuk dead-drop resolver tag (capability present, use unconfirmed) |
| Hash (SHA256) | `d9487fdc097f770e5661f9e5dee130068cb179d33716abff1a21c8cb901f25a6` | `RAMMap.msi` (Initial Access) |
| Hash (SHA256) | `8c2665adf8bfab65463f2a9bd1b7bb0231de3f5c1e6a2e51479e44aaac2e7bf0` | `MVnVmUYj.cmd` (EtherRAT) |
| Hash (SHA256) | `4142d5efd4ea2abab77f2f0a917610e2ff976bf9e19d7ad1e9156eccdc5412db` | `A7Pnj975bl.cfg` (EtherRAT) |
| Hash (SHA256) | `2d4b4bb18b8445e49eeda571982874403befcecf78266e3d405f6529d98bee46` | `v72HYLU3OpRBznc.ini` (EtherRAT) |
| Hash (SHA256) | `19021e53b9929fdf4b7d0e0707434d56bb73c1a9b7403c8837b44d1c417198dc` | `log4net.dll` (TukTuk) |
| Hash (SHA256) | `1795eacd2c58894ccdd6be8854fe6456c3b069a3a873432343b57b475b256aee` | `smokymo.msi` (GoTo Resolve installer) |

See the source report's Detection Engineering and Threat Hunting (DEATH) section for full Suricata/ET OPEN rule IDs (`2058788`, `2058739`, `2034552`, `2058175`, `2060250`, `2050130`, `2061992`, `2061989`, `2046657`) to validate against the artifacts this simulation produces.

## MITRE ATT&CK

T1204.002, T1036.005, T1105, T1071.001, T1568, T1547.001, T1219, T1082, T1518.001, T1069, T1087, T1018, T1046, T1574.002, T1102, T1558.003, T1003.001, T1003.003, T1021.001, T1021.002, T1021.006, T1078, T1098, T1560, T1567.002, T1562.001, T1490, T1070.001, T1486, T1484.001.
