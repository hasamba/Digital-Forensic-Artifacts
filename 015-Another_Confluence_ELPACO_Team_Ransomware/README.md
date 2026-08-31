# 015 - Another Confluence Bites the Dust: ELPACO-team Ransomware

Lab-safe PowerShell adversary emulation based on The DFIR Report's [Another Confluence Bites the Dust: Falling to ELPACO-team Ransomware](https://thedfirreport.com/2025/05/19/another-confluence-bites-the-dust-falling-to-elpaco-team-ransomware/) (May 19, 2025).

## Report sequence reproduced

| Report time | Scenario evidence |
|---|---|
| Day 1 | CVE-2023-22527 requests, `tomcat9.exe` discovery children, `HAHLGiDDb.exe` and randomized loader names, `91.191.209.46:12385` metadata, four DLL/named-pipe pairs, AnyDesk deployment, `u1.bat`, and synthetic local-account events |
| Day 2 | Short AnyDesk sessions plus additional Confluence scanning/discovery from the report's separate source IPs, including the `whaomi` typo |
| Day 3 | `Attacker\share` transfer records, `spider.dll`, failed and successful elevation evidence, Mimikatz x64/x86 executions, generated `Result.txt`, ProcessHacker/LSASS events, eight `secretsdump.exe` commands, `sessionresume_` artifact, NetScan, RPC/PrintNightmare discovery, WMIEXEC, share, and RDP telemetry |
| ~62 hours | `ELPACO-team.exe` copy to backup and file-server canaries, 7-Zip SFX layout, GUID directory, `svhostss.exe` child commands, Run-key evidence, `MIMIC_LOG.txt`, `session.tmp`, VM/security/log-deletion metadata, `.ELPACO-team` extension files, and `Decryption_INFO.txt` |

The runtime `sixty-two-hour-timeline.jsonl` and backdated files preserve the reported clusters. Process events themselves occur when the scenario runs.

## Fidelity and safety substitutions

- The scenario requires an explicit lab confirmation and refuses domain controllers by domain role and the presence of the NTDS service.
- Every executable or DLL decoy is a renamed, locally copied Windows `cmd.exe`, or a text canary. Published hashes are preserved separately and are not claimed as matches.
- Reported command lines execute only through `cmd.exe /c echo` after CMD metacharacters are escaped. Mimikatz, secretsdump, rpcdump, wmiexec, AnyDesk, NetScan, and ELPACO functionality is never invoked.
- `45.227.254.124`, `91.191.209.46`, and other report IPs remain metadata. TCP attempts go only to `127.0.0.1`; no proxy, DNS lookup, HTTP download, SMB connection, WMI call, or RDP session reaches another system.
- Account and group creation, Zerologon, PrintNightmare, named-pipe impersonation, token duplication, services, shares, RDP enablement, firewall changes, Defender policy changes, Run-key persistence, and remote execution are synthetic records only.
- LSASS, SAM, LSA secrets, Credential Manager, Remote Registry, and NTDS are never opened. `Result.txt` contains generated identities and an all-zero hash.
- NetScan's reported ports `88`, `137`, `445`, `3389`, and `6160` are attempted only on loopback. `delete.me` evidence is confined to generated local host trees.
- ELPACO's SFX folder and filenames are reproduced without unpacking software or a malicious binary. Its published extraction password is metadata only.
- VM stop/dismount, process termination/access, log deletion, and security-tool disabling are never executed.
- `.ELPACO-team` marker files are created beside intact, generated canaries. No cryptography or user-data traversal occurs.
- The report observed no meaningful exfiltration; the scenario records the roughly 70 MB AnyDesk total as metadata without transferring data.

## Run

Use an elevated Windows PowerShell 5.1 or later session on a disposable lab VM:

```powershell
$env:DFIR_LAB_CONFIRMATION = 'I_UNDERSTAND_THIS_IS_A_LAB'
.\ElpacoSim-Complete.ps1 -LabConfirmed
```

Artifacts are written only below `%PUBLIC%\ElpacoConfluenceSim` and remain in place for investigation. The root has a scenario ownership marker; execution refuses an existing unowned directory.

## Cleanup

Cleanup is a separate, explicit operation:

```powershell
.\Cleanup-ElpacoSim.ps1 -LabConfirmed -WhatIf
.\Cleanup-ElpacoSim.ps1 -LabConfirmed
```

Cleanup revalidates the lab gate, fixed path, and ownership marker before removing the scenario tree.

## ATT&CK mapping from the report

T1071, T1136, T1134.002, T1486, T1562.004, T1562.001, T1068, T1190,
T1105, T1136.001, T1003.001, T1112, T1003.003, T1059.001, T1057,
T1012, T1219, T1021.001, T1018, T1016, T1059.003, T1047, and T1543.003.

See [IOC-METADATA.json](IOC-METADATA.json) for report indicators and [scenario-manifest.json](scenario-manifest.json) for machine-readable phase and safety metadata.
