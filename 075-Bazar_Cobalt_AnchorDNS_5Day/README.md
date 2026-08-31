# 075 - Bazar, Cobalt Strike, and AnchorDNS Over Five Days

Lab-safe companion to The DFIR Report's [Bazar Drops the Anchor](https://thedfirreport.com/2021/03/08/bazar-drops-the-anchor/) (internal case 1017). It preserves the failed DocuSign XLS retrieval, manual Bazar follow-on, WerFault injection, Cobalt and AnchorDNS arrival, early domain-controller movement, four-day C2 dwell, honey-document access, day-three `Get-DataInfo`, day-four Advanced IP Scanner, and day-five access cutoff before the assessed Ryuk objective.

## Run

From an elevated PowerShell prompt on a disposable Windows member workstation or member server—not a domain controller:

```powershell
$env:DFIR_LAB_CONFIRMATION = 'I_UNDERSTAND_THIS_IS_A_LAB'
.\BazarAnchorSim-Complete.ps1 -LabConfirmed
```

Artifacts remain under `%PUBLIC%\BazarAnchorSim`. Cleanup is separate:

```powershell
.\Cleanup-BazarAnchorSim.ps1 -LabConfirmed
```

## Exercise map

| Report-relative time | Script | Evidence represented |
|---:|---|---|
| 0-2 hours | `BazarAnchorSim-Phase1-Entry-Domain.ps1` | XLS, failed retrieval, manual loader, Bazar/WerFault, discovery, Cobalt, AnchorDNS, credential marker, PowerShell/service/SMB/RDP movement to generated hosts |
| Days 1-4 | `BazarAnchorSim-Phase2-Dwell-Collection.ps1` | Three-family C2 dwell, report-listed task marker, honey docs, assessed C2 exfiltration, `C:\info\start.bat`, inert `Get-DataInfo.ps1`, Advanced IP Scanner, public-IP checks |
| Day 5 | `BazarAnchorSim-Phase3-Cutoff-NoRyuk.ps1` | Access cutoff and explicit absence of ransomware deployment or final impact |

Start with `artifact-manifest.jsonl` and `evidence\exercise-timeline.jsonl`, then pivot through reported-vs-actual process arguments, `dc-discovery-movement.json`, `four-day-c2.json`, `honey-doc-access.json`, `get-datainfo.json`, `day4-scan.json`, and `assessed-final-objective.json`. `IOC-METADATA.json` retains hashes, infrastructure, TLS fingerprints, Cobalt configuration, PDB paths, honey-document telemetry, and detection references.

## Safety boundary

All executables are copied, signed `cmd.exe` decoys and receive only a fixed benign `echo` command. Every C2, DNS, external-IP, SMB, and RDP attempt is forced to `127.0.0.1`, with proxy disabled and zero bytes transferred. The scenario performs no malware retrieval, macro execution, injection, task creation, real discovery or scan, credential/LSASS access, remote service/SMB/RDP movement, user-data access, exfiltration, security-control change, log clearing, or ransomware impact. `Get-DataInfo.ps1` and `start.bat` are inert comment-only canaries. Targets are generated local directories, and real domain controllers are refused.

The report's ATT&CK set is retained in `scenario-manifest.json`: T1566.002, T1059, T1204.002, T1053.005, T1204, T1055, T1071.004, T1043, T1071, T1041, T1021.002, T1482, T1087.002, T1018, T1082, and T1003.
