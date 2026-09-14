# 074 - IcedID, Cobalt Strike, Rclone, and Sodinokibi in 4.5 Hours

Lab-safe companion to The DFIR Report's [Sodinokibi (aka REvil) Ransomware](https://thedfirreport.com/2021/03/29/sodinokibi-aka-revil-ransomware/) (internal case 1051). It preserves the report's malspam-to-IcedID ancestry, two Cobalt profiles, deceptive Exchange pivot, domain discovery and movement, Rclone double-extortion path, BITS deployment, Safe Mode sequence, domain-controller DLL path, and 4.5-hour completion point.

## Run

Use an elevated PowerShell prompt on a disposable Windows member workstation or member server—not a domain controller:

```powershell
.\IcedRevilSim-Complete.ps1 -LabConfirmed
```

Artifacts remain under `%PUBLIC%\IcedRevilSim` for investigation. Cleanup is a separate, explicit action:

```powershell
.\Cleanup-IcedRevilSim.ps1 -LabConfirmed
```

## Exercise map

| Report-relative time | Script | Evidence represented |
|---:|---|---|
| 0-90 minutes | `IcedRevilSim-Phase1-IcedID-Entry.ps1` | XLSM lure, `microsoft.security`, `index.gif`, Excel → WMIC → regsvr32 → rundll32 ancestry, IcedID task, discovery, and C2 |
| 90-210 minutes | `IcedRevilSim-Phase2-Cobalt-Domain.ps1` | Two Cobalt profiles, UAC/injection markers, BloodHound/LDAP, Exchange pivot, AdFind, SMB/service/PowerShell movement, RDP, credential and GPO markers |
| 210-270 minutes | `IcedRevilSim-Phase3-Rclone-REvil.ps1` | Rclone-as-`svchost`, exfiltration marker, BITS fan-out, `-smode`, RunOnce/boot markers, generated-host impact, DC DLL route, ransom notes |

Useful pivots include `artifact-manifest.jsonl`, `evidence\exercise-timeline.jsonl`, reported-vs-actual process arguments, `bloodhound-ldap.json`, `some.csv`, `rclone-exfiltration.json`, `runonce-safe-mode.json`, generated host trees, and the synthetic ransom-note fan-out. `IOC-METADATA.json` retains the report's infrastructure, sample hashes, TLS fingerprints, and detections without retrieving any sample or resolving/contacting an IOC.

## Safety boundary

Every executable is a copied, signed `cmd.exe` decoy invoked only with a fixed benign `echo` command. IOC network telemetry is forced to `127.0.0.1`, proxy use is false, and zero bytes are transferred. The scenario performs no malware retrieval, macro execution, process injection, scheduled-task or registry creation, credential/LSASS access, LDAP or network scanning, SMB/RDP/service movement, GPO/SYSVOL change, security impairment, BITS job, boot or logon change, reboot, data theft, file encryption, or real ransom activity. Host and share targets are generated local canaries. Real domain controllers are refused before artifact creation.

The report's ATT&CK set is retained in `scenario-manifest.json`: T1566.001, T1204, T1047, T1055, T1482, T1087.002, T1082, T1016, T1518.001, T1021.002, T1021.001, T1043, T1071, T1048.002, T1486, T1204.002, T1059, T1059.001, T1053.005, T1018, and T1218.011.
