# 011 - Cat's Got Your Files: Lynx Ransomware

Lab-safe PowerShell adversary emulation based on The DFIR Report's [Cat's Got Your Files: Lynx Ransomware](https://thedfirreport.com/2025/12/17/cats-got-your-files-lynx-ransomware/) (December 17, 2025).

## Report-faithful chain

The scenario represents the report's approximately 178-hour, nine-day intrusion:

| Report time | Represented activity |
|---|---|
| Day 1 | Valid-account RDP from `195.211.190.189`, native discovery, NetScan v7.2.7, RDP pivot to a DC, look-alike privileged accounts, and AnyDesk persistence |
| Day 2 | Privileged-account validation against hypervisor targets |
| Day 6 | NetScan repeat, NetExec SMB enumeration, share browsing, 7-Zip collection, and individual `temp.sh/upload` submissions |
| Day 8 | RDP return from `77.90.153.30`, local policy review, DC/hypervisor discovery, and appliance browsing cues |
| Day 9 | RDP to backup/file servers, Veeam job deletion, and `w.exe --dir E:\ --mode fast --verbose --noprint` |

File timestamps and `nine-day-timeline.jsonl` preserve those clusters. Current process events necessarily occur when the scenario is run.

## Fidelity and safety substitutions

- `netscan.exe`, `nxc.exe`, `AnyDesk.exe`, `7zG.exe`, and `w.exe` are renamed copies of signed Windows `cmd.exe`. They create authentic executable-name, Prefetch, Amcache, shortcut, and process telemetry but only execute `echo` canaries.
- Interactive decoys are launched through `.lnk` files and Windows Shell where available, providing `explorer.exe`-brokered ancestry. A direct safe launch is used if shell automation is unavailable.
- The two public RDP source IPs, hostname `DESKTOP-BUL6K1U`, victim subnet, domain controllers, hypervisors, and file servers are metadata only.
- Actual RDP, SMB, scan, and upload attempts target only `127.0.0.1`. The `temp.sh` command uses `curl --resolve temp.sh:443:127.0.0.1 --noproxy *` and never follows redirects.
- Domain users, non-expiring passwords, group memberships, AnyDesk service state, and NetExec results are local JSON/configuration canaries. No AD cmdlet, domain, GPO, service, or remote host is changed.
- Collected documents are generated beneath `%PUBLIC%\LynxSim\shares`; no user or network-share data is read.
- The Veeam before/after state and deletion log are local canaries. Veeam and real backups are never accessed.
- `w.exe` creates `.LYNX` representation files beside intact generated canaries. It performs no cryptography and touches no user data.
- No shadow-copy command is executed, no security control is impaired, and no log is cleared.

Reported malicious hashes are retained as metadata. The signed decoys intentionally do not match them, and the runtime manifest records both values.

## Run

From an elevated Windows PowerShell 5.1 or later console on a disposable investigation VM:

```powershell
.\LynxSim-Complete.ps1 -LabConfirmed
```

The script refuses domain controllers by checking `Win32_ComputerSystem.DomainRole` and the `NTDS` service. It also refuses to overwrite an existing Desktop `000` folder or `w.exe` unless its scenario ownership marker is present.

Artifacts remain for acquisition beneath `%PUBLIC%\LynxSim`, plus these report-faithful Desktop artifacts:

- `%USERPROFILE%\Desktop\000\netscan.exe`
- `%USERPROFILE%\Desktop\000\netscan.xml`
- `%USERPROFILE%\Desktop\000\netscan.lic`
- `%USERPROFILE%\Desktop\000\ss.xml`
- `%USERPROFILE%\Desktop\000\nxc.exe`
- `%USERPROFILE%\Desktop\000\nxc.txt`
- `%USERPROFILE%\Desktop\000\7zG.exe`
- `%USERPROFILE%\Desktop\w.exe`

Review `artifact-manifest.jsonl`, `nine-day-timeline.jsonl`, process creation, shortcut, Prefetch, Amcache, MFT, USN Journal, RDP, and browser/network evidence before cleanup.

## Cleanup

Cleanup is deliberately separate. Preview it first:

```powershell
.\Cleanup-LynxSim.ps1 -LabConfirmed -WhatIf
.\Cleanup-LynxSim.ps1 -LabConfirmed
```

The cleanup script validates the fixed scenario root and ownership markers. It removes only known Desktop artifacts, refuses to remove an unowned `000` directory, and leaves that directory in place if an analyst added unrelated files.

## ATT&CK mapping from the report

| Technique | ID |
|---|---|
| Valid Accounts | T1078 |
| External Remote Services | T1133 |
| Remote Desktop Protocol | T1021.001 |
| Windows Command Shell | T1059.003 |
| PowerShell | T1059.001 |
| System Network Configuration Discovery | T1016 |
| System Information Discovery | T1082 |
| Network Service Scanning | T1046 |
| Remote System Discovery | T1018 |
| Network Share Discovery | T1135 |
| Query Registry | T1012 |
| Create Account: Domain Account | T1136.002 |
| Additional Local or Domain Groups | T1098.007 |
| Remote Access Software | T1219 |
| Windows Service | T1543.003 |
| Account Discovery: Local Account | T1087.001 |
| Archive Collected Data: Archive via Utility | T1560.001 |
| Exfiltration Over Web Service | T1567 |
| Inhibit System Recovery | T1490 |
| Data Encrypted for Impact | T1486 |

T1490 and T1486 are represented entirely through backup-state and extension canaries; the underlying destructive actions never occur.

## Primary IOCs

See [IOC-METADATA.json](IOC-METADATA.json) for MD5, SHA-1, SHA-256, source IP, hostname, service, and detection-rule metadata taken from the report.
