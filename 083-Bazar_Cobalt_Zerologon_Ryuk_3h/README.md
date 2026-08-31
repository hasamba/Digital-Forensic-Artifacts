# 083 - Bazar, Cobalt Strike, Zerologon, and Ryuk in three hours

Lab-safe companion to The DFIR Report's [Ryuk Speed Run, 2 Hours to Ransom](https://thedfirreport.com/2020/11/05/ryuk-speed-run-2-hours-to-ransom/) (internal case 1007). It preserves the phishing link and Google Drive lure, `Report-Review20-10.exe`, Bazar Loader, unusual scheduled-task and Run-key persistence, domain recon, two Cobalt channels, AdFind, Zerologon, Rubeus, process-injection metadata, FTP staging, RDP/SMB movement to two DC representations, and Ryuk's server-first deployment. The report's exact timing is retained: ransomware deployment starts around two hours and reported domain-wide impact completes around three hours.

Run elevated on a disposable Windows member workstation or member server—not a domain controller:

```powershell
$env:DFIR_LAB_CONFIRMATION = 'I_UNDERSTAND_THIS_IS_A_LAB'
.\RyukSpeedSim-Complete.ps1 -LabConfirmed
```

Artifacts remain under `%PUBLIC%\RyukSpeedSim`; cleanup is a separate, explicit action with `.\Cleanup-RyukSpeedSim.ps1 -LabConfirmed`.

Start with `artifact-manifest.jsonl` and `evidence\exercise-timeline.jsonl`. Then inspect `persistence-markers.json`, `bazar-recon.json`, `adfind-execution.json`, `zerologon-marker.json`, `injection-marker.json`, `lateral-movement.json`, `ftp-exfiltration.json`, `pre-impact-commands.json`, and `impact-summary.json`. Generated server/workstation trees and synthetic AdFind/Kerberoast output give an analyst evidence to trace without touching a real domain.

All executable names are signed `cmd.exe` copies invoked only with fixed benign `echo` arguments. Published malware hashes never match the decoys. Every reported endpoint is metadata-only; runtime socket attempts are forced to `127.0.0.1`, use no proxy, and transfer zero bytes. No malware, phishing link, download, task, Run key, domain query, Zerologon action, credential access, process injection, PowerShell, RDP/SMB/FTP session, service, process termination, ACL change, or user-data encryption occurs. Real domain controllers are refused.

The report maps T1566.002, T1059.001, T1059, T1204, T1055, T1068, T1482, T1069.002, T1087.002, T1018, T1021.002, T1021.001, T1560, T1048.003, T1071, T1043, T1486, T1553.002, T1569.002, T1053.005, T1547.001, and T1558.003.
