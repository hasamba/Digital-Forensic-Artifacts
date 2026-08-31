# 081 - RDP, Empire, Koadic, and PYSA in Eight Hours

Lab-safe companion to The DFIR Report's [PYSA/Mespinoza Ransomware](https://thedfirreport.com/2020/11/23/pysa-mespinoza-ransomware/) (internal case 1010). It preserves three Tor RDP handoffs, valid Domain Administrator access, minute-three DC pivot, Empire fallback, Koadic/MSHTA and task persistence, extensive credential collection, security-tool markers, discovery, RDP/PsExec/PowerShell Remoting, post-ransom canary-document access, and PYSA deployment around hour 7.5.

Run elevated on a disposable Windows member workstation or member server—not a domain controller:

```powershell
$env:DFIR_LAB_CONFIRMATION = 'I_UNDERSTAND_THIS_IS_A_LAB'
.\PysaSim-Complete.ps1 -LabConfirmed
```

Artifacts remain under `%PUBLIC%\PysaSim`; cleanup is separate with `.\Cleanup-PysaSim.ps1 -LabConfirmed`.

The phases cover RDP/Empire entry, Koadic/credentials/discovery/movement, and exfiltration/PYSA impact. Investigators should begin with `artifact-manifest.jsonl` and `evidence\exercise-timeline.jsonl`, then review `rdp-empire.json`, `koadic-task.json`, `credential-checklist.json`, `security-impairment.json`, `discovery-movement.json`, `exfiltration.json`, generated host and honey-document trees, `impact.json`, and synthetic ransom notes.

All executables are copied, signed `cmd.exe` decoys with a fixed benign `echo`; HTA and PowerShell artifacts are inert text. Network attempts are forced to `127.0.0.1`, proxy use is false, and zero bytes are transferred. No authentication/RDP, malware/C2, task, policy/Defender/exclusion/process/firewall change, LSASS/NTDS/shadow-copy/backup/LSA access, PsExec/PowerShell Remoting, real DC or remote-host access, user-data read, exfiltration, encryption, or impairment occurs. Real domain controllers are refused.

The report maps: T1133, T1078, T1061, T1218.005, T1059.001, T1087.001, T1018, T1083, T1482, T1087, T1053.005, T1570, T1021.002, T1021.001, T1003, T1003.001, T1057, T1071, T1041, T1486, and T1218.011.
